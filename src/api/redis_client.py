"""
Redis client singleton — used for JWT blocklist, rate limiting, and user_revoke markers.

Design notes:
- Lazy initialization: connection only attempted when first call is made.
- If Redis is unavailable, all auth methods degrade gracefully (blocklist is a
  best-effort check; if Redis is down, accept the token — log a warning).
  This is the correct trade-off: in a production SOC, you'd want Redis HA.
  Here, we err on the side of "service stays up if Redis flaps."
- All keys are namespaced with a version prefix to allow future schema migration.
- P2-32 (closed by P2.1): this client is now `redis.asyncio`. Every op is a
  coroutine awaited from async request paths, so a Redis outage can no longer
  block the event loop with sync socket timeouts. The bounded-retry + cooldown
  pattern (F-08) is preserved: 3 connect attempts with exponential backoff
  (awaited, not slept), then a 30s cooldown before the next connect round.
- Callers MUST await: is_jti_blocked / get_latest_user_revoke_ts run per
  authenticated request (auth.py), blocklist_jti / set_user_revoke_marker on
  auth mutations, and login_lockout on the login path.
"""
from __future__ import annotations

import asyncio
import time as _time
from datetime import datetime
from typing import Any, Callable, Coroutine, Optional

import redis.asyncio as aioredis

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("api.redis_client")

_KEY_PREFIX = "scarletai:v1:"
_client: Optional[aioredis.Redis] = None
# F-08: bounded retry state. One failed attempt used to silence revocation
# checks FOREVER (one transient outage at boot -> logout dead until restart).
_last_failure_ts: float = 0.0
_FAILURE_COOLDOWN_SECONDS = 30.0  # wait between failed connect attempts
_MAX_CONNECT_ATTEMPTS = 3
_SLEEP: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep  # test seam
# Test seam: the client factory. Tests monkeypatch this instead of reaching
# into redis.asyncio internals.
_from_url: Callable[..., aioredis.Redis] = aioredis.Redis.from_url


async def _get_client() -> Optional[aioredis.Redis]:
    """Get or lazily (re-)initialize the Redis client. Returns None on failure.

    F-08: bounded retry (3 attempts, exponential backoff 0.25/0.5/1.0s) — the
    backoff awaits asyncio.sleep so the event loop is NEVER blocked (P2-32).
    After a failed round, a 30s cooldown suppresses further attempts so we
    don't hammer; a Redis outage then costs at most one slow request per 30s
    and recovers WITHOUT a restart (the old one-shot flag never retried).
    """
    global _client, _last_failure_ts
    if _client is not None:
        return _client
    if _last_failure_ts and (
        _time.monotonic() - _last_failure_ts < _FAILURE_COOLDOWN_SECONDS
    ):
        return None  # in cooldown after a failed round — don't hammer

    last_err: Optional[Exception] = None
    for attempt in range(1, _MAX_CONNECT_ATTEMPTS + 1):
        try:
            candidate = _from_url(
                settings.redis_url,
                socket_connect_timeout=1.0,
                socket_timeout=1.0,
                decode_responses=True,
            )
            await candidate.ping()
            _client = candidate
            log.info("redis_connected", attempt=attempt)
            return _client
        except Exception as e:
            last_err = e
            log.warning(
                "redis_connect_attempt_failed",
                attempt=attempt,
                of=_MAX_CONNECT_ATTEMPTS,
                error=str(e),
            )
            # Close the half-open client so its transport doesn't leak.
            try:
                await candidate.aclose()
            except Exception as close_err:  # pragma: no cover — defensive
                log.debug("redis_half_open_close_failed", error=str(close_err))
            if attempt < _MAX_CONNECT_ATTEMPTS:
                await _SLEEP(0.25 * (2 ** (attempt - 1)))

    _last_failure_ts = _time.monotonic()
    log.warning(
        "redis_unavailable",
        attempts=_MAX_CONNECT_ATTEMPTS,
        cooldown_seconds=_FAILURE_COOLDOWN_SECONDS,
        error=str(last_err),
    )
    _client = None
    return None


def reset_client() -> None:
    """Reset the singleton (for tests). Safe from sync test code: when no
    event loop is running the close runs via asyncio.run; inside a running
    loop the close is scheduled as a task. Either way the singleton ref is
    dropped immediately so the next call starts fresh."""
    global _client, _last_failure_ts
    client = _client
    _client = None
    _last_failure_ts = 0.0
    if client is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (sync test teardown) — close on a fresh loop.
        try:
            asyncio.run(client.aclose())
        except Exception:  # pragma: no cover — defensive
            log.debug("redis_close_noop", note="client already closed or unreachable")
        return

    async def _close() -> None:
        try:
            await client.aclose()
        except Exception as close_err:  # pragma: no cover — defensive
            log.debug("redis_close_noop", note="already closed", error=str(close_err))

    loop.create_task(_close())


# ───────────────────────────────────────────────────────────────
# JWT blocklist (Epic 5)
# ───────────────────────────────────────────────────────────────

async def blocklist_jti(jti: str, ttl_seconds: int) -> bool:
    """Add a jti to the blocklist with TTL. Returns True on success."""
    client = await _get_client()
    if client is None:
        return False
    try:
        await client.setex(f"{_KEY_PREFIX}jwt_blocklist:{jti}", ttl_seconds, "1")
        return True
    except Exception as e:
        log.warning("redis_blocklist_set_failed", error=str(e))
        return False


async def is_jti_blocked(jti: str) -> bool:
    """Check if a jti is in the blocklist. Returns False on Redis error (fail-open)."""
    client = await _get_client()
    if client is None:
        return False
    try:
        return bool(await client.exists(f"{_KEY_PREFIX}jwt_blocklist:{jti}"))
    except Exception as e:
        log.warning("redis_blocklist_check_failed", error=str(e))
        return False


# ───────────────────────────────────────────────────────────────
# User revocation (Epic 5 — change-password invalidates all tokens)
# ───────────────────────────────────────────────────────────────

def _user_revoke_key(username: str) -> str:
    """F-09: one fixed key per user — latest revocation wins, no SCAN to read."""
    return f"{_KEY_PREFIX}user_revoke:{username}"


async def set_user_revoke_marker(
    username: str, issued_at: datetime, ttl_seconds: int
) -> bool:
    """Set a user_revoke marker. All tokens issued BEFORE this ts are invalid.

    F-09: writes the ts to the fixed key scarletai:v1:user_revoke:<username>
    (overwrite semantics — latest revocation wins, matching the reader). Also
    writes the legacy timestamped key for one release so a rolling deploy
    where an old worker still scan-reads keeps working.
    """
    client = await _get_client()
    if client is None:
        return False
    try:
        ts = int(issued_at.timestamp())
        await client.setex(_user_revoke_key(username), ttl_seconds, str(ts))
        # legacy scan-format key (read fallback), same TTL
        await client.setex(f"{_KEY_PREFIX}user_revoke:{username}:{ts}", ttl_seconds, "1")
        return True
    except Exception as e:
        log.warning("redis_user_revoke_set_failed", error=str(e))
        return False


async def get_latest_user_revoke_ts(username: str) -> Optional[float]:
    """Get the latest user_revoke timestamp for a user, or None if none.

    F-09: O(1) GET on the fixed key. Falls back to a SCAN of the legacy
    timestamped keys and backfills the fixed key when the fixed key is
    absent (e.g. markers written before this change).
    """
    client = await _get_client()
    if client is None:
        return None
    try:
        fixed = await client.get(_user_revoke_key(username))
        if fixed is not None:
            try:
                return float(fixed)
            except (TypeError, ValueError):
                pass

        # one-release fallback: scan legacy timestamped keys, backfill.
        latest: Optional[float] = None
        pattern = f"{_KEY_PREFIX}user_revoke:{username}:*"
        async for key in client.scan_iter(match=pattern, count=100):
            try:
                ts_str = key.rsplit(":", 1)[-1]
                ts = float(ts_str)
                if latest is None or ts > latest:
                    latest = ts
            except (ValueError, IndexError):
                continue
        if latest is not None:
            try:
                ttl = await client.ttl(_user_revoke_key(username))
                await client.setex(
                    _user_revoke_key(username),
                    ttl if ttl and ttl > 0 else 3600,
                    str(int(latest)),
                )
            except Exception as e:  # pragma: no cover — backfill best-effort
                log.debug("redis_revoke_backfill_failed", error=str(e))
        return latest
    except Exception as e:
        log.warning("redis_user_revoke_check_failed", error=str(e))
        return None
