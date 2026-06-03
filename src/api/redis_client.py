"""
Redis client singleton — used for JWT blocklist, rate limiting, and user_revoke markers.

Design notes:
- Lazy initialization: connection only attempted when first call is made.
- If Redis is unavailable, all auth methods degrade gracefully (blocklist is a
  best-effort check; if Redis is down, accept the token — log a warning).
  This is the correct trade-off: in a production SOC, you'd want Redis HA.
  Here, we err on the side of "service stays up if Redis flaps."
- All keys are namespaced with a version prefix to allow future schema migration.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import redis

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("api.redis_client")

_KEY_PREFIX = "scarletai:v1:"
_client: Optional[redis.Redis] = None
_connect_attempted = False


def _get_client() -> Optional[redis.Redis]:
    """Get or lazily initialize the Redis client. Returns None on failure."""
    global _client, _connect_attempted
    if _client is not None:
        return _client
    if _connect_attempted:
        return None  # Already failed once, don't hammer
    _connect_attempted = True
    try:
        _client = redis.Redis.from_url(
            settings.redis_url,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
            decode_responses=True,
        )
        _client.ping()
        log.info("redis_connected")
        return _client
    except Exception as e:
        log.warning("redis_unavailable", error=str(e))
        _client = None
        return None


def reset_client() -> None:
    """Reset the singleton (for tests)."""
    global _client, _connect_attempted
    if _client is not None:
        try:
            _client.close()
        except Exception:  # pragma: no cover — defensive
            log.debug("redis_close_noop", note="client already closed or unreachable")
    _client = None
    _connect_attempted = False


# ───────────────────────────────────────────────────────────────
# JWT blocklist (Epic 5)
# ───────────────────────────────────────────────────────────────

def blocklist_jti(jti: str, ttl_seconds: int) -> bool:
    """Add a jti to the blocklist with TTL. Returns True on success."""
    client = _get_client()
    if client is None:
        return False
    try:
        client.setex(f"{_KEY_PREFIX}jwt_blocklist:{jti}", ttl_seconds, "1")
        return True
    except Exception as e:
        log.warning("redis_blocklist_set_failed", error=str(e))
        return False


def is_jti_blocked(jti: str) -> bool:
    """Check if a jti is in the blocklist. Returns False on Redis error (fail-open)."""
    client = _get_client()
    if client is None:
        return False
    try:
        return client.exists(f"{_KEY_PREFIX}jwt_blocklist:{jti}") > 0
    except Exception as e:
        log.warning("redis_blocklist_check_failed", error=str(e))
        return False


# ───────────────────────────────────────────────────────────────
# User revocation (Epic 5 — change-password invalidates all tokens)
# ───────────────────────────────────────────────────────────────

def set_user_revoke_marker(username: str, issued_at: datetime, ttl_seconds: int) -> bool:
    """Set a user_revoke marker. All tokens issued BEFORE this ts are invalid.

    Stored as user_revoke:<username>:<ts> with a TTL.
    """
    client = _get_client()
    if client is None:
        return False
    try:
        ts = int(issued_at.timestamp())
        client.setex(f"{_KEY_PREFIX}user_revoke:{username}:{ts}", ttl_seconds, "1")
        return True
    except Exception as e:
        log.warning("redis_user_revoke_set_failed", error=str(e))
        return False


def get_latest_user_revoke_ts(username: str) -> Optional[float]:
    """Get the latest user_revoke timestamp for a user, or None if no revocations."""
    client = _get_client()
    if client is None:
        return None
    try:
        latest: Optional[float] = None
        pattern = f"{_KEY_PREFIX}user_revoke:{username}:*"
        for key in client.scan_iter(match=pattern, count=100):
            # key format: scarletai:v1:user_revoke:<username>:<ts>
            try:
                ts_str = key.rsplit(":", 1)[-1]
                ts = float(ts_str)
                if latest is None or ts > latest:
                    latest = ts
            except (ValueError, IndexError):
                continue
        return latest
    except Exception as e:
        log.warning("redis_user_revoke_check_failed", error=str(e))
        return None
