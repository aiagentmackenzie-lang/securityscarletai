"""Composite login-lockout gate (remediation F-05 — plan phase 3).

Problem with the flat model (proven live 2026-08-28, "P1-F"): per-username
5-failure locking that RENEWS on every failure means a permanent targeted
lockout of any known username at 4 req/min — under the 5/min IP login limit.
Valid-username lockout DoS.

Composite policy (documented tradeoff; zero-risk doesn't exist):
  1. Failures count PER (username, ip) pair in Redis, window = 15 minutes.
  2. When ONE ip accumulates FAILS_TO_LOCK (5) failures, the account locks
     with an EXPONENTIAL duration: 15m, then 1h, then 6h (cap). Offense grows
     more expensive; a correct login or admin intervention resets the streak.
  3. Distributed noise defense: if failures for the username arrive from
     more than MAX_DISTINCT_IPS distinct IPs in the window, DO NOT lock —
     that is bot traffic; the IP rate limiter caps the volumetric side and
     locking would just DoS the victim account.
  4. A correct password clears the (username, ip) counter and the lock streak.

RESIDUAL RISK (deliberate, written down): an attacker able to drive 5
failures from 20 distinct IPs each could still lock an account — countering
that with an account-wide counter would reintroduce the original DoS. This
control favors availability while making single-IP brute force expensive.

Redis ops are best-effort: with Redis unavailable, the module returns
verdict=None and the caller falls back to the legacy DB-only rule (5 failed
attempts -> flat 15-min lock) — the pre-F-05 behavior, wrong on distributed
noise but functional without Redis (fail-open availability tradeoff).
"""

from __future__ import annotations

from typing import Any, Optional

from src.api.redis_client import _get_client
from src.config.logging import get_logger

log = get_logger("api.lockout")

_FAIL_PREFIX = "scarletai:v1:login_fail"
_IPS_PREFIX = "scarletai:v1:login_fail_ips"
_STREAK_PREFIX = "scarletai:v1:lock_streak"

FAILS_TO_LOCK = 5
FAIL_WINDOW_SECONDS = 15 * 60
LOCK_STEPS: tuple[int, ...] = (900, 3600, 21600)  # 15min, 1h, 6h(cap)
MAX_DISTINCT_IPS = 20


def _key_fail(username: str, ip: str) -> str:
    return f"{_FAIL_PREFIX}:{username}:{ip}"


def _key_ips(username: str) -> str:
    return f"{_IPS_PREFIX}:{username}"


def _key_streak(username: str) -> str:
    return f"{_STREAK_PREFIX}:{username}"


def register_failure(
    username: str,
    ip: str,
    client: Any = None,
) -> tuple[Optional[bool], int]:
    """Record one failed attempt. Returns (should_lock, lock_seconds).

    should_lock:
      True  -> caller must set locked_until = now + lock_seconds
      False -> do not lock (under threshold, or distributed noise)
      None  -> Redis unavailable: caller falls back to legacy DB-only rule
    """
    c = client if client is not None else _get_client()
    if c is None:
        log.debug("lockout_no_redis_legacy_fallback")
        return (None, 0)

    try:
        fail_key = _key_fail(username, ip)
        count = int(c.incr(fail_key) or 0)
        if count == 1:
            c.expire(fail_key, FAIL_WINDOW_SECONDS)
        c.sadd(_key_ips(username), ip)
        c.expire(_key_ips(username), FAIL_WINDOW_SECONDS)

        distinct = int(c.scard(_key_ips(username)) or 0)
        if distinct > MAX_DISTINCT_IPS:
            log.warning(
                "lockout_distributed_noise_no_lock",
                username=username,
                distinct_ips=distinct,
            )
            return (False, 0)

        if count >= FAILS_TO_LOCK:
            streak = 0
            try:
                streak = int(c.get(_key_streak(username)) or 0)
            except Exception:  # noqa: S110 — streak is best-effort
                streak = 0
            sidx = min(max(streak, 0), len(LOCK_STEPS) - 1)
            seconds = LOCK_STEPS[sidx]
            c.incr(_key_streak(username))
            log.warning(
                "account_lock_issued",
                username=username,
                ip=ip,
                attempts=count,
                lock_seconds=seconds,
                streak=streak,
            )
            return (True, seconds)

        return (False, 0)
    except Exception as e:
        log.warning("lockout_redis_failed", error=str(e))
        return (None, 0)


def register_success(username: str, ip: str, client: Any = None) -> None:
    """Clear the failure counter for (username, ip) and the lock streak."""
    c = client if client is not None else _get_client()
    if c is None:
        return
    try:
        c.delete(_key_fail(username, ip))
        c.delete(_key_streak(username))
    except Exception as e:
        log.debug("lockout_success_clear_failed", error=str(e))


def reset_streak(username: str, client: Any = None) -> None:
    """Admin reset of the exponential lock streak (not wired to an endpoint yet)."""
    c = client if client is not None else _get_client()
    if c is None:
        return
    try:
        c.delete(_key_streak(username))
    except Exception as e:  # pragma: no cover — defensive
        log.debug("lockout_streak_reset_failed", error=str(e))
