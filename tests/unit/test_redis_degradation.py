"""P2.1 — Redis degradation honesty.

Before this remediation:
- The rate limiter's documented "fails back to in-memory storage" never
  happened: slowapi's `in_memory_fallback_enabled` was never passed, and
  `Limiter(storage_uri=...)` connects lazily, so the old construction-time
  try/except was dead code. With Redis actually down, every rate-limited
  endpoint 500'd instead of degrading.
- The redis client was SYNC inside async paths (P2-32): a Redis outage
  blocked the event loop for up to the socket timeout per call.

Covered here:
- The limiter ships with a real memory fallback strategy (configured at
  construction, not per-request improvisation).
- A storage failure at request time engages the fallback (no 500), the
  request is evaluated against memory, and the backend recovers
  automatically when it comes back.
- With Redis in cooldown (simulated outage), auth/lockout calls fail open
  immediately — no event-loop stall.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
os.environ.setdefault("API_SECRET_KEY", "x" * 64)
os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)

from tests.unit._test_request import make_test_request  # noqa: E402, I001


# ───────────────────────────────────────────────────────────────
# Rate limiter — real memory fallback (the dead-code fallback is gone)
# ───────────────────────────────────────────────────────────────


class TestRateLimiterMemoryFallback:
    def test_limiter_configured_with_memory_fallback(self):
        from limits.storage import MemoryStorage

        from src.api.rate_limit import limiter

        assert limiter._in_memory_fallback_enabled is True  # noqa: SLF001
        assert limiter._fallback_limiter is not None  # noqa: SLF001
        assert isinstance(  # noqa: SLF001
            limiter._fallback_limiter.storage, MemoryStorage  # noqa: SLF001
        )

    def test_storage_failure_engages_fallback_without_500(self, monkeypatch):
        """A ConnectionError from the storage at request time must be caught
        and served from the memory fallback — NOT raised to the endpoint."""
        from src.api import rate_limit
        from src.api.auth_login import login

        limiter = rate_limit.limiter
        calls = {"n": 0}

        def failing_hit(*args, **kwargs):
            calls["n"] += 1
            raise ConnectionError("redis down")

        monkeypatch.setattr(limiter._limiter, "hit", failing_hit)  # noqa: SLF001
        req = make_test_request(path="/api/v1/auth/login", method="POST")

        # Must NOT raise — first failure flips to fallback, retry is served
        # from the memory-backed strategy.
        limiter._check_request_limit(req, login, in_middleware=False)  # noqa: SLF001
        assert limiter._storage_dead is True  # noqa: SLF001
        # the fallback strategy (memory) served the retried evaluation
        assert limiter.limiter is limiter._fallback_limiter  # noqa: SLF001

    def test_dead_storage_still_enforces_route_limits(self):
        """With the storage marked dead, checks run against the fallback and
        still ENFORCE (limit exhaustion raises RateLimitExceeded, not 500)."""
        from slowapi.errors import RateLimitExceeded

        from src.api import rate_limit
        from src.api.auth_login import login

        limiter = rate_limit.limiter
        original_dead = limiter._storage_dead  # noqa: SLF001
        limiter._storage_dead = True  # noqa: SLF001
        try:
            req = make_test_request(path="/api/v1/auth/login", method="POST")
            # Exhaust the 5/minute login limit against the memory fallback.
            for _ in range(5):
                limiter._check_request_limit(req, login, in_middleware=False)  # noqa: SLF001
            with pytest.raises(RateLimitExceeded):
                limiter._check_request_limit(req, login, in_middleware=False)  # noqa: SLF001
        finally:
            limiter._storage_dead = original_dead  # noqa: SLF001

    def test_backend_recovery_after_outage(self, monkeypatch):
        """When the backend comes back, the next backend probe recovers the
        limiter to the primary storage (no restart needed) — slowapi's
        exponential-backoff probe plays the F-08 cooldown role here."""
        from src.api import rate_limit
        from src.api.auth_login import login

        limiter = rate_limit.limiter
        original_dead = limiter._storage_dead  # noqa: SLF001
        limiter._storage_dead = True  # noqa: SLF001
        # Deterministic probe: reset slowapi's backoff bookkeeping so the
        # first check probes the backend immediately instead of after the
        # exponential-backoff window.
        monkeypatch.setattr(limiter, "_Limiter__last_check_backend", 0.0)
        monkeypatch.setattr(limiter, "_Limiter__check_backend_count", 0)
        try:
            # _storage is healthy (conftest-swapped MemoryStorage.check() is
            # True), so the first probe must recover instead of 500ing.
            req = make_test_request(path="/api/v1/auth/login", method="POST")
            limiter._check_request_limit(req, login, in_middleware=False)  # noqa: SLF001
            assert limiter._storage_dead is False  # noqa: SLF001
        finally:
            limiter._storage_dead = original_dead  # noqa: SLF001


# ───────────────────────────────────────────────────────────────
# Auth client — async, fail-open, no event-loop stall
# ───────────────────────────────────────────────────────────────


class TestAuthFailOpenDeadRedis:
    async def test_revocation_checks_fail_open_fast_in_cooldown(self):
        """With Redis in cooldown (simulated outage), the per-request
        revocation checks return fail-open values WITHOUT attempting any
        connection (and therefore without blocking the loop)."""
        import time as _time

        from src.api import redis_client
        from src.api.redis_client import get_latest_user_revoke_ts, is_jti_blocked

        redis_client._client = None  # noqa: SLF001
        redis_client._last_failure_ts = _time.monotonic()  # noqa: SLF001
        try:
            t0 = _time.monotonic()
            assert await is_jti_blocked("some-jti") is False
            assert await get_latest_user_revoke_ts("some-user") is None
            elapsed = _time.monotonic() - t0
            # cooldown short-circuit: no connect attempts, no backoff sleeps
            assert elapsed < 0.05
        finally:
            redis_client._last_failure_ts = 0.0  # noqa: SLF001

    async def test_async_sleep_is_the_only_backoff_mechanism(self):
        """P2-32 closure guarantee: the client's backoff awaits asyncio.sleep —
        there is no sync time.sleep call anywhere in the module."""
        import ast
        import pathlib

        source = pathlib.Path(redis_client_module()).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                if (
                    isinstance(fn, ast.Attribute)
                    and fn.attr == "sleep"
                    and isinstance(fn.value, ast.Name)
                    and fn.value.id == "_time"
                ):
                    raise AssertionError(
                        "redis_client must not call sync time.sleep — "
                        "the backoff must await asyncio.sleep (P2-32)"
                    )

    async def test_connect_failure_closes_half_open_client(self, monkeypatch):
        """A failed connect round must not leak a half-open client: the
        failure path closes the candidate before backoff/retry."""
        from src.api import redis_client

        redis_client._client = None  # noqa: SLF001
        redis_client._last_failure_ts = 0.0  # noqa: SLF001

        closed = {"n": 0}

        class _DyingClient:
            async def ping(self):
                raise ConnectionError("refused")

            async def aclose(self):
                closed["n"] += 1

        async def fake_sleep(s: float) -> None:
            return None

        monkeypatch.setattr(redis_client, "_from_url", lambda *a, **k: _DyingClient())
        monkeypatch.setattr(redis_client, "_SLEEP", fake_sleep)

        assert await redis_client._get_client() is None
        assert redis_client._last_failure_ts > 0  # noqa: SLF001
        assert closed["n"] == redis_client._MAX_CONNECT_ATTEMPTS  # noqa: SLF001
        redis_client._last_failure_ts = 0.0  # noqa: SLF001


def redis_client_module() -> str:
    import src.api.redis_client as m

    return m.__file__
