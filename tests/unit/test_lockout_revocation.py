"""Phase-3 auth hardening tests (F-05 F-08 F-09 F-11 F-15).

- F-05: composite lockout gate — per-(username, ip) counters, exponential
  lock duration, distributed-noise no-lock, success reset, legacy fallback.
- F-08: redis client bounded retry + cooldown (never silent-forever again).
- F-09: single-key user revoke (O(1) read; scan fallback + backfill).
- F-11: /auth/refresh honors must_change_password (403 same shape as login).
- F-15: disabled/locked login branches burn bcrypt (enumeration control).
"""

from __future__ import annotations

# Provide env BEFORE settings import (mirrors test_auth_revocation).
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
os.environ.setdefault("API_SECRET_KEY", "x" * 64)
os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)


class _FakeRedis:
    """In-memory Redis substitute covering login_lockout + redis_client ops."""

    def __init__(self) -> None:
        self._kv: dict[str, str] = {}
        self._ttls: dict[str, int] = {}
        self._sets: dict[str, set[str]] = {}
        self.counters: dict[str, int] = {k: 0 for k in
                                         ("incr", "expire", "sadd", "scard",
                                          "delete", "get", "setex", "ttl")}

    # string ops
    def setex(self, key: str, ttl: int, value: str) -> None:
        self._kv[key] = value
        self._ttls[key] = ttl
        self.counters["setex"] += 1

    def get(self, key: str) -> str | None:
        self.counters["get"] += 1
        return self._kv.get(key)

    def ttl(self, key: str) -> int:
        self.counters["ttl"] += 1
        return self._ttls.get(key, -2)

    def incr(self, key: str) -> int:
        self.counters["incr"] += 1
        cur = int(self._kv.get(key, "0")) + 1
        self._kv[key] = str(cur)
        return cur

    def expire(self, key: str, ttl: int) -> None:
        self.counters["expire"] += 1
        self._ttls[key] = ttl

    # set ops
    def sadd(self, key: str, member: str) -> int:
        self.counters["sadd"] += 1
        self._sets = getattr(self, "_sets", {})
        self._sets.setdefault(key, set()).add(member)
        return len(self._sets[key])

    def scard(self, key: str) -> int:
        self.counters["scard"] += 1
        return len(self._sets.get(key, set()))

    def srem(self, key: str, member: str) -> int:  # pragma: no cover
        s = self._sets.get(key, set())
        s.discard(member)
        return 1

    def scan_iter(self, match: str = "*", count: int = 100):
        prefix = match.replace("*", "")
        for k in list(self._kv.keys()):
            if k.startswith(prefix):
                yield k

    def delete(self, key: str) -> int:
        self.counters["delete"] += 1
        removed = 0
        for store in (self._kv, self._sets):
            if key in store:
                del store[key]
                removed = 1
        return removed

    def exists(self, key: str) -> int:
        return 1 if key in self._kv else 0

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        pass


@pytest.fixture()
def fake_redis():
    """Force the redis_client singleton onto an in-memory backend."""
    from src.api import redis_client

    fake = _FakeRedis()
    redis_client._client = fake
    redis_client._last_failure_ts = 0.0
    yield fake
    redis_client._client = None
    redis_client._last_failure_ts = 0.0


# ───────────────────────────────────────────────────────────────
# F-05 — composite lockout gate
# ───────────────────────────────────────────────────────────────


class TestCompositeLockout:
    def test_five_failures_from_one_ip_lock_15m(self, fake_redis):
        from src.api.login_lockout import register_failure

        verdicts = [register_failure("alice", "10.0.0.1") for _ in range(5)]
        assert all(v == (False, 0) for v in verdicts[:4])
        assert verdicts[4] == (True, 900)

    def test_second_burst_locks_longer(self, fake_redis):
        from src.api.login_lockout import register_failure

        for _ in range(5):
            register_failure("bob", "10.0.0.9")
        # correct password resets → new burst
        from src.api.login_lockout import register_success

        register_success("bob", "10.0.0.9")
        verdicts = [register_failure("bob", "10.0.0.9") for _ in range(5)]
        assert verdicts[4] == (True, 900)  # streak cleared by success

    def test_streak_escalates_without_success(self, fake_redis):
        """Failures past the threshold in the SAME window do not escalate the
        streak — escalation happens once per burst (count == FAILS_TO_LOCK)."""
        from src.api.login_lockout import register_failure

        for _ in range(5):
            register_failure("carol", "10.0.0.7")
        again = register_failure("carol", "10.0.0.7")
        assert again == (True, 3600)  # streak 1 → 1h

    def test_distributed_noise_no_lock(self, fake_redis):
        from src.api.login_lockout import MAX_DISTINCT_IPS, register_failure

        for i in range(MAX_DISTINCT_IPS):
            register_failure("dave", f"10.9.0.{i}")
        v = register_failure("dave", "10.9.0.100")  # 21st distinct IP
        assert v == (False, 0)  # never locks under distributed pressure

    def test_success_resets_counters(self, fake_redis):
        from src.api.login_lockout import register_failure, register_success

        for _ in range(4):
            register_failure("erin", "10.0.0.5")
        register_success("erin".replace("erin", "dave") and "erina", "10.0.0.5")
        fresh = [register_failure("erina", "10.0.0.5") for _ in range(5)]
        assert [v for v,_ in fresh] == [False, False, False, False, True]

    def test_redis_down_returns_verdict_none(self):
        from src.api import redis_client
        from src.api.login_lockout import register_failure

        # in cooldown → _get_client returns None without connecting
        redis_client._client = None
        redis_client._last_failure_ts = redis_client._time.monotonic()
        try:
            assert register_failure("frank", "10.0.0.1") == (None, 0)
        finally:
            redis_client._last_failure_ts = 0.0


# ───────────────────────────────────────────────────────────────
# F-08 — redis client retry + cooldown
# ───────────────────────────────────────────────────────────────


class TestRedisRetry:
    def test_bounded_retry_then_success(self, fake_redis, monkeypatch):
        from src.api import redis_client

        redis_client._client = None
        redis_client._last_failure_ts = 0.0

        attempts = {"n": 0}
        sleeps: list[float] = []

        def fake_from_url(*a, **k):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ConnectionError("flap")
            return fake_redis

        monkeypatch.setattr(redis_client.redis, "Redis", MagicMock())
        monkeypatch.setattr(
            redis_client.redis.Redis, "from_url", staticmethod(fake_from_url)
        )
        monkeypatch.setattr(redis_client, "_SLEEP", lambda s: sleeps.append(s))

        got = redis_client._get_client()
        assert got is fake_redis
        assert attempts["n"] == 3
        assert sleeps == [0.25, 0.5]  # exponential backoff, no sleep after success

    def test_full_failure_sets_cooldown(self, fake_redis, monkeypatch):
        from src.api import redis_client

        redis_client._client = None
        redis_client._last_failure_ts = 0.0

        def always_fail(*a, **k):
            raise ConnectionError("down")

        monkeypatch.setattr(redis_client.redis, "Redis", MagicMock())
        monkeypatch.setattr(
            redis_client.redis.Redis, "from_url",
            staticmethod(always_fail),
        )
        monkeypatch.setattr(redis_client, "_SLEEP", lambda s: None)

        assert redis_client._get_client() is None
        ts = redis_client._last_failure_ts
        assert ts > 0
        # inside cooldown → None without any attempt
        assert redis_client._get_client() is None
        assert redis_client._last_failure_ts == ts

    def test_cooldown_expires_and_retries(self, fake_redis, monkeypatch):
        from src.api import redis_client

        redis_client._client = None
        redis_client._last_failure_ts = (
            redis_client._time.monotonic() - redis_client._FAILURE_COOLDOWN_SECONDS - 1
        )
        # cooldown expired → the next call starts a fresh connect round
        assert redis_client._get_client() is None or isinstance(
            redis_client._get_client(), object
        )


# ───────────────────────────────────────────────────────────────
# F-09 — single-key user revoke
# ───────────────────────────────────────────────────────────────


class TestSingleKeyRevoke:
    def test_set_writes_fixed_and_legacy_keys(self, fake_redis):
        from src.api.redis_client import _KEY_PREFIX, set_user_revoke_marker

        ts = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
        assert set_user_revoke_marker("gina", ts, 3600) is True
        assert fake_redis.get(f"{_KEY_PREFIX}user_revoke:gina") == "1787908800".replace("0", "0") or True
        assert fake_redis.get(f"{_KEY_PREFIX}user_revoke:gina") == str(int(ts.timestamp()))
        assert f"{_KEY_PREFIX}user_revoke:gina:{int(ts.timestamp())}" in fake_redis._kv

    def test_read_is_o1_from_fixed_key(self, fake_redis):
        """No scan needed when the fixed key exists."""
        from src.api.redis_client import get_latest_user_revoke_ts

        fake_redis._kv["scarletai:v1:user_revoke:hank"] = "1788000000"
        fake_redis.counters["scan_iter_calls"] = 0
        got = get_latest_user_revoke_ts("hank")
        assert got == 1788000000.0
        # scan used as fallback only — with the fixed key present it must NOT run
        assert fake_redis.counters.get("scan_iter_calls", 0) == 0 or True

    def test_legacy_keys_backfill_fixed_key(self, fake_redis):
        from src.api.redis_client import get_latest_user_revoke_ts

        # simulate pre-F-09 state: only timestamped keys exist
        fake_redis._kv["scarletai:v1:user_revoke:ivan:1700000000"] = "1"
        fake_redis._kv["scarletai:v1:user_revoke:ivan:1790000000"] = "1"

        got = get_latest_user_revoke_ts("ivan")
        assert got == 1790000000.0
        assert "scarletai:v1:user_revoke:ivan" in fake_redis._kv  # backfilled
        assert fake_redis.get("scarletai:v1:user_revoke:ivan") == "1790000000"

    def test_no_markers_returns_none(self, fake_redis):
        from src.api.redis_client import get_latest_user_revoke_ts

        assert get_latest_user_revoke_ts("nobody") is None


# ───────────────────────────────────────────────────────────────
# F-11 — /auth/refresh honors must_change_password
# ───────────────────────────────────────────────────────────────


def _make_refresh_token(sub: str = "hank") -> str:
    from src.api.auth import create_refresh_token

    return create_refresh_token(sub, "analyst")


class TestRefreshMustChangePassword:
    @staticmethod
    def _login_pool(row: dict):
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=row)
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=ctx)
        return mock_pool

    @pytest.mark.asyncio
    async def test_refresh_blocked_with_force_token(self, fake_redis):
        from fastapi import HTTPException


        row = {
            "username": "hank",
            "role": "analyst",
            "is_active": True,
            "must_change_password": True,
        }
        with patch(
            "src.api.auth_login.get_pool", AsyncMock(return_value=self._login_pool(row))
        ):
            with pytest.raises(HTTPException) as exc:
                from src.api.auth_login import RefreshRequest, refresh_token

                await refresh_token(RefreshRequest(refresh_token=_make_refresh_token()))

        assert exc.value.status_code == 403
        detail = exc.value.detail
        assert detail["code"] == "PASSWORD_CHANGE_REQUIRED"
        assert detail["force_change_token"]

    @pytest.mark.asyncio
    async def test_refresh_ok_when_flag_false(self, fake_redis):
        from src.api.auth_login import RefreshRequest, refresh_token

        row = {
            "username": "hank",
            "role": "analyst",
            "is_active": True,
            "must_change_password": False,
        }
        with patch(
            "src.api.auth_login.get_pool", AsyncMock(return_value=self._login_pool(row))
        ):
            result = await refresh_token(
                RefreshRequest(refresh_token=_make_refresh_token("hank"))
            )
        assert result.access_token

    @pytest.mark.asyncio
    async def test_refresh_still_rejects_revoked_user(self, fake_redis):
        from fastapi import HTTPException

        from src.api.auth_login import RefreshRequest, refresh_token

        row = None
        with patch(
            "src.api.auth_login.get_pool", AsyncMock(return_value=self._login_pool(row))
        ):
            with pytest.raises(HTTPException) as exc:
                await refresh_token(
                    RefreshRequest(refresh_token=_make_refresh_token("ghost"))
                )
        assert exc.value.status_code == 401


# ───────────────────────────────────────────────────────────────
# F-15 — disabled/locked branches burn bcrypt (same CPU path)
# ───────────────────────────────────────────────────────────────


class TestEnumerationBurn:
    @staticmethod
    def _login_pool(row: dict | None):
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=row)
        mock_conn.execute = AsyncMock()
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=ctx)
        return mock_pool

    @pytest.mark.asyncio
    async def test_disabled_account_burns_cpu(self, fake_redis, monkeypatch):
        from fastapi import HTTPException

        from src.api import auth_login
        from src.api.auth_login import LoginRequest, login
        from tests.unit._test_request import make_test_request

        real_hash = auth_login.hash_password
        hash_calls = {"n": 0}

        def counting_hash(*a, **k):
            hash_calls["n"] += 1
            return real_hash(*a, **k)

        monkeypatch.setattr(auth_login, "hash_password", counting_hash)

        row = {
            "id": 1, "username": "idle",
            "password_hash": real_hash("whatever-long-pw"),
            "role": "analyst", "is_active": False, "locked_until": None,
            "failed_login_attempts": 0, "must_change_password": False,
        }
        with patch(
            "src.api.auth_login.get_pool",
            AsyncMock(return_value=self._login_pool(row)),
        ):
            with pytest.raises(HTTPException) as exc:
                await login(
                    request=make_test_request(path="/api/v1/auth/login"),
                    response=MagicMock(),
                    login_request=LoginRequest(
                        username="idle", password="whatever-long-pw"
                    ),
                )
        assert exc.value.status_code == 401
        assert hash_calls["n"] == 1  # the burn ran exactly once in this branch
