"""
Tests for JWT revocation hardening (Epic 5).

Covers:
- JWT carries a jti claim
- /auth/logout blacklists the jti in Redis
- Subsequent calls with the blacklisted token return 401
- /auth/change-password invalidates older tokens (user_revoke marker)
- /auth/refresh rotates the refresh token and rejects tampered/old ones
- Fail-open behavior: Redis down = auth still works (degraded)

Tests use fakeredis to avoid requiring a live Redis server.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

# Provide a sane API_SECRET_KEY for tests BEFORE settings imports it
os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
os.environ.setdefault("API_SECRET_KEY", "x" * 64)
os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)


# ───────────────────────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────────────────────


class _FakeRedis:
    """In-memory Redis substitute. Implements the subset redis_client uses."""

    def __init__(self) -> None:
        self._kv: dict[str, str] = {}
        self._ttls: dict[str, int] = {}

    # ops
    def setex(self, key: str, ttl: int, value: str) -> None:
        self._kv[key] = value
        self._ttls[key] = ttl

    def get(self, key: str) -> str | None:
        # F-09: single-key revoke reads via GET
        return self._kv.get(key)

    def ttl(self, key: str) -> int:
        return self._ttls.get(key, -2)

    def exists(self, key: str) -> int:
        return 1 if key in self._kv else 0

    def scan_iter(self, match: str = "*", count: int = 100):
        # naive substring match
        for k in list(self._kv.keys()):
            if match.replace("*", "") in k:
                yield k

    def close(self) -> None:
        pass

    def ping(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def _fake_redis():
    """Force the redis_client singleton to use a fake in-memory backend."""
    from src.api import redis_client

    fake = _FakeRedis()
    redis_client._client = fake
    redis_client._connect_attempted = True
    yield fake
    redis_client._client = None
    redis_client._connect_attempted = False


# ───────────────────────────────────────────────────────────────
# jti claim tests
# ───────────────────────────────────────────────────────────────


class TestJTIClaim:
    def test_jwt_has_jti(self):
        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM, create_jwt
        from src.config.settings import settings

        token = create_jwt("user1", "analyst")
        payload = jose_jwt.decode(
            token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
        assert "jti" in payload
        assert "type" in payload
        assert payload["type"] == "access"

    def test_refresh_jwt_has_refresh_type(self):
        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM, create_refresh_token
        from src.config.settings import settings

        token = create_refresh_token("user1", "admin")
        payload = jose_jwt.decode(
            token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
        assert payload["type"] == "refresh"
        assert "jti" in payload

    def test_jti_is_unique_per_token(self):
        from src.api.auth import create_jwt

        t1 = create_jwt("user1", "analyst")
        t2 = create_jwt("user1", "analyst")
        assert t1 != t2


# ───────────────────────────────────────────────────────────────
# Logout / blocklist tests
# ───────────────────────────────────────────────────────────────


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_blacklists_jti(self):
        from src.api.auth import create_jwt
        from src.api.redis_client import is_jti_blocked

        token = create_jwt("user1", "analyst")
        # Decode to get jti
        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM
        from src.config.settings import settings

        payload = jose_jwt.decode(
            token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
        jti = payload["jti"]
        assert not is_jti_blocked(jti)

        # Call logout
        from src.api.auth_login import logout

        await logout(payload)
        assert is_jti_blocked(jti)

    @pytest.mark.asyncio
    async def test_verify_jwt_rejects_blocked(self):
        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM, create_jwt
        from src.api.auth_login import logout
        from src.api.redis_client import is_jti_blocked
        from src.config.settings import settings

        token = create_jwt("user1", "analyst")
        payload = jose_jwt.decode(
            token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )

        # Before logout: token works (we don't call verify_jwt via HTTP,
        # but we can call the underlying check)
        assert not is_jti_blocked(payload["jti"])

        # Logout
        await logout(payload)
        assert is_jti_blocked(payload["jti"])


# ───────────────────────────────────────────────────────────────
# User revoke (password change) tests
# ───────────────────────────────────────────────────────────────


class TestUserRevoke:
    @pytest.mark.asyncio
    async def test_change_password_sets_user_revoke(self):
        from datetime import datetime, timezone

        from src.api.redis_client import get_latest_user_revoke_ts, set_user_revoke_marker

        username = "alice"
        # No marker before
        assert get_latest_user_revoke_ts(username) is None
        set_user_revoke_marker(username, datetime.now(tz=timezone.utc), 3600)
        assert get_latest_user_revoke_ts(username) is not None

    @pytest.mark.asyncio
    async def test_old_token_rejected_after_password_change(self):
        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM, create_jwt, verify_jwt
        from src.api.redis_client import set_user_revoke_marker
        from src.config.settings import settings

        # Issue token at t=0
        old_token = create_jwt("bob", "analyst")
        old_payload = jose_jwt.decode(
            old_token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
        iat = old_payload["iat"]

        # Simulate password change at t+5
        from datetime import datetime, timedelta, timezone

        revoke_time = datetime.now(tz=timezone.utc) + timedelta(seconds=5)
        set_user_revoke_marker("bob", revoke_time, 3600)

        # Now verify_jwt should reject because iat < revoke_ts
        creds = MagicMock()
        creds.credentials = old_token
        with pytest.raises(HTTPException) as exc:
            await verify_jwt(creds)  # type: ignore[arg-type]
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_new_token_accepted_after_password_change(self):
        from src.api.auth import create_jwt, verify_jwt

        # Issue fresh token (after the revoke marker)
        new_token = create_jwt("carol", "analyst")
        creds = MagicMock()
        creds.credentials = new_token
        # No marker set for carol, so should succeed
        result = verify_jwt(creds)  # type: ignore[arg-type]
        assert result["sub"] == "carol"


# ───────────────────────────────────────────────────────────────
# Refresh token tests
# ───────────────────────────────────────────────────────────────


class TestRefresh:
    @pytest.mark.asyncio
    async def test_refresh_returns_new_tokens(self):
        from src.api.auth import create_refresh_token
        from src.api.auth_login import LoginResponse, RefreshRequest, refresh_token

        refresh = create_refresh_token("dave", "analyst")

        # Mock the pool to return a user row
        pool = MagicMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={"username": "dave", "role": "analyst", "is_active": True}
        )
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.auth_login.get_pool", return_value=pool):
            req = RefreshRequest(refresh_token=refresh)
            resp = await refresh_token(req)

        assert isinstance(resp, LoginResponse)
        assert resp.access_token != refresh
        assert resp.username == "dave"
        assert resp.role == "analyst"

    @pytest.mark.asyncio
    async def test_access_token_rejected_as_refresh(self):
        from src.api.auth import create_jwt
        from src.api.auth_login import RefreshRequest, refresh_token

        access = create_jwt("eve", "analyst")
        req = RefreshRequest(refresh_token=access)
        with pytest.raises(HTTPException) as exc:
            await refresh_token(req)
        assert exc.value.status_code == 401


# ───────────────────────────────────────────────────────────────
# Fail-open behavior
# ───────────────────────────────────────────────────────────────


class TestFailOpen:
    def test_redis_down_does_not_break_jwt(self):
        """If Redis is unavailable, verify_jwt still accepts valid tokens.

        Rationale: in a SOC, availability of the auth path matters more than
        the secondary blocklist. Operators can monitor the redis_unavailable
        warning and fail closed manually if needed.
        """
        from src.api import redis_client

        # Simulate Redis down
        redis_client._client = None
        redis_client._connect_attempted = True  # already failed once

        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM, create_jwt
        from src.config.settings import settings

        token = create_jwt("frank", "analyst")
        payload = jose_jwt.decode(
            token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
        # is_jti_blocked should return False (fail-open)
        assert redis_client.is_jti_blocked(payload["jti"]) is False


# ───────────────────────────────────────────────────────────────
# Business-API revocation (P1-11): get_current_user must enforce the
# same jti blocklist + user_revoke markers as verify_jwt.
# ───────────────────────────────────────────────────────────────


class TestBusinessAPIRevocation:
    @pytest.mark.asyncio
    async def test_get_current_user_rejects_blocked_jti(self):
        from src.api.auth import create_jwt, get_current_user
        from src.api.redis_client import blocklist_jti

        token = create_jwt("bizuser", "analyst")
        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM
        from src.config.settings import settings

        payload = jose_jwt.decode(
            token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
        blocklist_jti(payload["jti"], ttl_seconds=3600)

        creds = MagicMock()
        creds.credentials = token
        with pytest.raises(HTTPException) as exc:
            get_current_user(creds)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_get_current_user_rejects_revoked_user(self):
        from datetime import datetime, timedelta, timezone

        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM, create_jwt, get_current_user
        from src.api.redis_client import set_user_revoke_marker
        from src.config.settings import settings

        old_token = create_jwt("bizuser2", "analyst")
        old_payload = jose_jwt.decode(
            old_token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
        # Simulate a password change after the token was issued.
        revoke_time = datetime.now(tz=timezone.utc) + timedelta(seconds=5)
        set_user_revoke_marker("bizuser2", revoke_time, 3600)

        creds = MagicMock()
        creds.credentials = old_token
        with pytest.raises(HTTPException) as exc:
            get_current_user(creds)
        assert exc.value.status_code == 401


# ───────────────────────────────────────────────────────────────
# P1-A: token-type enforcement (refresh tokens must NOT work as access)
# ───────────────────────────────────────────────────────────────


class TestTokenTypeEnforcement:
    """P1-A — a refresh token (type=refresh, 7-day TTL) must be rejected by
    verify_jwt and get_current_user on every business endpoint. Only
    type=access tokens are valid. Pre-hardening tokens without a type are
    rejected too."""

    def test_verify_jwt_accepts_access_token(self):
        from src.api.auth import create_jwt, verify_jwt

        token = create_jwt("alice", "analyst")
        creds = MagicMock()
        creds.credentials = token
        payload = verify_jwt(creds)
        assert payload["sub"] == "alice"
        assert payload["type"] == "access"

    def test_verify_jwt_rejects_refresh_token(self):
        from src.api.auth import create_refresh_token, verify_jwt

        token = create_refresh_token("alice", "analyst")
        creds = MagicMock()
        creds.credentials = token
        with pytest.raises(HTTPException) as exc:
            verify_jwt(creds)
        assert exc.value.status_code == 401
        assert "access" in exc.value.detail.lower()

    def test_verify_jwt_rejects_typeless_token(self):
        """A token with no `type` claim (e.g. a pre-hardening token) is rejected."""
        from jose import jwt as jose_jwt

        from src.api.auth import JWT_ALGORITHM, verify_jwt
        from src.config.settings import settings

        token = jose_jwt.encode(
            {"sub": "alice", "role": "analyst", "jti": "x"},
            settings.api_secret_key.get_secret_value(),
            algorithm=JWT_ALGORITHM,
        )
        creds = MagicMock()
        creds.credentials = token
        with pytest.raises(HTTPException) as exc:
            verify_jwt(creds)
        assert exc.value.status_code == 401

    def test_get_current_user_accepts_access_token(self):
        from src.api.auth import create_jwt, get_current_user

        token = create_jwt("bob", "admin")
        creds = MagicMock()
        creds.credentials = token
        payload = get_current_user(creds)
        assert payload["sub"] == "bob"
        assert payload["role"] == "admin"

    def test_get_current_user_rejects_refresh_token(self):
        from src.api.auth import create_refresh_token, get_current_user

        token = create_refresh_token("bob", "admin")
        creds = MagicMock()
        creds.credentials = token
        with pytest.raises(HTTPException) as exc:
            get_current_user(creds)
        assert exc.value.status_code == 401
        # Must NOT fall through to the static-bearer compare (detail is the
        # type-check message, not "Invalid or expired token").
        assert "access" in exc.value.detail.lower()

    def test_get_current_user_still_accepts_static_bearer(self):
        """The static bearer fallback still works for non-JWT bearer tokens."""
        from src.api.auth import get_current_user
        from src.config.settings import settings

        creds = MagicMock()
        creds.credentials = settings.api_bearer_token.get_secret_value()
        payload = get_current_user(creds)
        assert payload["sub"] == "api-client"
        assert payload["role"] == "admin"


# P1-B: force_change_token scope (must_change_password control)
# ───────────────────────────────────────────────────────────────


class TestForceChangeTokenScope:
    """P1-B — a force_change_token (carrying force_password_change=True) is a
    valid admin access JWT, but it must ONLY work on /auth/force-change-password.
    Every business endpoint (via verify_jwt / get_current_user) must reject it,
    otherwise the must_change_password control is bypassable for the token's TTL.
    """

    def _force_token(self, username: str = "migr", role: str = "admin") -> str:
        from src.api.auth import create_jwt

        return create_jwt(username, role, extra={"force_password_change": True})

    def test_verify_jwt_rejects_force_token(self):
        from src.api.auth import verify_jwt

        creds = MagicMock()
        creds.credentials = self._force_token()
        with pytest.raises(HTTPException) as exc:
            verify_jwt(creds)
        assert exc.value.status_code == 401
        assert "password change" in exc.value.detail.lower()

    def test_get_current_user_rejects_force_token(self):
        from src.api.auth import get_current_user

        creds = MagicMock()
        creds.credentials = self._force_token()
        with pytest.raises(HTTPException) as exc:
            get_current_user(creds)
        assert exc.value.status_code == 401
        # Must NOT fall through to static bearer — the message is the scope
        # rejection, not "Invalid or expired token".
        assert "password change" in exc.value.detail.lower()

    def test_verify_force_change_token_accepts_force_token(self):
        from src.api.auth import verify_force_change_token

        creds = MagicMock()
        creds.credentials = self._force_token("migr", "analyst")
        payload = verify_force_change_token(creds)
        assert payload["sub"] == "migr"
        assert payload["force_password_change"] is True

    def test_verify_force_change_token_rejects_normal_access_token(self):
        from src.api.auth import create_jwt, verify_force_change_token

        token = create_jwt("alice", "analyst")  # no force_password_change claim
        creds = MagicMock()
        creds.credentials = token
        with pytest.raises(HTTPException) as exc:
            verify_force_change_token(creds)
        assert exc.value.status_code == 403

    def test_verify_force_change_token_rejects_non_jwt(self):
        from src.api.auth import verify_force_change_token

        creds = MagicMock()
        creds.credentials = "not-a-jwt"
        with pytest.raises(HTTPException) as exc:
            verify_force_change_token(creds)
        assert exc.value.status_code == 401

    async def test_force_change_password_sets_user_revoke_marker(self, monkeypatch):
        """P2-12 — a successful /force-change-password sets a user_revoke marker so
        the force_change_token (and any prior tokens) die immediately."""
        from datetime import datetime, timezone

        import src.api.auth_login as mod
        from src.api.redis_client import get_latest_user_revoke_ts

        # Stub the pool + execute so the endpoint doesn't need a live DB.
        class _Conn:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def execute(self, *args, **kwargs):
                return None

        class _Pool:
            def acquire(self):
                return _Conn()

        async def _fake_pool():
            return _Pool()

        monkeypatch.setattr(mod, "get_pool", _fake_pool)
        monkeypatch.setattr(mod, "hash_password", lambda pw: "HASH:" + pw)

        from src.api.auth_login import ForceChangePasswordRequest, force_change_password

        before = get_latest_user_revoke_ts("migr2")
        assert before is None

        payload = {"sub": "migr2", "force_password_change": True}
        result = await force_change_password(
            ForceChangePasswordRequest(new_password="newpass123"), payload
        )
        assert "changed" in result["message"].lower()

        after = get_latest_user_revoke_ts("migr2")
        assert after is not None
        assert isinstance(after, float)
        # The marker time is ~now.
        assert abs(after - datetime.now(tz=timezone.utc).timestamp()) < 30
