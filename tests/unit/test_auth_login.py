"""
Tests for auth_login API endpoints.

POST /api/v1/auth/login   — Authenticate and get JWT
POST /api/v1/auth/seed-admin — Create initial admin user
GET  /api/v1/auth/me      — Get current user info
POST /api/v1/auth/change-password — Change password
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api.auth import JWT_ALGORITHM, create_jwt
from src.config.settings import settings

# Pre-computed bcrypt hash for "testpass123" with SHA-256 pre-hash (M-10 fix).
# Generated via: hash_password('testpass123') which does SHA-256 then bcrypt.
# SHA-256 of 'testpass123' = '7e6e0c3079a08c5cc6036789b57e951f65f82383913ba1a49ae992544f1b4b6e'
# bcrypt hash of that hex digest:
TEST_PASSWORD_HASH = "$2b$12$YNQh8sU8gYbuyuT78FvzW.ywTViRGQbnMPk4Of9fQIviwxThEsk9S"
# Admin hash: properly generated via hash_password('adminpassword123')
TEST_ADMIN_HASH = "$2b$12$zutMf2AsHf14wrcjDue8IekvKCzlKJseJzirLZzwV5CsiB2Eoq3kq"


class TestCreateJWT:
    """Tests for JWT creation and verification."""

    def test_create_jwt_contains_role(self):
        """Test that JWT contains the correct role."""
        token = create_jwt("analyst1", "analyst")
        from jose import jwt

        payload = jwt.decode(token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "analyst1"
        assert payload["role"] == "analyst"

    def test_create_jwt_has_expiry(self):
        """Test that JWT has an expiry."""
        token = create_jwt("admin1", "admin")
        from jose import jwt

        payload = jwt.decode(token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM])
        assert "exp" in payload
        assert payload["exp"] > datetime.now(tz=timezone.utc).timestamp()

    def test_create_jwt_admin_role(self):
        """Test JWT with admin role."""
        token = create_jwt("superadmin", "admin")
        from jose import jwt

        payload = jwt.decode(token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM])
        assert payload["role"] == "admin"

    def test_create_jwt_viewer_role(self):
        """Test JWT with viewer role."""
        token = create_jwt("readonly", "viewer")
        from jose import jwt

        payload = jwt.decode(token, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM])
        assert payload["role"] == "viewer"


class TestLoginEndpoint:
    """Tests for POST /auth/login."""

    @pytest.fixture
    def mock_pool(self):
        """Mock the database pool with a user row using pre-computed hash."""
        pool = AsyncMock()
        conn = AsyncMock()

        user_row = {
            "id": 1,
            "username": "testadmin",
            "password_hash": TEST_PASSWORD_HASH,
            "role": "admin",
            "is_active": True,
        }

        conn.fetchrow = AsyncMock(return_value=user_row)
        conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        return pool, conn, user_row

    @pytest.mark.asyncio
    async def test_login_success(self, mock_pool):
        """Test successful login returns JWT token."""
        pool, conn, user_row = mock_pool

        # Mock verify_password to return True for our test password
        with patch("src.api.auth_login.get_pool", return_value=pool):
            with patch("src.api.auth_login.verify_password", return_value=True):
                from src.api.auth_login import LoginRequest, login

                request = LoginRequest(username="testadmin", password="testpass123")
                result = await login(request)

                assert result.access_token is not None
                assert result.username == "testadmin"
                assert result.role == "admin"
                assert result.token_type == "bearer"
                assert result.expires_in > 0

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, mock_pool):
        """Test login with wrong password returns 401."""
        pool, conn, user_row = mock_pool

        with patch("src.api.auth_login.get_pool", return_value=pool):
            with patch("src.api.auth_login.verify_password", return_value=False):
                from fastapi import HTTPException

                from src.api.auth_login import LoginRequest, login

                request = LoginRequest(username="testadmin", password="wrongpassword")

                with pytest.raises(HTTPException) as exc_info:
                    await login(request)
                assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self):
        """Test login with nonexistent user returns 401."""
        pool = AsyncMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)  # No user found

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.auth_login.get_pool", return_value=pool):
            with patch("src.api.auth_login.hash_password", return_value="dummy_hash"):
                from fastapi import HTTPException

                from src.api.auth_login import LoginRequest, login

                request = LoginRequest(username="ghost", password="whatever")

                with pytest.raises(HTTPException) as exc_info:
                    await login(request)
                assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_login_disabled_user(self, mock_pool):
        """Test login with disabled user returns 401."""
        pool, conn, user_row = mock_pool
        user_row["is_active"] = False

        with patch("src.api.auth_login.get_pool", return_value=pool):
            from fastapi import HTTPException

            from src.api.auth_login import LoginRequest, login

            request = LoginRequest(username="testadmin", password="testpass123")

            with pytest.raises(HTTPException) as exc_info:
                await login(request)
            assert exc_info.value.status_code == 401
            assert "disabled" in exc_info.value.detail.lower()


class TestSeedAdmin:
    """Tests for POST /auth/seed-admin."""

    @pytest.mark.asyncio
    async def test_seed_admin_creates_user(self):
        """Test that seed-admin creates user when none exist."""
        pool = AsyncMock()
        conn = AsyncMock()
        conn.fetchval = AsyncMock(return_value=0)  # No users
        conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.auth_login.get_pool", return_value=pool):
            with patch("src.api.auth_login.hash_password", return_value="hashed_admin"):
                from src.api.auth_login import seed_admin_user

                result = await seed_admin_user()
                assert "admin" in result["message"].lower()
                assert result["username"] == "admin"

    @pytest.mark.asyncio
    async def test_seed_admin_rejects_when_users_exist(self):
        """Test that seed-admin rejects when users already exist."""
        pool = AsyncMock()
        conn = AsyncMock()
        # Code uses fetchrow (INSERT ... ON CONFLICT DO NOTHING RETURNING username)
        # When users exist, ON CONFLICT DO NOTHING returns None
        conn.fetchrow = AsyncMock(return_value=None)
        conn.execute = AsyncMock(return_value=None)  # advisory lock/unlock

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.auth_login.get_pool", return_value=pool):
            from fastapi import HTTPException

            from src.api.auth_login import seed_admin_user

            with pytest.raises(HTTPException) as exc_info:
                await seed_admin_user()
            assert exc_info.value.status_code == 409


class TestChangePassword:
    """Tests for POST /auth/change-password."""

    @pytest.mark.asyncio
    async def test_change_password_success(self):
        """Test successful password change."""
        pool = AsyncMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": 1,
                "password_hash": "old_hash",
            }
        )
        conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        payload = {"sub": "testuser", "role": "analyst"}

        with patch("src.api.auth_login.get_pool", return_value=pool):
            with patch("src.api.auth_login.verify_password", return_value=True):
                with patch("src.api.auth_login.hash_password", return_value="new_hash"):
                    from src.api.auth_login import ChangePasswordRequest, change_password

                    request = ChangePasswordRequest(
                        current_password="oldpassword",
                        new_password="newpassword123",
                    )
                    result = await change_password(request, payload)
                    assert "success" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self):
        """Test password change with wrong current password."""
        pool = AsyncMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": 1,
                "password_hash": "real_hash",
            }
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        payload = {"sub": "testuser", "role": "analyst"}

        with patch("src.api.auth_login.get_pool", return_value=pool):
            with patch("src.api.auth_login.verify_password", return_value=False):
                from fastapi import HTTPException

                from src.api.auth_login import ChangePasswordRequest, change_password

                request = ChangePasswordRequest(
                    current_password="wrongpassword",
                    new_password="newpassword123",
                )

                with pytest.raises(HTTPException) as exc_info:
                    await change_password(request, payload)
                assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_change_password_user_not_found(self):
        """Test password change when user doesn't exist."""
        pool = AsyncMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        payload = {"sub": "ghost", "role": "analyst"}

        with patch("src.api.auth_login.get_pool", return_value=pool):
            from fastapi import HTTPException

            from src.api.auth_login import ChangePasswordRequest, change_password

            request = ChangePasswordRequest(
                current_password="whatever",
                new_password="newpassword123",
            )

            with pytest.raises(HTTPException) as exc_info:
                await change_password(request, payload)
            assert exc_info.value.status_code == 401


class TestGetMe:
    """Tests for GET /auth/me."""

    @pytest.mark.asyncio
    async def test_get_me_success(self):
        """Test getting current user info."""
        pool = AsyncMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "username": "testadmin",
                "role": "admin",
                "email": "admin@localhost",
                "is_active": True,
                "last_login": datetime.now(tz=timezone.utc),
            }
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        payload = {"sub": "testadmin", "role": "admin"}

        with patch("src.api.auth_login.get_pool", return_value=pool):
            from src.api.auth_login import get_current_user

            result = await get_current_user(payload)
            assert result.username == "testadmin"
            assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_get_me_user_not_found(self):
        """Test getting user info when user doesn't exist."""
        pool = AsyncMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        payload = {"sub": "ghost", "role": "viewer"}

        with patch("src.api.auth_login.get_pool", return_value=pool):
            from fastapi import HTTPException

            from src.api.auth_login import get_current_user

            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(payload)
            assert exc_info.value.status_code == 401
