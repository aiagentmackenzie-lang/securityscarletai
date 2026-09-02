"""
Phase 3.1 — User management API (admin-only) tests.

Endpoints: GET /users, POST /users, PATCH /users/{id}, POST /users/{id}/reset-password
All mutations audit-logged; deactivation/role-change/reset set the user_revoke marker;
listing never exposes password_hash; viewer/analyst get 403.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from tests.unit._test_request import make_test_request


def _mock_pool(fetchrow_results=None, fetch_results=None, execute_returns=None):
    """Build a mock asyncpg pool. fetchrow_results/fetch_results are lists
    consumed in call order."""
    pool = AsyncMock()
    conn = AsyncMock()

    fetchrow_iter = iter(fetchrow_results or [])
    fetch_iter = iter(fetch_results or [])
    exec_iter = iter(execute_returns or [])

    conn.fetchrow = AsyncMock(side_effect=lambda *a, **k: next(fetchrow_iter, None))
    conn.fetch = AsyncMock(side_effect=lambda *a, **k: next(fetch_iter, []))
    conn.execute = AsyncMock(side_effect=lambda *a, **k: next(exec_iter, None))

    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquirer)
    return pool, conn


ADMIN = {"sub": "admin1", "role": "admin"}


class TestListUsers:
    @pytest.mark.asyncio
    async def test_list_returns_users_without_password_hash(self):
        from src.api.users import list_users

        row = {
            "id": 1,
            "username": "analyst1",
            "email": "a@x.io",
            "role": "analyst",
            "is_active": True,
            "must_change_password": False,
            "last_login": None,
            "created_at": None,
        }
        pool, conn = _mock_pool(fetch_results=[[row]])
        with patch("src.api.users.get_pool", return_value=pool):
            result = await list_users(user=ADMIN)

        assert len(result) == 1
        assert result[0].username == "analyst1"
        dumped = result[0].model_dump()
        assert "password_hash" not in dumped
        # and the SQL must not select it either
        sql = conn.fetch.call_args[0][0]
        assert "password_hash" not in sql

    @pytest.mark.asyncio
    async def test_list_rbac_viewer_forbidden(self):
        from src.api.auth import require_role

        check = require_role("admin")
        with patch("src.api.auth.get_current_user", return_value={"sub": "v", "role": "viewer"}):
            with pytest.raises(HTTPException) as exc:
                await check(credentials=MagicMock())
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_list_rbac_analyst_forbidden(self):
        from src.api.auth import require_role

        check = require_role("admin")
        with patch("src.api.auth.get_current_user", return_value={"sub": "a", "role": "analyst"}):
            with pytest.raises(HTTPException) as exc:
                await check(credentials=MagicMock())
        assert exc.value.status_code == 403


class TestCreateUser:
    @pytest.mark.asyncio
    async def test_create_user_forces_password_change(self):
        from src.api.users import UserCreateRequest, create_user

        row = {
            "id": 5,
            "username": "newuser",
            "email": None,
            "role": "viewer",
            "is_active": True,
            "must_change_password": True,
            "last_login": None,
            "created_at": None,
        }
        pool, conn = _mock_pool(fetchrow_results=[row])
        with (
            patch("src.api.users.get_pool", return_value=pool),
            patch("src.api.users.log_audit_action", new=AsyncMock()) as audit,
        ):
            resp = await create_user(
                UserCreateRequest(username="newuser", password="supersecret9", role="viewer"),
                request=make_test_request(),
                user=ADMIN,
            )

        assert resp.must_change_password is True
        assert resp.username == "newuser"
        # password hashed, not stored raw
        args = conn.fetchrow.call_args[0]
        sql, params = args[0], args[1:]
        assert "$3" in sql
        assert params[2] != "supersecret9"  # hashed
        assert params[2].startswith("$2")  # bcrypt
        # audit logged
        audit.assert_awaited_once()
        assert audit.call_args.kwargs["action"] == "user.create"

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username_409(self):
        from asyncpg.exceptions import UniqueViolationError

        from src.api.users import UserCreateRequest, create_user

        pool, conn = _mock_pool()
        err = UniqueViolationError("duplicate key")
        err.constraint_name = "siem_users_username_key"
        conn.fetchrow = AsyncMock(side_effect=err)

        with (
            patch("src.api.users.get_pool", return_value=pool),
            patch("src.api.users.hash_password", return_value="x"),
        ):
            with pytest.raises(HTTPException) as exc:
                await create_user(
                    UserCreateRequest(username="dup", password="supersecret9"),
                    request=make_test_request(),
                    user=ADMIN,
                )
        assert exc.value.status_code == 409

    @pytest.mark.asyncio
    async def test_create_user_short_password_422(self):
        from src.api.users import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="x1", password="short")  # < 8 chars

    @pytest.mark.asyncio
    async def test_create_user_invalid_role_422(self):
        from src.api.users import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="x1", password="supersecret9", role="superadmin")


class TestPatchUser:
    @pytest.mark.asyncio
    async def test_deactivate_sets_revoke_marker(self):
        from src.api.users import UserPatchRequest, patch_user

        existing = {"id": 7, "username": "analyst2", "role": "analyst", "is_active": True}
        updated = dict(
            id=7,
            username="analyst2",
            email=None,
            role="analyst",
            is_active=False,
            must_change_password=False,
            last_login=None,
            created_at=None,
        )
        pool, _conn = _mock_pool(fetchrow_results=[existing, updated])
        with (
            patch("src.api.users.get_pool", return_value=pool),
            patch("src.api.users.log_audit_action", new=AsyncMock()),
            patch("src.api.redis_client.set_user_revoke_marker", new=AsyncMock(return_value=True)) as rev,
        ):
            resp = await patch_user(
                7,
                UserPatchRequest(is_active=False),
                request=make_test_request(),
                user=ADMIN,
            )
        assert resp.is_active is False
        assert resp.revoked_older_tokens is True
        rev.assert_awaited_once()
        assert rev.call_args.args[0] == "analyst2"  # username, not id

    @pytest.mark.asyncio
    async def test_role_change_sets_revoke_marker(self):
        """JWT carries the role claim — old tokens must die on a demotion."""
        from src.api.users import UserPatchRequest, patch_user

        existing = {"id": 3, "username": "rogue", "role": "admin", "is_active": True}
        updated = dict(
            id=3,
            username="rogue",
            email=None,
            role="viewer",
            is_active=True,
            must_change_password=False,
            last_login=None,
            created_at=None,
        )
        pool, _conn = _mock_pool(fetchrow_results=[existing, updated])
        with (
            patch("src.api.users.get_pool", return_value=pool),
            patch("src.api.users.log_audit_action", new=AsyncMock()),
            patch("src.api.redis_client.set_user_revoke_marker", new=AsyncMock(return_value=True)) as rev,
        ):
            resp = await patch_user(
                3, UserPatchRequest(role="viewer"), request=make_test_request(), user=ADMIN
            )
        assert resp.role == "viewer"
        assert resp.revoked_older_tokens is True
        rev.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_role_change_to_same_role_no_revoke(self):
        from src.api.users import UserPatchRequest, patch_user

        existing = {"id": 3, "username": "a1", "role": "analyst", "is_active": True}
        updated = dict(
            id=3,
            username="a1",
            email=None,
            role="analyst",
            is_active=True,
            must_change_password=False,
            last_login=None,
            created_at=None,
        )
        pool, _conn = _mock_pool(fetchrow_results=[existing, updated])
        with (
            patch("src.api.users.get_pool", return_value=pool),
            patch("src.api.users.log_audit_action", new=AsyncMock()),
            patch("src.api.redis_client.set_user_revoke_marker", new=AsyncMock()) as rev,
        ):
            await patch_user(
                3, UserPatchRequest(role="analyst"), request=make_test_request(), user=ADMIN
            )
        rev.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cannot_deactivate_self(self):
        from src.api.users import UserPatchRequest, patch_user

        existing = {"id": 1, "username": "admin1", "role": "admin", "is_active": True}
        pool, _conn = _mock_pool(fetchrow_results=[existing])
        with patch("src.api.users.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc:
                await patch_user(
                    1,
                    UserPatchRequest(is_active=False),
                    request=make_test_request(),
                    user={"sub": "admin1", "role": "admin"},
                )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_cannot_change_own_role(self):
        from src.api.users import UserPatchRequest, patch_user

        existing = {"id": 1, "username": "admin1", "role": "admin", "is_active": True}
        pool, _conn = _mock_pool(fetchrow_results=[existing])
        with patch("src.api.users.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc:
                await patch_user(
                    1,
                    UserPatchRequest(role="viewer"),
                    request=make_test_request(),
                    user={"sub": "admin1", "role": "admin"},
                )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_patch_unknown_user_404(self):
        from src.api.users import UserPatchRequest, patch_user

        pool, _conn = _mock_pool(fetchrow_results=[None])
        with patch("src.api.users.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc:
                await patch_user(
                    999,
                    UserPatchRequest(is_active=False),
                    request=make_test_request(),
                    user=ADMIN,
                )
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_patch_empty_body_422(self):
        from src.api.users import UserPatchRequest, patch_user

        with pytest.raises(HTTPException) as exc:
            await patch_user(
                1, UserPatchRequest(), request=make_test_request(), user=ADMIN
            )
        assert exc.value.status_code == 422

    @pytest.mark.asyncio
    async def test_patch_rbac_viewer_forbidden(self):
        from src.api.auth import require_role

        check = require_role("admin")
        with patch("src.api.auth.get_current_user", return_value={"sub": "v", "role": "viewer"}):
            with pytest.raises(HTTPException) as exc:
                await check(credentials=MagicMock())
        assert exc.value.status_code == 403


class TestResetPassword:
    @pytest.mark.asyncio
    async def test_reset_returns_one_time_password_and_revokes(self):
        from src.api.users import reset_password

        existing = {"id": 4, "username": "locked", "role": "analyst", "is_active": True}
        pool, conn = _mock_pool(fetchrow_results=[existing])
        with (
            patch("src.api.users.get_pool", return_value=pool),
            patch("src.api.users.log_audit_action", new=AsyncMock()) as audit,
            patch("src.api.redis_client.set_user_revoke_marker", new=AsyncMock(return_value=True)) as rev,
            patch("src.api.users.hash_password", return_value="$2b$12$fake") as hp,
        ):
            resp = await reset_password(4, request=make_test_request(), user=ADMIN)

        assert len(resp.temporary_password) >= 20  # token_urlsafe(16) ≈ 22 chars
        assert resp.must_change_password is True
        assert resp.revoked_older_tokens is True
        hp.assert_called_once_with(resp.temporary_password)
        # the UPDATE stores the hash, never the plaintext
        args = conn.execute.call_args[0]
        sql, params = args[0], args[1:]
        assert params[0] == "$2b$12$fake"
        assert resp.temporary_password not in str(params)
        # audit entry carries no plaintext
        audit.assert_awaited_once()
        assert resp.temporary_password not in str(audit.call_args)
        assert audit.call_args.kwargs["action"] == "user.reset_password"
        # lockout state cleared
        assert "locked_until = NULL" in sql

    @pytest.mark.asyncio
    async def test_reset_unknown_user_404(self):
        from src.api.users import reset_password

        pool, _conn = _mock_pool(fetchrow_results=[None])
        with patch("src.api.users.get_pool", return_value=pool):
            with pytest.raises(HTTPException) as exc:
                await reset_password(999, request=make_test_request(), user=ADMIN)
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_reset_rbac_analyst_forbidden(self):
        from src.api.auth import require_role

        check = require_role("admin")
        with patch("src.api.auth.get_current_user", return_value={"sub": "a", "role": "analyst"}):
            with pytest.raises(HTTPException) as exc:
                await check(credentials=MagicMock())
        assert exc.value.status_code == 403


class TestWiring:
    def test_users_router_registered_in_main(self):
        from src.api.main import app

        paths = {r.path for r in app.routes}
        assert "/api/v1/users" in paths
        assert "/api/v1/users/{user_id}" in paths
        assert "/api/v1/users/{user_id}/reset-password" in paths

    def test_endpoints_depend_on_admin_role(self):
        import inspect

        from src.api.users import create_user, list_users, patch_user, reset_password

        for fn in (list_users, create_user, patch_user, reset_password):
            sig = inspect.signature(fn)
            dep = sig.parameters["user"].default
            assert hasattr(dep, "dependency")
            assert dep.dependency.__name__ == "_check_role"
