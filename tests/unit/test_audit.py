"""
Tests for the DB-backed audit log (Epic 6).

Covers:
- audit_logs table is appended to schema.sql with expected columns
- log_request_audit() never raises on DB failure (audit must not break requests)
- query_request_audit() endpoint exists and accepts the documented filters
- AuditLogMiddleware writes one row per state-changing request
- Audit middleware catches and logs write failures (request still succeeds)
- GRANT/REVOKE hardening is documented in schema.sql
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from src.api.audit import log_request_audit
from tests.unit._test_request import make_test_request


REPO_ROOT = Path(__file__).resolve().parents[2]


# ───────────────────────────────────────────────────────────────
# Schema
# ───────────────────────────────────────────────────────────────


class TestAuditLogsTable:
    @pytest.fixture(scope="class")
    def schema(self) -> str:
        with open(REPO_ROOT / "src/db/schema.sql") as f:
            return f.read()

    def test_audit_logs_table_present(self, schema: str):
        assert "CREATE TABLE IF NOT EXISTS audit_logs (" in schema

    def test_has_required_columns(self, schema: str):
        # The CREATE TABLE audit_logs block should contain the columns
        # specified in the Epic 6 brief.
        block_match = re.search(
            r"CREATE TABLE IF NOT EXISTS audit_logs \((.*?)\);",
            schema,
            re.DOTALL,
        )
        assert block_match is not None
        block = block_match.group(1)
        for col in (
            "id",
            "timestamp",
            "user",
            "role",
            "method",
            "path",
            "ip",
            "status_code",
            "request_body_hash",
            "duration_ms",
        ):
            assert col in block, f"audit_logs missing column: {col}"

    def test_has_indexes(self, schema: str):
        # At least the user + timestamp indexes from the brief
        assert "idx_audit_logs_user" in schema
        assert "idx_audit_logs_timestamp" in schema

    def test_grant_revoke_documented(self, schema: str):
        # The hardening commands must be present as a comment so a DBA
        # can apply them in the order they appear in the file.
        assert "REVOKE" in schema and "audit_logs" in schema
        assert "GRANT" in schema and "audit_logs" in schema

    def test_user_column_quoted(self, schema: str):
        # "user" is a reserved word in Postgres; the column must be quoted.
        # Check the actual CREATE TABLE block.
        block_match = re.search(
            r"CREATE TABLE IF NOT EXISTS audit_logs \((.*?)\);",
            schema,
            re.DOTALL,
        )
        assert block_match is not None
        block = block_match.group(1)
        # Look for "user" with double quotes
        assert '"user"' in block, '"user" column must be quoted (reserved word)'


# ───────────────────────────────────────────────────────────────
# log_request_audit
# ───────────────────────────────────────────────────────────────


class TestLogRequestAudit:
    @pytest.mark.asyncio
    async def test_writes_row(self):
        pool = MagicMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", return_value=pool):
            await log_request_audit(
                user="alice",
                role="analyst",
                method="POST",
                path="/api/v1/alerts",
                ip="10.0.0.1",
                status_code=201,
                duration_ms=42,
                request_body_hash="abc123",
            )

        conn.execute.assert_called_once()
        args = conn.execute.call_args
        # The SQL string is positional arg 0
        assert "INSERT INTO audit_logs" in args[0][0]
        # Bound params start at positional arg 1
        sql_params = args[0][1:]
        assert sql_params[0] == "alice"
        assert sql_params[1] == "analyst"
        assert sql_params[2] == "POST"
        assert sql_params[3] == "/api/v1/alerts"
        assert sql_params[4] == "10.0.0.1"
        assert sql_params[5] == 201
        assert sql_params[7] == 42

    @pytest.mark.asyncio
    async def test_swallows_db_failure(self):
        """Audit failure must not raise — the request has already succeeded."""
        pool = MagicMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(side_effect=Exception("DB went away"))
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", return_value=pool):
            # Should NOT raise
            await log_request_audit(
                user="bob",
                role="viewer",
                method="PUT",
                path="/api/v1/cases/1",
                ip="10.0.0.2",
                status_code=200,
                duration_ms=15,
            )

    @pytest.mark.asyncio
    async def test_handles_none_user(self):
        """Pre-auth requests may have no user. Should still write a row."""
        pool = MagicMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", return_value=pool):
            await log_request_audit(
                user=None,
                role=None,
                method="POST",
                path="/api/v1/auth/login",
                ip="10.0.0.3",
                status_code=401,
                duration_ms=8,
            )

        params = conn.execute.call_args[0][1:]
        assert params[0] is None  # user
        assert params[1] is None  # role


# ───────────────────────────────────────────────────────────────
# query_request_audit endpoint
# ───────────────────────────────────────────────────────────────


class TestQueryRequestAudit:
    def test_endpoint_registered(self):
        """GET /api/v1/audit/requests must be wired."""
        from src.api.audit import router

        paths = {r.path for r in router.routes}
        assert "/audit/requests" in paths
        # And the existing action-level endpoint should still be there
        assert "/audit" in paths

    def test_audit_router_url_prefix(self):
        from src.api.audit import router

        assert router.prefix == "/audit"

    @pytest.mark.asyncio
    async def test_query_with_filters(self):
        # Smoke test: build a fake pool, call the function, verify SQL shape
        from src.api.audit import query_request_audit

        pool = MagicMock()
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", return_value=pool):
            result = await query_request_audit(
                user="alice",
                method="post",
                path="/api/v1/alerts",
                since="2026-06-01T00:00:00Z",
                until="2026-06-02T00:00:00Z",
                limit=10,
                offset=0,
                _user={"sub": "viewer", "role": "analyst"},
            )

        assert result == []
        # Verify the SQL is from audit_logs (NOT audit_log)
        sql = conn.fetch.call_args[0][0]
        assert "FROM audit_logs" in sql
        assert "FROM audit_log " not in sql  # singular
        # Filters should appear in the WHERE clause
        assert '"user" = $1' in sql
        assert "method = $2" in sql
        assert "path = $3" in sql


# ───────────────────────────────────────────────────────────────
# AuditLogMiddleware
# ───────────────────────────────────────────────────────────────


class TestAuditLogMiddleware:
    @pytest.mark.asyncio
    async def test_writes_for_state_changing_methods(self):
        from src.api.middleware import AuditLogMiddleware

        middleware = AuditLogMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/v1/alerts", method="POST")
        req.state.user = {"sub": "alice", "role": "analyst"}

        # The next handler returns a 201 response
        async def fake_call_next(_request):
            from starlette.responses import Response

            return Response(content="ok", status_code=201)

        with patch("src.api.audit.log_request_audit") as mock_audit:
            mock_audit.return_value = AsyncMock()
            response = await middleware.dispatch(req, fake_call_next)

        assert response.status_code == 201
        mock_audit.assert_called_once()
        kwargs = mock_audit.call_args.kwargs
        assert kwargs["user"] == "alice"
        assert kwargs["role"] == "analyst"
        assert kwargs["method"] == "POST"
        assert kwargs["path"] == "/api/v1/alerts"
        assert kwargs["status_code"] == 201
        assert kwargs["duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_skips_health_checks(self):
        from src.api.middleware import AuditLogMiddleware

        middleware = AuditLogMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/v1/health", method="POST")

        async def fake_call_next(_request):
            from starlette.responses import Response

            return Response(content="ok", status_code=200)

        with patch("src.api.audit.log_request_audit") as mock_audit:
            response = await middleware.dispatch(req, fake_call_next)

        mock_audit.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_docs(self):
        from src.api.middleware import AuditLogMiddleware

        middleware = AuditLogMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/docs", method="POST")

        async def fake_call_next(_request):
            from starlette.responses import Response

            return Response(content="ok", status_code=200)

        with patch("src.api.audit.log_request_audit") as mock_audit:
            response = await middleware.dispatch(req, fake_call_next)

        mock_audit.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_gets(self):
        from src.api.middleware import AuditLogMiddleware

        middleware = AuditLogMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/v1/alerts", method="GET")

        async def fake_call_next(_request):
            from starlette.responses import Response

            return Response(content="ok", status_code=200)

        with patch("src.api.audit.log_request_audit") as mock_audit:
            response = await middleware.dispatch(req, fake_call_next)

        mock_audit.assert_not_called()

    @pytest.mark.asyncio
    async def test_audit_failure_does_not_break_request(self):
        from src.api.middleware import AuditLogMiddleware

        middleware = AuditLogMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/v1/alerts", method="POST")

        async def fake_call_next(_request):
            from starlette.responses import Response

            return Response(content="ok", status_code=201)

        # Make audit raise — middleware should swallow
        with patch(
            "src.api.audit.log_request_audit",
            new=AsyncMock(side_effect=Exception("audit db down")),
        ):
            response = await middleware.dispatch(req, fake_call_next)

        # Request still succeeded
        assert response.status_code == 201

    @pytest.mark.asyncio
    async def test_no_user_state_still_audits(self):
        """Pre-auth requests (e.g. /auth/login itself) have no user.
        The middleware should still log the request with user=None."""
        from src.api.middleware import AuditLogMiddleware

        middleware = AuditLogMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/v1/auth/login", method="POST")
        # Note: no req.state.user set

        async def fake_call_next(_request):
            from starlette.responses import Response

            return Response(content="ok", status_code=401)

        with patch("src.api.audit.log_request_audit") as mock_audit:
            response = await middleware.dispatch(req, fake_call_next)

        mock_audit.assert_called_once()
        kwargs = mock_audit.call_args.kwargs
        assert kwargs["user"] is None
        assert kwargs["status_code"] == 401
