"""Tests for the SIEM MCP server (V0.4/5 item 2): the closed tool surface,
fail-closed auth, the scoped-role verifier, the tools/call dispatch, and
the audit behavior.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from pydantic import SecretStr

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TOKEN = "correct-token-value-123"


def _rpc(method: str, params: dict | None = None, request_id: int | str = 1) -> bytes:
    body: dict = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    return json.dumps(body).encode()


def _post(body: bytes, headers: dict[str, str] | None = None) -> Request:
    """A real starlette Request carrying a POST body (the endpoint reads it)."""
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
        "root_path": "",
        "asgi": {"version": "3.0", "spec_version": "2.0"},
        "http_version": "1.1",
        "extensions": {},
    }
    return Request(scope, receive)


def _authed(body: bytes, session: str = "sess-1") -> Request:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if session:
        headers["Mcp-Session-Id"] = session
    return _post(body, headers)


class _AuditRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict, str]] = []

    async def __call__(self, action: str, details: dict, actor: str) -> None:
        self.events.append((action, details, actor))


@pytest.fixture(autouse=True)
def _server_state(monkeypatch):
    """Default server state per test: auth ready, scope OK, token set."""
    from src.mcp_server import app as app_module

    monkeypatch.setattr(
        "src.mcp_server.app.settings",
        _settings(mcp_token=TOKEN),
    )
    monkeypatch.setattr(
        app_module, "_state", {"auth_ready": True, "scope_ok": True, "scope_violations": []}
    )
    yield


def _settings(mcp_token: str | None, **overrides):
    s = MagicMock()
    s.mcp_bearer_token = SecretStr(mcp_token) if mcp_token is not None else None
    s.db_user = "scarletai_readonly"
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


def _audits() -> _AuditRecorder:
    return _AuditRecorder()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Protocol
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestProtocol:
    def test_parse_rpc_accepts_valid(self):
        from src.mcp_server.protocol import parse_rpc

        rpc, err = parse_rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert err is None
        assert rpc["method"] == "ping"

    def test_parse_rpc_rejects_bad_jsonrpc_version(self):
        from src.mcp_server.protocol import INVALID_REQUEST, parse_rpc

        rpc, err = parse_rpc({"jsonrpc": "1.0", "id": 1, "method": "x"})
        assert rpc is None
        assert err is not None
        assert err["error"]["code"] == INVALID_REQUEST

    def test_parse_rpc_rejects_missing_method(self):
        from src.mcp_server.protocol import parse_rpc

        rpc, err = parse_rpc({"jsonrpc": "2.0", "id": 1})
        assert rpc is None and err is not None

    def test_tool_errors_are_results_with_is_error(self):
        from src.mcp_server.protocol import error_result, text_result

        ok = text_result({"a": 1})
        assert ok["isError"] is False
        assert '"a"' in ok["content"][0]["text"]
        bad = error_result("nope")
        assert bad["isError"] is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# The closed tool surface
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestToolCatalog:
    def test_exactly_three_read_only_tools(self):
        from src.mcp_server.tools import tool_catalog

        tools = tool_catalog()
        assert [t["name"] for t in tools] == ["investigate", "hunt", "explain"]
        assert all(t["annotations"]["readOnlyHint"] is True for t in tools)

    def test_no_mutation_tool_exists_anywhere(self):
        """Structural: no write-ish tool name may ever join the catalog."""
        from src.mcp_server.tools import TOOL_IMPLEMENTATIONS

        forbidden = (
            "quarantine",
            "disable",
            "isolate",
            "block",
            "delete",
            "create",
            "update",
            "execute_action",
            "request_action",
            "approve",
        )
        for name in TOOL_IMPLEMENTATIONS:
            assert not any(f in name for f in forbidden), name


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scoped-role verifier
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _pool_with_grants(grants: dict[str, set[str]], current_user: str = "scarletai_readonly"):
    pool = AsyncMock()
    conn = AsyncMock()
    acq = AsyncMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq)
    conn.fetchval.return_value = current_user
    conn.fetch.return_value = [
        {"table_name": t, "privilege_type": p} for t, privs in grants.items() for p in privs
    ]
    return pool


_CLEAN_GRANTS = {
    "logs": {"SELECT"},
    "alerts": {"SELECT"},
    "rules": {"SELECT"},
    "correlation_matches": {"SELECT"},
    "cases": {"SELECT"},
    "case_events": {"SELECT"},
    "response_actions": {"SELECT"},
    "agent_investigations": {"SELECT", "INSERT", "UPDATE"},
    "audit_log": {"INSERT", "SELECT"},
    "audit_logs": {"INSERT", "SELECT"},
    "ai_usage": {"INSERT", "SELECT"},
}


class TestVerifyScopedRole:
    @pytest.mark.asyncio
    async def test_clean_grants_pass(self):
        from src.mcp_server.tools import verify_scoped_role

        pool = _pool_with_grants(_CLEAN_GRANTS)
        with patch("src.db.connection.get_pool", AsyncMock(return_value=pool)):
            violations = await verify_scoped_role("scarletai_readonly")

        assert violations == []

    @pytest.mark.asyncio
    async def test_mutation_right_on_data_table_is_a_violation(self):
        from src.mcp_server.tools import verify_scoped_role

        grants = {**_CLEAN_GRANTS, "logs": {"SELECT", "UPDATE"}}
        pool = _pool_with_grants(grants)
        with patch("src.db.connection.get_pool", AsyncMock(return_value=pool)):
            violations = await verify_scoped_role("scarletai_readonly")

        assert any("logs" in v and "UPDATE" in v for v in violations)

    @pytest.mark.asyncio
    async def test_missing_select_is_a_violation(self):
        from src.mcp_server.tools import verify_scoped_role

        grants = {k: v for k, v in _CLEAN_GRANTS.items() if k != "alerts"}
        pool = _pool_with_grants(grants)
        with patch("src.db.connection.get_pool", AsyncMock(return_value=pool)):
            violations = await verify_scoped_role("scarletai_readonly")

        assert any("alerts" in v for v in violations)

    @pytest.mark.asyncio
    async def test_wrong_role_identity_is_a_violation(self):
        from src.mcp_server.tools import verify_scoped_role

        pool = _pool_with_grants(_CLEAN_GRANTS, current_user="scarletai")
        with patch("src.db.connection.get_pool", AsyncMock(return_value=pool)):
            violations = await verify_scoped_role("scarletai_readonly")

        assert any("connected as" in v for v in violations)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# The /mcp endpoint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestMcpEndpoint:
    @pytest.mark.asyncio
    async def test_unauthenticated_refused(self, monkeypatch):
        from src.mcp_server import app as app_module

        response = await app_module.mcp_endpoint(_post(_rpc("ping")))
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_token_refused(self, monkeypatch):
        from src.mcp_server import app as app_module

        response = await app_module.mcp_endpoint(
            _post(_rpc("ping"), headers={"Authorization": "Bearer wrong-token-value"})
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_disabled_refuses_everything(self, monkeypatch):
        from src.mcp_server import app as app_module

        monkeypatch.setattr(
            app_module, "_state", {"auth_ready": False, "scope_ok": False, "scope_violations": []}
        )
        response = await app_module.mcp_endpoint(
            _post(_rpc("ping"), headers={"Authorization": f"Bearer {TOKEN}"})
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_sse_refused(self):
        from src.mcp_server import app as app_module

        response = await app_module.mcp_endpoint(
            _post(
                _rpc("tools/list"),
                headers={"Authorization": f"Bearer {TOKEN}", "Accept": "text/event-stream"},
            )
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_json_400(self):
        from src.mcp_server import app as app_module

        response = await app_module.mcp_endpoint(
            _post(b"not json", headers={"Authorization": f"Bearer {TOKEN}"})
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_bad_envelope_400(self):
        from src.mcp_server import app as app_module

        response = await app_module.mcp_endpoint(
            _post(
                json.dumps({"jsonrpc": "1.0"}).encode(),
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_unknown_method(self):
        from src.mcp_server import app as app_module

        with patch("src.mcp_server.app._audit_fn", return_value=("mcp:x", _AuditRecorder())):
            response = await app_module.mcp_endpoint(_authed(_rpc("resources/list")))

        body = json.loads(response.body)
        assert body["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_initialize_and_tools_list(self):
        from src.mcp_server import app as app_module

        with patch("src.mcp_server.app._audit_fn", return_value=("mcp:x", _AuditRecorder())):
            init = await app_module.mcp_endpoint(_authed(_rpc("initialize", {})))
            listing = await app_module.mcp_endpoint(_authed(_rpc("tools/list")))

        assert json.loads(init.body)["result"]["serverInfo"]["name"] == "securityscarletai"
        tools = json.loads(listing.body)["result"]["tools"]
        assert [t["name"] for t in tools] == ["investigate", "hunt", "explain"]

    @pytest.mark.asyncio
    async def test_tools_call_unknown_tool_denied_and_audited(self):
        from src.mcp_server import app as app_module

        audits = _AuditRecorder()

        with patch("src.mcp_server.app._audit_fn", return_value=("mcp:sess-1", audits)):
            response = await app_module.mcp_endpoint(
                _authed(_rpc("tools/call", {"name": "quarantine_host", "arguments": {}}))
            )

        body = json.loads(response.body)
        assert body["error"]["code"] == -32002
        assert "closed" in body["error"]["message"]
        assert any(a == "mcp.tool_denied" for a, _, _ in audits.events)
        # Session attribution rides the audit details.
        denied = [e for e in audits.events if e[0] == "mcp.tool_denied"]
        assert denied[0][1]["tool"] == "quarantine_host"

    @pytest.mark.asyncio
    async def test_tools_call_scope_violation_refused(self, monkeypatch):
        from src.mcp_server import app as app_module

        monkeypatch.setattr(
            app_module, "_state", {"auth_ready": True, "scope_ok": False, "scope_violations": ["x"]}
        )
        audits = _AuditRecorder()

        with patch("src.mcp_server.app._audit_fn", return_value=("mcp:x", audits)):
            response = await app_module.mcp_endpoint(
                _authed(
                    _rpc("tools/call", {"name": "investigate", "arguments": {"objective": "obj"}})
                )
            )

        body = json.loads(response.body)
        assert body["result"]["isError"] is True
        assert "scope violation" in body["result"]["content"][0]["text"]
        assert any(a == "mcp.tool_denied" for a, _, _ in audits.events)

    @pytest.mark.asyncio
    async def test_tools_call_happy_path_audited(self, monkeypatch):
        from src.mcp_server import app as app_module

        async def _fake_call_tool(name, args, actor, audit):
            return {"ok": True}, None

        audits = _AuditRecorder()
        with (
            patch("src.mcp_server.app._audit_fn", return_value=("mcp:sess-1", audits)),
            patch("src.mcp_server.app.call_tool", _fake_call_tool),
        ):
            response = await app_module.mcp_endpoint(
                _authed(_rpc("tools/call", {"name": "hunt", "arguments": {"template_id": "t"}}))
            )

        body = json.loads(response.body)
        assert body["result"]["isError"] is False
        assert any(a == "mcp.tool_call" for a, _, _ in audits.events)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Auth
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAuth:
    def test_correct_token_accepted(self, monkeypatch):
        from src.mcp_server import app as app_module

        request = _post(b"", headers={"Authorization": f"Bearer {TOKEN}"})
        assert app_module._auth_ok(request) is True

    def test_wrong_token_rejected(self, monkeypatch):
        from src.mcp_server import app as app_module

        request = _post(b"", headers={"Authorization": "Bearer wrong-token-value"})
        assert app_module._auth_ok(request) is False

    def test_missing_header_rejected(self, monkeypatch):
        from src.mcp_server import app as app_module

        request = _post(b"")
        assert app_module._auth_ok(request) is False

    def test_no_token_configured_rejects_anything(self, monkeypatch):
        from src.mcp_server import app as app_module

        monkeypatch.setattr("src.mcp_server.app.settings", _settings(mcp_token=None))
        request = _post(b"", headers={"Authorization": "Bearer anything"})
        assert app_module._auth_ok(request) is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool dispatch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCallTool:
    @pytest.mark.asyncio
    async def test_investigate_args_validated(self):
        from src.mcp_server.tools import call_tool

        result, err = await call_tool(
            "investigate", {"objective": "x"}, "mcp:test", _AuditRecorder()
        )
        assert result is None
        assert "objective" in (err or "")

    @pytest.mark.asyncio
    async def test_unknown_tool_denied(self):
        from src.mcp_server.tools import call_tool

        result, err = await call_tool("delete_all", {}, "mcp:test", _AuditRecorder())
        assert result is None
        assert "unknown tool" in (err or "")

    @pytest.mark.asyncio
    async def test_hunt_happy_path(self):
        from src.mcp_server.tools import call_tool

        async def _fake_hunt(template_id, actor=None):
            return {"success": True, "results": [], "row_count": 0}

        with patch("src.mcp_server.tools.execute_hunt", _fake_hunt):
            result, err = await call_tool(
                "hunt",
                {"template_id": "c2_beaconing_connections"},
                "mcp:test",
                _AuditRecorder(),
            )
        assert err is None
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_investigation_failure_is_an_error_result(self):
        from src.mcp_server.tools import call_tool

        async def _fail(*args, **kwargs):
            raise RuntimeError("LLM down")

        with patch("src.mcp_server.tools.run_investigation", _fail):
            result, err = await call_tool(
                "investigate", {"objective": "investigate the alert"}, "mcp:test", _AuditRecorder()
            )
        assert result is None
        assert "failed" in (err or "")
