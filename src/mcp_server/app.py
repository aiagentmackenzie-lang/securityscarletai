"""The MCP server ASGI app: auth, dispatch, audit.

One endpoint: POST /mcp (JSON-RPC 2.0). Plus GET /healthz for ops.

Fail-closed posture:
  - MCP_BEARER_TOKEN unset -> the lifespan marks the server disabled and
    EVERY call is refused 503 (no silent open server).
  - DB-scope violations (verify_scoped_role) -> every tool call refused.
  - Unknown methods -> -32601; unknown tools -> -32002 denial + audit.
  - SSE requests -> 422 (request/response only, same posture as
    NeuralGuard's gateway).
  - Every tools/call (allowed or denied) rides the append-only audit chain
    via log_audit_action with session attribution.
"""

from __future__ import annotations

import hmac
import socket
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.config.logging import get_logger, setup_logging
from src.config.settings import settings
from src.config.version import APP_VERSION
from src.ingestion.ai_usage import build_ai_usage_event, emit_ai_usage_event
from src.mcp_server import protocol as rpc
from src.mcp_server.tools import TOOL_IMPLEMENTATIONS, call_tool, tool_catalog, verify_scoped_role

log = get_logger("mcp_server")

# Process state, set by the lifespan. Fail-closed defaults: a tool call
# before boot completes (impossible in practice) is refused.
_state: dict = {
    "auth_ready": False,  # MCP_BEARER_TOKEN configured
    "scope_ok": False,  # DB role verified scoped
    "scope_violations": [],
}

# AUD-031: the app-level _tool_semaphore that used to be created here was
# dead — never acquired; the REAL bounded-concurrency cap is tools.py's
# module-level _tool_semaphore (acquired in call_tool).


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()

    # Auth gate: no token -> no service.
    if settings.mcp_bearer_token is None:
        _state["auth_ready"] = False
        log.warning("mcp_server_disabled_no_token")
    else:
        _state["auth_ready"] = True

    # DB-scope gate: the process must run as the scoped read-only role.
    if _state["auth_ready"]:
        try:
            from src.db.connection import get_pool

            await get_pool()
            violations = await verify_scoped_role(settings.db_user)
            _state["scope_violations"] = violations
            if violations:
                _state["scope_ok"] = False
                for v in violations:
                    log.error("mcp_scope_violation", violation=v)
            else:
                _state["scope_ok"] = True
                log.info("mcp_scope_verified", db_user=settings.db_user)
        except Exception as e:
            _state["scope_ok"] = False
            _state["scope_violations"] = [f"scope check failed: {str(e)[:200]}"]
            log.error("mcp_scope_check_failed", error=str(e))
    yield
    try:
        from src.db.connection import close_pool

        await close_pool()
    except Exception as e:  # pragma: no cover -- best-effort shutdown
        log.warning("mcp_pool_close_failed", error=str(e))
    log.info("mcp_server_shutdown")


app = FastAPI(
    title="SecurityScarletAI MCP Server",
    version=APP_VERSION,  # AUD-037: single source, not a stale literal
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _auth_ok(request: "Request") -> bool:
    """Constant-time bearer check. MCP_BEARER_TOKEN only."""
    if settings.mcp_bearer_token is None:
        return False
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return False
    provided = header[7:]
    expected = settings.mcp_bearer_token.get_secret_value()
    # W3-B: compare_digest raises TypeError on non-ASCII str — a hostile
    # non-ASCII bearer got a 500 instead of a 401. Compare on UTF-8 bytes:
    # still constant-time, any bytes accepted, mismatch still refuses
    # (noise hygiene, not an auth bypass fix).
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _audit_fn(session: str) -> tuple[str, Any]:
    """Audit closure for the append-only chain (INSERT on the scoped role)."""
    from src.api.audit import log_audit_action

    actor = f"mcp:{session or 'anonymous'}"

    async def _audit(action: str, details: dict, audit_actor: str) -> None:
        await log_audit_action(
            actor=audit_actor,
            action=action,
            target_type="mcp_tool",
            target_id=None,
            new_values=details,
            ip_address=None,
        )

    return actor, _audit


async def _emit_tool_event(
    *, kind: str, actor: str, tool: str | None, session: str, detail: dict
) -> None:
    """Emit one AI-usage event through the real ingest pipe (V0.4/5 item 3:
    the SIEM watches its own MCP surface). Best-effort: the append-only
    audit row is the source of truth; a failed emission is logged."""
    try:
        event = build_ai_usage_event(
            kind,
            actor=actor,
            tool=tool,
            session=session or None,
            detail=detail,
            host_name=getattr(settings, "ai_usage_hostname", None) or socket.gethostname(),
        )
        await emit_ai_usage_event(event)
    except Exception as e:  # telemetry is best-effort; the tool result stands
        log.warning("mcp_ai_usage_emit_failed", tool=tool, error=str(e)[:200])


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "status": "ok",
        "auth_ready": _state["auth_ready"],
        "scope_ok": _state["scope_ok"],
        "scope_violations": _state["scope_violations"],
    }


@app.post("/mcp")
async def mcp_endpoint(request: "Request") -> "JSONResponse":
    session = request.headers.get("mcp-session-id") or ""
    headers = {"Mcp-Session-Id": session} if session else {}

    # SSE is refused (fail-closed, request/response only).
    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept and "application/json" not in accept:
        return JSONResponse(
            status_code=422,
            content=rpc.error_response(None, rpc.INVALID_REQUEST, "SSE streaming is not supported"),
            headers=headers,
        )

    if not _state["auth_ready"] or not _auth_ok(request):
        return JSONResponse(
            status_code=401,
            content=rpc.error_response(None, rpc.INVALID_REQUEST, "unauthorized"),
            headers=headers,
        )

    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(
            status_code=400,
            content=rpc.error_response(None, rpc.PARSE_ERROR, "invalid JSON"),
            headers=headers,
        )
    parsed, parse_err = rpc.parse_rpc(body)
    if parse_err is not None:
        return JSONResponse(status_code=400, content=parse_err, headers=headers)
    if parsed is None:  # defensive: parse_err None implies parsed
        return JSONResponse(
            status_code=400,
            content=rpc.error_response(None, rpc.INTERNAL_ERROR, "parse inconsistency"),
            headers=headers,
        )
    method = parsed["method"]
    request_id = parsed.get("id")
    params = parsed.get("params") or {}
    actor, audit = _audit_fn(session)

    if method == "initialize":
        return JSONResponse(
            content=rpc.result_response(
                request_id,
                {
                    "protocolVersion": rpc.SUPPORTED_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "securityscarletai", "version": APP_VERSION},
                },
            ),
            headers=headers,
        )

    if method == "ping":
        return JSONResponse(content=rpc.result_response(request_id, {}), headers=headers)

    if method == "tools/list":
        return JSONResponse(
            content=rpc.result_response(request_id, {"tools": tool_catalog()}),
            headers=headers,
        )

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not _state["scope_ok"]:
            detail = "DB role scope violation -- tools refused (fail-closed)"
            log.warning("mcp_tool_refused_scope", tool=name, actor=actor)
            await audit("mcp.tool_denied", {"tool": name, "reason": "scope_violation"}, actor)
            return JSONResponse(
                content=rpc.result_response(request_id, rpc.error_result(detail)),
                headers=headers,
            )
        if not isinstance(name, str):
            await audit("mcp.tool_denied", {"tool": None, "reason": "invalid_params"}, actor)
            await _emit_tool_event(
                kind="mcp_tool_denied",
                actor=actor,
                tool=None,
                session=session,
                detail={"reason": "invalid_params"},
            )
            return JSONResponse(
                content=rpc.error_response(
                    request_id, rpc.INVALID_PARAMS, "params.name must be a string"
                ),
                headers=headers,
            )
        if name not in TOOL_IMPLEMENTATIONS:
            log.warning("mcp_tool_denied_unknown", tool=name, actor=actor)
            await audit(
                "mcp.tool_denied",
                {"tool": name, "reason": "unknown_tool"},
                actor,
            )
            await _emit_tool_event(
                kind="mcp_tool_denied",
                actor=actor,
                tool=name if isinstance(name, str) else None,
                session=session,
                detail={"reason": "unknown_tool"},
            )
            return JSONResponse(
                content=rpc.error_response(
                    request_id,
                    rpc.TOOL_DENIED,
                    f"unknown tool '{name}' (the tool surface is closed: "
                    "investigate, hunt, explain)",
                ),
                headers=headers,
            )

        started = time.monotonic()
        result, err = await call_tool(name, arguments, actor, audit)
        elapsed = int((time.monotonic() - started) * 1000)
        if err is not None:
            # Tool-level failure -> isError RESULT (MCP convention: the
            # agent loop sees and reacts to it), plus the audit row.
            log.warning("mcp_tool_error", tool=name, actor=actor, error=err)
            await audit("mcp.tool_call", {"tool": name, "error": err, "latency_ms": elapsed}, actor)
            await _emit_tool_event(
                kind="mcp_tool_denied",
                actor=actor,
                tool=name,
                session=session,
                detail={"error": err, "latency_ms": elapsed},
            )
            return JSONResponse(
                content=rpc.result_response(request_id, rpc.error_result(err)),
                headers=headers,
            )
        await audit(
            "mcp.tool_call",
            {"tool": name, "latency_ms": elapsed},
            actor,
        )
        await _emit_tool_event(
            kind="mcp_tool_call",
            actor=actor,
            tool=name,
            session=session,
            detail={"latency_ms": elapsed},
        )
        return JSONResponse(
            content=rpc.result_response(request_id, rpc.text_result(result)),
            headers=headers,
        )

    return JSONResponse(
        content=rpc.error_response(request_id, rpc.METHOD_NOT_FOUND, f"unknown method '{method}'"),
        headers=headers,
    )
