"""JSON-RPC 2.0 envelope + MCP method/error constants.

MCP rides JSON-RPC 2.0 over HTTP POST (streamable-HTTP transport,
request/response). SSE streaming is refused upstream (fail-closed) --
this module only shapes the single-response form.
"""

from __future__ import annotations

from typing import Any

# JSON-RPC / MCP error codes (spec-aligned; -32000..-32099 server-defined).
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
TOOL_UNAVAILABLE = -32001  # server-defined: auth disabled / DB scope drift
TOOL_DENIED = -32002  # server-defined: unknown tool / denied call

SUPPORTED_PROTOCOL_VERSION = "2025-06-18"


def error_response(request_id: Any, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def result_response(request_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def parse_rpc(body: Any) -> tuple[dict | None, dict | None]:
    """Validate the JSON-RPC request envelope. Returns (rpc, error)."""
    if not isinstance(body, dict):
        return None, error_response(None, INVALID_REQUEST, "body must be a JSON-RPC object")
    if body.get("jsonrpc") != "2.0":
        return None, error_response(body.get("id"), INVALID_REQUEST, 'jsonrpc must be "2.0"')
    method = body.get("method")
    if not isinstance(method, str) or not method:
        return None, error_response(
            body.get("id"), INVALID_REQUEST, "method must be a non-empty string"
        )
    return body, None


def text_result(payload: Any) -> dict:
    """MCP tools/call result: one text content block with the JSON payload.

    Tool-level failures are reported as isError=true RESULTS (the MCP
    convention: protocol errors are JSON-RPC errors, tool errors are
    results) so a client's agent loop can see and react to them.
    """
    return {
        "content": [
            {
                "type": "text",
                "text": payload if isinstance(payload, str) else json_dumps(payload),
            }
        ],
        "isError": False,
    }


def error_result(message: str) -> dict:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, default=str, indent=1)
