"""SIEM MCP server (V0.4/5 "Agentic SOC", item 2).

The SecurityScarletAI SIEM exposed as an MCP server for the analyst's
agents. Tools: investigate / hunt / explain -- ALL read-only.

Transport: JSON-RPC 2.0 over streamable-HTTP POST (request/response only;
SSE is refused 422, fail-closed -- the same posture as NeuralGuard's MCP
gateway, which is the portfolio's reference shape).

Trust boundary:
  - The MCP process runs as a SCOPED READ-ONLY DB role (scarletai_readonly,
    provisioned by scripts/provision_readonly.sql). The scope is verified at
    boot; on drift every tool call is refused (fail-closed).
  - MCP auth is MCP_BEARER_TOKEN only, constant-time compared. Unset token
    -> the server refuses all calls (no silent open server).
  - The tool surface is CLOSED: exactly three tools, no mutation tool exists.
  - Untrusted content crossing into LLM prompts (evidence, query results,
    objectives) rides the existing untrusted-content stack (src/ai/untrusted)
    inside the agent core and the explanation path.
  - Every tools/call (allowed or denied) rides the append-only audit chain
    with session attribution.

Modules:
    protocol.py -- JSON-RPC 2.0 envelope + MCP error codes
    tools.py    -- the tool surface + the DB-scope verifier
    app.py      -- the ASGI app: auth, dispatch, audit
"""
