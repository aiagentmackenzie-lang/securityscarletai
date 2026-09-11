"""The MCP tool surface + the scoped-role verifier.

THREE tools, all read-only:
  investigate {objective, alert_id?} -- the read-only agentic investigation
    (src.agents.investigator): plan -> query (NL->SQL guardrail stack) ->
    correlate -> verdict DRAFT (HITL required). The agent has no write
    tools; a verdict draft is advisory until a human decides.
  hunt {template_id} -- execute a pre-built hunting query (parameterized,
    bounded SQL; the LLM analysis is advisory).
  explain {alert_id} -- AI explanation for one alert (evidence fenced).

The tool list is CLOSED. A tool/call for anything else is denied and
audited -- there is no mutation tool to fall back to, by construction.

The DB-scope verifier is the runtime half of the two-role posture:
scripts/provision_readonly.sql grants the MCP process's role exactly the
privileges below; this module re-checks them at boot and refuses tools on
drift (defense in depth below the code-level read-only paths).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from src.agents.investigator import run_investigation
from src.ai.alert_explanation import explain_alert
from src.ai.hunting_assistant import execute_hunt
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("mcp_server.tools")

# Concurrency cap: bounded everything. The investigate tool runs a
# multi-step LLM loop; two concurrent runs are the working set.
MAX_CONCURRENT_TOOL_CALLS = 2
# Created at module level: asyncio primitives do not bind to a loop until
# awaited (Python 3.10+), so this is safe across test event loops.
_tool_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TOOL_CALLS)


def tool_catalog() -> list[dict]:
    """The closed tool surface (tools/list payload)."""
    return [
        {
            "name": "investigate",
            "description": (
                "Run a read-only security investigation: plan-generate -> "
                "query -> correlate -> verdict DRAFT. Every step rides the "
                "SIEM audit chain. The AI verdict is a DRAFT requiring human "
                "confirmation (HITL); the agent has no write tools."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "objective": {
                        "type": "string",
                        "minLength": 3,
                        "maxLength": 2000,
                        "description": "What to investigate (natural language).",
                    },
                    "alert_id": {
                        "type": "integer",
                        "description": "Optional alert to investigate (fenced context).",
                    },
                },
                "required": ["objective"],
            },
            "annotations": {"readOnlyHint": True},
        },
        {
            "name": "hunt",
            "description": (
                "Execute a pre-built, parameterized hunting query by template "
                "id. Read-only; results are bounded and the analysis is "
                "advisory."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "A hunt template id (see the SIEM API /hunt/templates).",
                    }
                },
                "required": ["template_id"],
            },
            "annotations": {"readOnlyHint": True},
        },
        {
            "name": "explain",
            "description": (
                "AI explanation for one alert: what the detection means, what "
                "to check next. Evidence is fenced as untrusted data."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "integer", "description": "The alert to explain."}
                },
                "required": ["alert_id"],
            },
            "annotations": {"readOnlyHint": True},
        },
    ]


# ───────────────────────────────────────────────────────────────
# Scoped-role verification (fail-closed boot check)
# ───────────────────────────────────────────────────────────────

# The privilege contract per table for the MCP process's DB role.
_READ_ONLY_DATA_TABLES = (
    "logs",
    "alerts",
    "rules",
    "correlation_matches",
    "cases",
    "case_events",
    "response_actions",
)
_LIFECYCLE_TABLES = ("agent_investigations",)
_APPEND_ONLY_TABLES = ("audit_log", "audit_logs", "ai_usage")


async def verify_scoped_role(expected_user: str) -> list[str]:
    """Verify the connected DB role's actual grants match the contract.

    Returns a list of violations (empty = scoped). Queries
    information_schema.role_table_grants -- the DB's own view, not our
    config's claim. A violation list is fatal for tool calls: the server
    refuses tools until the role is re-scoped.
    """
    from src.db.connection import get_pool

    violations: list[str] = []
    pool = await get_pool()
    async with pool.acquire() as conn:
        current = await conn.fetchval("SELECT current_user")
        if str(current).lower() != expected_user.lower():
            violations.append(f"connected as '{current}' but the scoped role is '{expected_user}'")
        rows = await conn.fetch(
            """
            SELECT table_name, privilege_type
            FROM information_schema.role_table_grants
            WHERE grantee = current_user AND table_schema = 'public'
            """
        )
    grants: dict[str, set[str]] = {}
    for r in rows:
        grants.setdefault(r["table_name"], set()).add(r["privilege_type"].upper())

    for table in _READ_ONLY_DATA_TABLES:
        privs = grants.get(table, set())
        if "SELECT" not in privs:
            violations.append(f"{table}: SELECT missing")
        for forbidden in ("UPDATE", "DELETE", "INSERT", "TRUNCATE"):
            if forbidden in privs:
                violations.append(f"{table}: {forbidden} forbidden on SIEM data")
    for table in _LIFECYCLE_TABLES:
        privs = grants.get(table, set())
        if not {"SELECT", "INSERT", "UPDATE"} <= privs:
            violations.append(f"{table}: run-record lifecycle grants missing")
        for forbidden in ("DELETE", "TRUNCATE"):
            if forbidden in privs:
                violations.append(f"{table}: {forbidden} forbidden")
    for table in _APPEND_ONLY_TABLES:
        privs = grants.get(table, set())
        if not {"INSERT", "SELECT"} <= privs:
            violations.append(f"{table}: append-only grants missing")
        for forbidden in ("UPDATE", "DELETE", "TRUNCATE"):
            if forbidden in privs:
                violations.append(f"{table}: forbidden mutation right")
    return violations


# ───────────────────────────────────────────────────────────────
# Tool implementations (all read-only; LLM advisory content fenced)
# ───────────────────────────────────────────────────────────────


async def _tool_investigate(args: dict, actor: str, audit: Any) -> dict:
    objective = args.get("objective")
    if not isinstance(objective, str) or len(objective) < 3 or len(objective) > 2000:
        raise ValueError("objective must be a string of 3..2000 characters")
    alert_id = args.get("alert_id")
    if alert_id is not None and not isinstance(alert_id, int):
        raise ValueError("alert_id must be an integer")

    result = await run_investigation(
        objective,
        requested_by=actor,
        alert_id=alert_id,
        audit=audit,
    )
    return {
        "run_id": result.run_id,
        "status": result.status,
        "actor": result.actor,
        "plan": result.plan,
        "steps": result.steps,
        "verdict_draft": result.verdict_draft,
        "hitl_state": result.hitl_state,
        "error": result.error,
        "note": (
            "The verdict is an AI DRAFT. A human must confirm it via the "
            "SIEM API (POST /api/v1/agent/runs/{id}/hitl); the agent holds "
            "no write tools and cannot commit anything."
            if result.verdict_draft
            else "No verdict draft was produced (failed run)."
        ),
    }


async def _tool_hunt(args: dict, actor: str, audit: Any) -> dict:
    template_id = args.get("template_id")
    if not isinstance(template_id, str) or not template_id:
        raise ValueError("template_id must be a non-empty string")
    result = await execute_hunt(template_id, actor=actor)
    return result


async def _tool_explain(args: dict, actor: str, audit: Any) -> dict:
    alert_id = args.get("alert_id")
    if not isinstance(alert_id, int):
        raise ValueError("alert_id must be an integer")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, rule_name, severity, host_name, description,
                   evidence, mitre_techniques
            FROM alerts WHERE id = $1
            """,
            alert_id,
        )
    if row is None:
        raise ValueError(f"alert {alert_id} not found")
    alert = dict(row)
    evidence = alert.get("evidence")
    if isinstance(evidence, str):  # asyncpg JSONB quirk (LRN-20260911-001)
        try:
            evidence = json.loads(evidence)
        except (ValueError, TypeError):
            evidence = None
    explanation = await explain_alert(
        rule_name=alert.get("rule_name", ""),
        rule_description=alert.get("description", ""),
        severity=alert.get("severity", "unknown"),
        host_name=alert.get("host_name", "unknown"),
        mitre_techniques=alert.get("mitre_techniques") or [],
        evidence=evidence if isinstance(evidence, dict) else None,
        user=actor,
    )
    return {
        "alert_id": alert_id,
        "rule": alert.get("rule_name"),
        "severity": alert.get("severity"),
        "host": alert.get("host_name"),
        "explanation": explanation,
    }


TOOL_IMPLEMENTATIONS = {
    "investigate": _tool_investigate,
    "hunt": _tool_hunt,
    "explain": _tool_explain,
}


async def call_tool(
    name: str, args: dict, actor: str, audit: Any
) -> tuple[dict | None, str | None]:
    """Dispatch one tools/call. Returns (result, error_message).

    Unknown tools -> (None, denied message); tool failures are returned as
    an isError result by the caller, not raised.
    """
    impl = TOOL_IMPLEMENTATIONS.get(name)
    if impl is None:
        return None, (
            f"unknown tool '{name}' -- the tool surface is closed: investigate, hunt, explain"
        )

    async with _tool_semaphore:
        started = time.monotonic()
        try:
            result = await impl(args or {}, actor, audit)
            log.info(
                "mcp_tool_call",
                tool=name,
                actor=actor,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
            return result, None
        except ValueError as e:  # argument/validation failures -> isError result
            return None, str(e)
        except Exception as e:  # never leak a stack to the MCP client
            log.error("mcp_tool_failed", tool=name, actor=actor, error=str(e))
            return None, f"tool '{name}' failed: {str(e)[:200]}"
