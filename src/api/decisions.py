"""Governed decision records (V0.4 "Trusted Loop").

A read-only view that assembles every autonomous and human decision the
SOC made into ONE governed, auditable surface -- the "decision record"
a governed-autonomy buyer (EU AI Act Art. 14, NIST AI RMF GOVERN) asks
for. Nothing new is computed here: every decision already rides the
tamper-evident audit chain; this module surfaces them.

Decision types and their sources of truth:
  ai_triage       -- alerts.ai_summary/risk_score (the AI's triage decision
                     on an alert; actor = the configured LLM model)
  correlation     -- correlation_matches (a detection chain decided these
                     events belong together; actor = the chain name)
  verdict         -- case_events WHERE event_type = 'verdict' (human
                     adjudication with a mandatory rationale)
  response_action -- response_actions (requested -> approved -> executed ->
                     verified with the re-query proof)
  policy_refusal  -- audit_log response.refused rows (the policy engine's
                     refusals are decisions too)
  agent_investigation -- agent_investigations (V0.4/5: the read-only agent's
                     verdict DRAFT; actor_kind='ai'; the human HITL decision
                     on the draft rides the audit chain as agent.hitl_decision)

Read-only, analyst role or above, paginated, filterable. No endpoint in
this module mutates anything.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_role
from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool
from src.db.jsonb import load_jsonb

log = get_logger("api.decisions")
router = APIRouter(tags=["decisions"], prefix="/decisions")

DECISION_TYPES = (
    "ai_triage",
    "correlation",
    "verdict",
    "response_action",
    "policy_refusal",
    "agent_investigation",
)


def _truncate(text: Any, n: int = 400) -> str | None:
    if text is None:
        return None
    text_str: str = str(text)
    return (text_str[: n - 1] + "...") if len(text_str) > n else text_str


def _load_json(value: Any) -> dict:
    """JSONB columns come back as str in some asyncpg codec setups (the
    same quirk is handled in cases.py and api/response.py). Alias of the
    canonical src.db.jsonb.load_jsonb (LRN-20260911-001 -- one
    implementation, reused everywhere)."""
    result = load_jsonb(value, source="api.decisions")
    return result if isinstance(result, dict) else {}


def _window_conditions(
    column: str, since: datetime | None, until: datetime | None, params: list[Any]
) -> list[str]:
    """The W4-D window contract: every decision-type query filters its
    records on the timestamp column that type actually sorts on (the
    record's `ts`), with the same ::timestamptz cast the policy_refusal
    query established. since/until are appended to `params` in order; the
    caller adds the LIMIT parameter last so its $n index always follows."""
    conditions: list[str] = []
    if since:
        params.append(since)
        conditions.append(f"{column} >= ${len(params)}::timestamptz")
    if until:
        params.append(until)
        conditions.append(f"{column} < ${len(params)}::timestamptz")
    return conditions


@router.get("")
async def list_decisions(
    decision_type: Annotated[
        str | None, Query(description=f"One of {', '.join(DECISION_TYPES)}")
    ] = None,
    actor: Annotated[
        str | None, Query(description="Filter by actor (username, chain, or model)")
    ] = None,
    subject_id: Annotated[int | None, Query(description="Subject id (alert/case/action)")] = None,
    since: Annotated[datetime | None, Query(description="ISO timestamp lower bound")] = None,
    until: Annotated[datetime | None, Query(description="ISO timestamp upper bound")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    user: dict = Depends(require_role("analyst")),
):
    """The governed decision record: every AI, rule, and human decision in
    one chronological, filterable, read-only surface."""
    if decision_type and decision_type not in DECISION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown decision_type '{decision_type}' (valid: {', '.join(DECISION_TYPES)})",
        )

    pool = await get_pool()
    records: list[dict] = []
    per_type_limit = limit + offset  # fetch enough to merge + paginate

    async with pool.acquire() as conn:
        if decision_type in (None, "ai_triage"):
            conditions = ["ai_summary IS NOT NULL"]
            params: list[Any] = []
            conditions += _window_conditions("updated_at", since, until, params)
            params.append(per_type_limit)
            limit_idx = len(params)
            rows = await conn.fetch(
                f"SELECT id, created_at, updated_at, host_name, rule_name, severity, "  # noqa: S608
                f"ai_summary, risk_score FROM alerts "
                f"WHERE {' AND '.join(conditions)} "
                f"ORDER BY updated_at DESC LIMIT ${limit_idx}",
                *params,
            )
            records += [
                {
                    "id": f"ai_triage:{r['id']}",
                    "ts": r["updated_at"],
                    "decision_type": "ai_triage",
                    "actor": f"ai:{settings.ollama_model}",
                    "actor_kind": "ai",
                    "subject_type": "alert",
                    "subject_id": r["id"],
                    "summary": _truncate(r["ai_summary"], 300),
                    "rationale": _truncate(r["ai_summary"]),
                    "evidence": {
                        "rule": r["rule_name"],
                        "host": r["host_name"],
                        "severity": r["severity"],
                        "risk_score": r["risk_score"],
                    },
                    "outcome": f"risk_score={r['risk_score']}",
                }
                for r in rows
            ]

        if decision_type in (None, "correlation"):
            params = []
            conditions = _window_conditions("created_at", since, until, params)
            where = f"WHERE {' AND '.join(conditions)} " if conditions else ""
            params.append(per_type_limit)
            limit_idx = len(params)
            rows = await conn.fetch(
                f"SELECT id, created_at, correlation_rule, severity, match_data "  # noqa: S608
                f"FROM correlation_matches {where}"
                f"ORDER BY created_at DESC LIMIT ${limit_idx}",
                *params,
            )
            records += [
                {
                    "id": f"correlation:{r['id']}",
                    "ts": r["created_at"],
                    "decision_type": "correlation",
                    "actor": r["correlation_rule"],
                    "actor_kind": "rule",
                    "subject_type": "correlation_match",
                    "subject_id": r["id"],
                    "summary": (
                        f"chain '{r['correlation_rule']}' matched (severity={r['severity']})"
                    ),
                    "rationale": _truncate(_load_json(r["match_data"])),
                    "evidence": {"rule": r["correlation_rule"], "severity": r["severity"]},
                    "outcome": "matched",
                }
                for r in rows
            ]

        if decision_type in (None, "verdict"):
            conditions = ["event_type = 'verdict'"]
            params = []
            conditions += _window_conditions("created_at", since, until, params)
            params.append(per_type_limit)
            limit_idx = len(params)
            rows = await conn.fetch(
                f"SELECT id, created_at, actor, payload, case_id, alert_id "  # noqa: S608
                f"FROM case_events WHERE {' AND '.join(conditions)} "
                f"ORDER BY created_at DESC LIMIT ${limit_idx}",
                *params,
            )
            records += [
                {
                    "id": f"verdict:{r['id']}",
                    "ts": r["created_at"],
                    "decision_type": "verdict",
                    "actor": r["actor"],
                    "actor_kind": "human",
                    "subject_type": "case",
                    "subject_id": r["case_id"],
                    "summary": _truncate(_load_json(r["payload"]).get("verdict", "unknown"), 300),
                    "rationale": _truncate(_load_json(r["payload"]).get("rationale")),
                    "evidence": {
                        "case_id": r["case_id"],
                        "alert_id": r["alert_id"],
                        "confidence": _load_json(r["payload"]).get("confidence"),
                    },
                    "outcome": str(_load_json(r["payload"]).get("verdict", "unknown")),
                }
                for r in rows
            ]

        if decision_type in (None, "response_action"):
            params = []
            conditions = _window_conditions("created_at", since, until, params)
            where = f"WHERE {' AND '.join(conditions)} " if conditions else ""
            params.append(per_type_limit)
            limit_idx = len(params)
            rows = await conn.fetch(
                f"SELECT id, case_id, action_type, policy_effect, status, "  # noqa: S608
                f"requested_by, approved_by, justification, executed_at, "
                f"verified_at, evidence, created_at FROM response_actions {where}"
                f"ORDER BY created_at DESC LIMIT ${limit_idx}",
                *params,
            )
            records += [
                {
                    "id": f"response_action:{r['id']}",
                    "ts": r["created_at"],
                    "decision_type": "response_action",
                    "actor": r["approved_by"] or r["requested_by"],
                    "actor_kind": "human",
                    "subject_type": "response_action",
                    "subject_id": r["id"],
                    "summary": (
                        f"{r['action_type']} [{r['status']}] "
                        f"requested by {r['requested_by']}"
                        + (f", approved by {r['approved_by']}" if r["approved_by"] else "")
                    ),
                    "rationale": _truncate(r["justification"]),
                    "evidence": {
                        "case_id": r["case_id"],
                        "policy_effect": r["policy_effect"],
                        "verification": (_load_json(r["evidence"]) or {}).get("verification"),
                    },
                    "outcome": str(r["status"]),
                }
                for r in rows
            ]

        if decision_type in (None, "policy_refusal"):
            conditions = ["action = 'response.refused'"]
            params = []
            conditions += _window_conditions("created_at", since, until, params)
            params.append(per_type_limit)
            limit_idx = len(params)
            rows = await conn.fetch(
                f"SELECT id, created_at, actor, target_type, target_id, new_values "  # noqa: S608
                f"FROM audit_log WHERE {' AND '.join(conditions)} "
                f"ORDER BY created_at DESC LIMIT ${limit_idx}",
                *params,
            )
            records += [
                {
                    "id": f"policy_refusal:{r['id']}",
                    "ts": r["created_at"],
                    "decision_type": "policy_refusal",
                    "actor": r["actor"],
                    "actor_kind": "system",
                    "subject_type": "response_action",
                    "subject_id": r["target_id"],
                    "summary": _truncate(_load_json(r["new_values"]).get("reason"), 300)
                    or "policy refused the action",
                    "rationale": _truncate(_load_json(r["new_values"]).get("reason")),
                    "evidence": {
                        "action_type": _load_json(r["new_values"]).get("action_type"),
                        "case_id": _load_json(r["new_values"]).get("case_id"),
                    },
                    "outcome": "refused",
                }
                for r in rows
            ]

        if decision_type in (None, "agent_investigation"):
            conditions = ["verdict_draft IS NOT NULL"]
            params = []
            conditions += _window_conditions("updated_at", since, until, params)
            params.append(per_type_limit)
            limit_idx = len(params)
            rows = await conn.fetch(
                f"SELECT id, created_at, updated_at, objective, alert_id, status, "  # noqa: S608
                f"actor, requested_by, verdict_draft, hitl_state "
                f"FROM agent_investigations WHERE {' AND '.join(conditions)} "
                f"ORDER BY updated_at DESC LIMIT ${limit_idx}",
                *params,
            )
            records += [
                {
                    "id": f"agent_investigation:{r['id']}",
                    "ts": r["updated_at"],
                    "decision_type": "agent_investigation",
                    "actor": r["actor"],
                    "actor_kind": "ai",
                    "subject_type": "agent_run",
                    "subject_id": r["id"],
                    "summary": (
                        (
                            _truncate(_load_json(r["verdict_draft"]).get("verdict", "unknown"), 300)
                            or "unknown"
                        )
                        + f" (hitl: {r['hitl_state']})"
                    ),
                    "rationale": _truncate(_load_json(r["verdict_draft"]).get("rationale")),
                    "evidence": {
                        "objective": _truncate(r["objective"], 200),
                        "alert_id": r["alert_id"],
                        "run_status": r["status"],
                        "hitl_state": r["hitl_state"],
                        "requested_by": r["requested_by"],
                        "confidence": _load_json(r["verdict_draft"]).get("confidence"),
                    },
                    "outcome": f"draft [{r['hitl_state']}]",
                }
                for r in rows
            ]

    # Actor filter (post-merge: actors come from different tables)
    if actor:
        records = [r for r in records if r["actor"] == actor]
    if subject_id is not None:
        records = [r for r in records if r.get("subject_id") == subject_id]

    # Chronological, newest first, then paginate
    def _ts(r: dict) -> datetime:
        ts = r.get("ts")
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return datetime.min.replace(tzinfo=timezone.utc)

    records.sort(key=_ts, reverse=True)
    return {
        "total_returned": len(records),
        "decision_types": DECISION_TYPES,
        "decisions": records[offset : offset + limit],
    }
