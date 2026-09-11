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

Read-only, analyst role or above, paginated, filterable. No endpoint in
this module mutates anything.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_role
from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("api.decisions")
router = APIRouter(tags=["decisions"], prefix="/decisions")

DECISION_TYPES = ("ai_triage", "correlation", "verdict", "response_action", "policy_refusal")


def _truncate(text: Any, n: int = 400) -> str | None:
    if text is None:
        return None
    text_str: str = str(text)
    return (text_str[: n - 1] + "...") if len(text_str) > n else text_str


def _load_json(value: Any) -> dict:
    """JSONB columns come back as str in some asyncpg codec setups (the
    same quirk is handled in cases.py and api/response.py)."""
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            return cast("dict", json.loads(value))
        except (ValueError, TypeError):
            log.warning("decisions_jsonb_unparseable", preview=str(value)[:80])
            return {}
    return value if isinstance(value, dict) else {}


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
            rows = await conn.fetch(
                """
                SELECT id, created_at, updated_at, host_name, rule_name, severity,
                       ai_summary, risk_score
                FROM alerts
                WHERE ai_summary IS NOT NULL
                ORDER BY updated_at DESC
                LIMIT $1
                """,
                per_type_limit,
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
            rows = await conn.fetch(
                """
                SELECT id, created_at, correlation_rule, severity, match_data
                FROM correlation_matches
                ORDER BY created_at DESC
                LIMIT $1
                """,
                per_type_limit,
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
            rows = await conn.fetch(
                """
                SELECT id, created_at, actor, payload, case_id, alert_id
                FROM case_events
                WHERE event_type = 'verdict'
                ORDER BY created_at DESC
                LIMIT $1
                """,
                per_type_limit,
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
            rows = await conn.fetch(
                """
                SELECT id, case_id, action_type, policy_effect, status,
                       requested_by, approved_by, justification, executed_at,
                       verified_at, evidence, created_at
                FROM response_actions
                ORDER BY created_at DESC
                LIMIT $1
                """,
                per_type_limit,
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
            params: list = []
            if since:
                params.append(since)
                conditions.append(f"created_at >= ${len(params)}::timestamptz")
            if until:
                params.append(until)
                conditions.append(f"created_at < ${len(params)}::timestamptz")
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
