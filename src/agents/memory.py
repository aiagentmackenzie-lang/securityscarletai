"""Agentic memory (Wave 1 W1.6) -- institutional memory for the investigator.

The raw material has persisted since V0.7b (HITL dispositions: alert labels,
alert statuses, case verdicts) and the agent persisted runs -- but nothing
reused it. This module closes the gap with three read-only pieces:

(a) FEW-SHOT EXEMPLARS: the K most similar past ADJUDICATED alerts (same
    rule_name shape, excluding the current alert) with their human verdicts
    and short rationale, retrieved bounded and PII-conscious (rationale
    truncated, no evidence blobs) into the investigation's verdict prompt.
    The disposition precedence is the scorecard's (documented there):
    alert_labels > alert status false_positive > case verdict.

(b) DEAD-END TRACKING: the verdict step asks the LLM to assess the plan's
    hypotheses against the gathered evidence and report, per hypothesis,
    whether it is supported, ruled out, or unresolved (and by what) -- the
    story a reader six months from now sees. Validated against a closed
    status vocabulary; entries that are unparseable, oversized, or name
    hypotheses that are NOT in the plan are dropped (fail-closed).

(c) OUTCOME LINKAGE: an agent run's final disposition is joinable to the
    alert's human ground truth (the documented disposition precedence), so
    draft-vs-human agreement is MEASURABLE over time. Read-only: no schema
    change, no persistence -- the linkage is derived from the tables that
    already hold both halves.

Doctrine: READ-ONLY. Memory retrieval never writes, never widens authority;
the agent still proposes drafts only (HITL unchanged).
"""

from __future__ import annotations

import json
from typing import Any

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.db.jsonb import load_jsonb

log = get_logger("agents.memory")

# Few-shot exemplar bounds (PII-conscious by construction: rationale is
# truncated, evidence blobs are never included, rows are capped).
MAX_EXEMPLARS = 3
MAX_EXEMPLAR_RATIONALE_CHARS = 280

# Dead-end tracking bounds.
MAX_HYPOTHESES_ASSESSED = 3
_HYPOTHESIS_STATUS = ("supported", "ruled_out", "unresolved")

VERDICT_TOKENS = ("true_positive", "false_positive", "benign", "needs_review")


async def fetch_adjudicated_exemplars(
    rule_name: str, *, exclude_alert_id: int | None = None, k: int = MAX_EXEMPLARS
) -> list[dict[str, Any]]:
    """The K most recent past alerts of the SAME rule shape with a human
    disposition (the scorecard's documented precedence) + short rationale.

    The governed rationale lives in case verdict events (mandatory
    rationale). Read-only, parameterized, bounded.
    """
    # The cap lives HERE, not in the caller's discipline.
    k = max(1, min(k, MAX_EXEMPLARS))
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                a.id,
                a.rule_name,
                a.severity,
                a.host_name,
                COALESCE(
                    l.label,
                    CASE WHEN a.status = 'false_positive' THEN 'false_positive' END,
                    cv.v
                ) AS disposition,
                cv.rationale
            FROM alerts a
            LEFT JOIN alert_labels l ON l.alert_id = a.id
            LEFT JOIN LATERAL (
                SELECT ce.payload->>'verdict' AS v,
                       ce.payload->>'rationale' AS rationale
                FROM case_events ce
                WHERE ce.event_type = 'verdict' AND ce.alert_id = a.id
                  AND ce.payload->>'verdict' = ANY($3::text[])
                ORDER BY ce.created_at DESC
                LIMIT 1
            ) cv ON TRUE
            WHERE a.rule_name = $1
              AND a.id <> COALESCE($2, -1)
              AND COALESCE(
                    l.label,
                    CASE WHEN a.status = 'false_positive' THEN 'false_positive' END,
                    cv.v
                  ) IS NOT NULL
            ORDER BY a.time DESC
            LIMIT $4
            """,
            rule_name,
            exclude_alert_id,
            list(VERDICT_TOKENS),
            max(k, 0),
        )
    return [
        {
            "alert_id": r["id"],
            "rule_name": r["rule_name"],
            "host_name": r["host_name"],
            "disposition": r["disposition"],
            "rationale": (r["rationale"] or "")[:MAX_EXEMPLAR_RATIONALE_CHARS],
        }
        for r in rows
    ][: max(k, 0)]


def format_exemplars_block(exemplars: list[dict[str, Any]]) -> str:
    """The exemplar block for the verdict prompt (empty = no exemplars; the
    caller passes an honest none-note instead of silence)."""
    if not exemplars:
        return "(no past adjudicated alerts of this rule shape)"
    lines = []
    for e in exemplars:
        rationale = e.get("rationale") or "(no written rationale recorded)"
        lines.append(
            json.dumps(
                {
                    "verdict": e.get("disposition"),
                    "host": e.get("host_name"),
                    "rationale": rationale,
                },
                default=str,
            )[:MAX_EXEMPLAR_RATIONALE_CHARS]
        )
    return "\n".join(lines)


async def outcome_for_alert(alert_id: int) -> dict[str, Any] | None:
    """The alert's current human disposition (the scorecard precedence) --
    the ground-truth half of the outcome linkage."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                COALESCE(
                    l.label,
                    CASE WHEN a.status = 'false_positive' THEN 'false_positive' END,
                    cv.v
                ) AS disposition
            FROM alerts a
            LEFT JOIN alert_labels l ON l.alert_id = a.id
            LEFT JOIN LATERAL (
                SELECT ce.payload->>'verdict' AS v
                FROM case_events ce
                WHERE ce.event_type = 'verdict' AND ce.alert_id = a.id
                  AND ce.payload->>'verdict' = ANY($2::text[])
                ORDER BY ce.created_at DESC
                LIMIT 1
            ) cv ON TRUE
            WHERE a.id = $1
            """,
            alert_id,
            list(VERDICT_TOKENS),
        )
    if row is None:
        return None
    return {"alert_id": alert_id, "disposition": row["disposition"]}


async def link_outcome(run_id: int) -> dict[str, Any] | None:
    """(c) The run's final outcome linkage: the agent's DRAFT verdict plus
    the alert's current human disposition, so agreement is measurable.

    Returns None when the run does not exist or has no verdict draft.
    agreement is None (unmeasured) when the alert has no human disposition
    yet -- the honesty gate: unmeasured, never a fake 0.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        run = await conn.fetchrow(
            """
            SELECT id, alert_id, verdict_draft, hitl_state, hitl_actor, created_at
            FROM agent_investigations WHERE id = $1
            """,
            run_id,
        )
    if run is None:
        return None
    draft = load_jsonb(run["verdict_draft"], source="agents.memory")
    if not isinstance(draft, dict) or not draft.get("verdict"):
        return None
    linkage: dict[str, Any] = {
        "run_id": run["id"],
        "alert_id": run["alert_id"],
        "draft_verdict": draft.get("verdict"),
        "hitl_state": run["hitl_state"],
        "created_at": run["created_at"].isoformat() if run["created_at"] else None,
        "final_disposition": None,
        "agreement": None,
    }
    if run["alert_id"] is not None:
        outcome = await outcome_for_alert(run["alert_id"])
        disposition = (outcome or {}).get("disposition")
        if disposition is not None:
            linkage["final_disposition"] = disposition
            linkage["agreement"] = draft.get("verdict") == disposition
    return linkage


async def agreement_stats(window_hours: int = 720) -> dict[str, Any]:
    """Agreement over time: for CONFIRMED runs whose alert carries a human
    disposition, how often the draft matched the final disposition.

    The sigmaforge honesty gate applies to the aggregate too: with no
    measurable linkage, the report says unmeasured -- never a fake rate.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        runs = await conn.fetch(
            """
            SELECT id, alert_id, verdict_draft
            FROM agent_investigations
            WHERE hitl_state = 'confirmed'
              AND verdict_draft IS NOT NULL
              AND created_at > NOW() - ($1::int * INTERVAL '1 hour')
            ORDER BY created_at DESC
            LIMIT 200
            """,
            max(window_hours, 1),
        )
    measured = 0
    agreed = 0
    for run in runs:
        draft = load_jsonb(run["verdict_draft"], source="agents.memory")
        verdict = draft.get("verdict") if isinstance(draft, dict) else None
        if not verdict or run["alert_id"] is None:
            continue
        outcome = await outcome_for_alert(run["alert_id"])
        disposition = (outcome or {}).get("disposition")
        if disposition is None:
            continue  # unmeasured linkage
        measured += 1
        if verdict == disposition:
            agreed += 1
    return {
        "window_hours": window_hours,
        "confirmed_runs": len(runs),
        "measured": measured,
        "agreed": agreed,
        "agreement_rate": (agreed / measured) if measured else None,
        "note": (
            "agreement = confirmed agent draft verdict vs the alert's "
            "current human disposition (labels > status-fp > case verdict); "
            "runs whose alert has no human disposition yet are unmeasured"
        ),
    }


def validate_hypotheses_assessed(raw: Any, plan_hypotheses: list[str]) -> list[dict[str, str]]:
    """(b) Bounded, fail-closed validation of the verdict LLM's dead-end
    field: closed status tokens, capped length, and only hypotheses that
    appear VERBATIM in the plan (an invented hypothesis is dropped)."""
    assessed: list[dict[str, str]] = []
    if not isinstance(plan_hypotheses, list):
        return assessed
    if not isinstance(raw, list):
        return assessed
    for entry in raw:
        if len(assessed) >= MAX_HYPOTHESES_ASSESSED:
            break
        if not isinstance(entry, dict):
            continue
        hypothesis = str(entry.get("hypothesis", ""))[:300]
        if hypothesis not in plan_hypotheses:
            continue
        status = str(entry.get("status", "")).strip().lower()
        if status not in ("supported", "ruled_out"):
            continue
        assessed.append(
            {
                "hypothesis": hypothesis,
                "status": status,
                "evidence": str(entry.get("evidence", ""))[:280],
            }
        )
    return assessed
