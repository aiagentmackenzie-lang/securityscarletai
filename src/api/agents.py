"""Agentic SOC API (V0.4/5 "Agentic SOC") -- read-only investigation agent.

Endpoints:
  POST /api/v1/agent/investigate        -- run one read-only investigation
                                           (plan -> query -> correlate ->
                                           verdict DRAFT; analyst role+)
  GET  /api/v1/agent/runs               -- list run records (read-only)
  GET  /api/v1/agent/runs/{run_id}      -- one run record (read-only)
  POST /api/v1/agent/runs/{run_id}/hitl -- the HITL gate: a human confirms or
                                           rejects the AI's verdict draft

Governance contract:
  - The agent runs with NO write tools (see src/agents/investigator.py).
  - Every run is born hitl_state='required'; only this HITL endpoint moves
    it, and only to confirmed/rejected, always with an attributed human actor
    and a note. The audit chain records the transition.
  - Committing a verdict to a case stays the existing human-only
    POST /cases/{id}/verdict path (mandatory rationale). This module never
    touches cases, response actions, or any other mutation surface.
  - AGENT_ENABLED=false refuses every endpoint here (423) -- the operator
    kill switch. Fail-closed: unknown run ids, unknown decision tokens, and
    disabled agent all refuse honestly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from src.agents.investigator import AgentRunResult, record_hitl_decision, run_investigation
from src.api.audit import log_audit_action
from src.api.auth import require_role
from src.api.rate_limit import LIMIT_LLM, limiter, user_or_ip_key
from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool
from src.db.jsonb import load_jsonb

log = get_logger("api.agents")
router = APIRouter(tags=["agent"], prefix="/agent")

AGENT_RUN_STATUSES = ("running", "completed", "failed", "refused")
HITL_DECISIONS = ("confirmed", "rejected")


def _require_agent_enabled() -> None:
    """The operator kill switch. 423 (Locked): the feature exists and is
    disabled on purpose -- not a 404 that hides the surface."""
    if not settings.agent_enabled:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="agentic investigation is disabled (AGENT_ENABLED=false)",
        )


def _audit_for(run_id: int | None, ip_address: str | None) -> Any:
    """One audit closure per request: every agent event for this run carries
    the requesting actor's IP into the append-only audit chain. When the run
    id is not known yet (the investigate path), the event's own details
    supply it."""

    async def _audit(action: str, details: dict, actor: str) -> None:
        await log_audit_action(
            actor=actor,
            action=action,
            target_type="agent_run",
            target_id=(run_id if run_id is not None else details.get("run_id")),
            new_values=details,
            ip_address=ip_address,
        )

    return _audit


class InvestigateRequest(BaseModel):
    objective: str = Field(
        ...,
        min_length=3,
        max_length=2000,
        description=(
            "What to investigate. Natural language; sanitized then fenced before any LLM sees it."
        ),
    )
    alert_id: int | None = Field(
        None, description=("Optional alert to investigate (its evidence becomes fenced context).")
    )


class HitlDecisionRequest(BaseModel):
    decision: str = Field(..., pattern="^(confirmed|rejected)$")
    note: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description=(
            "The human reviewer's rationale (mandatory -- a HITL decision "
            "without a stated reason is not a governed decision)."
        ),
    )


def _serialize_run(row: dict) -> dict:
    """One run row -> API dict (JSONB normalized via the canonical helper)."""
    created = row.get("created_at")
    return {
        "id": row["id"],
        "objective": row.get("objective"),
        "alert_id": row.get("alert_id"),
        "status": row.get("status"),
        "actor": row.get("actor"),
        "requested_by": row.get("requested_by"),
        "plan": load_jsonb(row.get("plan"), source="api.agents.plan"),
        "steps": load_jsonb(row.get("steps"), source="api.agents.steps"),
        "verdict_draft": load_jsonb(row.get("verdict_draft"), source="api.agents.verdict"),
        "hitl_state": row.get("hitl_state"),
        "hitl_actor": row.get("hitl_actor"),
        "error": row.get("error"),
        "created_at": created.isoformat() if isinstance(created, datetime) else created,
    }


async def _fetch_run(run_id: int) -> dict | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, objective, alert_id, status, actor, requested_by,
                   plan, steps, verdict_draft, hitl_state, hitl_actor,
                   hitl_note, error, created_at, updated_at
            FROM agent_investigations WHERE id = $1
            """,
            run_id,
        )
    return dict(row) if row is not None else None


@router.post(
    "/investigate",
    response_model=dict,
    status_code=status.HTTP_200_OK,
    summary="Run a read-only agentic investigation",
    description=(
        "plan-generate -> query -> correlate -> verdict DRAFT. Read-only: the "
        "agent has no mutation tools; the verdict is a draft requiring human "
        "confirmation (POST /agent/runs/{id}/hitl). Requires analyst role."
    ),
)
@limiter.limit(LIMIT_LLM, key_func=user_or_ip_key)
async def investigate(
    request: Request,  # slowapi requires this exact name
    response: Response,  # slowapi injects X-RateLimit-* headers
    body: InvestigateRequest,
    user: dict = Depends(require_role("analyst")),
) -> dict:
    _require_agent_enabled()
    username = str(user.get("sub", "unknown"))
    client_host = None
    if request.client is not None:
        client_host = request.client.host

    log.info(
        "agent_investigate_request",
        user=username,
        alert_id=body.alert_id,
        objective_len=len(body.objective),
    )
    try:
        result: AgentRunResult = await run_investigation(
            body.objective,
            requested_by=username,
            alert_id=body.alert_id,
            audit=_audit_for(None, client_host),
        )
    except ValueError as e:
        # Empty objective after sanitization -- 400, nothing was created.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return {
        "id": result.run_id,
        "objective": result.objective,
        "status": result.status,
        "actor": result.actor,
        "requested_by": result.requested_by,
        "alert_id": result.alert_id,
        "plan": result.plan,
        "steps": result.steps,
        "verdict_draft": result.verdict_draft,
        "hitl_state": result.hitl_state,
        "error": result.error,
        "hitl": (
            "This verdict is an AI DRAFT. Confirm or reject it via "
            "POST /agent/runs/{id}/hitl; committing a verdict to a case "
            "stays the human-only case-verdict path."
            if result.verdict_draft
            else "No verdict draft was produced (failed run)."
        ),
    }


@router.get(
    "/runs",
    response_model=dict,
    summary="List agent investigation runs (read-only)",
)
async def list_runs(
    run_status: Annotated[
        str | None, Query(description=f"One of {', '.join(AGENT_RUN_STATUSES)}")
    ] = None,
    requested_by: Annotated[str | None, Query(description="Filter by requester")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    _user: dict = Depends(require_role("analyst")),
) -> dict:
    _require_agent_enabled()
    if run_status and run_status not in AGENT_RUN_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown status '{run_status}' (valid: {', '.join(AGENT_RUN_STATUSES)})",
        )
    pool = await get_pool()
    async with pool.acquire() as conn:
        conditions = ["1=1"]
        params: list[Any] = []
        if run_status:
            params.append(run_status)
            conditions.append(f"status = ${len(params)}::agent_run_status")
        if requested_by:
            params.append(requested_by)
            conditions.append(f"requested_by = ${len(params)}")
        params.append(limit)
        limit_idx = len(params)
        params.append(offset)
        rows = await conn.fetch(
            "SELECT id, objective, alert_id, status, actor, requested_by, "  # noqa: S608
            "hitl_state, error, created_at, updated_at "
            f"FROM agent_investigations WHERE {' AND '.join(conditions)} "
            f"ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${len(params)}",
            *params,
        )
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM agent_investigations WHERE {' AND '.join(conditions)}",  # noqa: S608
            *params[: len(params) - 2],
        )
    runs = []
    for r in rows:
        rec = dict(r)
        rec["created_at"] = rec["created_at"].isoformat() if rec["created_at"] else None
        rec["updated_at"] = rec["updated_at"].isoformat() if rec["updated_at"] else None
        runs.append(rec)
    return {"total": int(total or 0), "runs": runs}


@router.get(
    "/runs/{run_id}",
    response_model=dict,
    summary="One agent run record (read-only)",
)
async def get_run(
    run_id: int,
    _user: dict = Depends(require_role("analyst")),
) -> dict:
    _require_agent_enabled()
    row = await _fetch_run(run_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
    return _serialize_run(row)


@router.post(
    "/runs/{run_id}/hitl",
    response_model=dict,
    summary="HITL gate: confirm or reject the AI's verdict draft",
    description=(
        "Human-only transition. The draft verdict is advisory; this records "
        "the accountable human decision. Committing a verdict to a case "
        "stays the existing human-only case-verdict endpoint."
    ),
)
async def hitl_decision(
    run_id: int,
    body: HitlDecisionRequest,
    user: dict = Depends(require_role("analyst")),
) -> dict:
    _require_agent_enabled()
    username = str(user.get("sub", "unknown"))

    row = await _fetch_run(run_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
    if row.get("hitl_state") not in ("required",):
        # Fail-closed: an already-decided (or never-proposed) draft cannot be
        # re-decided; the audit chain holds the original transition.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"run hitl_state is '{row.get('hitl_state')}' -- only a "
                "'required' draft can be confirmed or rejected"
            ),
        )

    updated = await record_hitl_decision(
        run_id,
        decision=body.decision,
        actor=username,
        note=body.note,
        audit=_audit_for(run_id, None),
    )
    if updated is None:  # pragma: no cover -- raced delete; row existed above
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
    log.info(
        "agent_hitl_decided",
        run_id=run_id,
        decision=body.decision,
        user=username,
    )
    return {
        "id": run_id,
        "hitl_state": updated.get("hitl_state"),
        "hitl_actor": updated.get("hitl_actor"),
        "note": (
            "verdict draft remains a DRAFT; use POST /cases/{id}/verdict to "
            "commit a human verdict to a case"
        ),
    }
