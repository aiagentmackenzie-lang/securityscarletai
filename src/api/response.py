"""Response actions API (V0.4 "Trusted Loop") -- bounded response authority
with HITL approval and VERIFIED OUTCOMES.

Flow (every step recorded on the case timeline and the audit chain):

  1. REQUEST   POST /response/actions
     The policy engine (config/response_policy.yaml, fail-closed) decides:
       allow             -> executes immediately (still recorded + verified)
       approval_required -> parked as 'requested'; an admin must approve
       never / disabled / limit / requires_case -> refused (403, honest reason)
  2. APPROVE   POST /response/actions/{id}/approve   (admin, four-eyes)
     The approver cannot be the requester. On approval the action executes
     and the executor RE-QUERIES the source system to prove the intended
     state change; verification is recorded in the action's evidence.
  3. REJECT    POST /response/actions/{id}/reject    (admin, reason required)
  4. EXECUTE   POST /response/actions/{id}/execute   (admin; approved actions)
     Separates the approval decision from the execution moment when wanted.

Governance invariants (what a governed-autonomy buyer audits):
- Containment actions NEVER auto-execute: approval_required actions sit in
  'requested' until a different human (four-eyes) approves.
- Every action carries a rollback note (from the policy file) before it can
  be approved.
- Every executed action carries a verification record with its mode
  ("live" re-query, or an honest capability refusal). Unverified is never
  reported as verified.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.api.audit import log_audit_action
from src.api.auth import require_role
from src.api.cases import _record_case_event
from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool
from src.db.jsonb import load_jsonb
from src.response import policy as policy_mod
from src.response.executors import get_executor

log = get_logger("api.response")
router = APIRouter(tags=["response"], prefix="/response")


# ───────────────────────────────────────────────────────────────
# Request / response models
# ───────────────────────────────────────────────────────────────


class ActionRequest(BaseModel):
    action_type: str = Field(..., min_length=1, max_length=64)
    params: dict = Field(default_factory=dict)
    case_id: int | None = None
    justification: str = Field("", max_length=5000)


class ApproveRequest(BaseModel):
    note: str = Field("", max_length=2000)


class RejectRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=2000)


# ───────────────────────────────────────────────────────────────
# Policy loading + blast-radius counting
# ───────────────────────────────────────────────────────────────

policy_cache: tuple[tuple[str, str], dict[str, policy_mod.PolicyEntry]] | None = None


def _load_policy() -> tuple[tuple[str, str], dict[str, policy_mod.PolicyEntry]]:
    """Load the policy file (cached by path + mtime so runtime stays
    deterministic; a missing file yields the empty/never policy)."""
    global policy_cache
    path = settings.response_policy_path
    try:
        from pathlib import Path

        mtime = str(Path(path).stat().st_mtime_ns)
    except OSError:
        mtime = "missing"
    if policy_cache is None or policy_cache[0] != (path, mtime):
        entries = policy_mod.load_policy_file(path)
        policy_cache = ((path, mtime), entries)
    return policy_cache


async def _actions_today(action_type: str) -> int:
    """How many non-rejected actions of this type were requested today
    (UTC) -- the blast-radius counter for max_per_day."""
    pool = await get_pool()
    since = datetime.now(tz=timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    async with pool.acquire() as conn:
        return int(
            await conn.fetchval(
                "SELECT COUNT(*) FROM response_actions "
                "WHERE action_type = $1::response_action_type "
                "AND created_at >= $2 AND status != 'rejected'",
                action_type,
                since,
            )
            or 0
        )


def _json(data: Any) -> str:
    return json.dumps(data, default=str)


def _load_json(value: Any) -> Any:
    """JSONB columns come back as str in some asyncpg codec setups (the
    cases module handles the same quirk for notes). Normalize to a dict.
    Found live 2026-09-11: dict(evidence_string) crashed execution.
    Alias of the canonical src.db.jsonb.load_jsonb (LRN-20260911-001 -- one
    implementation, reused everywhere)."""
    return load_jsonb(value, source="api.response")


# ───────────────────────────────────────────────────────────────
# Execution + verification (shared by approve and execute endpoints)
# ───────────────────────────────────────────────────────────────


async def _execute_and_verify(action_row: dict, approver: str | None) -> dict:
    """Execute an approved action, then verify by re-querying the source
    system. Updates the row's status/evidence and writes case events.
    Returns the final action state."""
    action_id = action_row["id"]
    action_type = str(action_row["action_type"])
    params = _load_json(action_row["params"])
    evidence: dict[str, Any] = dict(_load_json(action_row["evidence"]))

    executor_obj = get_executor(action_type)
    pool = await get_pool()

    if executor_obj is None:
        # Belt and braces: the request endpoint already refuses unknown
        # action types; this is the fail-closed backstop.
        await _transition(
            pool,
            action_id,
            "execution_failed",
            evidence={**evidence, "failure": f"no executor for '{action_type}' (fail-closed)"},
            rollback_note=None,
        )
        await _case_event_for_action(
            pool, action_row, "action_failed", "system", "system", {"reason": "unknown action type"}
        )
        return {"status": "execution_failed"}

    await _transition(pool, action_id, "executing", evidence=evidence, rollback_note=None)
    exec_result = await executor_obj.execute(params)

    if not exec_result.ok:
        evidence["execution"] = {"ok": False, "detail": exec_result.detail}
        await _transition(
            pool,
            action_id,
            "execution_failed",
            evidence=evidence,
            rollback_note=None,
        )
        await _case_event_for_action(
            pool,
            action_row,
            "action_failed",
            approver or "system",
            "system",
            {"detail": exec_result.detail},
        )
        await log_audit_action(
            actor=approver or "system",
            action="response.execute_failed",
            target_type="response_action",
            target_id=int(action_id),
            new_values={"action_type": action_type, "detail": exec_result.detail},
        )
        return {"status": "execution_failed", "detail": exec_result.detail}

    await _transition(pool, action_id, "executed", evidence=evidence, rollback_note=None)
    await _case_event_for_action(
        pool,
        action_row,
        "action_executed",
        approver or "system",
        "human" if approver else "system",
        {"detail": exec_result.detail},
    )

    verification = await executor_obj.verify(
        params, before=evidence.get("before"), execution=exec_result
    )
    evidence["execution"] = {
        "ok": True,
        "detail": exec_result.detail,
        "intended_state": exec_result.intended_state,
    }
    evidence["verification"] = {
        "verified": verification.verified,
        "mode": verification.mode,
        "before": verification.before,
        "after": verification.after,
        "detail": verification.detail,
    }
    final_status = "verified" if verification.verified else "verification_failed"
    await _transition(
        pool,
        action_id,
        cast(Any, final_status),
        evidence=evidence,
        rollback_note=None,
    )
    await _case_event_for_action(
        pool,
        action_row,
        "action_verified" if verification.verified else "action_failed",
        approver or "system",
        "human" if approver else "system",
        {
            "verified": verification.verified,
            "mode": verification.mode,
            "detail": verification.detail,
        },
    )
    await log_audit_action(
        actor=approver or "system",
        action="response.verified" if verification.verified else "response.verification_failed",
        target_type="response_action",
        target_id=int(action_id),
        new_values={
            "action_type": action_type,
            "verified": verification.verified,
            "mode": verification.mode,
        },
    )
    log.info(
        "response_action_outcome",
        action_id=action_id,
        action_type=action_type,
        verified=verification.verified,
        mode=verification.mode,
    )
    return {
        "status": final_status,
        "execution": evidence["execution"],
        "verification": evidence["verification"],
    }


async def _transition(
    pool, action_id: int, new_status: str, *, evidence: dict | None, rollback_note: str | None
) -> None:
    async with pool.acquire() as conn:
        if rollback_note is not None:
            await conn.execute(
                "UPDATE response_actions SET status = $1::response_action_status, "
                "evidence = $2::jsonb, rollback_note = $3, "
                "executed_at = CASE WHEN $1::response_action_status IN "
                "('executing','executed','verified') THEN COALESCE(executed_at, NOW()) "
                "ELSE executed_at END, "
                "verified_at = CASE WHEN $1::response_action_status = 'verified' "
                "THEN NOW() ELSE verified_at END, updated_at = NOW() WHERE id = $4",
                new_status,
                _json(evidence or {}),
                rollback_note,
                action_id,
            )
        else:
            await conn.execute(
                "UPDATE response_actions SET status = $1::response_action_status, "
                "evidence = $2::jsonb, "
                "executed_at = CASE WHEN $1::response_action_status IN "
                "('executing','executed','verified') THEN COALESCE(executed_at, NOW()) "
                "ELSE executed_at END, "
                "verified_at = CASE WHEN $1::response_action_status = 'verified' "
                "THEN NOW() ELSE verified_at END, updated_at = NOW() WHERE id = $3",
                new_status,
                _json(evidence or {}),
                action_id,
            )


async def _case_event_for_action(
    pool, action_row: dict, event_type: str, actor: str, actor_kind: str, payload: dict
) -> None:
    """Write the action event onto the case timeline (best-effort)."""
    case_id = action_row.get("case_id")
    if not case_id:
        return

    try:
        async with pool.acquire() as conn:
            await _record_case_event(
                conn,
                int(case_id),
                event_type,
                actor,
                payload,
                actor_kind=actor_kind,
                action_id=int(action_row["id"]),
            )
    except Exception as e:  # pragma: no cover - defensive
        log.warning("response_case_event_failed", action_id=action_row.get("id"), error=str(e))


# ───────────────────────────────────────────────────────────────
# Endpoints
# ───────────────────────────────────────────────────────────────


@router.post("/actions", status_code=status.HTTP_201_CREATED)
async def request_action(
    body: ActionRequest,
    user: dict = Depends(require_role("analyst")),
):
    """Request a response action. The policy engine decides what happens."""
    username = user.get("sub", "unknown")
    executor = get_executor(body.action_type)
    if executor is None:
        raise HTTPException(
            status_code=403,
            detail=f"unknown action type '{body.action_type}' (fail-closed: nothing executes)",
        )
    param_error = executor.validate_params(body.params)
    if param_error:
        raise HTTPException(status_code=400, detail=param_error)

    _, entries = _load_policy()
    actions_today = await _actions_today(body.action_type)
    decision = policy_mod.evaluate_action(
        body.action_type,
        entries,
        has_case=body.case_id is not None,
        actions_today=actions_today,
    )
    if not decision.allowed:
        await log_audit_action(
            actor=username,
            action="response.refused",
            target_type="response_action",
            new_values={
                "action_type": body.action_type,
                "reason": decision.reason,
                "case_id": body.case_id,
            },
        )
        raise HTTPException(status_code=403, detail=decision.reason)

    # Pre-flight: capability check + BEFORE state for the evidence package
    try:
        before = await executor.plan(body.params)
    except Exception as e:
        before = {"plan_error": str(e)}

    pool = await get_pool()
    rollback_note = (
        decision.entry.rollback_note if decision.entry else executor.default_rollback_note
    )
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO response_actions
                (case_id, action_type, params, policy_effect, status, requested_by,
                 justification, evidence, rollback_note)
            VALUES ($1, $2::response_action_type, $3::jsonb, $4, 'requested', $5, $6,
                    $7::jsonb, $8)
            RETURNING *
            """,
            body.case_id,
            body.action_type,
            _json(body.params),
            decision.effect,
            username,
            body.justification,
            _json({"before": before, "policy_reason": decision.reason}),
            rollback_note,
        )
    action = dict(row)

    await log_audit_action(
        actor=username,
        action="response.requested",
        target_type="response_action",
        target_id=int(action["id"]),
        new_values={
            "action_type": body.action_type,
            "effect": decision.effect,
            "requires_approval": decision.requires_approval,
            "case_id": body.case_id,
        },
    )

    if body.case_id is not None:
        await _case_event_for_action(
            pool,
            action,
            "action_requested",
            username,
            "human",
            {
                "action_type": body.action_type,
                "effect": decision.effect,
                "justification": body.justification,
            },
        )

    if decision.requires_approval:
        # Park it: containment actions never auto-execute. Best-effort Slack
        # heads-up so an approver knows a decision is waiting.
        from src.response.notifications import send_slack_notification

        await send_slack_notification(
            f"[SecurityScarletAI] approval required: {body.action_type} "
            f"(action #{action['id']}) requested by {username}"
        )
        return {"action": action, "policy": decision.reason, "approval_required": True}

    # Allow tier: execute immediately (still fully recorded + verified)
    outcome = await _execute_and_verify(action, approver=None)
    refreshed = await get_action(int(action["id"]), user=user)
    return {
        "action": refreshed,
        "policy": decision.reason,
        "approval_required": False,
        "outcome": outcome,
    }


@router.get("/actions")
async def list_actions(
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    action_type: str | None = None,
    case_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    user: dict = Depends(require_role("analyst")),
):
    """List response actions (filters: status, action_type, case_id)."""
    pool = await get_pool()
    conditions = ["1=1"]
    params: list = []
    if status_filter:
        params.append(status_filter)
        conditions.append(f"status = ${len(params)}::response_action_status")
    if action_type:
        params.append(action_type)
        conditions.append(f"action_type = ${len(params)}::response_action_type")
    if case_id is not None:
        params.append(case_id)
        conditions.append(f"case_id = ${len(params)}")

    params.extend([limit, offset])
    limit_idx = len(params) - 1
    offset_idx = len(params)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT id, case_id, action_type, params, policy_effect, status, "  # noqa: S608
            f"requested_by, approved_by, executed_at, verified_at, rollback_note, "
            f"created_at, updated_at "
            f"FROM response_actions WHERE {' AND '.join(conditions)} "
            f"ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}",
            *params,
        )
        return [dict(r) for r in rows]


@router.get("/actions/{action_id}")
async def get_action(
    action_id: int,
    user: dict = Depends(require_role("analyst")),
):
    """Full evidence package for one action: policy decision, approval
    trail, execution record, and the verification (re-query) proof."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM response_actions WHERE id = $1", action_id)
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")
        action = dict(row)
        action["params"] = _load_json(action["params"])
        action["evidence"] = _load_json(action.get("evidence"))
        if action.get("case_id"):
            case = await conn.fetchrow(
                "SELECT id, title, status, severity FROM cases WHERE id = $1",
                action["case_id"],
            )
            action["case"] = dict(case) if case else None
    return action


@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: int,
    body: ApproveRequest,
    user: dict = Depends(require_role("admin")),
):
    """HITL approval (four-eyes: approver != requester), then immediate
    execution + outcome verification."""
    username = user.get("sub", "unknown")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM response_actions WHERE id = $1", action_id)
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")
        if row["status"] != "requested":
            raise HTTPException(
                status_code=400,
                detail=f"action is '{row['status']}', only 'requested' actions can be approved",
            )
        if row["requested_by"] == username:
            raise HTTPException(
                status_code=403,
                detail=(
                    "four-eyes violation: the requester cannot approve their own "
                    "action (HITL is non-negotiable for containment)"
                ),
            )

    await log_audit_action(
        actor=username,
        action="response.approved",
        target_type="response_action",
        target_id=action_id,
        new_values={"action_type": row["action_type"], "note": body.note},
    )

    # Approve, then execute + verify (outside the approve transaction so an
    # execution failure cannot roll the approval record back).
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'approved', approved_by = $1, "
            "approval_note = $2, updated_at = NOW() WHERE id = $3",
            username,
            body.note,
            action_id,
        )
    await _case_event_for_action(
        pool,
        dict(row),
        "action_approved",
        username,
        "human",
        {"approved_by": username, "note": body.note},
    )

    outcome = await _execute_and_verify(dict(row), approver=username)
    refreshed = await get_action(action_id, user=user)
    return {"action": refreshed, "approved_by": username, "outcome": outcome}


@router.post("/actions/{action_id}/reject")
async def reject_action(
    action_id: int,
    body: RejectRequest,
    user: dict = Depends(require_role("admin")),
):
    """Reject a requested action. The refusal is a decision record too."""
    username = user.get("sub", "unknown")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM response_actions WHERE id = $1", action_id)
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")
        if row["status"] != "requested":
            raise HTTPException(
                status_code=400,
                detail=f"action is '{row['status']}', only 'requested' actions can be rejected",
            )
        await conn.execute(
            "UPDATE response_actions SET status = 'rejected', rejection_reason = $1, "
            "updated_at = NOW() WHERE id = $2",
            body.reason,
            action_id,
        )

    await log_audit_action(
        actor=username,
        action="response.rejected",
        target_type="response_action",
        target_id=action_id,
        new_values={"action_type": row["action_type"], "reason": body.reason},
    )
    await _case_event_for_action(
        pool,
        dict(row),
        "action_rejected",
        username,
        "human",
        {"rejected_by": username, "reason": body.reason},
    )
    return {"id": action_id, "status": "rejected"}


@router.post("/actions/{action_id}/execute")
async def execute_action(
    action_id: int,
    user: dict = Depends(require_role("admin")),
):
    """Execute an approved action (separates the approval decision from the
    execution moment). Allow-tier actions may also be executed here if
    their auto-execution at request time was interrupted."""
    username = user.get("sub", "unknown")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM response_actions WHERE id = $1", action_id)
        if not row:
            raise HTTPException(status_code=404, detail="Action not found")
        if row["status"] != "approved" and not (
            row["status"] == "requested" and row["policy_effect"] == "allow"
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"action is '{row['status']}': only approved actions execute "
                    "(containment never auto-executes)"
                ),
            )
        if row["status"] == "requested":
            await conn.execute(
                "UPDATE response_actions SET status = 'approved', approved_by = $1, "
                "approval_note = 'executed via execute endpoint (policy: allow)', "
                "updated_at = NOW() WHERE id = $2",
                username,
                action_id,
            )

    await log_audit_action(
        actor=username,
        action="response.execute",
        target_type="response_action",
        target_id=action_id,
        new_values={"action_type": row["action_type"]},
    )
    outcome = await _execute_and_verify(dict(row), approver=username)
    refreshed = await get_action(action_id, user=user)
    return {"action": refreshed, "executed_by": username, "outcome": outcome}
