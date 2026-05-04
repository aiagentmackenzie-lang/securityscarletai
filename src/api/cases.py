"""
Cases CRUD API — Full case management independent of alerts.

Endpoints:
  GET    /cases                        — List cases with optional filters
  POST   /cases                        — Create a new case
  GET    /cases/{id}                   — Get case detail with linked alerts
  PATCH  /cases/{id}                   — Update case fields
  DELETE /cases/{id}                   — Soft-delete (set status to closed)
  POST   /cases/{id}/alerts            — Link an alert to this case
  DELETE /cases/{id}/alerts/{alert_id}  — Unlink an alert from case
  POST   /cases/{id}/notes             — Add a note to the case
  GET    /cases/{id}/notes             — Get all notes for a case
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.audit import log_audit_action
from src.api.auth import require_role, verify_bearer_token
from src.config.logging import get_logger
from src.db.connection import get_pool

router = APIRouter(tags=["cases"], prefix="/cases")
log = get_logger("api.cases")


# ───────────────────────────────────────────────────────────────
# Request / Response models
# ───────────────────────────────────────────────────────────────


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field("", max_length=5000)
    severity: str = Field("medium", pattern=r"^(info|low|medium|high|critical)$")
    alert_ids: list[int] = Field(default_factory=list)
    assigned_to: str | None = None


class CaseUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = Field(None, max_length=5000)
    status: str | None = Field(None, pattern=r"^(open|in_progress|resolved|closed)$")
    severity: str | None = Field(None, pattern=r"^(info|low|medium|high|critical)$")
    assigned_to: str | None = None
    lessons_learned: str | None = None
    resolution_note: str | None = None


class AlertLink(BaseModel):
    alert_id: int


class CaseNote(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)


# ───────────────────────────────────────────────────────────────
# Helper: enforce lessons_learned on resolve/close
# ───────────────────────────────────────────────────────────────


def _validate_resolve(update: CaseUpdate) -> None:
    """Require lessons_learned text when transitioning to resolved or closed."""
    if update.status in ("resolved", "closed") and not update.lessons_learned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="lessons_learned is required when resolving or closing a case",
        )


# ───────────────────────────────────────────────────────────────
# Endpoints
# ───────────────────────────────────────────────────────────────


@router.get("")
async def list_cases(
    status_filter: str | None = None,
    severity: str | None = None,
    assigned_to: str | None = None,
    limit: int = 100,
    offset: int = 0,
    user: str = Depends(verify_bearer_token),
):
    """List cases with optional filters (status, severity, assigned_to)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        conditions = ["1=1"]
        params: list = []

        if status_filter:
            params.append(status_filter)
            conditions.append(f"status = ${len(params)}")
        if severity:
            params.append(severity)
            conditions.append(f"severity = ${len(params)}")
        if assigned_to:
            params.append(assigned_to)
            conditions.append(f"assigned_to = ${len(params)}")

        params.extend([limit, offset])
        limit_idx = len(params) - 1
        offset_idx = len(params)

        rows = await conn.fetch(
            "SELECT id, title, description, status, severity, assigned_to, "
            "alert_ids, notes, lessons_learned, resolution_note, "
            "resolved_at, created_at, updated_at "
            "FROM cases "
            "WHERE " + " AND ".join(conditions) + " "
            f"ORDER BY updated_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}",  # noqa: S608
            *params,
        )
        return [dict(r) for r in rows]


@router.post("")
async def create_case(
    case: CaseCreate,
    user: dict = Depends(require_role("analyst")),
):
    """Create a new case. alert_ids are optional — cases can exist without alerts."""
    pool = await get_pool()
    username = user.get("sub", "unknown")

    async with pool.acquire() as conn:
        # Insert the case
        row = await conn.fetchrow(
            """
            INSERT INTO cases (title, description, status, severity, assigned_to, alert_ids)
            VALUES ($1, $2, 'open', $3, $4, $5)
            RETURNING *
            """,
            case.title,
            case.description,
            case.severity,
            case.assigned_to,
            case.alert_ids,
        )

        case_id = row["id"]

        # Link any provided alerts (set alerts.case_id)
        if case.alert_ids:
            for aid in case.alert_ids:
                await conn.execute(
                    "UPDATE alerts SET case_id = $1, updated_at = NOW() WHERE id = $2",
                    case_id,
                    aid,
                )

    # Audit log
    await log_audit_action(
        actor=username,
        action="case.create",
        target_type="case",
        target_id=case_id,
        new_values={
            "title": case.title,
            "severity": case.severity,
            "alert_ids": case.alert_ids,
        },
    )

    log.info("case_created", case_id=case_id, title=case.title, user=username)
    return dict(row)


@router.get("/{case_id}")
async def get_case(
    case_id: int,
    user: str = Depends(verify_bearer_token),
):
    """Get case detail including linked alerts."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        case_row = await conn.fetchrow(
            "SELECT id, title, description, status, severity, assigned_to, "
            "alert_ids, notes, lessons_learned, resolution_note, "
            "resolved_at, created_at, updated_at "
            "FROM cases WHERE id = $1",
            case_id,
        )
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found")

        # Fetch linked alerts (using ANY($1) for safe parameterized query)
        alert_ids = case_row["alert_ids"] or []
        alerts = []
        if alert_ids:
            alerts = [
                dict(r) for r in await conn.fetch(
                    "SELECT id, time, rule_name, severity, status, "
                    "host_name, description, assigned_to "
                    "FROM alerts WHERE id = ANY($1)",
                    alert_ids,
                )
            ]

        result = dict(case_row)
        result["linked_alerts"] = alerts
        return result


@router.patch("/{case_id}")
async def update_case(
    case_id: int,
    update: CaseUpdate,
    user: dict = Depends(require_role("analyst")),
):
    """Update case fields. When resolving/closing, lessons_learned is required."""
    # Validate lessons_learned on resolve/close
    _validate_resolve(update)

    pool = await get_pool()
    username = user.get("sub", "unknown")

    async with pool.acquire() as conn:
        # Fetch current state for audit
        current = await conn.fetchrow("SELECT * FROM cases WHERE id = $1", case_id)
        if not current:
            raise HTTPException(status_code=404, detail="Case not found")

        # Build dynamic UPDATE
        set_clauses: list[str] = []
        params: list = []
        param_idx = 1

        updatable_fields = {
            "title": update.title,
            "description": update.description,
            "status": update.status,
            "severity": update.severity,
            "assigned_to": update.assigned_to,
            "lessons_learned": update.lessons_learned,
            "resolution_note": update.resolution_note,
        }

        for field, value in updatable_fields.items():
            if value is not None:
                set_clauses.append(f"{field} = ${param_idx}")
                params.append(value)
                param_idx += 1

        # Set resolved_at timestamp when status changes to resolved
        if update.status == "resolved":
            set_clauses.append(f"resolved_at = ${param_idx}")
            params.append(datetime.now(tz=timezone.utc))
            param_idx += 1

        if not set_clauses:
            return dict(current)

        set_clauses.append(f"updated_at = ${param_idx}")
        params.append(datetime.now(tz=timezone.utc))
        param_idx += 1
        params.append(case_id)

        sql = (
            f"UPDATE cases SET {', '.join(set_clauses)} WHERE id = ${param_idx} "  # noqa: S608
            f"RETURNING *"
        )
        row = await conn.fetchrow(sql, *params)

    # Audit log
    await log_audit_action(
        actor=username,
        action="case.update",
        target_type="case",
        target_id=case_id,
        old_values={
            k: str(v) for k, v in dict(current).items()
            if k in ("status", "assigned_to", "title", "lessons_learned")
        },
        new_values=update.model_dump(exclude_none=True),
    )

    log.info("case_updated", case_id=case_id, user=username)
    return dict(row)


@router.delete("/{case_id}")
async def delete_case(
    case_id: int,
    user: dict = Depends(require_role("admin")),
):
    """Soft-delete: set case status to closed. Admin only."""
    pool = await get_pool()
    username = user.get("sub", "unknown")

    async with pool.acquire() as conn:
        current = await conn.fetchrow("SELECT * FROM cases WHERE id = $1", case_id)
        if not current:
            raise HTTPException(status_code=404, detail="Case not found")

        if current["status"] == "closed":
            raise HTTPException(status_code=400, detail="Case is already closed")

        row = await conn.fetchrow(
            "UPDATE cases SET status = 'closed', updated_at = NOW() WHERE id = $1 RETURNING *",
            case_id,
        )

    # Audit log
    await log_audit_action(
        actor=username,
        action="case.delete",
        target_type="case",
        target_id=case_id,
        old_values={"status": current["status"]},
        new_values={"status": "closed"},
    )

    log.info("case_soft_deleted", case_id=case_id, user=username)
    return dict(row)


@router.post("/{case_id}/alerts")
async def link_alert(
    case_id: int,
    body: AlertLink,
    user: dict = Depends(require_role("analyst")),
):
    """Link an alert to this case. Updates alert.case_id AND appends to cases.alert_ids."""
    pool = await get_pool()
    username = user.get("sub", "unknown")
    alert_id = body.alert_id

    async with pool.acquire() as conn:
        # Verify case exists
        case_row = await conn.fetchrow("SELECT id, alert_ids FROM cases WHERE id = $1", case_id)
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found")

        # Verify alert exists
        alert_row = await conn.fetchrow("SELECT id, case_id FROM alerts WHERE id = $1", alert_id)
        if not alert_row:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Check for duplicate link
        current_alert_ids = case_row["alert_ids"] or []
        if alert_id in current_alert_ids:
            raise HTTPException(status_code=409, detail="Alert already linked to this case")

        # Update alert.case_id
        await conn.execute(
            "UPDATE alerts SET case_id = $1, updated_at = NOW() WHERE id = $2",
            case_id,
            alert_id,
        )

        # Append to cases.alert_ids
        current_alert_ids.append(alert_id)
        await conn.execute(
            "UPDATE cases SET alert_ids = $1, updated_at = NOW() WHERE id = $2",
            current_alert_ids,
            case_id,
        )

    # Audit log
    await log_audit_action(
        actor=username,
        action="case.link_alert",
        target_type="case",
        target_id=case_id,
        new_values={"alert_id": alert_id},
    )

    log.info("alert_linked_to_case", case_id=case_id, alert_id=alert_id, user=username)
    return {"case_id": case_id, "alert_id": alert_id, "status": "linked"}


@router.delete("/{case_id}/alerts/{alert_id}")
async def unlink_alert(
    case_id: int,
    alert_id: int,
    user: dict = Depends(require_role("analyst")),
):
    """Unlink an alert from this case.

    Sets alert.case_id to null and removes from cases.alert_ids.
    """
    pool = await get_pool()
    username = user.get("sub", "unknown")

    async with pool.acquire() as conn:
        # Verify case exists
        case_row = await conn.fetchrow("SELECT id, alert_ids FROM cases WHERE id = $1", case_id)
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found")

        # Remove from cases.alert_ids
        current_alert_ids = case_row["alert_ids"] or []
        if alert_id not in current_alert_ids:
            raise HTTPException(
                status_code=404,
                detail="Alert is not linked to this case",
            )

        current_alert_ids.remove(alert_id)
        await conn.execute(
            "UPDATE cases SET alert_ids = $1, updated_at = NOW() WHERE id = $2",
            current_alert_ids,
            case_id,
        )

        # Set alert.case_id to null
        await conn.execute(
            "UPDATE alerts SET case_id = NULL, updated_at = NOW() WHERE id = $1",
            alert_id,
        )

    # Audit log
    await log_audit_action(
        actor=username,
        action="case.unlink_alert",
        target_type="case",
        target_id=case_id,
        new_values={"alert_id": alert_id},
    )

    log.info("alert_unlinked_from_case", case_id=case_id, alert_id=alert_id, user=username)
    return {"case_id": case_id, "alert_id": alert_id, "status": "unlinked"}


@router.post("/{case_id}/notes")
async def add_case_note(
    case_id: int,
    note: CaseNote,
    user: dict = Depends(require_role("analyst")),
):
    """Add a note to the case. Notes are stored as JSONB array."""
    pool = await get_pool()
    username = user.get("sub", "unknown")

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, notes FROM cases WHERE id = $1", case_id)
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")

        import json
        notes = row["notes"] or []
        if isinstance(notes, str):
            notes = json.loads(notes)

        new_note = {
            "author": username,
            "text": note.text,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }
        notes.append(new_note)

        updated = await conn.fetchrow(
            "UPDATE cases SET notes = $1::jsonb, updated_at = NOW() "
            "WHERE id = $2 RETURNING id, notes",
            json.dumps(notes),
            case_id,
        )

    # Audit log
    await log_audit_action(
        actor=username,
        action="case.add_note",
        target_type="case",
        target_id=case_id,
        new_values={"text": note.text[:200]},  # Truncate for audit
    )

    return dict(updated)


@router.get("/{case_id}/notes")
async def get_case_notes(
    case_id: int,
    user: str = Depends(verify_bearer_token),
):
    """Get all notes for a case."""
    pool = await get_pool()
    import json

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT notes FROM cases WHERE id = $1", case_id)
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")

        notes = row["notes"]
        if isinstance(notes, str):
            notes = json.loads(notes)
        return notes if notes else []
