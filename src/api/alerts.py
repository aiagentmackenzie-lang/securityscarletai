"""
Alerts API endpoints v2.

Enhanced with:
- Bulk operations (acknowledge, assign, mark FP, resolve)
- Alert notes/timeline
- Alert export (CSV, STIX)
- Suppression rules
- Configurable filtering
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.api.auth import require_role, verify_bearer_token
from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.alerts import (
    add_alert_note,
    bulk_acknowledge,
    bulk_assign,
    bulk_mark_false_positive,
    bulk_resolve,
    create_suppression_rule,
    export_alerts_csv,
    export_alerts_stix,
    get_alert_stats,
    list_suppression_rules,
    update_alert_status,
)

router = APIRouter(tags=["alerts"], prefix="/alerts")
log = get_logger("api.alerts")


# ───────────────────────────────────────────────────────────────
# Request/Response models
# ───────────────────────────────────────────────────────────────

class AlertUpdate(BaseModel):
    status: str = Field(..., pattern=r"^(new|investigating|resolved|false_positive|closed)$")
    assigned_to: Optional[str] = Field(None, max_length=100)
    resolution_note: Optional[str] = None


class BulkOperation(BaseModel):
    alert_ids: list[int] = Field(..., min_length=1)
    assigned_to: Optional[str] = None
    note: Optional[str] = None


class AlertNote(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)


class SuppressionRuleCreate(BaseModel):
    rule_name: Optional[str] = None
    host_name: Optional[str] = None
    reason: str = Field(..., min_length=1, max_length=500)


class AlertResponse(BaseModel):
    id: int
    time: datetime
    rule_name: str
    severity: str
    status: str
    host_name: str
    description: str
    assigned_to: Optional[str]


# ───────────────────────────────────────────────────────────────
# Alert listing and filtering
# ───────────────────────────────────────────────────────────────

@router.get("")
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    host_name: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    user: str = Depends(verify_bearer_token),
):
    """List alerts with optional filtering. All filters are parameterized."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        conditions = ["1=1"]
        params: list = []

        if status:
            params.append(status)
            conditions.append(f"status = ${len(params)}")
        if severity:
            params.append(severity)
            conditions.append(f"severity = ${len(params)}")
        if host_name:
            params.append(f"%{host_name}%")
            conditions.append(f"host_name ILIKE ${len(params)}")
        if assigned_to:
            params.append(assigned_to)
            conditions.append(f"assigned_to = ${len(params)}")

        params.append(limit)
        params.append(offset)
        limit_idx = len(params) - 1
        offset_idx = len(params)

        # ruff: noqa: S608 — conditions use parameterized $N placeholders, not user input
        sql = (
            "SELECT * FROM alerts "
            "WHERE " + " AND ".join(conditions) + " "
            f"ORDER BY time DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
        )

        rows = await conn.fetch(sql, *params)
        return [dict(r) for r in rows]


@router.get("/stats")
async def alert_statistics(
    hours: int = 24,
    user: str = Depends(verify_bearer_token),
):
    """Get alert statistics for dashboard."""
    return await get_alert_stats(hours)


# ───────────────────────────────────────────────────────────────
# Single alert operations
# ───────────────────────────────────────────────────────────────

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    user: str = Depends(verify_bearer_token),
):
    """Get a specific alert by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        return dict(row)


@router.put("/{alert_id}")
@router.patch("/{alert_id}")
async def update_alert(
    alert_id: int,
    update: AlertUpdate,
    user: str = Depends(require_role("analyst")),
):
    """Update alert status and assignment. Requires analyst role or above."""
    await update_alert_status(
        alert_id=alert_id,
        status=update.status,
        assigned_to=update.assigned_to,
        resolution_note=update.resolution_note,
        updated_by=str(user),
    )

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
        return dict(row)


@router.post("/{alert_id}/notes")
async def add_note(
    alert_id: int,
    note: AlertNote,
    user: str = Depends(require_role("analyst")),
):
    """Add a note/timeline entry to an alert."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id FROM alerts WHERE id = $1", alert_id)
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")

    await add_alert_note(alert_id=alert_id, author=str(user), text=note.text)
    return {"status": "note_added", "alert_id": alert_id}


@router.get("/{alert_id}/notes")
async def get_notes(
    alert_id: int,
    user: str = Depends(verify_bearer_token),
):
    """Get all notes/timeline entries for an alert."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT notes FROM alerts WHERE id = $1", alert_id)
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")

        import json
        notes = row["notes"]
        if isinstance(notes, str):
            notes = json.loads(notes)
        return notes if notes else []


class LinkCaseRequest(BaseModel):
    """Request body for linking an alert to a case.

    Either provide case_id to link to an existing case,
    or provide title (and optionally description) to create a new case.
    """
    case_id: int | None = None
    title: str | None = None
    description: str | None = None


@router.post("/{alert_id}/case")
async def link_to_case(
    alert_id: int,
    body: LinkCaseRequest,
    user: dict = Depends(require_role("analyst")),
):
    """Link an alert to a case.

    If case_id is provided, link the alert to that existing case.
    If case_id is not provided, create a new case with the given title and description,
    then link the alert to it.
    """
    from src.api.audit import log_audit_action

    pool = await get_pool()
    username = user.get("sub", "unknown")

    async with pool.acquire() as conn:
        # Verify the alert exists
        alert_row = await conn.fetchrow("SELECT id, severity FROM alerts WHERE id = $1", alert_id)
        if not alert_row:
            raise HTTPException(status_code=404, detail="Alert not found")

        if body.case_id:
            # Link to existing case
            case_row = await conn.fetchrow(
                "SELECT id, alert_ids FROM cases WHERE id = $1", body.case_id
            )
            if not case_row:
                raise HTTPException(status_code=404, detail="Case not found")

            # Update alert.case_id
            await conn.execute(
                "UPDATE alerts SET case_id = $1, updated_at = NOW() WHERE id = $2",
                body.case_id,
                alert_id,
            )

            # Append alert to case's alert_ids array
            current_ids = case_row["alert_ids"] or []
            if alert_id not in current_ids:
                current_ids.append(alert_id)
                await conn.execute(
                    "UPDATE cases SET alert_ids = $1, updated_at = NOW() WHERE id = $2",
                    current_ids,
                    body.case_id,
                )

            result = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
            log.info("alert_linked_to_case", alert_id=alert_id, case_id=body.case_id, user=username)
            return dict(result)

        else:
            # Create a new case inline
            title = body.title or f"Investigation: Alert #{alert_id}"
            description = body.description or ""
            severity = alert_row["severity"]

            case_row = await conn.fetchrow(
                "INSERT INTO cases (title, description, severity, alert_ids) "
                "VALUES ($1, $2, $3, $4) RETURNING *",
                title,
                description,
                severity,
                [alert_id],
            )
            new_case_id = case_row["id"]

            # Update alert.case_id
            await conn.execute(
                "UPDATE alerts SET case_id = $1, updated_at = NOW() WHERE id = $2",
                new_case_id,
                alert_id,
            )

            await log_audit_action(
                actor=username,
                action="case.create_from_alert",
                target_type="case",
                target_id=new_case_id,
                new_values={"title": title, "alert_id": alert_id},
            )

            result = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
            log.info(
                "case_created_from_alert",
                alert_id=alert_id,
                case_id=new_case_id,
                user=username,
            )
            return dict(result)


# ───────────────────────────────────────────────────────────────
# Bulk operations
# ───────────────────────────────────────────────────────────────

@router.post("/bulk/acknowledge")
async def bulk_acknowledge_alerts(
    op: BulkOperation,
    user: str = Depends(require_role("analyst")),
):
    """Acknowledge multiple alerts (set to 'investigating' status)."""
    count = await bulk_acknowledge(op.alert_ids, op.assigned_to or str(user))
    return {"acknowledged": count, "alert_ids": op.alert_ids}


@router.post("/bulk/false-positive")
async def bulk_false_positive_alerts(
    op: BulkOperation,
    user: str = Depends(require_role("analyst")),
):
    """Mark multiple alerts as false positive."""
    count = await bulk_mark_false_positive(op.alert_ids, op.note or "Bulk marked as FP")
    return {"marked_false_positive": count, "alert_ids": op.alert_ids}


@router.post("/bulk/assign")
async def bulk_assign_alerts(
    op: BulkOperation,
    user: str = Depends(require_role("analyst")),
):
    """Assign multiple alerts to a user."""
    if not op.assigned_to:
        raise HTTPException(status_code=400, detail="assigned_to is required")
    count = await bulk_assign(op.alert_ids, op.assigned_to)
    return {"assigned": count, "alert_ids": op.alert_ids, "assigned_to": op.assigned_to}


@router.post("/bulk/resolve")
async def bulk_resolve_alerts(
    op: BulkOperation,
    user: str = Depends(require_role("analyst")),
):
    """Resolve multiple alerts at once."""
    count = await bulk_resolve(op.alert_ids, op.note or "Bulk resolved")
    return {"resolved": count, "alert_ids": op.alert_ids}


# ───────────────────────────────────────────────────────────────
# Alert export
# ───────────────────────────────────────────────────────────────

@router.get("/export/csv")
async def export_csv(
    hours: int = 24,
    status: Optional[str] = None,
    user: str = Depends(require_role("analyst")),
):
    """Export alerts as CSV download."""
    csv_data = await export_alerts_csv(hours=hours, status_filter=status)
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"},
    )


@router.get("/export/stix")
async def export_stix(
    hours: int = 24,
    user: str = Depends(require_role("analyst")),
):
    """Export alerts as STIX 2.1 bundle."""
    return await export_alerts_stix(hours=hours)


# ───────────────────────────────────────────────────────────────
# Alert suppression rules
# ───────────────────────────────────────────────────────────────

@router.get("/suppressions")
async def list_suppressions(
    user: str = Depends(require_role("analyst")),
):
    """List all alert suppression rules."""
    return await list_suppression_rules()


@router.post("/suppressions")
async def create_suppression(
    rule: SuppressionRuleCreate,
    user: str = Depends(require_role("admin")),
):
    """Create a new alert suppression rule. Admin only."""
    suppression_id = await create_suppression_rule(
        rule_name=rule.rule_name,
        host_name=rule.host_name,
        reason=rule.reason,
        created_by=str(user),
    )
    return {"id": suppression_id, "status": "created"}
