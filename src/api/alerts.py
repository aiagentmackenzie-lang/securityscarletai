"""
Alerts API endpoints.

List, filter, and update alert status.
"""
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Optional, List

from src.api.auth import verify_jwt
from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.alerts import update_alert_status, get_alert_stats

router = APIRouter(tags=["alerts"], prefix="/alerts")
log = get_logger("api.alerts")


class AlertUpdate(BaseModel):
    status: str = Field(..., pattern="^(new|investigating|resolved|false_positive|closed)$")
    assigned_to: Optional[str] = Field(None, max_length=100)
    resolution_note: Optional[str] = None


class AlertResponse(BaseModel):
    id: int
    time: str
    rule_name: str
    severity: str
    status: str
    host_name: str
    description: str
    assigned_to: Optional[str]


@router.get("", response_model=List[AlertResponse])
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    host_name: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    user: dict = Depends(verify_jwt),
):
    """List alerts with optional filtering."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Build query dynamically
        conditions = ["1=1"]
        params = []
        
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
        
        where_clause = " AND ".join(conditions)
        params.extend([limit, offset])
        
        rows = await conn.fetch(
            f"""
            SELECT * FROM alerts
            WHERE {where_clause}
            ORDER BY time DESC
            LIMIT ${len(params) - 1} OFFSET ${len(params)}
            """,
            *params
        )
        
        return [dict(r) for r in rows]


@router.get("/stats")
async def alert_statistics(
    time_range: str = "24 hours",
    user: dict = Depends(verify_jwt),
):
    """Get alert statistics for dashboard."""
    return await get_alert_stats(time_range)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    user: dict = Depends(verify_jwt),
):
    """Get a specific alert by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        return dict(row)


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update: AlertUpdate,
    user: dict = Depends(verify_jwt),
):
    """Update alert status and assignment."""
    await update_alert_status(
        alert_id=alert_id,
        status=update.status,
        assigned_to=update.assigned_to or user.get("sub"),
        resolution_note=update.resolution_note,
    )
    
    # Return updated alert
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
        return dict(row)


@router.post("/{alert_id}/case")
async def link_to_case(
    alert_id: int,
    case_id: int,
    user: dict = Depends(verify_jwt),
):
    """Link an alert to a case."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE alerts SET case_id = $1, updated_at = NOW() WHERE id = $2",
            case_id,
            alert_id,
        )
        
        log.info("alert_linked_to_case", alert_id=alert_id, case_id=case_id)
        
        row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
        return dict(row)
