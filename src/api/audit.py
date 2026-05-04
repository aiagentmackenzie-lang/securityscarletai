"""
Audit logging — every state-changing action is recorded.

Provides log_audit_action() for recording mutations, and RBAC
enforcement via require_role() dependency for FastAPI endpoints.
Also provides GET /audit endpoint for querying the audit log.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query

from src.api.auth import require_role
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("api.audit")
router = APIRouter(tags=["audit"], prefix="/audit")


async def log_audit_action(
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: int | None = None,
    old_values: dict | None = None,
    new_values: dict | None = None,
    ip_address: str | None = None,
) -> int | None:
    """
    Record an audit log entry.

    Args:
        actor: Username or 'system'
        action: What happened, e.g., 'rule.create', 'alert.update'
        target_type: What was affected, e.g., 'rule', 'alert', 'case'
        target_id: Primary key of the target
        old_values: Previous state (for updates)
        new_values: New state (for creates/updates)
        ip_address: Request IP address

    Returns:
        The audit log entry ID, or None on failure
    """
    import json

    pool = await get_pool()
    async with pool.acquire() as conn:
        try:
            audit_id = await conn.fetchval(
                """
                INSERT INTO audit_log
                    (actor, action, target_type, target_id, old_values, new_values, ip_address)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id
                """,
                actor,
                action,
                target_type,
                target_id,
                json.dumps(old_values, default=str) if old_values else None,
                json.dumps(new_values, default=str) if new_values else None,
                ip_address,
            )
            log.info(
                "audit_action",
                actor=actor,
                action=action,
                target_type=target_type,
                target_id=target_id,
            )
            return audit_id
        except Exception as e:
            log.error("audit_log_failed", actor=actor, action=action, error=str(e))
            return None


@router.get("")
async def query_audit_log(
    action: Optional[str] = Query(None, description="Filter by action type"),
    actor: Optional[str] = Query(None, description="Filter by actor username"),
    target_type: Optional[str] = Query(None, description="Filter by target type"),
    limit: int = Query(100, le=1000, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    user: dict = Depends(require_role("analyst")),
):
    """Query the audit log. Requires analyst role or above."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        conditions = ["1=1"]
        params: list = []

        if action:
            params.append(action)
            conditions.append(f"action = ${len(params)}")
        if actor:
            params.append(actor)
            conditions.append(f"actor = ${len(params)}")
        if target_type:
            params.append(target_type)
            conditions.append(f"target_type = ${len(params)}")

        params.extend([limit, offset])
        limit_idx = len(params) - 1
        offset_idx = len(params)

        rows = await conn.fetch(
            f"SELECT id, actor, action, target_type, target_id, "  # noqa: S608
            f"old_values, new_values, ip_address, created_at "
            f"FROM audit_log WHERE {' AND '.join(conditions)} "
            f"ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}",
            *params,
        )
        return [dict(r) for r in rows]
