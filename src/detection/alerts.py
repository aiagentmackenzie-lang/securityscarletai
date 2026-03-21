"""
Alert generation module.

Creates alerts from detection rule matches.
Handles alert deduplication, severity assignment, and notification triggers.
"""
import json
from datetime import datetime
from typing import Optional, Any

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("detection.alerts")


async def create_alert(
    rule_id: int,
    rule_name: str,
    severity: str,
    host_name: str,
    description: str,
    mitre_tactics: Optional[list] = None,
    mitre_techniques: Optional[list] = None,
    evidence: Optional[dict] = None,
    risk_score: Optional[float] = None,
) -> int:
    """
    Create a new alert in the database.
    
    Returns:
        The ID of the created alert
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check for duplicate alerts (same rule, same host, within 5 minutes)
        existing = await conn.fetchrow(
            """
            SELECT id FROM alerts 
            WHERE rule_id = $1 
              AND host_name = $2 
              AND time > NOW() - INTERVAL '5 minutes'
            ORDER BY time DESC 
            LIMIT 1
            """,
            rule_id,
            host_name,
        )
        
        if existing:
            log.info("duplicate_alert_suppressed", rule_id=rule_id, host_name=host_name)
            return existing["id"]
        
        # Insert new alert
        alert_id = await conn.fetchval(
            """
            INSERT INTO alerts (
                rule_id, rule_name, severity, host_name,
                description, mitre_tactics, mitre_techniques,
                evidence, risk_score, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'new')
            RETURNING id
            """,
            rule_id,
            rule_name,
            severity,
            host_name,
            description,
            mitre_tactics or [],
            mitre_techniques or [],
            json.dumps(evidence) if evidence else "[]",
            risk_score,
        )
        
        log.info("alert_created", alert_id=alert_id, rule_id=rule_id, host_name=host_name)
        
        # TODO: Trigger notifications (Slack, email) here
        
        return alert_id


async def update_alert_status(
    alert_id: int,
    status: str,  # new, investigating, resolved, false_positive, closed
    assigned_to: Optional[str] = None,
    resolution_note: Optional[str] = None,
) -> None:
    """Update the status of an existing alert."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE alerts 
            SET status = $1, 
                assigned_to = COALESCE($2, assigned_to),
                resolved_at = CASE WHEN $1 IN ('resolved', 'closed', 'false_positive') THEN NOW() ELSE resolved_at END,
                updated_at = NOW()
            WHERE id = $3
            """,
            status,
            assigned_to,
            alert_id,
        )
        
        log.info("alert_status_updated", alert_id=alert_id, status=status)


async def get_alert_stats(time_range: str = "24 hours") -> dict:
    """Get alert statistics for dashboard."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        stats = await conn.fetchrow(
            """
            SELECT 
                COUNT(*) FILTER (WHERE status = 'new') as new_count,
                COUNT(*) FILTER (WHERE status = 'investigating') as investigating_count,
                COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) as resolved_count,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
                COUNT(*) FILTER (WHERE severity = 'high') as high_count,
                COUNT(*) as total_count
            FROM alerts
            WHERE time > NOW() - INTERVAL $1
            """,
            time_range,
        )
        
        return dict(stats)
