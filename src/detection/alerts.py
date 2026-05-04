"""
Alert generation and lifecycle management v2.

Features:
- Configurable deduplication window (default 15 min)
- Alert suppression rules (whitelist known false positives)
- Alert severity escalation (3x fires in 1hr → bump severity)
- Bulk alert operations (acknowledge, assign, mark as FP)
- Alert notes/timeline (analyst comments tracked)
- Notification triggers wired into alert creation
- Alert export (CSV, STIX)
"""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("detection.alerts")

# Default deduplication window (seconds)
DEDUP_WINDOW_SECONDS = 900  # 15 minutes

# Severity escalation thresholds
ESCALATION_WINDOW_HOURS = 1
ESCALATION_FIRE_THRESHOLD = 3  # If same rule fires 3x in 1hr, bump severity

# Severity ordering for escalation
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITY_ORDER)}


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
    dedup_window_seconds: int = DEDUP_WINDOW_SECONDS,
) -> int:
    """
    Create a new alert with deduplication, severity escalation, and notification.

    Steps:
    1. Check deduplication — suppress if same rule+host within window
    2. Check escalation — bump severity if same rule fires frequently
    3. Check suppression rules — suppress if whitelisted
    4. Insert alert
    5. Trigger notifications

    Args:
        dedup_window_seconds: Deduplication window in seconds (default 15 min)

    Returns:
        The ID of the created alert (or existing alert ID if suppressed)
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # ── Step 1: Deduplication ────────────────────────────
        existing = await conn.fetchrow(
            """
            SELECT id FROM alerts
            WHERE rule_id = $1
              AND host_name = $2
              AND time > NOW() - INTERVAL '1 second' * $3
            ORDER BY time DESC
            LIMIT 1
            """,
            rule_id,
            host_name,
            dedup_window_seconds,
        )

        if existing:
            log.info(
                "duplicate_alert_suppressed",
                rule_id=rule_id,
                host_name=host_name,
                alert_id=existing["id"],
            )
            return existing["id"]

        # ── Step 2: Severity escalation ──────────────────────
        escalated_severity = await _check_severity_escalation(
            conn, rule_id, host_name, severity
        )

        # ── Step 3: Suppression rules ────────────────────────
        if await _is_suppressed(conn, rule_name, host_name, escalated_severity):
            log.info("alert_suppressed_by_rule", rule_name=rule_name, host_name=host_name)
            return 0  # Suppressed — no alert created

        # ── Step 4: Insert alert ─────────────────────────────
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
            escalated_severity,
            host_name,
            description,
            mitre_tactics or [],
            mitre_techniques or [],
            json.dumps(evidence, default=str) if evidence else "[]",
            risk_score,
        )

        # Add system note about creation
        await _add_note(conn, alert_id, "system", f"Alert created (severity: {escalated_severity})")
        if escalated_severity != severity:
            await _add_note(conn, alert_id, "system",
                            f"Severity escalated from {severity} to {escalated_severity}")

        log.info("alert_created", alert_id=alert_id, rule_id=rule_id,
                 host_name=host_name, severity=escalated_severity)

        # ── Step 5: Trigger notifications ─────────────────────
        await _send_alert_notification(
            alert_id, rule_name, escalated_severity, host_name, description
        )

        return alert_id


async def _check_severity_escalation(
    conn, rule_id: int, host_name: str, current_severity: str
) -> str:
    """
    Check if the same rule has fired enough times to warrant severity escalation.

    If same rule fires ESCALATION_FIRE_THRESHOLD times within the lookback window,
    bump severity one level.
    """
    recent_count = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE rule_id = $1
          AND host_name = $2
          AND time > NOW() - INTERVAL '1 hour' * $3
        """,
        rule_id,
        host_name,
        ESCALATION_WINDOW_HOURS,
    )

    if recent_count >= ESCALATION_FIRE_THRESHOLD:
        current_idx = SEVERITY_INDEX.get(current_severity, 2)
        new_idx = min(current_idx + 1, len(SEVERITY_ORDER) - 1)
        new_severity = SEVERITY_ORDER[new_idx]
        if new_severity != current_severity:
            log.info("severity_escalated",
                     rule_id=rule_id, host_name=host_name,
                     from_severity=current_severity, to_severity=new_severity,
                     recent_count=recent_count)
            return new_severity

    return current_severity


async def _is_suppressed(
    conn, rule_name: str, host_name: str, severity: str
) -> bool:
    """Check if an alert should be suppressed by suppression rules."""
    row = await conn.fetchrow(
        """
        SELECT id FROM alert_suppressions
        WHERE (rule_name = $1 OR rule_name IS NULL)
          AND (host_name = $2 OR host_name IS NULL)
          AND enabled = TRUE
        LIMIT 1
        """,
        rule_name,
        host_name,
    )
    return row is not None


async def _add_note(conn, alert_id: int, author: str, text: str) -> None:
    """Add a note/timeline entry to an alert."""
    await conn.execute(
        """
        UPDATE alerts
        SET notes = CASE
            WHEN notes IS NULL OR notes = '[]'::jsonb
            THEN $1::jsonb
            ELSE notes || $1::jsonb
        END,
        updated_at = NOW()
        WHERE id = $2
        """,
        json.dumps([{
            "author": author,
            "text": text,
            "time": datetime.now(timezone.utc).isoformat(),
        }]),
        alert_id,
    )


async def _send_alert_notification(
    alert_id: int, rule_name: str, severity: str, host_name: str, description: str
) -> None:
    """Send alert notification via configured channels (Slack, email)."""
    try:
        from src.response.notifications import send_notification
        await send_notification(
            title=f"[{severity.upper()}] {rule_name}",
            body=f"Host: {host_name}\n{description}\nAlert ID: {alert_id}",
            severity=severity,
        )
    except Exception as e:
        log.warning("notification_failed", alert_id=alert_id, error=str(e))


# ───────────────────────────────────────────────────────────────
# Alert status updates
# ───────────────────────────────────────────────────────────────

async def update_alert_status(
    alert_id: int,
    status: str,
    assigned_to: Optional[str] = None,
    resolution_note: Optional[str] = None,
    updated_by: str = "system",
) -> None:
    """Update the status of an existing alert with audit note."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE alerts
            SET status = $1,
                assigned_to = COALESCE($2, assigned_to),
                resolved_at = CASE
                    WHEN $1 IN ('resolved', 'closed', 'false_positive')
                    THEN NOW() ELSE resolved_at
                END,
                updated_at = NOW()
            WHERE id = $3
            """,
            status,
            assigned_to,
            alert_id,
        )

        # Add timeline note
        note_text = f"Status changed to: {status}"
        if resolution_note:
            note_text += f" — {resolution_note}"
        await _add_note(conn, alert_id, updated_by, note_text)

        log.info("alert_status_updated", alert_id=alert_id, status=status, by=updated_by)


# ───────────────────────────────────────────────────────────────
# Bulk operations
# ───────────────────────────────────────────────────────────────

async def bulk_acknowledge(alert_ids: list[int], assigned_to: str) -> int:
    """Acknowledge multiple alerts at once (set status to 'investigating')."""
    if not alert_ids:
        return 0

    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE alerts
            SET status = 'investigating',
                assigned_to = $1,
                updated_at = NOW()
            WHERE id = ANY($2::int[]) AND status = 'new'
            """,
            assigned_to,
            alert_ids,
        )
        count = int(result.split()[-1])
        log.info("bulk_acknowledge", count=count, assigned_to=assigned_to)
        return count


async def bulk_mark_false_positive(
    alert_ids: list[int], note: str = "Marked as false positive"
) -> int:
    """Mark multiple alerts as false positive."""
    if not alert_ids:
        return 0

    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE alerts
            SET status = 'false_positive',
                resolved_at = NOW(),
                updated_at = NOW()
            WHERE id = ANY($1::int[]) AND status NOT IN ('resolved', 'closed')
            """,
            alert_ids,
        )
        count = int(result.split()[-1])
        log.info("bulk_false_positive", count=count, note=note)
        return count


async def bulk_assign(alert_ids: list[int], assigned_to: str) -> int:
    """Assign multiple alerts to a specific user."""
    if not alert_ids:
        return 0

    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE alerts
            SET assigned_to = $1, updated_at = NOW()
            WHERE id = ANY($2::int[])
            """,
            assigned_to,
            alert_ids,
        )
        count = int(result.split()[-1])
        log.info("bulk_assign", count=count, assigned_to=assigned_to)
        return count


async def bulk_resolve(alert_ids: list[int], resolution_note: str = "Bulk resolved") -> int:
    """Resolve multiple alerts at once."""
    if not alert_ids:
        return 0

    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE alerts
            SET status = 'resolved',
                resolved_at = NOW(),
                updated_at = NOW()
            WHERE id = ANY($1::int[]) AND status NOT IN ('resolved', 'closed')
            """,
            alert_ids,
        )
        count = int(result.split()[-1])
        log.info("bulk_resolve", count=count, note=resolution_note)
        return count


# ───────────────────────────────────────────────────────────────
# Alert notes/timeline
# ───────────────────────────────────────────────────────────────

async def add_alert_note(alert_id: int, author: str, text: str) -> None:
    """Add an analyst note to an alert's timeline."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        note_entry = json.dumps([{
            "author": author,
            "text": text,
            "time": datetime.now(timezone.utc).isoformat(),
        }])

        await conn.execute(
            """
            UPDATE alerts
            SET notes = CASE
                WHEN notes IS NULL OR notes = '[]'::jsonb
                THEN $1::jsonb
                ELSE notes || $1::jsonb
            END,
            updated_at = NOW()
            WHERE id = $2
            """,
            note_entry,
            alert_id,
        )

        log.info("alert_note_added", alert_id=alert_id, author=author)


# ───────────────────────────────────────────────────────────────
# Alert statistics
# ───────────────────────────────────────────────────────────────

async def get_alert_stats(hours: int = 24) -> dict:
    """Get alert statistics for dashboard."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        stats = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'new') as new_count,
                COUNT(*) FILTER (WHERE status = 'investigating') as investigating_count,
                COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) as resolved_count,
                COUNT(*) FILTER (WHERE status = 'false_positive') as false_positive_count,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
                COUNT(*) FILTER (WHERE severity = 'high') as high_count,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium_count,
                COUNT(*) FILTER (WHERE severity = 'low') as low_count,
                COUNT(*) as total_count
            FROM alerts
            WHERE time > NOW() - INTERVAL '1 hour' * $1
            """,
            hours,
        )
        return dict(stats)


# ───────────────────────────────────────────────────────────────
# Alert suppression rules
# ───────────────────────────────────────────────────────────────

async def create_suppression_rule(
    rule_name: Optional[str],
    host_name: Optional[str],
    reason: str,
    created_by: str = "admin",
) -> int:
    """Create an alert suppression rule (false positive whitelist)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Create table if not exists (lazy migration)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_suppressions (
                id SERIAL PRIMARY KEY,
                rule_name TEXT,
                host_name TEXT,
                reason TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_by TEXT NOT NULL DEFAULT 'admin',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)

        suppression_id = await conn.fetchval(
            """
            INSERT INTO alert_suppressions (rule_name, host_name, reason, created_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            rule_name,
            host_name,
            reason,
            created_by,
        )

        log.info("suppression_rule_created", suppression_id=suppression_id,
                  rule_name=rule_name, host_name=host_name)
        return suppression_id


async def list_suppression_rules() -> list[dict]:
    """List all alert suppression rules."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM alert_suppressions ORDER BY created_at DESC"
        )
        return [dict(r) for r in rows]


# ───────────────────────────────────────────────────────────────
# Alert export
# ───────────────────────────────────────────────────────────────

async def export_alerts_csv(hours: int = 24, status_filter: Optional[str] = None) -> str:
    """Export alerts as CSV for external analysis."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        if status_filter:
            rows = await conn.fetch(
                """
                SELECT id, time, rule_name, severity, status, host_name,
                       description, assigned_to, risk_score
                FROM alerts
                WHERE time > NOW() - INTERVAL '1 hour' * $1
                  AND status = $2
                ORDER BY time DESC
                """,
                hours,
                status_filter,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT id, time, rule_name, severity, status, host_name,
                       description, assigned_to, risk_score
                FROM alerts
                WHERE time > NOW() - INTERVAL '1 hour' * $1
                ORDER BY time DESC
                """,
                hours,
            )

    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(row))

    log.info("alerts_exported_csv", count=len(rows), hours=hours, status=status_filter)
    return output.getvalue()


async def export_alerts_stix(hours: int = 24) -> dict:
    """Export alerts as a simplified STIX 2.1 bundle for threat sharing."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, time, rule_name, severity, status, host_name,
                   description, mitre_tactics, mitre_techniques
            FROM alerts
            WHERE time > NOW() - INTERVAL '1 hour' * $1
            ORDER BY time DESC
            """,
            hours,
        )

    objects = []
    for row in rows:
        d = dict(row)
        # Generate STIX Indicator object
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{d['id']:012d}",
            "created": (
                d["time"].isoformat()
                if isinstance(d["time"], datetime)
                else str(d["time"])
            ),
            "modified": (
                d["time"].isoformat()
                if isinstance(d["time"], datetime)
                else str(d["time"])
            ),
            "name": d["rule_name"],
            "description": d["description"],
            "pattern": f"[host_name = '{d['host_name']}']",
            "pattern_type": "stix",
            "valid_from": (
                d["time"].isoformat()
                if isinstance(d["time"], datetime)
                else str(d["time"])
            ),
            "labels": d.get("mitre_techniques", []),
            "confidence": 80 if d["severity"] in ("high", "critical") else 50,
        }
        objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": "bundle--securityscarletai-export",
        "objects": objects,
    }

    log.info("alerts_exported_stix", count=len(objects), hours=hours)
    return bundle
