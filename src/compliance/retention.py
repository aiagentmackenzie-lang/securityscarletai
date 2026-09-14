"""Retention policy AS EVIDENCE (V0.7 -- closes G7's policy half).

A duty-holder's auditor asks about log retention; the honest answer is
the CONFIGURED TRUTH (per-table windows, including 0 = keep forever) plus
the TimescaleDB engine policies when they exist. This module surfaces
both, fail-closed: a vanilla-PostgreSQL deployment reports the absence of
Timescale policies rather than pretending they exist.

The retention MECHANICS live in src/services/retention.py (the sweep job)
and the schema's guarded TimescaleDB block (compression + retention
policies). This module makes the policy EXPORTABLE as evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("compliance.retention")

# (table, time_column, settings_attr) -- mirrors src/services/retention.py's
# _RETENTION_TARGETS so the evidence always matches what the job enforces.
_RETENTION_TARGETS: tuple[tuple[str, str, str], ...] = (
    ("logs", "time", "logs_retention_days"),
    ("alerts", "time", "alerts_retention_days"),
    ("audit_logs", "timestamp", "audit_retention_days"),
    ("audit_log", "created_at", "audit_retention_days"),
    ("correlation_matches", "created_at", "correlation_retention_days"),
    ("ai_usage", "created_at", "ai_usage_retention_days"),
)


async def retention_policy_evidence(as_of: datetime | None = None) -> dict:
    """The retention policy as an exportable evidence document."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)

    configured = []
    for table, time_col, attr in _RETENTION_TARGETS:
        days = int(getattr(settings, attr))
        configured.append(
            {
                "table": table,
                "window_days": days,
                "window_human": "keep forever" if days <= 0 else f"{days} days",
                "time_column": time_col,
                "enforced_by": "src/services/retention.py hourly sweep (batched deletes)",
                "note": "0 = keep forever (documented pre-retention behaviour)"
                if days <= 0
                else None,
            }
        )

    engine = await _timescaledb_policy_state()
    return {
        "document": {
            "kind": "retention_policy_evidence",
            "version": 1,
            "generated_at": as_of.isoformat(),
        },
        "configured": configured,
        "engine": engine,
        "compliance_note": (
            "the M-Trends 2026 dwell-time data puts single-source retention "
            ">= 1 year at the industry bar; this deployment's windows are "
            "operator-configured and reported here AS CONFIGURED -- tune "
            "them per the regime you answer to"
        ),
    }


async def _timescaledb_policy_state() -> dict:
    """TimescaleDB policy state probe -- fail-closed.

    Returns {"timescaledb": bool, "policies": [...]} -- on vanilla
    PostgreSQL (extension unavailable) the honest answer is
    {"timescaledb": False, "policies": [], "note": ...}.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        try:
            rows = await conn.fetch(
                """
                SELECT proc_name, schedule_interval, config, job_id
                FROM timescaledb_information.jobs
                WHERE proc_name IN ('policy_compression', 'policy_retention')
                ORDER BY proc_name
                """
            )
        except Exception as e:
            log.info("timescale_probe_unavailable", error=str(e))
            return {
                "timescaledb": False,
                "policies": [],
                "note": (
                    "TimescaleDB policies not present (vanilla PostgreSQL or "
                    "unavailable extension) -- the app-level hourly sweep is "
                    "the retention mechanism in this deployment"
                ),
            }
        return {
            "timescaledb": True,
            "policies": [
                {
                    "job_id": r["job_id"],
                    "procedure": r["proc_name"],
                    "schedule_interval": str(r["schedule_interval"]),
                    "config": _parse_ts_config(r["config"]),
                }
                for r in rows
            ],
        }


def _parse_ts_config(config) -> dict:
    """TimescaleDB 2.30 job config arrives as a JSON-ish string."""
    import json

    if isinstance(config, dict):
        return config
    try:
        parsed = json.loads(config)
        return parsed if isinstance(parsed, dict) else {"raw": str(config)}
    except (TypeError, ValueError):
        return {"raw": str(config)}
