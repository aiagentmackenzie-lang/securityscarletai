"""
Data retention — bounded storage for a SIEM (P1-D).

Without retention, `logs`, `alerts`, `audit_logs`, `correlation_matches` and
`ai_usage` grow forever; query performance collapses and there is no ILM /
tiering. This module runs an APScheduler job (hourly by default) that deletes
rows older than env-configured windows in **batched parameterized DELETEs** so
a huge delete never takes a long table lock.

Design notes:
- Every delete is parameterized (`$1` timestamp + `$2` LIMIT via a CTE). No
  string-interpolated user input. The table names are static literals.
- Batched: a CTE selects the IDs to delete, then DELETEs them, capped at
  `retention_batch_size` per iteration. The job loops until the batch returns
  0 rows (or a safety max-iterations cap) so a very large backlog drains
  across several runs without monopolising the event loop.
- `0` retention = keep forever (the pre-retention behaviour) — the job skips
  that table.
- Failures are logged and swallowed: a retention job error must never crash
  the API (the response path is unaffected; the job runs on the scheduler).
- Audit tables: `audit_logs` (HTTP-level) and `audit_log` (action-level) are
  both retained on `audit_retention_days`. NOTE: if `audit_logs` has been
  hardened append-only (REVOKE UPDATE/DELETE — see harden_audit.sql), the app
  role CANNOT delete from it and the retention job will log an error. In that
  case retention of audit_logs must be done by a superuser job (documented in
  DEPLOYMENT.md). The job attempts the delete and reports the outcome honestly.
"""
from typing import Any

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("services.retention")

# (table, time_column, settings_attr). Static literals — never user input.
# `ai_usage` and `audit_log` use created_at; the rest use `time`.
_RETENTION_TARGETS: tuple[tuple[str, str, str], ...] = (
    ("logs", "time", "logs_retention_days"),
    ("alerts", "time", "alerts_retention_days"),
    ("audit_logs", "timestamp", "audit_retention_days"),
    ("audit_log", "created_at", "audit_retention_days"),
    ("correlation_matches", "created_at", "correlation_retention_days"),
    ("ai_usage", "created_at", "ai_usage_retention_days"),
)

# Safety cap so a single job run never loops forever on a pathological backlog.
_MAX_BATCHES_PER_TABLE = 100


async def _delete_old_rows(table: str, time_col: str, cutoff: Any, batch_size: int) -> int:
    """Delete rows older than cutoff from `table`, in batches. Returns total deleted.

    Uses a CTE + LIMIT so each DELETE is bounded and never takes a table-wide
    lock. All values are parameterized; the table/column are static literals
    from _RETENTION_TARGETS (not user input).
    """
    pool = await get_pool()
    total = 0
    async with pool.acquire() as conn:
        for _ in range(_MAX_BATCHES_PER_TABLE):
            # Delete up to batch_size rows older than the cutoff. The CTE
            # selects IDs first so the DELETE is bounded and the planner can
            # use the time index for the selection.
            deleted = await conn.execute(
                f"""
                WITH old AS (
                    SELECT id FROM {table}
                    WHERE {time_col} < $1
                    ORDER BY {time_col}
                    LIMIT $2
                    FOR UPDATE SKIP LOCKED
                )
                DELETE FROM {table}
                WHERE id IN (SELECT id FROM old)
                """,
                cutoff,
                batch_size,
            )
            n = _parse_rowcount(deleted)
            if n <= 0:
                break
            total += n
            if n < batch_size:
                break  # drained this run
    return total


def _parse_rowcount(status: str) -> int:
    """Parse asyncpg's DELETE status string ('DELETE N' or 'DELETE 0')."""
    try:
        return int(str(status).split()[-1])
    except (ValueError, IndexError):
        return 0


async def run_retention_once() -> dict[str, int]:
    """Run one retention sweep across all configured tables.

    Returns a {table: rows_deleted} dict (for logging/tests). Tables with
    retention_days == 0 are skipped (keep forever).
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(tz=timezone.utc)
    results: dict[str, int] = {}
    batch_size = max(1, settings.retention_batch_size)

    for table, time_col, attr in _RETENTION_TARGETS:
        days: int = int(getattr(settings, attr))
        if days <= 0:
            results[table] = -1  # sentinel: retention disabled for this table
            continue
        cutoff = now - timedelta(days=days)
        try:
            deleted = await _delete_old_rows(table, time_col, cutoff, batch_size)
            results[table] = deleted
            if deleted > 0:
                log.info("retention_swept", table=table, deleted=deleted, cutoff=cutoff.isoformat())
        except Exception as e:
            # A retention error must not crash the scheduler/API. Log and move
            # on; the next run retries. Common cause: audit_logs hardened
            # append-only (REVOKE DELETE) — documented in DEPLOYMENT.md.
            log.warning("retention_sweep_failed", table=table, error=str(e))
            results[table] = -2  # sentinel: error

    return results


# ---------------------------------------------------------------------------
# Scheduler wiring (mirrors src/intel/threat_intel.py's pattern)
# ---------------------------------------------------------------------------

_async_scheduler: Any = None


async def start_retention_scheduler() -> None:
    """Start the periodic retention job (every retention_interval_hours)."""
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    global _async_scheduler
    _async_scheduler = AsyncIOScheduler()
    _async_scheduler.add_job(
        run_retention_once,
        trigger=IntervalTrigger(hours=max(1, settings.retention_interval_hours)),
        id="retention_sweep",
        replace_existing=True,
    )
    _async_scheduler.start()
    log.info(
        "retention_scheduler_started",
        interval_hours=settings.retention_interval_hours,
        logs_days=settings.logs_retention_days,
        alerts_days=settings.alerts_retention_days,
        audit_days=settings.audit_retention_days,
    )


async def stop_retention_scheduler() -> None:
    """Stop the retention scheduler."""
    global _async_scheduler
    if _async_scheduler:
        _async_scheduler.shutdown()
        log.info("retention_scheduler_stopped")
