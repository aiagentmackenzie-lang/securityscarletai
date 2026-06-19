"""
Log viewer API endpoints.

Provides REST access to ingested logs for the dashboard.
"""

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from src.api.auth import get_current_user
from src.config.logging import get_logger
from src.db.connection import get_pool

router = APIRouter(tags=["logs"], prefix="/logs")
log = get_logger("api.logs")


@router.get("")
async def list_logs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    category: Optional[str] = None,
    host: Optional[str] = None,
    time_minutes: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    """Fetch recent logs with optional filtering.

    Args:
        limit: Maximum number of log entries to return (1-500).
        offset: Number of entries to skip.
        category: Filter by event_category (e.g., 'authentication', 'network').
        host: Filter by host_name (substring match).
        time_minutes: Only return logs from the last N minutes.
    """
    pool = await get_pool()

    conditions = []
    params: list[Any] = []
    idx = 1

    if category:
        conditions.append(f"event_category = ${idx}")
        params.append(category)
        idx += 1

    if host:
        conditions.append(f"host_name ILIKE ${idx}")
        params.append(f"%{host}%")
        idx += 1

    if time_minutes:
        # C-01 fix: Validate and inline safely — int() cast prevents injection;
        # PostgreSQL doesn't support parameterized INTERVAL literals.
        safe_minutes = int(time_minutes)
        conditions.append(f"time > NOW() - INTERVAL '{safe_minutes} minutes'")

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    query = f"""
        SELECT
            time, host_name, host_ip, source,
            event_category, event_type, event_action,
            user_name, process_name, process_cmdline, process_path, process_pid,
            source_ip, destination_ip, destination_port,
            file_path, file_hash,
            raw_data, normalized, enrichment, ingested_at
        FROM logs
        {where}
        ORDER BY time DESC
        LIMIT ${idx} OFFSET ${idx + 1}
    """
    params.extend([limit, offset])

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    results = []
    for r in rows:
        d = dict(r)
        # Serialize datetime and inet fields for JSON
        for dt_field in ("time", "ingested_at"):
            if d.get(dt_field) and hasattr(d[dt_field], "isoformat"):
                d[dt_field] = d[dt_field].isoformat()
        for inet_field in ("host_ip", "source_ip", "destination_ip"):
            if d.get(inet_field) and not isinstance(d[inet_field], str):
                d[inet_field] = str(d[inet_field])
        results.append(d)

    log.info("logs_fetched", count=len(results), user=str(user))
    return results
