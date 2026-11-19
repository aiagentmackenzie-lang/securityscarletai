"""Datetime boundary helpers (SS-063).

`datetime.fromisoformat("2026-11-18T12:00:00")` returns a NAIVE datetime.
asyncpg binds a naive datetime to `timestamptz` through `.timestamp()`, i.e.
the process-local timezone, so on a host running Europe/London an
analyst-supplied window silently shifted by the UTC offset (the container
posture, UTC, hid it). The API boundary now refuses naive input instead of
guessing.
"""

from __future__ import annotations

from datetime import datetime


def require_aware(value: datetime | str, *, field: str) -> datetime:
    """Return `value` (parsed if a string) if it carries a timezone; raise
    ValueError otherwise."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            f"{field} must include a timezone offset (e.g. 2026-11-18T12:00:00Z or "
            "+00:00); a naive value would be interpreted in the server's local timezone"
        )
    return value


async def aware_query_datetime(value: "datetime | None" = None) -> "datetime | None":
    """FastAPI dependency: a query datetime must carry an offset (SS-063).

    A naive value would be bound to timestamptz in the server's local timezone,
    so the window silently shifts by the host offset (hidden in the UTC
    container posture). 422 instead of a wrong answer.
    """
    from fastapi import HTTPException

    if value is None:
        return None
    try:
        return require_aware(value, field="timestamp filter")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
