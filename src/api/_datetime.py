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


def require_aware(value: datetime, *, field: str) -> datetime:
    """Return `value` if it carries a timezone; raise ValueError otherwise."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            f"{field} must include a timezone offset (e.g. 2026-11-18T12:00:00Z or "
            "+00:00); a naive value would be interpreted in the server's local timezone"
        )
    return value
