#!/usr/bin/env python3
"""Refresh demo-data timestamps so the demo always shows recent activity.

WHY THIS EXISTS
---------------
scripts/seed_demo_data.py generates timestamps relative to "now" AT SEED TIME
(logs now-1..2880min, alerts now-1..48h, cases now-6..72h), and the
entrypoint only seeds when the alerts table is EMPTY. So every spin-up after
the first reuses the original snapshot — and within ~24-48h of wall-clock
time the data ages out of every dashboard time window. The demo then LOOKS
broken (empty Log Viewer, stale Overview) while the API is perfectly healthy.

This script shifts every demo timestamp by ONE interval —
    delta = (now - buffer) - max(logs.time, alerts.time)
— so the newest attack event lands `--buffer-minutes` (default 10) before
now and ALL relative offsets between events, cases, notes and IOC
seen-windows are preserved exactly. The attack story, case timelines and
correlation relationships stay intact; the whole clock just slides forward.

Not touched: siem_users, rules, alert_suppressions, audit_log / audit_logs
(append-only trail), schema objects. Idempotent: if the anchor is already
fresher than --fresh-threshold-minutes (default 60), the script exits 0
without writing.

Run inside the stack (has settings + network):
    docker compose exec api python -m scripts.refresh_demo_timestamps
    make demo-refresh          # same thing, from the repo root
Dry run (no writes):
    docker compose exec api python -m scripts.refresh_demo_timestamps --dry-run

See docs/DEMO.md (section "Demo data freshness") for the full sequence.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone

import asyncpg

from src.config.settings import settings

# ────────────────────────────────────────────────────────────────
# What gets shifted — ONE delta across ALL of these so every
# cross-table relationship (alert ↔ log ↔ case ↔ IOC window) survives.
# audit_log / audit_logs / siem_users / rules / alert_suppressions are
# deliberately ABSENT: the audit trail is append-only truth, user and
# rule timestamps are operational, not demo-set-dressing.
# ────────────────────────────────────────────────────────────────
TABLE_COLUMNS: list[tuple[str, str]] = [
    ("logs", "time"),
    ("logs", "ingested_at"),
    ("alerts", "time"),
    ("alerts", "created_at"),
    ("alerts", "updated_at"),
    ("alerts", "resolved_at"),
    ("cases", "created_at"),
    ("cases", "updated_at"),
    ("cases", "resolved_at"),
    ("correlation_matches", "created_at"),
    ("threat_intel", "fetched_at"),
    ("threat_intel", "first_seen"),
    ("threat_intel", "last_seen"),
    ("ai_usage", "created_at"),
]

# cases.notes is a JSON array of {text, author, timestamp}; the embedded
# ISO timestamps are shifted too (alerts.notes is "[]" in the seed — no-op).
NOTES_TABLE_COLUMN = ("cases", "notes")

IDENTIFIER_OK = set("abcdefghijklmnopqrstuvwxyz_")


def compute_delta_seconds(anchor_max: datetime, now: datetime, buffer_minutes: int) -> float:
    """Seconds to shift so anchor_max lands buffer_minutes before now.

    Pure function — unit-tested. Negative input (anchor in the future) yields
    a negative delta, which is still correct: the clock slides backward.
    """
    target = now - timedelta(minutes=buffer_minutes)
    return (target - anchor_max).total_seconds()


def shift_iso_timestamps_in_json(notes_text: str | None, delta: timedelta) -> str | None:
    """Shift every `timestamp` field inside a JSON array of note objects.

    Pure function — unit-tested. Returns the input unchanged when it is not
    a JSON array (e.g. the seed's `[]` stays `[]`, plain strings pass through).
    """
    if notes_text is None:
        return None
    try:
        parsed = json.loads(notes_text)
    except (json.JSONDecodeError, TypeError):
        return notes_text
    if not isinstance(parsed, list):
        return notes_text

    shifted: list[dict] = []
    changed = False
    for elem in parsed:
        if isinstance(elem, dict) and isinstance(elem.get("timestamp"), str):
            try:
                ts = datetime.fromisoformat(elem["timestamp"])
            except ValueError:
                shifted.append(elem)
                continue
            new = dict(elem)
            new["timestamp"] = (ts + delta).isoformat()
            shifted.append(new)
            changed = True
        else:
            shifted.append(elem)

    return json.dumps(shifted) if changed else notes_text


def build_shift_sql(table: str, column: str) -> str:
    """Parameterized shift statement. Identifiers come from TABLE_COLUMNS, but
    validate anyway — this script runs against a real DB (property-security
    rule: never interpolate unvalidated identifiers into SQL)."""
    if not (table and column) or not set(table + column) <= IDENTIFIER_OK:
        raise ValueError(f"unsafe identifier: {table}.{column}")
    return f"UPDATE {table} SET {column} = {column} + make_interval(secs => $1)"


async def find_anchor_max(conn: asyncpg.Connection) -> datetime | None:
    """Newest attack-event timestamp across the event-clock anchor tables."""
    row = await conn.fetchrow(
        "SELECT GREATEST("
        "  COALESCE((SELECT max(time) FROM logs), '-infinity'::timestamptz),"
        "  COALESCE((SELECT max(time) FROM alerts), '-infinity'::timestamptz)"
        ") AS anchor"
    )
    value = row["anchor"] if row else None
    if value is None or value == datetime.min.replace(tzinfo=timezone.utc):
        return None
    return value


async def apply_shift(conn: asyncpg.Connection, delta_seconds: float) -> dict[str, int]:
    """Apply the interval shift to every (table, column) pair. Returns row counts."""
    counts: dict[str, int] = {}
    for table, column in TABLE_COLUMNS:
        status = await conn.execute(build_shift_sql(table, column), delta_seconds)
        counts[f"{table}.{column}"] = int(status.split()[-1]) if status else 0
    return counts


async def shift_case_notes(conn: asyncpg.Connection, delta_seconds: float) -> int:
    """Shift timestamps embedded in cases.notes JSON. Returns rows updated."""
    delta = timedelta(seconds=delta_seconds)
    rows = await conn.fetch("SELECT id, notes FROM cases")
    updated = 0
    for row in rows:
        new_notes = shift_iso_timestamps_in_json(row["notes"], delta)
        if new_notes is not None and new_notes != row["notes"]:
            await conn.execute(
                "UPDATE cases SET notes = $1 WHERE id = $2", new_notes, row["id"]
            )
            updated += 1
    return updated


async def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--buffer-minutes",
        type=int,
        default=10,
        help="Newest event lands this many minutes before now (default 10).",
    )
    parser.add_argument(
        "--fresh-threshold-minutes",
        type=int,
        default=60,
        help="If the newest event is already younger than this, do nothing (default 60).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan and shift without writing.",
    )
    args = parser.parse_args(argv)

    dsn = settings.database_url.replace("+asyncpg", "")
    conn = await asyncpg.connect(dsn)
    try:
        anchor = await find_anchor_max(conn)
        if anchor is None:
            print("⏩  No demo data found (logs and alerts empty) — nothing to refresh.")
            print("    Run the seed first: docs/DEMO.md § Demo data freshness.")
            return 1

        now = datetime.now(tz=timezone.utc)
        age_minutes = (now - anchor).total_seconds() / 60
        delta_seconds = compute_delta_seconds(anchor, now, args.buffer_minutes)

        if age_minutes < args.fresh_threshold_minutes:
            newest = f"{age_minutes:.0f} min ago"
            print(f"✅  Demo data is already fresh (newest event {newest}). Nothing to do.")
            print("    Use --fresh-threshold-minutes 0 to force a refresh anyway.")
            return 0

        print("clock before :", anchor.isoformat())
        print("clock after  :", (anchor + timedelta(seconds=delta_seconds)).isoformat())
        print(f"shift        : {delta_seconds / 3600:+.2f} h ({delta_seconds:+.0f} s)")

        if args.dry_run:
            print("dry run      : no writes performed.")
            return 0

        counts = await apply_shift(conn, delta_seconds)
        notes_rows = await shift_case_notes(conn, delta_seconds)
        total = sum(counts.values())
        print(f"\n✅  Shifted {total} timestamp columns across {len(counts)} pairs "
              f"(+{notes_rows} cases with embedded note timestamps).")
        return 0
    finally:
        await conn.close()


def main() -> None:
    raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()
