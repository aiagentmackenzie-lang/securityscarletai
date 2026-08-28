"""Tests for scripts/refresh_demo_timestamps.py (feat/demo-refresh).

Demo seed timestamps are relative to seed time and the entrypoint only seeds
an empty alerts table — so demo data ages out of every dashboard window
within ~48h of the seed. The refresh script shifts all demo timestamps by ONE
interval, preserving relative offsets. These tests cover the pure logic and
the safety rails; the live behavior is verified in docs/DEMO.md's checklist.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from scripts.refresh_demo_timestamps import (
    NOTES_TABLE_COLUMN,
    TABLE_COLUMNS,
    build_shift_sql,
    compute_delta_seconds,
    find_anchor_max,
    shift_case_notes,
    shift_iso_timestamps_in_json,
)

NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


class TestComputeDeltaSeconds:
    def test_stale_data_shifts_forward(self):
        anchor = NOW - timedelta(days=3)
        delta = compute_delta_seconds(anchor, NOW, buffer_minutes=10)
        assert delta == pytest.approx((3 * 24 * 60 - 10) * 60)

    def test_fresh_data_yields_nonpositive_delta(self):
        anchor = NOW - timedelta(minutes=5)
        delta = compute_delta_seconds(anchor, NOW, buffer_minutes=10)
        assert delta < 0  # would move the clock slightly back — gate blocks it

    def test_exact_buffer_target(self):
        anchor = NOW - timedelta(hours=2)
        delta = compute_delta_seconds(anchor, NOW, buffer_minutes=30)
        shifted = anchor + timedelta(seconds=delta)
        assert shifted == NOW - timedelta(minutes=30)


class TestShiftIsoTimestampsInJson:
    def test_shifts_note_timestamps(self):
        base = NOW - timedelta(days=3)
        notes = json.dumps(
            [
                {"text": "Blocked IP", "author": "jsmith", "timestamp": base.isoformat()},
                {"text": "No lateral movement", "author": "jsmith", "timestamp": (base + timedelta(hours=2)).isoformat()},
            ]
        )
        out = shift_iso_timestamps_in_json(notes, timedelta(days=3))
        parsed = json.loads(out)  # type: ignore[arg-type]
        assert parsed[0]["timestamp"] == base.isoformat().replace("2026-08-25", "2026-08-28")
        assert parsed[1]["timestamp"] == (base + timedelta(hours=2) + timedelta(days=3)).isoformat()
        assert parsed[0]["text"] == "Blocked IP"

    def test_preserves_non_timestamp_keys(self):
        notes = json.dumps([{"text": "t", "author": "a", "timestamp": "2026-08-25T07:51:03.417031+00:00"}])
        out = json.loads(shift_iso_timestamps_in_json(notes, timedelta(days=1)))
        assert out[0]["text"] == "t"
        assert out[0]["author"] == "a"
        assert out[0]["timestamp"].startswith("2026-08-26")

    def test_empty_array_passes_through(self):
        assert shift_iso_timestamps_in_json("[]", timedelta(days=1)) == "[]"

    def test_non_array_json_passes_through(self):
        assert shift_iso_timestamps_in_json('{"a": 1}', timedelta(days=1)) == '{"a": 1}'

    def test_invalid_json_passes_through(self):
        assert shift_iso_timestamps_in_json("not json", timedelta(days=1)) == "not json"

    def test_none_passes_through(self):
        assert shift_iso_timestamps_in_json(None, timedelta(days=1)) is None

    def test_bad_timestamp_string_left_alone(self):
        notes = json.dumps([{"text": "t", "timestamp": "not-a-date"}])
        out = json.loads(shift_iso_timestamps_in_json(notes, timedelta(days=1)))
        assert out[0]["timestamp"] == "not-a-date"


class TestBuildShiftSql:
    def test_parameterized_statement(self):
        sql = build_shift_sql("logs", "time")
        assert sql == "UPDATE logs SET time = time + make_interval(secs => $1)"

    def test_rejects_unsafe_identifiers(self):
        with pytest.raises(ValueError):
            build_shift_sql("logs; DROP TABLE users", "time")
        with pytest.raises(ValueError):
            build_shift_sql("logs", "time; DROP TABLE users")
        with pytest.raises(ValueError):
            build_shift_sql("", "time")


class TestScopeSafety:
    """The script must never touch append-only / operational tables."""

    def test_audit_tables_absent(self):
        tables = {t for t, _ in TABLE_COLUMNS}
        assert "audit_log" not in tables
        assert "audit_logs" not in tables

    def test_users_rules_suppressions_absent(self):
        tables = {t for t, _ in TABLE_COLUMNS}
        assert "siem_users" not in tables
        assert "rules" not in tables
        assert "alert_suppressions" not in tables

    def test_expected_demo_pairs_present(self):
        assert ("logs", "time") in TABLE_COLUMNS
        assert ("alerts", "time") in TABLE_COLUMNS
        assert ("cases", "created_at") in TABLE_COLUMNS
        assert ("threat_intel", "last_seen") in TABLE_COLUMNS
        assert NOTES_TABLE_COLUMN == ("cases", "notes")


class TestAgainstFakeConn:
    """Light async coverage with a fake connection (no DB)."""

    @pytest.mark.asyncio
    async def test_find_anchor_max_picks_newest(self):
        class FakeConn:
            async def fetchrow(self, sql):
                return {"anchor": datetime(2026, 8, 25, 8, 8, tzinfo=timezone.utc)}

        anchor = await find_anchor_max(FakeConn())  # type: ignore[arg-type]
        assert anchor == datetime(2026, 8, 25, 8, 8, tzinfo=timezone.utc)

    @pytest.mark.asyncio
    async def test_find_anchor_max_empty_db(self):
        class FakeConn:
            async def fetchrow(self, sql):
                return {"anchor": datetime.min.replace(tzinfo=timezone.utc)}

        assert await find_anchor_max(FakeConn()) is None  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_shift_case_notes_updates_changed_rows(self):
        base = "2026-08-25T07:51:03.417031+00:00"
        notes = json.dumps([{"text": "n", "author": "a", "timestamp": base}])
        other = json.dumps([{"text": "no-timestamp-here"}])

        executed: list[tuple] = []

        class FakeConn:
            async def fetch(self, sql):
                return [
                    {"id": 1, "notes": notes},
                    {"id": 2, "notes": other},
                ]

            async def execute(self, sql, *params):
                executed.append((sql, *params))
                return "UPDATE 1"

        updated = await shift_case_notes(FakeConn(), 86400.0)  # type: ignore[arg-type]
        assert updated == 1
        assert any("UPDATE cases SET notes" in entry[0] for entry in executed)

    @pytest.mark.asyncio
    async def test_apply_shift_runs_every_pair(self):
        from scripts.refresh_demo_timestamps import apply_shift

        calls: list[str] = []

        class FakeConn:
            async def execute(self, sql, *params):
                calls.append(sql)
                return "UPDATE 5"

        counts = await apply_shift(FakeConn(), 3600.0)  # type: ignore[arg-type]
        assert len(calls) == len(TABLE_COLUMNS)
        assert all("$1" not in sql or "make_interval" in sql for sql in calls)
        assert sum(counts.values()) == 5 * len(TABLE_COLUMNS)
