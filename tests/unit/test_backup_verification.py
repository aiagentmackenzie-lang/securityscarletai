"""SS-044: backup "verified" must mean rows, not dump TOC entries.

`pg_restore --list | grep -c "TABLE DATA"` proves the dump carries a data
section for a table — not that rows exist, and not that they come back. The
weekly restore test then counted *tables*, so an empty or half-populated
source produced a green "verified" backup.

These tests exercise the comparison logic and the CLI contract; the shell side
(recording source counts at dump time, reading them back from the restored
database) is pinned in test_local_prod_ops.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.verify_backup_rows import (
    DEFAULT_TABLES,
    evaluate_row_counts,
    parse_counts,
    parse_tables,
)

_repo = Path(__file__).resolve().parents[2]
_SCRIPT = _repo / "scripts" / "verify_backup_rows.py"


class TestEvaluateRowCounts:
    def test_matching_counts_pass(self):
        result = evaluate_row_counts({"logs": 100, "alerts": 5}, {"logs": 100, "alerts": 5})
        assert result.ok
        assert result.problems == []

    def test_restored_zero_when_source_had_rows_fails(self):
        """The defect: the TOC gate called this dump 'verified'."""
        result = evaluate_row_counts({"logs": 100, "alerts": 5}, {"logs": 0, "alerts": 0})
        assert not result.ok
        assert any("did not come back" in p for p in result.problems)

    def test_restored_fewer_rows_fails(self):
        result = evaluate_row_counts({"alerts": 50}, {"alerts": 49})
        assert not result.ok
        assert any("rows lost" in p for p in result.problems)

    def test_missing_restored_table_fails(self):
        result = evaluate_row_counts({"cases": 3}, {})
        assert not result.ok

    def test_more_rows_than_source_is_allowed(self):
        """The source is live; rows can arrive after the dump snapshot."""
        result = evaluate_row_counts({"logs": 100}, {"logs": 130})
        assert result.ok
        assert any("acceptable" in n for n in result.notes)

    def test_empty_source_is_reported_not_silently_green(self):
        result = evaluate_row_counts({"logs": 0, "alerts": 0}, {"logs": 0, "alerts": 0})
        assert result.ok
        assert any("schema only" in n for n in result.notes)

    def test_default_table_set_is_the_high_value_set(self):
        assert set(DEFAULT_TABLES) == {"logs", "alerts", "cases", "audit_log", "audit_logs"}


class TestParseHelpers:
    def test_parse_counts_ignores_psql_noise(self):
        text = "logs=1523\nalerts=42\n\nNOTICE something=notanumber\n"
        assert parse_counts(text) == {"logs": 1523, "alerts": 42}

    def test_parse_tables_accepts_spaces_and_commas(self):
        assert parse_tables("logs, alerts cases") == ("logs", "alerts", "cases")

    def test_parse_tables_defaults(self):
        assert parse_tables("") == DEFAULT_TABLES
        assert parse_tables(None) == DEFAULT_TABLES


class TestCli:
    def _run(self, tmp_path: Path, expected: dict, actual: dict) -> subprocess.CompletedProcess:
        e = tmp_path / "counts.json"
        a = tmp_path / "restored.json"
        e.write_text(json.dumps(expected))
        a.write_text(json.dumps(actual))
        return subprocess.run(  # noqa: S603 — repo-owned script, pinned interpreter
            [sys.executable, str(_SCRIPT), "--expected", str(e), "--actual", str(a)],
            capture_output=True,
            text=True,
        )

    def test_cli_passes_on_equal_counts(self, tmp_path):
        proc = self._run(tmp_path, {"logs": 10}, {"logs": 10})
        assert proc.returncode == 0, proc.stderr
        assert "PASS" in proc.stdout

    def test_cli_fails_on_zero_restore(self, tmp_path):
        proc = self._run(tmp_path, {"logs": 10}, {"logs": 0})
        assert proc.returncode == 1
        assert "did not come back" in proc.stderr

    def test_cli_usage_error_when_counts_missing(self, tmp_path):
        proc = subprocess.run(  # noqa: S603 — repo-owned script
            [
                sys.executable,
                str(_SCRIPT),
                "--expected",
                "/nonexistent",
                "--actual",
                "/nonexistent",
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 2


@pytest.mark.parametrize("table", ["logs", "alerts", "cases", "audit_log", "audit_logs"])
def test_every_default_table_is_individually_checked(table):
    result = evaluate_row_counts({table: 1}, {table: 0})
    assert not result.ok
    assert any(table in p for p in result.problems)
