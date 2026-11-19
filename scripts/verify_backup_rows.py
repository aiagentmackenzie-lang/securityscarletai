#!/usr/bin/env python3
"""Backup data verification — counts rows, not TOC entries (SS-044).

`pg_restore --list | grep -c "TABLE DATA"` proves the dump *carries a data
section* for a table. It says nothing about whether rows exist or whether they
come back. A dump taken from an empty or half-populated source passed
"verified", and the weekly restore test only asserted that the restored
database had >= 10 tables — schema presence, never data.

This module is the comparison half of the row-count gate:

  * ``backup_local.sh`` records per-table row counts from the SOURCE database
    at dump time into ``<dump>.counts.json``.
  * the ``--restore-test`` run reads the same counts from the RESTORED
    throwaway database and calls this script.

Exit codes: 0 = verified, 1 = verification FAILED, 2 = usage error.

Comparison semantics (documented deliberately — the source is live):
  * restored == 0 while the source had rows  -> FAIL (the data did not come back)
  * restored <  source                        -> FAIL (rows were lost)
  * restored >  source                        -> PASS with a note: rows are
    allowed to arrive after the dump snapshot; the backup cannot be newer than
    the source it was taken from.
  * every verified table empty at the source  -> PASS with an ``empty`` warning,
    because that dump only proved schema. It is reported, never silently green.

The default table set is the high-value set: logs, alerts, cases, audit_log,
audit_logs. Override with BACKUP_VERIFY_TABLES (space- or comma-separated).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Mapping

DEFAULT_TABLES: tuple[str, ...] = ("logs", "alerts", "cases", "audit_log", "audit_logs")


@dataclass
class VerificationResult:
    ok: bool
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    rows: list[tuple[str, int, int]] = field(default_factory=list)

    @property
    def all_empty(self) -> bool:
        return all(expected == 0 for _, expected, _ in self.rows)


def evaluate_row_counts(
    expected: Mapping[str, int], actual: Mapping[str, int]
) -> VerificationResult:
    """Compare source vs restored row counts.

    ``expected`` is the source snapshot recorded at dump time, ``actual`` the
    counts read from the restored database. A missing ``actual`` entry is
    treated as 0 — if the table did not restore, that is a failure, not a
    silent skip.
    """
    problems: list[str] = []
    notes: list[str] = []
    rows: list[tuple[str, int, int]] = []

    for table in sorted(expected):
        want = int(expected[table])
        got = int(actual.get(table, 0))
        rows.append((table, want, got))

        if want > 0 and got == 0:
            problems.append(f"{table}: source had {want} rows, restored 0 — data did not come back")
        elif got < want:
            problems.append(f"{table}: source had {want} rows, restored {got} — rows lost")
        elif got > want:
            notes.append(f"{table}: restored {got} > source {want} (live source; acceptable)")

    result = VerificationResult(ok=not problems, problems=problems, notes=notes, rows=rows)
    if result.ok and result.all_empty and rows:
        notes.append("every verified table was empty at the source — this dump proves schema only")
    return result


def parse_counts(text: str) -> dict[str, int]:
    """Parse the ``<table>=<count>`` lines emitted by the shell side."""
    counts: dict[str, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        table, _, value = line.rpartition("=")
        value = value.strip()
        if not value.isdigit():
            continue
        counts[table.strip()] = int(value)
    return counts


def parse_tables(spec: str | None) -> tuple[str, ...]:
    if not spec:
        return DEFAULT_TABLES
    parts = [p.strip() for p in spec.replace(",", " ").split() if p.strip()]
    return tuple(parts) if parts else DEFAULT_TABLES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify restored row counts against the source")
    parser.add_argument("--expected", required=True, help="<dump>.counts.json from the source")
    parser.add_argument("--actual", required=True, help="counts JSON read from the restored DB")
    args = parser.parse_args(argv)

    try:
        with open(args.expected) as fh:
            expected = json.load(fh)
        with open(args.actual) as fh:
            actual = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR backup row verification could not read counts: {exc}", file=sys.stderr)
        return 2

    result = evaluate_row_counts(expected, actual)
    for table, want, got in result.rows:
        print(f"{'FAIL' if (want > 0 and got < want) else 'PASS'} {table} {got}/{want}")
    for note in result.notes:
        print(f"NOTE {note}")
    for problem in result.problems:
        print(f"ERROR {problem}", file=sys.stderr)
    print("BACKUP ROW VERIFICATION: PASS" if result.ok else "BACKUP ROW VERIFICATION: FAIL")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
