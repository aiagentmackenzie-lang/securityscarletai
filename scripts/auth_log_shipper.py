#!/usr/bin/env python3
"""Auth log shipper — macOS unified log → SecurityScarletAI (V0.3 identity telemetry).

Reads sshd authentication events from the macOS unified log and appends
them as NDJSON in the auth-vocabulary contract (event_action =
auth_failed / auth_success, src/ingestion/auth_source.py) to the file the
API's normalized FileShipper tails (AUTH_EVENTS_LOG_PATH).

    log show --style ndjson --last 5m --predicate 'process == "sshd"'

Parsed message shapes (real sshd unified-log lines):
    "Failed password for invalid user X from IP port N ssh2"  → auth_failed
    "Failed password for X from IP port N ssh2"               → auth_failed
    "Invalid user X from IP port N"                           → auth_failed
    "Accepted publickey/password for X from IP port N"        → auth_success

Duplicate control: a WATERMARK checkpoint (last emitted unixTime) — only
events strictly newer than the watermark are emitted, so overlapping
launchd windows never double-ship. The watermark is per-host file
(AUTH_SHIPPER_STATE, default data/auth_shipper_state) and atomic.

Scope honesty (v1): SSH auth only. sudo/authd/WindowServer auth events
need their own parsers — extend SHIPPER_PATTERNS with a documented
regex + source, do not widen the SSH patterns to "hope it fits".

Requirements:
  - Full Disk Access (TCC) for the calling terminal/launchd context —
    the same grant osqueryd needs (see docs/PRODUCTION.md §1).
  - Remote Login (sshd) enabled on the host; otherwise the chain is
    DORMANT by design (see the coverage map — no telemetry, no firing).

Usage (launchd every 5 min):
    python3 scripts/auth_log_shipper.py --once --last-minutes 5
    python3 scripts/auth_log_shipper.py --once --last-minutes 5 --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Make src/ importable when run as a script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config.logging import get_logger  # noqa: E402
from src.ingestion.auth_source import build_auth_event, event_to_shipper_line  # noqa: E402

log = get_logger("auth_shipper")

DEFAULT_PREDICATE = 'process == "sshd"'

# (compiled regex, outcome) — first match wins; ordered by specificity.
SHIPPER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"),
        "failed",
    ),
    (
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
        "failed",
    ),
    (
        re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)"),
        "success",
    ),
]


def parse_sshd_message(message: str) -> tuple[str, str, str] | None:
    """Return (outcome, user, source_ip) for a known sshd message, else None."""
    for pattern, outcome in SHIPPER_PATTERNS:
        m = pattern.search(message)
        if m:
            return outcome, m.group("user"), m.group("ip")
    return None


def read_auth_events(last_minutes: int, predicate: str) -> list[dict]:
    """Query the macOS unified log and return raw NDJSON dicts.

    Raises RuntimeError with the stderr tail on failure — callers decide
    whether that is fatal (the launchd job should keep the machine honest:
    no telemetry, no fake rows).
    """
    cmd = [
        "log",
        "show",
        "--style",
        "ndjson",
        "--last",
        f"{last_minutes}m",
        "--predicate",
        predicate,
    ]
    try:
        # nosec S603: cmd is built from module constants + argparse ints/strs,
        # no shell=True, predicate is a documented operator override.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)  # noqa: S603
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"log show timed out after 120s: {e}") from e
    if proc.returncode != 0:
        stderr_tail = (proc.stderr or "").strip().splitlines()[-3:]
        raise RuntimeError(
            "log show failed (returncode %s). TCC/FDA missing? stderr tail: %s"
            % (proc.returncode, " | ".join(stderr_tail[-2:]))
        )
    events = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning("auth_shipper_bad_ndjson", line_preview=line[:120])
    return events


def extract_ts(entry: dict) -> datetime:
    """Parse the unified-log entry timestamp (ISO-8601 with tz)."""
    ts_raw = entry.get("timestamp")
    if not ts_raw:
        return datetime.now(tz=timezone.utc)
    try:
        return datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(tz=timezone.utc)


def ship_events(
    entries: list[dict],
    host_name: str,
    watermark: float | None,
    output_path: str,
    dry_run: bool = False,
) -> tuple[int, float | None]:
    """Parse unified-log entries → auth events → append NDJSON lines.

    Returns (emitted_count, new_watermark). Only events STRICTLY newer than
    the watermark are emitted (overlap-proof across launchd runs).
    """
    parsed = []
    for entry in entries:
        message = entry.get("eventMessage") or ""
        result = parse_sshd_message(message)
        if not result:
            continue  # session open/close/noise — not an auth attempt
        outcome, user, src_ip = result
        ts = extract_ts(entry)
        unix_ts = ts.timestamp()
        if watermark is not None and unix_ts <= watermark:
            continue  # already shipped in a previous window
        parsed.append((unix_ts, ts, outcome, user, src_ip, message))

    if not parsed:
        return 0, watermark

    parsed.sort(key=lambda x: x[0])
    lines = []
    for _unix, ts, outcome, user, src_ip, message in parsed:
        event = build_auth_event(
            timestamp=ts,
            host_name=host_name,
            outcome=outcome,
            user_name=user,
            source_ip=src_ip,
            raw_message=message,
        )
        lines.append(event_to_shipper_line(event))

    new_watermark = parsed[-1][0]
    if dry_run:
        for ln in lines:
            print(ln)
        return len(lines), new_watermark

    # Append atomically-buffered, then persist the watermark AFTER the file
    # write succeeded (at-least-once ordering: crash between append and
    # watermark save re-emits ≤ the last batch — same semantics the osquery
    # FileShipper documents).
    with open(output_path, "a") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines), new_watermark


def load_watermark(path: str) -> float | None:
    try:
        return float(open(path).read().strip())  # noqa: SIM115 — tiny state file
    except (FileNotFoundError, ValueError):
        return None


def save_watermark(path: str, value: float) -> None:
    """Atomic write (temp + os.replace) — crash mid-write must not corrupt."""
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
        with os.fdopen(fd, "w") as f:
            f.write(str(value))
        os.replace(tmp, path)
    except OSError as e:
        log.error("auth_shipper_watermark_save_failed", error=str(e))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="single pass (launchd mode)")
    parser.add_argument("--last-minutes", type=int, default=5, help="log show window (default 5)")
    parser.add_argument("--predicate", default=DEFAULT_PREDICATE, help="log show predicate")
    parser.add_argument("--host", default=os.uname().nodename, help="host_name field override")
    parser.add_argument(
        "--output", default="data/osquery/auth_events.log", help="NDJSON output file"
    )
    parser.add_argument(
        "--state", default="data/auth_shipper_state", help="watermark checkpoint file"
    )
    parser.add_argument("--dry-run", action="store_true", help="print lines, write nothing")
    args = parser.parse_args()

    watermark = load_watermark(args.state)
    try:
        entries = read_auth_events(args.last_minutes, args.predicate)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    emitted, new_watermark = ship_events(
        entries, args.host, watermark, args.output, dry_run=args.dry_run
    )
    if new_watermark is not None and not args.dry_run:
        save_watermark(args.state, new_watermark)

    print(
        f"auth_shipper: {len(entries)} unified-log entries scanned, "
        f"{emitted} auth events emitted -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
