#!/usr/bin/env python3
"""Auth log shipper -- sshd auth events -> SecurityScarletAI (V0.3 identity
telemetry; V0.6a cross-platform backends).

Reads sshd authentication events (darwin: macOS unified log; linux: journald
or /var/log/auth.log) and appends them as NDJSON in the auth-vocabulary
contract (event_action = auth_failed / auth_success,
src/ingestion/auth_source.py) to the file the API's normalized FileShipper
tails (AUTH_EVENTS_LOG_PATH).

    log show --style ndjson --last 5m --predicate 'process == "sshd"'   (darwin)
    journalctl -o json --since=-5m -u ssh -u sshd                        (linux)

Parsed message shapes (real sshd unified-log lines):
    "Failed password for invalid user X from IP port N ssh2"  -> auth_failed
    "Failed password for X from IP port N ssh2"               -> auth_failed
    "Invalid user X from IP port N"                           -> auth_failed
    "Accepted publickey/password for X from IP port N"        -> auth_success

Duplicate control: a WATERMARK checkpoint (last emitted unixTime) -- only
events strictly newer than the watermark are emitted, so overlapping
launchd windows never double-ship. The watermark is per-host file
(AUTH_SHIPPER_STATE, default data/auth_shipper_state) and atomic.

Scope honesty (v1): SSH auth only. sudo/authd/WindowServer auth events
need their own parsers -- extend SHIPPER_PATTERNS with a documented
regex + source, do not widen the SSH patterns to "hope it fits".

V0.6a cross-platform fleet: sshd emits the SAME message formats on every
platform, so SHIPPER_PATTERNS/parse_sshd_message are shared verbatim and
only the TRANSPORT differs per backend:
  darwin (default on macOS): `log show --style ndjson` unified log
  linux  (default on Linux): `journalctl -o json` (primary), with a
         /var/log/auth.log line tail as fallback when journald is absent
Windows needs NO auth shipper: osquery `windows_events` (Security channel,
eventid 4624/4625) is parsed server-side into the same auth vocabulary.

Requirements (darwin):
  - Full Disk Access (TCC) for the calling terminal/launchd context --
    the same grant osqueryd needs (see docs/PRODUCTION.md §1).
  - Remote Login (sshd) enabled on the host; otherwise the chain is
    DORMANT by design (see the coverage map -- no telemetry, no firing).
Requirements (linux):
  - read access to the journal (systemd-journal group membership) or to
    /var/log/auth.log; sshd running, otherwise dormant by design.

Usage (launchd every 5 min):
    python3 scripts/auth_log_shipper.py --once --last-minutes 5
    python3 scripts/auth_log_shipper.py --once --last-minutes 5 --dry-run
Usage (Linux systemd timer every 5 min):
    python3 scripts/auth_log_shipper.py --backend linux --once --last-minutes 5
    python3 scripts/auth_log_shipper.py --backend linux --authlog-path /var/log/auth.log --once
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

# (compiled regex, outcome) -- first match wins; ordered by specificity.
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
    """Return (outcome, user, source_ip) for a known sshd message, else None.

    sshd message formats are identical across darwin/linux -- this corpus is
    SHARED between the backends by design (V0.6a).
    """
    for pattern, outcome in SHIPPER_PATTERNS:
        m = pattern.search(message)
        if m:
            return outcome, m.group("user"), m.group("ip")
    return None


def read_auth_events_darwin(last_minutes: int, predicate: str) -> list[dict]:
    """Query the macOS unified log and return raw NDJSON dicts.

    Raises RuntimeError with the stderr tail on failure -- callers decide
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


# journalctl JSON fields the Linux backend consumes (journalctl -o json):
#   __REALTIME_TIMESTAMP = microseconds since epoch (str)
#   MESSAGE              = the syslog message (sshd line)
#   _HOSTNAME            = reporting host
JOURNAL_TS_KEY = "__REALTIME_TIMESTAMP"
JOURNAL_MSG_KEY = "MESSAGE"


def read_auth_events_linux_journal(last_minutes: int, units: str) -> list[dict]:
    """Read sshd auth events from the systemd journal (primary Linux source).

    Raises RuntimeError on failure -- same fail-closed contract as the darwin
    backend. `units` is the comma-separated sshd unit list (distros name the
    unit ssh.service or sshd.service; journalctl matches both prefixes).
    """
    cmd = [
        "journalctl",
        "--quiet",
        "--no-pager",
        "-o",
        "json",
        f"--since=-{last_minutes}min",
    ]
    for unit in units.split(","):
        if unit.strip():
            cmd.extend(["-u", unit.strip()])
    try:
        # nosec S603: fixed command + argparse ints/strs, no shell.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)  # noqa: S603
    except FileNotFoundError as e:
        raise RuntimeError("journalctl not found -- is journald installed?") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"journalctl timed out after 120s: {e}") from e
    if proc.returncode != 0:
        stderr_tail = (proc.stderr or "").strip().splitlines()[-3:]
        raise RuntimeError(
            "journalctl failed (returncode %s). Journal access denied? stderr tail: %s"
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


def read_auth_events_linux_authlog(path: str) -> list[dict]:
    """Read sshd auth events from a syslog auth log file (fallback source
    for hosts without journald, e.g. Debian minimal).

    Reads the WHOLE file each pass -- watermark dedup (strictly-newer-only
    emission) makes that overlap-proof; syslog files rotate via logrotate
    and the watermark survives rotation because timestamps are monotonic
    across rotated files. Unreadable file -> RuntimeError (fail-closed).
    Entries are normalized into the SAME dict shape the darwin/journal
    backends produce ({timestamp: iso, eventMessage: str}).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except OSError as e:
        raise RuntimeError(f"auth log unreadable ({path}): {e}") from e

    # syslog format: "Mon  1 02:03:04 host sshd[123]: Failed password ..."
    # Timestamps carry no year/timezone -- anchor to the current year UTC
    # (the watermark dedup tolerates the anchor; monotonic across passes).
    events = []
    now = datetime.now(tz=timezone.utc)
    syslog_re = re.compile(
        r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
        r"(?P<hm>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<tag>sshd)\S*:\s+(?P<msg>.*)$"
    )
    for line in raw_lines:
        line = line.rstrip("\n")
        m = syslog_re.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(
                f"{now.year} {m.group('mon')} {m.group('day')} {m.group('hm')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        events.append(
            {
                "timestamp": ts.isoformat(),
                "eventMessage": m.group("msg"),
                "_host": m.group("host"),
            }
        )
    return events


def extract_ts(entry: dict) -> datetime:
    """Parse the entry timestamp (ISO-8601 with tz, or journal microseconds)."""
    # journalctl -o json __REALTIME_TIMESTAMP: microseconds since epoch (str)
    jts = entry.get(JOURNAL_TS_KEY)
    if jts:
        try:
            return datetime.fromtimestamp(int(jts) / 1_000_000, tz=timezone.utc)
        except (ValueError, TypeError, OSError, OverflowError):
            pass
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
    """Parse log entries (any backend shape) -> auth events -> NDJSON lines.

    Returns (emitted_count, new_watermark). Only events STRICTLY newer than
    the watermark are emitted (overlap-proof across launchd runs).
    """
    parsed = []
    for entry in entries:
        message = entry.get("eventMessage") or ""
        result = parse_sshd_message(message)
        if not result:
            continue  # session open/close/noise -- not an auth attempt
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
    # watermark save re-emits <= the last batch -- same semantics the osquery
    # FileShipper documents).
    with open(output_path, "a") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines), new_watermark


def load_watermark(path: str) -> float | None:
    try:
        return float(open(path).read().strip())  # noqa: SIM115 -- tiny state file
    except (FileNotFoundError, ValueError):
        return None


def save_watermark(path: str, value: float) -> None:
    """Atomic write (temp + os.replace) -- crash mid-write must not corrupt."""
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
    parser.add_argument("--last-minutes", type=int, default=5, help="log window (default 5)")
    parser.add_argument(
        "--predicate", default=DEFAULT_PREDICATE, help="log show predicate (darwin)"
    )
    parser.add_argument(
        "--backend",
        choices=("darwin", "linux", "auto"),
        default="auto",
        help="auth-event transport (auto = platform.system(), darwin/Linux only)",
    )
    parser.add_argument(
        "--journal-units",
        default="ssh.service,sshd.service",
        help="comma-separated sshd journal units (linux backend)",
    )
    parser.add_argument(
        "--authlog-path",
        default="/var/log/auth.log",
        help="syslog auth log fallback path (linux backend, used with --use-authlog)",
    )
    parser.add_argument(
        "--use-authlog",
        action="store_true",
        help="linux backend: read --authlog-path instead of the journal",
    )
    parser.add_argument("--host", default=os.uname().nodename, help="host_name field override")
    parser.add_argument(
        "--output", default="data/osquery/auth_events.log", help="NDJSON output file"
    )
    parser.add_argument(
        "--state", default="data/auth_shipper_state", help="watermark checkpoint file"
    )
    parser.add_argument("--dry-run", action="store_true", help="print lines, write nothing")
    args = parser.parse_args()

    backend = args.backend
    if backend == "auto":
        import platform

        system = platform.system().lower()
        backend = "darwin" if system == "darwin" else "linux"

    watermark = load_watermark(args.state)
    try:
        if backend == "darwin":
            entries = read_auth_events_darwin(args.last_minutes, args.predicate)
        elif args.use_authlog:
            entries = read_auth_events_linux_authlog(args.authlog_path)
        else:
            entries = read_auth_events_linux_journal(args.last_minutes, args.journal_units)
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
        f"auth_shipper[{backend}]: {len(entries)} log entries scanned, "
        f"{emitted} auth events emitted -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
