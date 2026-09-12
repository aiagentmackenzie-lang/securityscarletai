#!/usr/bin/env python3
"""SecurityScarletAI fleet shipper (V0.5b "Fleet & Scale", roadmap group C).

Standalone remote-host agent: tails a local osquery results log and POSTs
the RAW differential lines to the SIEM's /ingest/osquery endpoint in
batches. Deliberately dumb — parsing, ECS mapping, and the closed event
vocabulary live server-side, so this script carries zero SIEM logic.

Auth: a per-host fleet enrollment token (admin enrolls via POST
/api/v1/fleet/enroll; the plaintext is shown ONCE). The token is HOST-BOUND
server-side: only events for the enrolled host pass. The token is read
from --token or the SCARLETAI_FLEET_TOKEN environment variable and is
NEVER logged.

Delivery semantics (honest, documented): the checkpoint advances ONLY on a
2xx response, so SIEM outages re-send unacked batches — at-least-once
DELIVERY with at-most-once loss if the shipper dies between read and send
(the same documented bound as the local FileShipper). Parse failures are
dropped SERVER-side (the response reports rejected_parse counts).

Usage:
  python3 fleet_shipper.py \
      --url https://siem.example.com/api/v1/ingest/osquery \
      --token "$SCARLETAI_FLEET_TOKEN" \
      --log-path /var/log/osquery/osqueryd.results.log

Run it under launchd/systemd (templates in deploy/).
"""

# Annotations are strings under the future import below, so the modern
# signatures (tuple[int, int | None]) stay compatible with the system
# python3 on older fleet hosts (macOS ships 3.9; the shipper targets 3.8+).
# Live-fire finding 2026-09-12: a launchd agent died on this exact TypeError
# at import time without it.
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

POLL_INTERVAL_S = 1.0
IDLE_FLUSH_S = 5.0
BATCH_MAX_BYTES = 4 * 1024 * 1024  # 4 MB per POST
BACKOFF_BASE_S = 2.0
BACKOFF_MAX_S = 120.0
CHECKPOINT_VERSION = 1


def load_checkpoint(path: Path) -> tuple[int, int | None]:
    """Returns (byte_offset, inode). Corrupt/absent checkpoint = 0 (honest:
    re-reading a few lines beats silently losing them)."""
    try:
        data = json.loads(path.read_text())
        if data.get("version") != CHECKPOINT_VERSION:
            return 0, None
        return int(data["offset"]), data.get("inode")
    except Exception:
        return 0, None


def save_checkpoint(path: Path, offset: int, inode: int | None) -> None:
    """Atomic write (tmp + rename) — a torn checkpoint must not ship gaps."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"version": CHECKPOINT_VERSION, "offset": offset, "inode": inode}))
    os.replace(tmp, path)


def get_inode(path: Path) -> int | None:
    try:
        return os.stat(path).st_ino
    except OSError:
        return None


def post_batch(url: str, token: str, lines: list[str], timeout_s: float = 30.0) -> dict:
    """POST one batch. Returns the response JSON. Raises on failure.

    Scheme allowlist (S310): only https/http — never file: or custom schemes.
    """
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"refusing non-HTTP(S) SIEM url: {url.split(':')[0]}:")
    body = json.dumps({"lines": lines}).encode("utf-8")
    # S310: scheme allowlisted above (https/http only) -- the audit fix IS
    # the runtime check; ruff cannot see it.
    req = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "scarletai-fleet-shipper/0.5",
        },
        method="POST",
    )
    # S310 can't see the https/http allowlist enforced above --
    # scheme validation IS the audit fix.
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


class Shipper:
    def __init__(self, args, token: str):
        self.args = args
        self.token = token
        self.log_path = Path(args.log_path)
        self.checkpoint_path = Path(args.checkpoint)
        self.offset, self.inode = load_checkpoint(self.checkpoint_path)
        self.pending: list[str] = []
        self.pending_bytes = 0
        self.last_flush = time.monotonic()
        self.backoff_s = BACKOFF_BASE_S

    # ── read side ────────────────────────────────────────────────

    def read_new_lines(self) -> None:
        """Read complete lines past the checkpoint into pending. The offset
        only advances over COMPLETE lines (a trailing partial line waits for
        its newline — never ship half a JSON object)."""
        try:
            cur_inode = get_inode(self.log_path)
            if cur_inode is not None and self.inode is not None and cur_inode != self.inode:
                print("fleet_shipper: rotation detected, restarting at 0", file=sys.stderr)
                self.offset, self.inode = 0, cur_inode
                self.pending, self.pending_bytes = [], 0
            size = self.log_path.stat().st_size
            if size <= self.offset:
                return
            with self.log_path.open("rb") as f:
                f.seek(self.offset)
                chunk = f.read()
            if not chunk:
                return
            text = chunk.decode("utf-8", errors="replace")
            if not text.endswith("\n"):
                # hold the trailing partial line: only consume up to its start
                cut = text.rfind("\n")
                if cut == -1:
                    return
                text = text[: cut + 1]
            for line in text.splitlines():
                if line.strip():
                    self.pending.append(line)
                    self.pending_bytes += len(line.encode("utf-8")) + 1
            self.offset += len(text.encode("utf-8"))
            self.inode = get_inode(self.log_path)
        except FileNotFoundError:
            return
        except Exception as e:  # noqa: BLE001 — never crash the tail loop
            print(f"fleet_shipper: read error: {e}", file=sys.stderr)

    # ── ship side ────────────────────────────────────────────────

    def should_ship(self) -> bool:
        if not self.pending:
            return False
        if len(self.pending) >= self.args.batch_max_lines:
            return True
        if self.pending_bytes >= BATCH_MAX_BYTES:
            return True
        return (time.monotonic() - self.last_flush) >= IDLE_FLUSH_S

    def ship(self) -> None:
        while True:
            try:
                resp = post_batch(self.args.url, self.token, self.pending)
                print(
                    "fleet_shipper: shipped {} lines (accepted={} parse_rejected={} "
                    "quarantine_rejected={})".format(
                        len(self.pending),
                        resp.get("accepted", 0),
                        resp.get("rejected_parse", 0),
                        resp.get("rejected_quarantine", 0),
                    ),
                    file=sys.stderr,
                )
                self.last_flush = time.monotonic()
                self.backoff_s = BACKOFF_BASE_S
                return
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    # auth/binding failures are FATAL: retrying cannot fix a
                    # revoked token and hammering the SIEM is hostile.
                    print(
                        f"fleet_shipper: FATAL auth failure {e.code} — check "
                        "enrollment/revocation; stopping (checkpoint NOT advanced)",
                        file=sys.stderr,
                    )
                    sys.exit(3)
                print(
                    f"fleet_shipper: HTTP {e.code}, backing off {self.backoff_s:.0f}s",
                    file=sys.stderr,
                )
            except Exception as e:  # noqa: BLE001 — network errors: backoff, retry
                print(
                    f"fleet_shipper: ship error: {e}, backing off {self.backoff_s:.0f}s",
                    file=sys.stderr,
                )
            time.sleep(self.backoff_s)
            self.backoff_s = min(self.backoff_s * 2, BACKOFF_MAX_S)

    def flush(self) -> None:
        if not self.pending:
            return
        self.ship()
        self.pending, self.pending_bytes = [], 0
        save_checkpoint(self.checkpoint_path, self.offset, self.inode)

    # ── main loop ────────────────────────────────────────────────

    def run(self) -> None:
        print(
            f"fleet_shipper: tailing {self.log_path} from offset {self.offset}",
            file=sys.stderr,
        )
        while True:
            self.read_new_lines()
            if self.should_ship():
                self.flush()
            time.sleep(POLL_INTERVAL_S)


def main() -> None:
    p = argparse.ArgumentParser(description="SecurityScarletAI fleet shipper")
    p.add_argument("--url", required=True, help="SIEM /api/v1/ingest/osquery URL")
    p.add_argument(
        "--token", default="", help="fleet enrollment token (or env SCARLETAI_FLEET_TOKEN)"
    )
    p.add_argument("--log-path", required=True, help="osquery results log to tail")
    p.add_argument("--checkpoint", default="/var/tmp/scarletai_fleet_shipper_checkpoint.json")
    p.add_argument("--batch-max-lines", type=int, default=500)
    args = p.parse_args()
    if args.batch_max_lines > 2000:
        print("fleet_shipper: --batch-max-lines capped to 2000 (server cap)", file=sys.stderr)
        args.batch_max_lines = 2000

    token = args.token or os.environ.get("SCARLETAI_FLEET_TOKEN", "")
    if not token:
        print("fleet_shipper: no token (--token or SCARLETAI_FLEET_TOKEN)", file=sys.stderr)
        sys.exit(2)
    try:
        Shipper(args, token).run()
    except KeyboardInterrupt:
        print("fleet_shipper: stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
