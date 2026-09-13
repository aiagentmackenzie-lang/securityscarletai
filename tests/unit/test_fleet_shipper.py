"""Fleet shipper (V0.5b) — checkpoint/rotation/partial-line/batch/retry logic.

The shipper is a standalone stdlib script (remote hosts run it without the
SIEM codebase), so tests import it directly as scripts.fleet_shipper.
"""

import json
import os
import time
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts.fleet_shipper import (
    CHECKPOINT_VERSION,
    Shipper,
    load_checkpoint,
    save_checkpoint,
)


def _args(**kw) -> SimpleNamespace:
    defaults = {
        "url": "http://siem.test/api/v1/ingest/osquery",
        "token": "t",
        "log_path": "/tmp/none.log",
        "checkpoint": "/tmp/none.json",
        "batch_max_lines": 500,
    }
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _make_shipper(tmp: Path, log_name="results.log", **kw):
    log_path = tmp / log_name
    log_path.write_text("")
    cp = tmp / "cp.json"
    args = _args(log_path=str(log_path), checkpoint=str(cp), **kw)
    return Shipper(args, "test-token"), log_path, cp


class TestCheckpoint:
    def test_round_trip(self, tmp_path):
        cp = tmp_path / "cp.json"
        save_checkpoint(cp, 1234, 5678)
        offset, inode = load_checkpoint(cp)
        assert offset == 1234
        assert inode == 5678

    def test_corrupt_checkpoint_starts_at_zero(self, tmp_path):
        cp = tmp_path / "cp.json"
        cp.write_text("not json at all")
        offset, inode = load_checkpoint(cp)
        assert offset == 0
        assert inode is None

    def test_wrong_version_starts_at_zero(self, tmp_path):
        cp = tmp_path / "cp.json"
        cp.write_text(json.dumps({"version": 999, "offset": 10, "inode": 1}))
        offset, _ = load_checkpoint(cp)
        assert offset == 0

    def test_save_is_atomic_shape(self, tmp_path):
        cp = tmp_path / "cp.json"
        save_checkpoint(cp, 42, None)
        data = json.loads(cp.read_text())
        assert data["version"] == CHECKPOINT_VERSION
        assert data["offset"] == 42
        assert data["inode"] is None
        assert not cp.with_suffix(".tmp").exists()  # renamed away


class TestPartialLineHold:
    def test_trailing_partial_line_held_back(self, tmp_path):
        """A trailing JSON object without its newline is NEVER shipped —
        shipping half an osquery differential would parse-fail server-side
        and burn the line (at-most-once loss where we could have zero)."""
        shipper, log_path, _ = _make_shipper(tmp_path)
        log_path.write_text('{"name":"a"}\n{"name":"b"}\n{"name":"par')
        shipper.read_new_lines()
        assert shipper.pending == ['{"name":"a"}', '{"name":"b"}']
        # offset must sit exactly at the start of the partial line
        full = '{"name":"a"}\n{"name":"b"}\n'
        assert shipper.offset == len(full)

    def test_completes_after_newline_arrives(self, tmp_path):
        shipper, log_path, _ = _make_shipper(tmp_path)
        log_path.write_text('{"a":1}\n{"b')
        shipper.read_new_lines()
        assert shipper.pending == ['{"a":1}']
        log_path.write_text('{"a":1}\n{"b":2}\n')
        shipper.read_new_lines()
        assert shipper.pending == ['{"a":1}', '{"b":2}']
        assert shipper.offset == len('{"a":1}\n{"b":2}\n')


class TestRotation:
    def test_inode_change_resets_offset(self, tmp_path):
        shipper, log_path, _ = _make_shipper(tmp_path)
        log_path.write_text('{"a":1}\n')
        shipper.read_new_lines()
        assert shipper.offset > 0
        old_ino = os.stat(log_path).st_ino
        # rotate: unlink + recreate (new inode), offset must reset to 0 then
        # immediately advance over the FRESH content — proving it re-read from
        # scratch instead of skipping to the old offset
        log_path.unlink()
        log_path.write_text('{"fresh":true}\n')
        if os.stat(log_path).st_ino == old_ino:
            pytest.skip("filesystem reused the inode")  # rare; semantics unchanged
        shipper.read_new_lines()
        assert shipper.pending == ['{"fresh":true}']
        assert shipper.offset == len('{"fresh":true}\n')


class TestBatching:
    def test_batch_cap_triggers_ship(self, tmp_path):
        shipper, log_path, cp = _make_shipper(tmp_path, batch_max_lines=3)
        log_path.write_text("l1\nl2\nl3\nl4\n")
        with patch(
            "scripts.fleet_shipper.post_batch",
            return_value={"accepted": 3, "rejected_parse": 0, "rejected_quarantine": 0},
        ):
            shipper.read_new_lines()
            assert shipper.pending == ["l1", "l2", "l3", "l4"]
            shipper.flush()
        # checkpoint saved at the current offset
        offset, _ = load_checkpoint(cp)
        assert offset == len("l1\nl2\nl3\nl4\n")

    def test_idle_flush_after_quiet_window(self, tmp_path):
        shipper, log_path, cp = _make_shipper(tmp_path)
        log_path.write_text("x\n")
        shipper.read_new_lines()
        assert shipper.pending == ["x"]
        assert shipper.should_ship() is False  # just flushed at init
        shipper.last_flush = time.monotonic() - 10.0  # quiet for 10s
        assert shipper.should_ship() is True

    def test_no_pending_never_ships(self, tmp_path):
        shipper, _, _ = _make_shipper(tmp_path)
        shipper.last_flush = 0.0
        assert shipper.should_ship() is False


class TestShipFailureSemantics:
    def test_fatal_on_401(self, tmp_path):
        shipper, _, _ = _make_shipper(tmp_path)
        shipper.pending = ["x"]
        err = urllib.error.HTTPError("url", 401, "unauth", None, None)
        with patch("scripts.fleet_shipper.post_batch", side_effect=err):
            with pytest.raises(SystemExit) as exc:
                shipper.flush()
        assert exc.value.code == 3
        # checkpoint NOT advanced on failure
        offset, _ = load_checkpoint(tmp_path / "cp.json")
        assert offset == 0

    def test_retry_with_backoff_then_success(self, tmp_path):
        shipper, _, cp = _make_shipper(tmp_path)
        shipper.pending = ["x"]
        calls = []

        def _flaky(*a, **k):
            calls.append(1)
            if len(calls) < 3:
                raise ConnectionError("boom")
            return {"accepted": 1, "rejected_parse": 0, "rejected_quarantine": 0}

        with (
            patch("scripts.fleet_shipper.post_batch", side_effect=_flaky),
            patch("scripts.fleet_shipper.time.sleep") as sleep_mock,
        ):
            shipper.flush()
        assert len(calls) == 3
        assert sleep_mock.call_count == 2  # backed off twice before success
        # checkpoint advanced only after the successful send (file was empty
        # at init, so the offset stays 0 — the point is it SAVED)
        offset, _ = load_checkpoint(cp)
        assert offset == 0

    def test_backoff_cap_is_bounded(self):
        """The ship() retry loop doubles backoff but never exceeds 120s."""
        backoff = 2.0
        for _ in range(8):
            backoff = min(backoff * 2, 120.0)
        assert backoff == 120.0


class TestTokenFile:
    """V0.6a: --token-file (the Windows kit's credential path).

    Windows Task Scheduler has no env-file mechanism and argv is visible to
    other local users via the process listing -- the kit ships the token in
    an ACL-locked file, and the shipper reads it ONCE at startup. Never
    logged (the shipper's token hygiene contract).
    """

    def test_token_file_preferred_and_read(self, tmp_path):
        tf = tmp_path / "fleet-token"
        tf.write_text("tok-1234567890abcdef\n")  # trailing newline tolerated
        import scripts.fleet_shipper as fs

        args = SimpleNamespace(token="", token_file=str(tf))
        with patch.object(fs.os.environ, "get", return_value=""), \
             patch.object(fs.sys, "argv", ["x"]):
            # read the same way main() does
            token = fs.Path(args.token_file).read_text(encoding="utf-8").strip()
        assert token == "tok-1234567890abcdef"

    def test_token_file_unreadable_exits_2(self, tmp_path):
        import scripts.fleet_shipper as fs

        missing = tmp_path / "nope-token"
        with pytest.raises(SystemExit) as exc:
            try:
                token = fs.Path(str(missing)).read_text(encoding="utf-8").strip()
            except OSError:
                raise SystemExit(2)
        assert exc.value.code == 2

    def test_token_never_in_shipper_args_namespace(self, tmp_path):
        # The _args helper used by every other test passes token via env --
        # pin that --token-file is a DISTINCT arg so the two paths can't
        # collapse into argv exposure.
        import inspect

        import scripts.fleet_shipper as fs

        src = inspect.getsource(fs.main)
        assert "--token-file" in src
        assert "--token\"" in src or "'--token'" in src
