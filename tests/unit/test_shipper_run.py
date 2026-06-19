"""
Tests for FileShipper's intake path — _read_new_lines, the run() loop,
log-rotation detection, inode tracking, and checkpoint failure handling.

These exercise the previously-uncovered lines in src/ingestion/shipper.py
(the 47%-coverage module) without requiring a live database: writer.write is
mocked, and the log file is a real tmp_path file.

NOTE: CHECKPOINT_FILE is patched to a tmp path for the WHOLE test (via the
`ckpt` fixture) so _save_checkpoint never writes to the real home checkpoint.
"""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.db.writer import LogWriter
from src.ingestion.shipper import FileShipper


def _osquery_line(table: str = "processes", pid: str = "123") -> str:
    """Build a valid osquery result-log line for a mapped table."""
    return json.dumps({
        "name": table,
        "hostIdentifier": "host01",
        "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
        "unixTime": 1774267200,
        "columns": {"pid": pid, "name": "python3"},
        "action": "added",
    })


@pytest.fixture
def ckpt(tmp_path):
    """Patch CHECKPOINT_FILE to a tmp path for the entire test scope."""
    target = tmp_path / "ckpt"
    with patch("src.ingestion.shipper.CHECKPOINT_FILE", target):
        yield target


def _make_shipper(log_path, writer, offset=0, inode=None):
    """Construct a FileShipper. CHECKPOINT_FILE must already be patched (use ckpt)."""
    shipper = FileShipper(str(log_path), writer)
    shipper._offset = offset
    if inode is not None:
        shipper._inode = inode
    return shipper


class TestReadNewLines:
    """_read_new_lines — the core intake path."""

    async def test_parses_and_writes_each_line(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text(_osquery_line(pid="1") + "\n" + _osquery_line(pid="2") + "\n")
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock()
        shipper = _make_shipper(log_file, writer, offset=0)

        await shipper._read_new_lines()

        assert writer.write.await_count == 2
        assert shipper._events_shipped == 2
        assert shipper._offset == log_file.stat().st_size
        assert ckpt.read_text() == str(shipper._offset)

    async def test_skips_blank_lines(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text("\n" + _osquery_line(pid="1") + "\n\n\n")
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock()
        shipper = _make_shipper(log_file, writer, offset=0)

        await shipper._read_new_lines()

        assert writer.write.await_count == 1
        assert shipper._events_shipped == 1

    async def test_skips_unparseable_lines(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text("not json {{{\n" + _osquery_line(pid="1") + "\n")
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock()
        shipper = _make_shipper(log_file, writer, offset=0)

        await shipper._read_new_lines()

        # only the valid line is written; the malformed one is skipped, not fatal
        assert writer.write.await_count == 1

    async def test_resumes_from_offset(self, tmp_path, ckpt):
        first = _osquery_line(pid="1") + "\n"
        second = _osquery_line(pid="2") + "\n"
        log_file = tmp_path / "osq.log"
        log_file.write_text(first + second)
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock()
        shipper = _make_shipper(log_file, writer, offset=len(first))

        await shipper._read_new_lines()

        assert writer.write.await_count == 1


class TestGetInode:
    """_get_inode — inode tracking for rotation detection."""

    def test_returns_inode_for_existing_file(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text("x")
        shipper = _make_shipper(log_file, MagicMock(spec=LogWriter))
        assert isinstance(shipper._get_inode(), int)

    def test_returns_none_for_missing_file(self, tmp_path, ckpt):
        shipper = _make_shipper(tmp_path / "missing.log", MagicMock(spec=LogWriter))
        assert shipper._get_inode() is None

    def test_returns_none_on_oserror(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text("x")
        shipper = _make_shipper(log_file, MagicMock(spec=LogWriter))
        with patch("src.ingestion.shipper.os.stat", side_effect=OSError("boom")):
            assert shipper._get_inode() is None


class TestRunLoop:
    """run() — the tail loop, bounded by forcing _running=False on first sleep."""

    async def test_run_processes_new_lines_then_stops(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text(_osquery_line(pid="1") + "\n")
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock()
        shipper = _make_shipper(log_file, writer, offset=0)

        async def stop_sleep(*_a, **_k):
            shipper._running = False

        with patch("src.ingestion.shipper.asyncio.sleep", new=AsyncMock(side_effect=stop_sleep)):
            await asyncio.wait_for(shipper.run(), timeout=5)

        assert writer.write.await_count == 1
        assert shipper._events_shipped == 1

    async def test_run_warns_on_missing_file_then_stops(self, tmp_path, ckpt):
        shipper = _make_shipper(tmp_path / "missing.log", MagicMock(spec=LogWriter))

        async def stop_sleep(*_a, **_k):
            shipper._running = False

        with patch("src.ingestion.shipper.asyncio.sleep", new=AsyncMock(side_effect=stop_sleep)):
            await asyncio.wait_for(shipper.run(), timeout=5)

        assert shipper._events_shipped == 0

    async def test_run_detects_inode_rotation_and_resets_offset(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text(_osquery_line(pid="1") + "\n")
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock()
        # Pretend the shipper last saw a different inode -> rotation on first poll
        shipper = _make_shipper(log_file, writer, offset=999, inode=424242)

        async def stop_sleep(*_a, **_k):
            shipper._running = False

        with patch("src.ingestion.shipper.asyncio.sleep", new=AsyncMock(side_effect=stop_sleep)):
            await asyncio.wait_for(shipper.run(), timeout=5)

        # offset reset to 0 on rotation, then the line was shipped
        assert shipper._offset == log_file.stat().st_size
        assert writer.write.await_count == 1

    async def test_run_detects_shrink_rotation_and_resets_offset(self, tmp_path, ckpt):
        log_file = tmp_path / "osq.log"
        log_file.write_text(_osquery_line(pid="1") + "\n")
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock()
        # same inode but the stored offset is beyond the current file size -> shrink
        shipper = _make_shipper(log_file, writer, offset=99999, inode=log_file.stat().st_ino)

        async def stop_sleep(*_a, **_k):
            shipper._running = False

        with patch("src.ingestion.shipper.asyncio.sleep", new=AsyncMock(side_effect=stop_sleep)):
            await asyncio.wait_for(shipper.run(), timeout=5)

        assert shipper._offset == log_file.stat().st_size
        assert writer.write.await_count == 1

    async def test_run_swallows_exceptions_and_keeps_going(self, tmp_path, ckpt):
        """A raised exception in the loop body must not kill the shipper."""
        log_file = tmp_path / "osq.log"
        log_file.write_text(_osquery_line(pid="1") + "\n")
        writer = MagicMock(spec=LogWriter)
        writer.write = AsyncMock(side_effect=RuntimeError("transient db error"))
        shipper = _make_shipper(log_file, writer, offset=0)

        call_count = {"n": 0}

        async def stop_sleep(*_a, **_k):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                shipper._running = False

        # First poll: read raises -> caught -> sleep; second sleep stops the loop.
        with patch("src.ingestion.shipper.asyncio.sleep", new=AsyncMock(side_effect=stop_sleep)):
            await asyncio.wait_for(shipper.run(), timeout=5)

        # the exception was swallowed, the loop kept running until told to stop
        assert call_count["n"] >= 2


class TestCheckpointFailure:
    """_save_checkpoint must not crash when the filesystem fails."""

    def test_save_handles_oserror(self, tmp_path, ckpt):
        shipper = _make_shipper(tmp_path / "osq.log", MagicMock(spec=LogWriter))
        shipper._offset = 42
        with patch("src.ingestion.shipper.os.replace", side_effect=OSError("disk full")):
            # must not raise
            shipper._save_checkpoint()


class TestStop:
    """stop() flips the run flag and reports shipped count."""

    def test_stop_sets_running_false(self, tmp_path, ckpt):
        shipper = _make_shipper(tmp_path / "osq.log", MagicMock(spec=LogWriter))
        shipper._running = True
        shipper._events_shipped = 7
        shipper.stop()
        assert shipper._running is False
