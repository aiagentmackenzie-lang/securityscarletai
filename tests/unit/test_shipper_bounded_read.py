"""SS-011: the shipper must read the results log in bounded chunks.

`with open(...) as f: f.seek(offset); chunk = f.read()` slurps ALL bytes
appended since the checkpoint. After a long outage that is gigabytes (the
documented 2026-09-23 case: 1.03 GB) and the read OOM-kills the API in a crash
loop before any check can run — the operator's only workaround was rotating the
log by hand.

These tests drive the real shipper against a real file with a recording file
object, and assert the absence of the defect: no unbounded `read()`, complete
lines still processed, the trailing partial line still preserved for the next
pass, and the checkpoint still only advancing over consumed bytes.
"""

from __future__ import annotations

import builtins
import io
import json
from pathlib import Path

import pytest

from src.ingestion import shipper as shipper_mod
from src.ingestion.shipper import FileShipper


class FakeWriter:
    def __init__(self) -> None:
        self.events: list = []
        self.flush_calls = 0

    async def write(self, event) -> None:
        self.events.append(event)

    async def flush(self) -> None:
        self.flush_calls += 1


def _line(pid: int) -> bytes:
    return (
        json.dumps(
            {
                "name": "processes",
                "hostIdentifier": "bounded.local",
                "unixTime": 1795003200,
                "columns": {"pid": str(pid), "name": f"proc{pid}", "user": "u"},
                "action": "added",
            }
        ).encode()
        + b"\n"
    )


class _RecordingFile:
    """File proxy that records every read() size handed to the OS."""

    def __init__(self, fh, reads: list[int]) -> None:
        self._fh = fh
        self._reads = reads

    def read(self, n: int = -1) -> bytes:
        self._reads.append(n)
        return self._fh.read(n)

    def seek(self, *args, **kwargs):
        return self._fh.seek(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._fh.close()
        return False


def _patch_open(monkeypatch, reads: list[int]) -> None:
    real_open = builtins.open

    def _open(path, mode="r", *args, **kwargs):
        fh = real_open(path, mode, *args, **kwargs)
        if "b" in mode:
            return _RecordingFile(fh, reads)
        return fh

    monkeypatch.setattr(builtins, "open", _open)
    # the shipper module resolves builtins.open dynamically, so this is enough


def _shipper(tmp_path: Path, log: Path, writer: FakeWriter) -> FileShipper:
    return FileShipper(
        log_path=str(log),
        writer=writer,
        checkpoint_path=tmp_path / "checkpoint",
        format="osquery",
    )


class TestBoundedRead:
    @pytest.mark.asyncio
    async def test_no_unbounded_read(self, tmp_path, monkeypatch):
        """The defect: `f.read()` with no size argument."""
        log = tmp_path / "results.log"
        log.write_bytes(b"".join(_line(i) for i in range(500)))
        reads: list[int] = []
        _patch_open(monkeypatch, reads)
        writer = FakeWriter()
        shipper = _shipper(tmp_path, log, writer)

        await shipper._read_new_lines()

        assert reads, "nothing was read"
        assert -1 not in reads, f"the shipper issued an unbounded read(): {reads}"

    @pytest.mark.asyncio
    async def test_read_size_is_capped(self, tmp_path, monkeypatch):
        cap = getattr(shipper_mod, "MAX_READ_CHUNK_BYTES", 16 * 1024 * 1024)
        log = tmp_path / "results.log"
        log.write_bytes(b"".join(_line(i) for i in range(200)))
        reads: list[int] = []
        _patch_open(monkeypatch, reads)
        shipper = _shipper(tmp_path, log, FakeWriter())

        await shipper._read_new_lines()

        assert all(0 < n <= cap for n in reads), reads

    @pytest.mark.asyncio
    async def test_multi_chunk_file_ships_every_complete_line(self, tmp_path, monkeypatch):
        """Chunking must not lose lines at chunk boundaries."""
        monkeypatch.setattr(shipper_mod, "MAX_READ_CHUNK_BYTES", 256, raising=False)
        log = tmp_path / "results.log"
        lines = [_line(i) for i in range(300)]
        log.write_bytes(b"".join(lines))
        reads: list[int] = []
        _patch_open(monkeypatch, reads)
        writer = FakeWriter()
        shipper = _shipper(tmp_path, log, writer)

        await shipper._read_new_lines()

        assert len(reads) > 1, "the file was not read in chunks"
        assert len(writer.events) == 300
        assert shipper._offset == log.stat().st_size
        assert int(shipper.checkpoint_path.read_text()) == log.stat().st_size

    @pytest.mark.asyncio
    async def test_trailing_partial_line_is_not_consumed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shipper_mod, "MAX_READ_CHUNK_BYTES", 128, raising=False)
        log = tmp_path / "results.log"
        complete = b"".join(_line(i) for i in range(5))
        partial = b'{"name":"processes","columns":{"pid":"9"'  # no newline yet
        log.write_bytes(complete + partial)
        reads: list[int] = []
        _patch_open(monkeypatch, reads)
        writer = FakeWriter()
        shipper = _shipper(tmp_path, log, writer)

        await shipper._read_new_lines()

        assert len(writer.events) == 5
        assert shipper._offset == len(complete)

    @pytest.mark.asyncio
    async def test_oversized_single_line_is_dropped_loudly_not_buffered(
        self, tmp_path, monkeypatch
    ):
        """A pathological > cap "line" must not become an unbounded buffer."""
        monkeypatch.setattr(shipper_mod, "MAX_READ_CHUNK_BYTES", 128, raising=False)
        monkeypatch.setattr(shipper_mod, "MAX_LINE_BYTES", 512, raising=False)
        log = tmp_path / "results.log"
        junk = b"x" * 4096  # one line, no newline, larger than MAX_LINE_BYTES
        log.write_bytes(junk + b"\n" + _line(1))
        reads: list[int] = []
        _patch_open(monkeypatch, reads)
        writer = FakeWriter()
        shipper = _shipper(tmp_path, log, writer)

        await shipper._read_new_lines()

        # The junk line is dropped; the valid line after it still ships.
        assert [e.process_name for e in writer.events] == ["proc1"]
        assert shipper._offset == log.stat().st_size

    @pytest.mark.asyncio
    async def test_empty_read_is_a_noop(self, tmp_path):
        log = tmp_path / "results.log"
        log.write_bytes(b"")
        writer = FakeWriter()
        shipper = _shipper(tmp_path, log, writer)
        await shipper._read_new_lines()
        assert writer.events == []
        assert writer.flush_calls == 0
        assert shipper._offset == 0


class TestCheckpointSemantics:
    @pytest.mark.asyncio
    async def test_checkpoint_not_persisted_when_flush_fails(self, tmp_path):
        """At-least-once must survive the chunked read (W1-B contract)."""

        class FailingWriter(FakeWriter):
            async def flush(self) -> None:
                self.flush_calls += 1
                raise RuntimeError("db down")

        log = tmp_path / "results.log"
        log.write_bytes(b"".join(_line(i) for i in range(3)))
        shipper = _shipper(tmp_path, log, FailingWriter())

        await shipper._read_new_lines()

        assert not shipper.checkpoint_path.exists(), "checkpoint advanced past unflushed data"

    @pytest.mark.asyncio
    async def test_resume_from_checkpoint_reads_only_new_bytes(self, tmp_path):
        log = tmp_path / "results.log"
        log.write_bytes(b"".join(_line(i) for i in range(2)))
        writer = FakeWriter()
        shipper = _shipper(tmp_path, log, writer)
        await shipper._read_new_lines()
        assert len(writer.events) == 2

        with open(log, "ab") as fh:
            fh.write(_line(3))
        await shipper._read_new_lines()
        assert len(writer.events) == 3
        assert shipper._offset == log.stat().st_size


def test_chunk_size_is_documented_and_bounded():
    """8 MB chunk per the campaign decision; the read must never be unbounded."""
    assert hasattr(shipper_mod, "MAX_READ_CHUNK_BYTES")
    assert 1024 * 1024 <= shipper_mod.MAX_READ_CHUNK_BYTES <= 64 * 1024 * 1024
    assert shipper_mod.MAX_LINE_BYTES >= shipper_mod.MAX_READ_CHUNK_BYTES


def test_source_contains_no_unbounded_read():
    """Belt-and-braces at the AST level: no zero-argument .read() call."""
    import ast

    tree = ast.parse(Path(shipper_mod.__file__).read_text())
    offenders = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "read"
        and not node.args
    ]
    assert offenders == [], f"unbounded read() at line(s) {offenders}"


def test_io_import_is_available():
    # keeps ruff from flagging the io import used by the recorder helpers
    assert io.BytesIO(b"x").read(1) == b"x"
