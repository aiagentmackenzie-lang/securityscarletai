"""SS-040: a poison row must not re-dead-letter itself forever.

A batch containing an unpalatable row (SS-014's invalid IP, say) failed on
replay, the writer re-dead-lettered the *whole batch* to a new file, and the
original moved to `processed/` — because `writer.flush()` swallows the DB
error. The poison row therefore returned on EVERY boot, and each boot
re-attempted the entire batch.

Replay is now per-row: a row that the database rejects is quarantined with an
attempt counter and skipped, the good rows in the same file still land, the
file is retired, and nothing re-dead-letters the batch.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import asyncpg
import pytest


def _dead_letter_line(idx: int, attempts: int | None = None) -> str:
    from src.ingestion.schemas import NormalizedEvent

    e = NormalizedEvent(
        timestamp=datetime.now(tz=timezone.utc),
        host_name=f"host{idx}",
        source="test",
        event_category="process",
        event_type="start",
        raw_data={"i": idx},
    )
    record = {
        "dead_letter": True,
        "written_at": datetime.now(tz=timezone.utc).isoformat(),
        "error": "simulated outage",
        "event": e.model_dump(mode="json"),
    }
    if attempts is not None:
        record["attempts"] = attempts
    return json.dumps(record, default=str)


def _data_error() -> asyncpg.DataError:
    return asyncpg.DataError("invalid input syntax for type inet")


class TestPerRowReplay:
    @pytest.mark.asyncio
    async def test_poison_row_is_quarantined_and_good_rows_land(self, tmp_path: Path, monkeypatch):
        import scripts.replay_dead_letter as mod

        monkeypatch.setattr(mod, "QUARANTINE_DIR", tmp_path / "quarantine")
        f = tmp_path / "2026-11-18.jsonl"
        f.write_text(_dead_letter_line(1) + "\n" + _dead_letter_line(2) + "\n")

        async def fake_persist(event):
            if event.host_name == "host2":
                raise _data_error()

        monkeypatch.setattr(mod, "_persist_event", fake_persist)

        replayed, skipped, quarantined = await mod.replay_file(f)

        assert (replayed, skipped, quarantined) == (1, 0, 1)
        qfiles = list((tmp_path / "quarantine").glob("*.jsonl"))
        assert len(qfiles) == 1
        record = json.loads(qfiles[0].read_text().splitlines()[0])
        assert record["attempts"] == 1
        assert record["event"]["host_name"] == "host2"
        assert "inet" in record["quarantine_reason"]

    @pytest.mark.asyncio
    async def test_attempt_counter_increments(self, tmp_path: Path, monkeypatch):
        import scripts.replay_dead_letter as mod

        monkeypatch.setattr(mod, "QUARANTINE_DIR", tmp_path / "quarantine")
        f = tmp_path / "d.jsonl"
        f.write_text(_dead_letter_line(1, attempts=2) + "\n")

        async def fake_persist(event):
            raise _data_error()

        monkeypatch.setattr(mod, "_persist_event", fake_persist)
        await mod.replay_file(f)

        record = json.loads(
            next((tmp_path / "quarantine").glob("*.jsonl")).read_text().splitlines()[0]
        )
        assert record["attempts"] == 3

    @pytest.mark.asyncio
    async def test_exhausted_attempts_are_dropped_not_requeued(self, tmp_path: Path, monkeypatch):
        import scripts.replay_dead_letter as mod

        monkeypatch.setattr(mod, "QUARANTINE_DIR", tmp_path / "quarantine")
        f = tmp_path / "d.jsonl"
        f.write_text(_dead_letter_line(1, attempts=mod.MAX_REPLAY_ATTEMPTS) + "\n")

        persist = AsyncMock()
        monkeypatch.setattr(mod, "_persist_event", persist)

        replayed, skipped, quarantined = await mod.replay_file(f)

        assert replayed == 0
        assert skipped == 1
        assert quarantined == 0
        persist.assert_not_awaited()
        assert not list((tmp_path / "quarantine").glob("*.jsonl"))

    @pytest.mark.asyncio
    async def test_db_outage_leaves_the_file_for_the_next_run(self, tmp_path: Path, monkeypatch):
        """A connection-class failure is NOT a poison row — never quarantine it."""
        import scripts.replay_dead_letter as mod

        monkeypatch.setattr(mod, "QUARANTINE_DIR", tmp_path / "quarantine")
        f = tmp_path / "d.jsonl"
        f.write_text(_dead_letter_line(1) + "\n")

        async def fake_persist(event):
            raise ConnectionError("db down")

        monkeypatch.setattr(mod, "_persist_event", fake_persist)
        monkeypatch.setattr(mod, "get_pool", AsyncMock())
        monkeypatch.setattr(mod, "close_pool", AsyncMock())
        monkeypatch.setattr(mod, "DEAD_LETTER_DIR", tmp_path)
        monkeypatch.setattr(mod, "PROCESSED_DIR", tmp_path / "processed")

        summary = await mod.replay_all(tmp_path)

        assert summary["replayed"] == 0
        assert f.exists(), "a DB outage must not retire the file"
        assert not list((tmp_path / "quarantine").glob("*.jsonl"))

    @pytest.mark.asyncio
    async def test_file_is_retired_after_poison_rows_are_quarantined(
        self, tmp_path: Path, monkeypatch
    ):
        import scripts.replay_dead_letter as mod

        monkeypatch.setattr(mod, "QUARANTINE_DIR", tmp_path / "quarantine")
        monkeypatch.setattr(mod, "DEAD_LETTER_DIR", tmp_path)
        monkeypatch.setattr(mod, "PROCESSED_DIR", tmp_path / "processed")
        monkeypatch.setattr(mod, "get_pool", AsyncMock())
        monkeypatch.setattr(mod, "close_pool", AsyncMock())

        f = tmp_path / "d.jsonl"
        f.write_text(_dead_letter_line(1) + "\n" + _dead_letter_line(2) + "\n")

        async def fake_persist(event):
            if event.host_name == "host1":
                raise _data_error()

        monkeypatch.setattr(mod, "_persist_event", fake_persist)

        summary = await mod.replay_all(tmp_path)

        assert summary["replayed"] == 1
        assert summary["quarantined"] == 1
        assert not f.exists()
        assert (tmp_path / "processed" / "d.jsonl").exists()

    @pytest.mark.asyncio
    async def test_no_row_is_re_dead_lettered(self, tmp_path: Path, monkeypatch):
        """The defect was a new dead-letter file per replay attempt."""
        import scripts.replay_dead_letter as mod

        monkeypatch.setattr(mod, "QUARANTINE_DIR", tmp_path / "quarantine")
        monkeypatch.setattr(mod, "DEAD_LETTER_DIR", tmp_path)
        monkeypatch.setattr(mod, "PROCESSED_DIR", tmp_path / "processed")
        monkeypatch.setattr(mod, "get_pool", AsyncMock())
        monkeypatch.setattr(mod, "close_pool", AsyncMock())

        f = tmp_path / "d.jsonl"
        f.write_text(_dead_letter_line(1) + "\n")

        async def fake_persist(event):
            raise _data_error()

        monkeypatch.setattr(mod, "_persist_event", fake_persist)
        await mod.replay_all(tmp_path)
        await mod.replay_all(tmp_path)  # second boot sees nothing to replay

        remaining = sorted(p.name for p in tmp_path.glob("*.jsonl"))
        assert remaining == [], f"poison row came back: {remaining}"
