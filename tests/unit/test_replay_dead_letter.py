"""Tests for the dead-letter replay script (P1-E)."""
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


def _dead_letter_line(idx: int) -> str:
    from src.ingestion.schemas import NormalizedEvent

    e = NormalizedEvent(
        timestamp=datetime.now(tz=timezone.utc),
        host_name=f"host{idx}",
        source="test",
        event_category="process",
        event_type="start",
        raw_data={"i": idx},
    )
    return json.dumps({
        "dead_letter": True,
        "written_at": datetime.now(tz=timezone.utc).isoformat(),
        "error": "simulated outage",
        "event": e.model_dump(mode="json"),
    }, default=str)


class TestReplayFile:
    @pytest.mark.asyncio
    async def test_replay_file_re_ingests_each_line(self, tmp_path: Path, monkeypatch):
        import scripts.replay_dead_letter as mod

        # A dead-letter file with 3 good lines + 1 malformed.
        f = tmp_path / "2026-08-26.jsonl"
        f.write_text(
            _dead_letter_line(1) + "\n"
            + _dead_letter_line(2) + "\n"
            + "{not valid json}\n"
            + _dead_letter_line(3) + "\n"
        )

        # Stub the writer so no DB is needed.
        writer = MagicMock()
        writer.write = AsyncMock()
        writer.flush = AsyncMock()
        monkeypatch.setattr(mod, "writer", writer)

        replayed, skipped = await mod.replay_file(f)

        assert replayed == 3
        assert skipped == 1
        assert writer.write.await_count == 3
        writer.flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_replay_all_moves_processed_files(self, tmp_path: Path, monkeypatch):
        import scripts.replay_dead_letter as mod

        dl_dir = tmp_path / "dead_letter"
        dl_dir.mkdir()
        f = dl_dir / "2026-08-26.jsonl"
        f.write_text(_dead_letter_line(10) + "\n" + _dead_letter_line(11) + "\n")

        writer = MagicMock()
        writer.write = AsyncMock()
        writer.flush = AsyncMock()
        writer.start = AsyncMock()
        writer.stop = AsyncMock()
        monkeypatch.setattr(mod, "writer", writer)
        monkeypatch.setattr(mod, "get_pool", AsyncMock())
        monkeypatch.setattr(mod, "close_pool", AsyncMock())
        # Point the module's dirs at the temp dir.
        monkeypatch.setattr(mod, "DEAD_LETTER_DIR", dl_dir)
        monkeypatch.setattr(mod, "PROCESSED_DIR", dl_dir / "processed")

        summary = await mod.replay_all(dl_dir)

        assert summary["replayed"] == 2
        assert summary["files"] == 1
        # The file moved to processed/.
        assert not f.exists()
        assert (dl_dir / "processed" / "2026-08-26.jsonl").exists()

    @pytest.mark.asyncio
    async def test_replay_all_no_dir(self, tmp_path: Path, monkeypatch):
        import scripts.replay_dead_letter as mod

        monkeypatch.setattr(mod, "get_pool", AsyncMock())
        summary = await mod.replay_all(tmp_path / "does_not_exist")
        assert summary == {"files": 0, "replayed": 0, "skipped": 0}
