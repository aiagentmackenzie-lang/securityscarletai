"""Tests for LogWriter backpressure (P1-E)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _event(idx: int):
    from datetime import datetime, timezone

    from src.ingestion.schemas import NormalizedEvent

    return NormalizedEvent(
        timestamp=datetime.now(tz=timezone.utc),
        host_name=f"host{idx}",
        source="test",
        event_category="process",
        event_type="start",
        raw_data={"i": idx},
    )


class TestWriterBackpressure:
    @pytest.mark.asyncio
    async def test_buffer_cap_triggers_flush(self):
        """When the buffer reaches the cap, write() flushes before appending
        (backpressure) so the buffer never exceeds MAX_BUFFER."""
        from src.db.writer import LogWriter

        writer = LogWriter(batch_size=10_000)  # batch flush never fires
        writer._max_buffer = 50  # small cap for a fast test
        flush_calls = 0

        async def _fake_flush():
            nonlocal flush_calls
            flush_calls += 1
            writer._buffer.clear()  # simulate the real clear-before-write

        writer._flush_unlocked = _fake_flush  # type: ignore[method-assign]

        max_seen = 0
        for i in range(60):
            await writer.write(_event(i))
            max_seen = max(max_seen, len(writer._buffer))

        # The cap fired at write 51 (len hit 50), flushing before appending.
        assert flush_calls >= 1
        # The buffer never exceeded the cap.
        assert max_seen <= writer._max_buffer

    @pytest.mark.asyncio
    async def test_normal_load_does_not_backpressure(self):
        """Under normal load (batch_size flushes keep up), the cap is never hit
        and no backpressure flush is triggered."""
        from src.db.writer import LogWriter

        writer = LogWriter(batch_size=10)  # flush every 10
        writer._max_buffer = 1000
        flush_calls = 0

        async def _fake_flush():
            nonlocal flush_calls
            flush_calls += 1
            writer._buffer.clear()

        writer._flush_unlocked = _fake_flush  # type: ignore[method-assign]

        for i in range(95):
            await writer.write(_event(i))

        # Only the batch-size flushes fired (9-10 of them); the cap (1000) was
        # never approached, so no extra backpressure flush beyond the batch ones.
        assert flush_calls == 9  # 95 // 10 = 9 batch flushes
        # Buffer stayed small.
        assert len(writer._buffer) < writer._batch_size


class TestWriterCapDerivation:
    def test_max_buffer_derives_from_instance_batch_size(self):
        """AUD-022: the cap is 10× THIS writer's batch_size — not a fixed
        module constant that ignored the instance's batch_size."""
        from src.db.writer import LogWriter

        assert LogWriter()._max_buffer == 10 * 100
        assert LogWriter(batch_size=10)._max_buffer == 100
        assert LogWriter(batch_size=10_000)._max_buffer == 100_000


class TestPeriodicFlushSurvivesUnexpectedException:
    """W1-F: _periodic_flush had no exception guard — an unexpected exception
    type (NOT PostgresError/OSError, e.g. a TypeError building rows) killed
    the flush task silently forever: nothing awaits it, so no error surfaced
    and every later flush never ran."""

    @pytest.mark.asyncio
    async def test_flush_loop_survives_unexpected_exception(self):
        import asyncio

        from src.db.writer import LogWriter

        writer = LogWriter(batch_size=10_000, flush_interval=0.01)
        calls = 0

        async def _sometimes_broken():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TypeError("unexpected — not PostgresError/OSError")
            writer._buffer.clear()

        writer._flush_unlocked = _sometimes_broken  # type: ignore[method-assign]
        await writer.start()
        try:
            await writer.write(_event(0))  # buffer holds it; the periodic task flushes
            await asyncio.sleep(0.1)  # >= 2 flush ticks

            # OLD CODE: the first TypeError killed the task silently — done()
            # True and no further flush ever ran.
            assert writer._flush_task is not None
            assert not writer._flush_task.done()
            assert calls >= 2
        finally:
            await writer.stop()


class TestFlushCancelledDeadLetters:
    """W1-F: stop() cancels the flush task possibly mid-executemany —
    CancelledError is a BaseException, so it bypassed the PostgresError/
    OSError dead-letter handler and the in-flight batch (already copied off
    _buffer) was silently LOST on shutdown."""

    def _mock_pool_with_executemany(self, executemany):
        import src.db.writer as writer_mod

        mock_conn = AsyncMock()
        mock_conn.executemany = executemany
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(return_value=acquirer)
        return writer_mod, mock_pool

    @pytest.mark.asyncio
    async def test_flush_unlocked_dead_letters_on_cancel(self, tmp_path, monkeypatch):
        import asyncio

        from src.db.writer import LogWriter

        writer_mod, mock_pool = self._mock_pool_with_executemany(
            AsyncMock(side_effect=asyncio.CancelledError)
        )
        monkeypatch.setattr(writer_mod, "DEAD_LETTER_DIR", tmp_path)

        writer = LogWriter()
        writer._buffer.append(_event(1))

        with patch("src.db.writer.get_pool", return_value=mock_pool):
            # The cancel is honored (re-raised)...
            with pytest.raises(asyncio.CancelledError):
                await writer._flush_unlocked()

        # ...but the batch is dead-lettered, not lost.
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
        assert len(files[0].read_text().strip().splitlines()) == 1
        assert writer._total_errors == 1
        assert writer._buffer == []

    @pytest.mark.asyncio
    async def test_stop_awaits_and_dead_letters_inflight_batch(self, tmp_path, monkeypatch):
        import asyncio

        from src.db.writer import LogWriter

        async def _hang(*args, **kwargs):
            await asyncio.sleep(3600)  # simulates a mid-executemany cancel target

        writer_mod, mock_pool = self._mock_pool_with_executemany(AsyncMock(side_effect=_hang))
        monkeypatch.setattr(writer_mod, "DEAD_LETTER_DIR", tmp_path)

        writer = LogWriter(batch_size=10_000, flush_interval=0.01)
        with patch("src.db.writer.get_pool", return_value=mock_pool):
            await writer.start()
            try:
                await writer.write(_event(0))
                await asyncio.sleep(0.1)  # the periodic flush is now hung mid-executemany
            finally:
                await writer.stop()  # cancel + await: the batch must dead-letter here

        assert writer._flush_task is not None
        assert writer._flush_task.done()
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1, "the cancelled in-flight batch was LOST on shutdown"
        assert len(files[0].read_text().strip().splitlines()) == 1
