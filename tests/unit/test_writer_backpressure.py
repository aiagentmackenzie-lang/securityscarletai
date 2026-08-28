"""Tests for LogWriter backpressure (P1-E)."""

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
