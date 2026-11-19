"""SS-016: any flush exception must dead-letter the batch, not lose it.

`flush()` copied the batch off `_buffer` and then only caught
`asyncpg.PostgresError` / `OSError`. A `TypeError`/`ValueError` raised while
building the rows (a non-serialisable enrichment value, a future codec change)
escaped with the batch already removed from the buffer — the events were
simply gone, with no dead letter and no metric. `CancelledError` has its own
handler (it is a BaseException) and must still re-raise.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.db.writer import LogWriter
from src.ingestion.schemas import NormalizedEvent


def _event(i: int = 0) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime.now(tz=timezone.utc),
        host_name=f"host{i}",
        source="test",
        event_category="process",
        event_type="start",
        raw_data={"i": i},
    )


def _pool(conn):
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=acquirer)
    return pool


class TestFlushErrorClasses:
    @pytest.mark.asyncio
    async def test_serialization_typeerror_dead_letters_the_batch(self):
        """The defect: a ValueError while building rows vanished the batch."""
        writer = LogWriter(batch_size=10)
        writer._buffer = [_event(1), _event(2)]
        conn = AsyncMock()
        dead_letter = AsyncMock()

        with (
            patch("src.db.writer.get_pool", AsyncMock(return_value=_pool(conn))),
            patch("src.db.writer.build_rows", side_effect=ValueError("bad enrichment")),
            patch.object(writer, "_write_to_dead_letter", dead_letter),
        ):
            await writer.flush()  # must not raise

        dead_letter.assert_awaited_once()
        batch = dead_letter.await_args.args[0]
        assert len(batch) == 2
        assert writer._total_errors == 2

    @pytest.mark.asyncio
    async def test_unexpected_runtime_error_dead_letters(self):
        writer = LogWriter(batch_size=10)
        writer._buffer = [_event(1)]
        dead_letter = AsyncMock()

        with (
            patch("src.db.writer.get_pool", AsyncMock(side_effect=RuntimeError("boom"))),
            patch.object(writer, "_write_to_dead_letter", dead_letter),
        ):
            await writer.flush()

        dead_letter.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cancelled_error_still_reraises(self):
        """CancelledError must keep propagating — stop() depends on it."""
        writer = LogWriter(batch_size=10)
        writer._buffer = [_event(1)]
        dead_letter = AsyncMock()

        with (
            patch("src.db.writer.get_pool", AsyncMock(side_effect=asyncio.CancelledError())),
            patch.object(writer, "_write_to_dead_letter", dead_letter),
        ):
            with pytest.raises(asyncio.CancelledError):
                await writer.flush()

        dead_letter.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_successful_flush_does_not_dead_letter(self):
        writer = LogWriter(batch_size=10)
        writer._buffer = [_event(1)]
        dead_letter = AsyncMock()

        with (
            patch("src.db.writer.get_pool", AsyncMock(return_value=_pool(AsyncMock()))),
            patch.object(writer, "_write_to_dead_letter", dead_letter),
        ):
            await writer.flush()

        dead_letter.assert_not_awaited()
        assert writer._total_written == 1
        assert writer._buffer == []
