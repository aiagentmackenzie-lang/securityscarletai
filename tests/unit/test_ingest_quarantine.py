"""
V0.4 quarantine enforcement: the ingest endpoint refuses events from hosts
on the quarantine list (the enforcement point of the quarantine_host
response action).
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api.ingest import IngestEvent, ingest_events
from src.services.writer import writer as writer_singleton
from tests.unit._test_request import make_test_request


def _event(host: str) -> IngestEvent:
    return IngestEvent(
        **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
        host_name=host,
        source="syslog",
        event_category="process",
        event_type="start",
    )


@pytest.mark.asyncio
async def test_quarantined_host_events_refused():
    """Events from a quarantined host never enter the pipeline; the batch
    still accepts other hosts and reports the rejection count."""
    pool = AsyncMock()
    conn = AsyncMock()
    acq = AsyncMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq)
    conn.fetch.return_value = [{"host_name": "bad-host"}]

    write_mock = AsyncMock()
    with (
        patch("src.api.ingest.get_pool", return_value=pool),
        patch.object(writer_singleton, "write", write_mock),
        patch.object(writer_singleton, "flush", AsyncMock()),
        patch("src.detection.correlation.run_all_correlations", AsyncMock()),
        patch("src.api.websocket.broadcast_event", AsyncMock()),
    ):
        result = await ingest_events(
            make_test_request(),
            MagicMock(),
            [_event("bad-host"), _event("good-host"), _event("bad-host")],
            "token",
        )
        for _ in range(10):
            await asyncio.sleep(0)

    assert result.accepted == 1
    assert result.rejected_quarantine == 2
    assert write_mock.await_count == 1
    written_host = write_mock.await_args_list[0].args[0].host_name
    assert written_host == "good-host"


@pytest.mark.asyncio
async def test_quarantine_lookup_failure_does_not_mask_the_write_failure():
    """If the quarantine lookup itself fails (DB down), the refusal never
    happens silently: the lookup is swallowed (empty list, nothing was
    proven quarantined) and the write path fails loudly right after --
    fail-loud, not fail-open into the pipeline."""
    pool = AsyncMock()
    pool.acquire = AsyncMock(side_effect=RuntimeError("db down"))

    with (
        patch("src.api.ingest.get_pool", return_value=pool),
        patch("src.db.connection.get_pool", AsyncMock(side_effect=RuntimeError("no db"))),
        patch.object(writer_singleton, "write", AsyncMock(side_effect=RuntimeError("no db"))),
    ):
        with pytest.raises(RuntimeError):
            await ingest_events(make_test_request(), MagicMock(), [_event("h")], "token")


@pytest.mark.asyncio
async def test_no_quarantine_records_means_everything_accepted():
    pool = AsyncMock()
    conn = AsyncMock()
    acq = AsyncMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq)
    conn.fetch.return_value = []  # empty quarantine list

    write_mock = AsyncMock()
    with (
        patch("src.api.ingest.get_pool", return_value=pool),
        patch.object(writer_singleton, "write", write_mock),
        patch.object(writer_singleton, "flush", AsyncMock()),
        patch("src.detection.correlation.run_all_correlations", AsyncMock()),
        patch("src.api.websocket.broadcast_event", AsyncMock()),
    ):
        result = await ingest_events(
            make_test_request(), MagicMock(), [_event("h1"), _event("h2")], "token"
        )
        for _ in range(10):
            await asyncio.sleep(0)

    assert result.accepted == 2
    assert result.rejected_quarantine == 0
