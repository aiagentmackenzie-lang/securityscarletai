"""
Integration test for the full ingestion pipeline.

Requires: PostgreSQL running with schema applied.
Run with: poetry run pytest tests/integration/test_ingestion.py -v
"""
import asyncio
import json

import pytest

from src.db.connection import close_pool, get_pool
from src.db.writer import LogWriter
from src.ingestion.parser import parse_osquery_line

SYNTHETIC_EVENT = json.dumps({
    "name": "processes",
    "hostIdentifier": "integration-test-host",
    "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
    "unixTime": 1774267200,
    "columns": {
        "pid": "9999",
        "name": "suspicious_binary",
        "path": "/tmp/suspicious_binary",
        "cmdline": "/tmp/suspicious_binary --exfil",
        "uid": "0",  # root — suspicious
    },
    "action": "added"
})


@pytest.fixture
async def db_pool():
    pool = await get_pool()
    yield pool
    await close_pool()


@pytest.mark.asyncio
async def test_full_ingestion_pipeline(db_pool):
    """Test: raw osquery line → parsed → written to DB → queryable."""
    # Parse
    event = parse_osquery_line(SYNTHETIC_EVENT)
    assert event is not None
    assert event.process_name == "suspicious_binary"
    assert event.event_category == "process"

    # Write
    writer = LogWriter(batch_size=1, flush_interval=0.1)
    await writer.start()
    await writer.write(event)
    await asyncio.sleep(1)  # Wait for flush
    await writer.stop()

    # Verify in database
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM logs WHERE host_name = $1 AND process_name = $2 ORDER BY time DESC LIMIT 1",
            "integration-test-host",
            "suspicious_binary",
        )
        assert row is not None
        assert row["event_category"] == "process"
        assert row["process_pid"] == 9999

        # Cleanup
        await conn.execute(
            "DELETE FROM logs WHERE host_name = $1", "integration-test-host"
        )
