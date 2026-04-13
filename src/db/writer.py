"""
Batched async log writer for PostgreSQL.

Design decisions:
- Batch inserts (configurable size, default 100) for throughput
- Flush on batch full OR timeout (whichever comes first) to bound latency
- On insert failure: log the error, skip the batch, continue.
  A dead writer is worse than a dropped batch.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

import asyncpg

from src.db.connection import get_pool
from src.ingestion.schemas import NormalizedEvent
from src.config.logging import get_logger

log = get_logger("db.writer")

BATCH_SIZE = 100
FLUSH_INTERVAL = 5.0  # seconds — flush even if batch isn't full


class LogWriter:
    """Async batched writer for the logs table."""

    def __init__(self, batch_size: int = BATCH_SIZE, flush_interval: float = FLUSH_INTERVAL):
        self._buffer: list[NormalizedEvent] = []
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None

        self._total_written = 0
        self._total_errors = 0

    async def start(self) -> None:
        """Start the periodic flush loop."""
        self._flush_task = asyncio.create_task(self._periodic_flush())
        log.info("writer_started", batch_size=self._batch_size, flush_interval=self._flush_interval)

    async def stop(self) -> None:
        """Flush remaining events and stop."""
        if self._flush_task:
            self._flush_task.cancel()
        await self._flush()
        log.info("writer_stopped", total_written=self._total_written, total_errors=self._total_errors)

    async def write(self, event: NormalizedEvent) -> None:
        """Add an event to the buffer. Flushes automatically when full."""
        async with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._batch_size:
                await self._flush_unlocked()

    async def _periodic_flush(self) -> None:
        """Flush the buffer every N seconds regardless of size."""
        while True:
            await asyncio.sleep(self._flush_interval)
            async with self._lock:
                if self._buffer:
                    await self._flush_unlocked()

    async def _flush(self) -> None:
        async with self._lock:
            await self._flush_unlocked()

    async def _flush_unlocked(self) -> None:
        """Actually write the batch to the database. Must be called with lock held."""
        if not self._buffer:
            return

        batch = self._buffer.copy()
        self._buffer.clear()

        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                # Use executemany for batch insert
                rows = [
                    (
                        e.timestamp,
                        e.host_name,
                        e.host_ip,
                        e.source,
                        e.event_category,
                        e.event_type,
                        e.event_action,
                        e.user_name,
                        e.process_name,
                        e.process_pid,
                        e.source_ip,
                        e.destination_ip,
                        e.destination_port,
                        e.file_path,
                        e.file_hash,
                        json.dumps(e.raw_data),
                        json.dumps(e.model_dump(exclude={"raw_data", "enrichment", "severity"}, mode="json")),
                        json.dumps(e.enrichment),
                        datetime.now(tz=timezone.utc),
                    )
                    for e in batch
                ]
                await conn.executemany(
                    """
                    INSERT INTO logs (
                        time, host_name, host_ip, source,
                        event_category, event_type, event_action,
                        user_name, process_name, process_pid,
                        source_ip, destination_ip, destination_port,
                        file_path, file_hash, raw_data, normalized,
                        enrichment, ingested_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
                    """,
                    rows,
                )
                self._total_written += len(batch)
                log.info("batch_flushed", count=len(batch), total=self._total_written)

        except (asyncpg.PostgresError, OSError) as e:
            self._total_errors += len(batch)
            log.error("batch_insert_failed", count=len(batch), error=str(e))
            # TODO: Dead letter queue — write failed batches to a local file for retry
