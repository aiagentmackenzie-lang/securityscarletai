"""
Batched async log writer for PostgreSQL.

Design decisions:
- Batch inserts (configurable size, default 100) for throughput
- Flush on batch full OR timeout (whichever comes first) to bound latency
- Failed batches are written to a dead letter queue for retry
- NEVER silently drops data
"""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import asyncpg

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.ingestion.schemas import NormalizedEvent

log = get_logger("db.writer")

BATCH_SIZE = 100
FLUSH_INTERVAL = 5.0  # seconds — flush even if batch isn't full
DEAD_LETTER_DIR = Path("data/dead_letter")
DEAD_LETTER_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB per daily file
DEAD_LETTER_RETENTION_DAYS = 30


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
        log.info(
            "writer_stopped",
            total_written=self._total_written,
            total_errors=self._total_errors,
        )

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
                        json.dumps(
                            e.model_dump(
                                exclude={"raw_data", "enrichment", "severity"},
                                mode="json",
                            )
                        ),
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
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9,
                        $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
                    )
                    """,
                    rows,
                )
                self._total_written += len(batch)
                log.info("batch_flushed", count=len(batch), total=self._total_written)

        except (asyncpg.PostgresError, OSError) as e:
            self._total_errors += len(batch)
            log.error("batch_insert_failed", count=len(batch), error=str(e))
            # Dead letter queue — write failed batches to disk for later retry
            await self._write_to_dead_letter(batch, str(e))

    async def _write_to_dead_letter(self, batch: list, error: str) -> None:
        """Write failed batch to dead letter queue for later retry.

        H-14 fix: Enforce max file size and clean up old files.
        """
        DEAD_LETTER_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        dead_letter_file = DEAD_LETTER_DIR / f"{timestamp}.jsonl"

        # Check file size — if too large, rotate to a numbered file
        if dead_letter_file.exists() and dead_letter_file.stat().st_size > DEAD_LETTER_MAX_FILE_SIZE:
            n = 1
            while (DEAD_LETTER_DIR / f"{timestamp}_{n}.jsonl").exists():
                n += 1
            dead_letter_file = DEAD_LETTER_DIR / f"{timestamp}_{n}.jsonl"

        try:
            with open(dead_letter_file, "a") as f:
                f.write(json.dumps({
                    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "error": error,
                    "batch_size": len(batch),
                    "events": [
                        e.model_dump(mode="json") if hasattr(e, "model_dump")
                        else e.__dict__
                        for e in batch
                    ],
                }, default=str) + "\n")
            log.info("dead_letter_written", count=len(batch), file=str(dead_letter_file))
        except Exception as write_error:
            log.error("dead_letter_write_failed", error=str(write_error))

        # Cleanup old dead letter files
        try:
            self._cleanup_old_dead_letters()
        except Exception as cleanup_error:
            log.error("dead_letter_cleanup_failed", error=str(cleanup_error))

    @staticmethod
    def _cleanup_old_dead_letters() -> None:
        """Remove dead letter files older than DEAD_LETTER_RETENTION_DAYS."""
        if not DEAD_LETTER_DIR.exists():
            return
        cutoff = datetime.now(tz=timezone.utc).timestamp() - (DEAD_LETTER_RETENTION_DAYS * 86400)
        for f in DEAD_LETTER_DIR.glob("*.jsonl"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    log.info("dead_letter_cleaned", file=str(f))
            except OSError:
                pass
