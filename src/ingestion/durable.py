"""Durable ingest buffer (W2.2) — Redis Streams between the API ingest
path and the batched writer: consumer group, ACK after DB persist,
crash-safe, bounded memory, dead-letter preserved.

Removes the documented at-most-once gap of the in-process writer buffer
(a process crash loses the writer's un-flushed buffer). With durable mode
enabled, an event is XADD'd to a Redis Stream BEFORE the API responds; a
consumer persists it through the EXISTING LogWriter (same batching, same
file dead-letter machinery) and ACKs only after the DB persist. A crash
between enqueue and ACK leaves the entry PENDING in Redis — reclaimed on
the next consumer pass (XAUTOCLAIM), never lost.

Delivery semantics: AT-LEAST-ONCE (the flip side of at-most-once). A crash
or writer failure after a flush attempt can redeliver an already-persisted
event — duplicates are possible and labeled, never silent.

Fail-closed: when durable mode is enabled and Redis is unavailable, the
ingest endpoints refuse with 503 (the quarantine doctrine shape) — the SIEM
does not silently degrade to at-most-once while promising durability.

Default OFF (`config/durable_ingest.yaml`): with the flag off, every path
behaves byte-identically to pre-W2.2 (direct writer.write, in-process
buffer, no Redis dependency on the ingest hot path).
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

import yaml

from src.config.logging import get_logger

log = get_logger("ingestion.durable")

CONFIG_FILENAME = "durable_ingest.yaml"


class DurableConfigError(Exception):
    """An invalid durable-ingest config — fail-closed at load/boot."""


class DurableIngestUnavailable(Exception):
    """Redis is unavailable in durable mode — the caller must refuse (503)."""


@dataclass
class DurableIngestConfig:
    enabled: bool = False
    stream: str = "scarletai:ingest:events"
    dead_letter_stream: str = "scarletai:ingest:dead"
    consumer_group: str = "writer"
    consumer_name: str = "siem-writer"
    max_stream_length: int = 100_000  # bounded memory (approximate MAXLEN)
    max_deliveries: int = 5  # attempts before dead-letter
    claim_idle_seconds: int = 60  # XAUTOCLAIM threshold (crash recovery)
    read_block_ms: int = 1000
    read_count: int = 100  # hand-off batch size (= writer BATCH_SIZE)


def load_durable_config(path: Path) -> DurableIngestConfig:
    """Load + validate the durable-ingest config. Raises DurableConfigError
    on any invalid entry — fail-closed; the caller must not partially use it."""
    try:
        raw = path.read_bytes()
        data = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as e:
        raise DurableConfigError(f"cannot read durable-ingest config {path}: {e}") from e
    if not isinstance(data, dict):
        raise DurableConfigError("durable_ingest config must be a mapping")
    if data.get("schema_version") != 1:
        raise DurableConfigError(
            f"durable_ingest schema_version must be 1 (got {data.get('schema_version')!r})"
        )

    cfg = DurableIngestConfig()
    section = data.get("durable_ingest") or {}
    if not isinstance(section, dict):
        raise DurableConfigError("durable_ingest section must be a mapping")
    cfg.enabled = bool(section.get("enabled", False))
    if not cfg.enabled:
        return cfg

    stream = str(section.get("stream") or "").strip()
    dead = str(section.get("dead_letter_stream") or "").strip()
    group = str(section.get("consumer_group") or "").strip()
    consumer = str(section.get("consumer_name") or "").strip()
    if not stream or not group:
        raise DurableConfigError("durable_ingest.enabled requires stream + consumer_group")
    if not dead:
        raise DurableConfigError("durable_ingest.enabled requires dead_letter_stream")
    if dead == stream:
        raise DurableConfigError("dead_letter_stream must differ from stream")
    try:
        max_len = int(section.get("max_stream_length", cfg.max_stream_length))
        max_deliveries = int(section.get("max_deliveries", cfg.max_deliveries))
        claim_idle = int(section.get("claim_idle_seconds", cfg.claim_idle_seconds))
        block_ms = int(section.get("read_block_ms", cfg.read_block_ms))
        read_count = int(section.get("read_count", cfg.read_count))
    except (TypeError, ValueError) as e:
        raise DurableConfigError(f"durable_ingest numeric fields must be integers: {e}") from e
    if max_len < 1000:
        raise DurableConfigError("max_stream_length must be >= 1000 (bounded backlog)")
    if not 1 <= max_deliveries <= 100:
        raise DurableConfigError("max_deliveries must be in [1, 100]")
    if claim_idle < 1:
        raise DurableConfigError("claim_idle_seconds must be >= 1")
    if not 1 <= read_count <= 1000:
        raise DurableConfigError("read_count must be in [1, 1000]")
    if block_ms < 0:
        raise DurableConfigError("read_block_ms must be >= 0")

    cfg.stream = stream
    cfg.dead_letter_stream = dead
    cfg.consumer_group = group
    cfg.consumer_name = consumer or f"siem-{socket.gethostname()}"
    cfg.max_stream_length = max_len
    cfg.max_deliveries = max_deliveries
    cfg.claim_idle_seconds = claim_idle
    cfg.read_block_ms = block_ms
    cfg.read_count = read_count
    return cfg


# ───────────────────────────────────────────────────────────────
# The process-level seam: the ingest path's single persist call
# ───────────────────────────────────────────────────────────────

_durable: Optional["DurableIngest"] = None


def configure_durable(instance: Optional["DurableIngest"]) -> None:
    """Boot-time wiring (lifespan): set the durable instance (or None when
    the feature is off — every path then behaves exactly as before W2.2)."""
    global _durable
    _durable = instance


def durable_mode() -> bool:
    return _durable is not None


async def durable_redis_probe() -> bool:
    """Bounded availability probe for the fail-closed gate: True when Redis
    answers (or durable mode is off — the caller only asks in durable mode).
    Uses the shared client seam's own connect/timeout budget."""
    if _durable is None:
        return True
    try:
        client = await _durable._client()
        if client is None:
            return False
        await client.ping()
        return True
    except Exception:  # noqa: BLE001 — any probe failure is 'unavailable'
        return False


async def persist_event(event: Any) -> None:
    """The one ingest-path seam: XADD to the stream (durable mode) or the
    in-process writer (default). Raises DurableIngestUnavailable only in
    durable mode when Redis is unavailable — callers fail closed (503)."""
    if _durable is not None:
        await _durable.enqueue(event)
    else:
        from src.services.writer import writer

        await writer.write(event)


class DurableIngest:
    """Redis-Streams ingest buffer + its persisting consumer.

    `client_factory` returns an awaitable yielding the redis client (the
    shared src.api.redis_client seam — bounded retry + cooldown) or None
    when Redis is unreachable.
    """

    def __init__(
        self,
        cfg: DurableIngestConfig,
        client_factory: Callable[[], Awaitable[Any]],
        writer: Any = None,
    ):
        self.cfg = cfg
        self._client_factory = client_factory
        self._writer = writer

    def _writer_inst(self) -> Any:
        if self._writer is None:
            from src.services.writer import writer

            self._writer = writer
        return self._writer

    async def _client(self) -> Any:
        return await self._client_factory()

    async def enqueue(self, event: Any) -> None:
        """XADD one event. Any Redis failure raises — the API fails closed."""
        client = await self._client()
        if client is None:
            raise DurableIngestUnavailable(
                "redis unavailable — durable ingest cannot accept events"
            )
        try:
            await client.xadd(
                self.cfg.stream,
                {"payload": event.model_dump_json()},
                maxlen=self.cfg.max_stream_length,
                approximate=True,
            )
        except Exception as e:  # noqa: BLE001 — any Redis failure is fail-closed
            raise DurableIngestUnavailable(f"redis XADD failed: {e}") from e

    async def run(self, stop: asyncio.Event) -> None:
        """The consumer loop: ensure group → reclaim orphans → dead-letter
        exhausted entries → read new → persist (writer.write + flush) →
        ACK. Exits when `stop` is set."""
        log.info(
            "durable_consumer_started",
            stream=self.cfg.stream,
            group=self.cfg.consumer_group,
            consumer=self.cfg.consumer_name,
            max_stream_length=self.cfg.max_stream_length,
        )
        idle_backoff = 1.0
        while not stop.is_set():
            try:
                client = await self._client()
            except Exception as e:  # noqa: BLE001 — the factory must never crash the loop
                log.warning("durable_client_factory_error", error=str(e))
                client = None
            if client is None:
                log.warning("durable_redis_unavailable_consumer_waiting", backoff_s=idle_backoff)
                await self._wait(stop, 5.0)
                continue
            try:
                await self._ensure_group(client)
                # 1. Reclaim orphaned pendings (a crashed consumer's entries).
                await self._reclaim(client)
                # 2. Dead-letter entries that exhausted their deliveries.
                await self._deadletter_exhausted(client)
                # 3. New entries (never-delivered only).
                batch = await client.xreadgroup(
                    self.cfg.consumer_group,
                    self.cfg.consumer_name,
                    {self.cfg.stream: ">"},
                    count=self.cfg.read_count,
                    block=self.cfg.read_block_ms,
                )
                for _stream, messages in batch or []:
                    await self._process(client, messages)
                idle_backoff = 1.0
            except Exception as e:  # noqa: BLE001 — the consumer survives Redis outages
                log.warning("durable_consumer_loop_error", error=str(e))
                await self._wait(stop, idle_backoff)
                idle_backoff = min(idle_backoff * 2, 10.0)
        log.info("durable_consumer_stopped")

    @staticmethod
    async def _wait(stop: asyncio.Event, timeout: float) -> None:
        try:
            await asyncio.wait_for(stop.wait(), timeout=timeout)
        except TimeoutError:
            pass

    async def _ensure_group(self, client: Any) -> None:
        try:
            await client.xgroup_create(
                self.cfg.stream, self.cfg.consumer_group, id="0", mkstream=True
            )
            log.info("durable_consumer_group_created", group=self.cfg.consumer_group)
        except Exception as e:  # noqa: BLE001 — BUSYGROUP is the happy path
            if "BUSYGROUP" not in str(e):
                raise

    async def _reclaim(self, client: Any) -> None:
        """XAUTOCLAIM idle pendings (bounded per sweep)."""
        cursor = "0-0"
        claimed_total = 0
        while True:
            result = await client.xautoclaim(
                self.cfg.stream,
                self.cfg.consumer_group,
                self.cfg.consumer_name,
                min_idle_time=self.cfg.claim_idle_seconds * 1000,
                start_id=cursor,
                count=self.cfg.read_count,
            )
            cursor, messages = result[0], result[1]
            if not messages:
                break
            await self._process(client, messages)
            claimed_total += len(messages)
            if len(messages) < self.cfg.read_count:
                break
        if claimed_total:
            log.info("durable_orphans_reclaimed", count=claimed_total)

    async def _process(self, client: Any, messages: list) -> None:
        """Persist a batch THROUGH THE EXISTING WRITER, then ACK — the ACK
        happens only after the DB persist (write + flush). A failure leaves
        the entries pending (redelivered later); after max_deliveries they
        are dead-lettered (never silently dropped)."""
        writer = self._writer_inst()
        to_ack: list = []
        events: list = []
        for entry_id, fields in messages:
            payload = fields.get("payload") if isinstance(fields, dict) else None
            if not payload:
                await self._deadletter(client, entry_id, str(fields), "empty payload")
                continue
            try:
                event = _event_from_payload(payload)
            except Exception as e:  # noqa: BLE001 — a poison payload never loops
                await self._deadletter(client, entry_id, payload, f"unparseable payload: {e}")
                continue
            events.append(event)
            to_ack.append(entry_id)
        if not to_ack:
            return
        try:
            for event in events:
                await writer.write(event)
            # ACK only after the DB persist (write buffers; flush persists).
            await writer.flush()
        except Exception as e:  # noqa: BLE001 — redelivery is the durability guarantee
            log.warning("durable_persist_failed_redelivery", entries=len(to_ack), error=str(e))
            return  # leave pending — the writer's own file dead-letter also fired
        await client.xack(self.cfg.stream, self.cfg.consumer_group, *to_ack)
        log.debug("durable_batch_acked", entries=len(to_ack))

    async def _deadletter(self, client: Any, entry_id: Any, payload: str, reason: str) -> None:
        """Move ONE poisoned entry to the dead-letter stream, then ACK the
        original (dead-letter PRESERVED, never silently dropped)."""
        try:
            await client.xadd(
                self.cfg.dead_letter_stream,
                {"payload": payload, "reason": reason, "attempts": "0"},
                maxlen=self.cfg.max_stream_length,
                approximate=True,
            )
            await client.xack(self.cfg.stream, self.cfg.consumer_group, entry_id)
            log.warning("durable_entry_dead_lettered", reason=reason, entry=str(entry_id))
        except Exception as e:  # noqa: BLE001 — DLQ failure must not crash the loop
            log.error("durable_dead_letter_failed", error=str(e))

    async def _deadletter_exhausted(self, client: Any) -> None:
        """Entries whose delivery count hit max_deliveries go to the DLQ."""
        try:
            pendings = await client.xpending_range(
                self.cfg.stream,
                self.cfg.consumer_group,
                min="-",
                max="+",
                count=100,
                idle=self.cfg.claim_idle_seconds * 1000,
            )
        except Exception as e:  # noqa: BLE001 — a pending-scan failure must not crash
            log.debug("durable_pending_scan_failed", error=str(e))
            return
        for p in pendings or []:
            if int(p.get("times_delivered", 0)) < self.cfg.max_deliveries:
                continue
            entry_id = p["message_id"]
            try:
                entries = await client.xrange(self.cfg.stream, min=entry_id, max=entry_id)
                payload = entries[0][1].get("payload", "<unreadable>") if entries else "<lost>"
                await client.xadd(
                    self.cfg.dead_letter_stream,
                    {
                        "payload": payload,
                        "reason": "max deliveries exceeded",
                        "attempts": str(p.get("times_delivered", 0)),
                    },
                    maxlen=self.cfg.max_stream_length,
                    approximate=True,
                )
                await client.xack(self.cfg.stream, self.cfg.consumer_group, entry_id)
                log.warning(
                    "durable_entry_dead_lettered", reason="max deliveries", entry=str(entry_id)
                )
            except Exception as e:  # noqa: BLE001 — retry on the next sweep
                log.error("durable_deadletter_move_failed", error=str(e))


def _event_from_payload(payload: str) -> Any:
    from src.ingestion.schemas import NormalizedEvent

    return NormalizedEvent.model_validate_json(payload)
