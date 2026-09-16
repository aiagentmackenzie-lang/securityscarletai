"""Tests for the durable ingest buffer (W2.2) — Redis Streams between the
API ingest path and the batched writer.

Covers:
- config loading/validation (versioned, fail-closed, OFF by default)
- the persist_event seam (disabled → writer; enabled → stream; Redis down →
  DurableIngestUnavailable → the API fails closed 503)
- the consumer: XADD → write+flush → ACK after persist; poison payloads →
  dead-letter stream + ACK (never silently dropped); redelivery on writer
  failure; orphan reclaim; exhausted deliveries dead-lettered
- the API contract in durable mode (503 on unavailable probe; default mode
  byte-identical)
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.ingestion.durable import (
    DurableConfigError,
    DurableIngest,
    DurableIngestConfig,
    DurableIngestUnavailable,
    configure_durable,
    durable_mode,
    durable_redis_probe,
    load_durable_config,
    persist_event,
)
from src.services.writer import writer as writer_singleton


def _event(host: str = "h1") -> object:
    from src.ingestion.schemas import NormalizedEvent

    return NormalizedEvent(
        timestamp=datetime.now(tz=timezone.utc),
        host_name=host,
        event_category="process",
        event_type="start",
        source="syslog",
        raw_data={"k": "v"},
    )


# ───────────────────────────────────────────────────────────────
# A minimal in-memory fake of the redis-py async stream API
# ───────────────────────────────────────────────────────────────


class FakeRedis:
    def __init__(self, fail_xadd: bool = False):
        self.streams: dict = defaultdict(list)
        self.groups: set = set()
        self.acked: set = set()
        self.delivered: set = set()
        self.pending: dict = {}  # id -> times_delivered
        self._id = 0
        self.fail_xadd = fail_xadd
        self.on_ack = None
        self.pings = 0

    async def ping(self):
        self.pings += 1
        return True

    async def xgroup_create(self, name, group, id="0", mkstream=False):
        if (name, group) in self.groups:
            raise RuntimeError("BUSYGROUP Consumer Group name already exists")
        self.groups.add((name, group))

    async def xadd(self, name, fields, maxlen=None, approximate=False):
        if self.fail_xadd:
            raise ConnectionError("redis down")
        self._id += 1
        entry_id = f"{self._id}-0"
        self.streams[name].append((entry_id, dict(fields)))
        return entry_id

    async def xreadgroup(self, group, consumer, streams, count=None, block=None):
        await asyncio.sleep(0)  # a real blocked read yields to the loop
        name = next(iter(streams))
        out = []
        for entry_id, fields in self.streams[name]:
            if entry_id in self.delivered or entry_id in self.acked:
                continue
            out.append((entry_id, fields))
            self.delivered.add(entry_id)
            self.pending[entry_id] = self.pending.get(entry_id, 0) + 1
            if count and len(out) >= count:
                break
        return [(name, out)] if out else []

    async def xack(self, name, group, *ids):
        for i in ids:
            self.acked.add(i)
            self.pending.pop(i, None)
        if self.on_ack:
            self.on_ack()

    async def xautoclaim(self, name, group, consumer, min_idle_time=0, start_id="0-0", count=None):
        await asyncio.sleep(0)  # a real claim yields to the loop
        # The fake delivers EVERY pending as claimable after start_id.
        out = []
        for entry_id, fields in self.streams[name]:
            if entry_id in self.pending and entry_id > start_id and entry_id not in self.acked:
                out.append((entry_id, fields))
                self.pending[entry_id] = self.pending.get(entry_id, 0) + 1
                if count and len(out) >= count:
                    break
        return ("0-0", out)

    async def xpending_range(self, name, group, min="-", max="+", count=100, idle=0):
        return [
            {"message_id": eid, "consumer": "c", "time_since_delivered": idle, "times_delivered": n}
            for eid, n in self.pending.items()
            if eid not in self.acked
        ][:count]

    async def xrange(self, name, min="-", max="+"):
        return [(eid, fields) for eid, fields in self.streams[name] if min <= eid <= max]


def _durable(cfg=None) -> DurableIngest:
    from src.ingestion.durable import DurableIngestConfig

    return DurableIngest(cfg or DurableIngestConfig(enabled=True), client_factory=_fake_client)


async def _fake_client():
    return FakeRedis()


# ───────────────────────────────────────────────────────────────
# Config (versioned, fail-closed, OFF by default)
# ───────────────────────────────────────────────────────────────


class TestConfig:
    def test_default_repo_config_loads_disabled(self):
        cfg = load_durable_config(
            Path(__file__).resolve().parents[2] / "config" / "durable_ingest.yaml"
        )
        assert cfg.enabled is False
        assert cfg.stream == "scarletai:ingest:events"

    def test_enabled_config_loads(self, tmp_path):
        p = tmp_path / "d.yaml"
        p.write_text(
            "schema_version: 1\ndurable_ingest:\n  enabled: true\n  stream: s\n"
            "  dead_letter_stream: d\n  consumer_group: g\n"
        )
        cfg = load_durable_config(p)
        assert cfg.enabled is True
        assert cfg.stream == "s"
        assert cfg.dead_letter_stream == "d"
        assert cfg.max_stream_length >= 1000

    def test_enabled_requires_stream_and_group(self, tmp_path):
        p = tmp_path / "d.yaml"
        p.write_text("schema_version: 1\ndurable_ingest:\n  enabled: true\n")
        with pytest.raises(DurableConfigError):
            load_durable_config(p)

    def test_dead_letter_must_differ(self, tmp_path):
        p = tmp_path / "d.yaml"
        p.write_text(
            "schema_version: 1\ndurable_ingest:\n  enabled: true\n  stream: s\n"
            "  dead_letter_stream: s\n  consumer_group: g\n"
        )
        with pytest.raises(DurableConfigError):
            load_durable_config(p)

    def test_bad_schema_version_refused(self, tmp_path):
        p = tmp_path / "d.yaml"
        p.write_text("schema_version: 2\ndurable_ingest:\n  enabled: false\n")
        with pytest.raises(DurableConfigError):
            load_durable_config(p)

    def test_max_stream_length_floor(self, tmp_path):
        p = tmp_path / "d.yaml"
        p.write_text(
            "schema_version: 1\ndurable_ingest:\n  enabled: true\n  stream: s\n"
            "  dead_letter_stream: d\n  consumer_group: g\n  max_stream_length: 10\n"
        )
        with pytest.raises(DurableConfigError):
            load_durable_config(p)

    def test_non_numeric_refused(self, tmp_path):
        p = tmp_path / "d.yaml"
        p.write_text(
            "schema_version: 1\ndurable_ingest:\n  enabled: true\n  stream: s\n"
            "  dead_letter_stream: d\n  consumer_group: g\n  max_deliveries: five\n"
        )
        with pytest.raises(DurableConfigError):
            load_durable_config(p)

    def test_consumer_name_defaults_to_hostname(self, tmp_path):
        p = tmp_path / "d.yaml"
        p.write_text(
            "schema_version: 1\ndurable_ingest:\n  enabled: true\n  stream: s\n"
            "  dead_letter_stream: d\n  consumer_group: g\n"
        )
        cfg = load_durable_config(p)
        assert cfg.consumer_name.startswith("siem-")


# ───────────────────────────────────────────────────────────────
# The persist seam
# ───────────────────────────────────────────────────────────────


class TestPersistSeam:
    async def test_disabled_uses_writer(self):
        configure_durable(None)
        with (
            patch.object(writer_singleton, "write", AsyncMock()) as write,
            patch.object(writer_singleton, "flush", AsyncMock()),
        ):
            await persist_event(_event())
            assert write.call_count == 1

    async def test_enabled_enqueues(self):
        fake = FakeRedis()
        instance = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_fake_client)
        configure_durable(instance)
        try:
            with patch.object(instance, "_client", AsyncMock(return_value=fake)):
                with patch.object(writer_singleton, "write", AsyncMock()) as w:
                    await persist_event(_event())
            assert w.call_count == 0  # NOT the writer — the stream
            assert len(fake.streams["scarletai:ingest:events"]) == 1
        finally:
            configure_durable(None)

    async def test_enabled_redis_down_fails_closed(self):
        async def _none():
            return None

        instance = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_none)
        configure_durable(instance)
        try:
            with pytest.raises(DurableIngestUnavailable):
                await persist_event(_event())
        finally:
            configure_durable(None)


async def _none():
    return None


class TestDurableModeFlag:
    def test_default_off(self):
        assert durable_mode() is False

    async def test_probe_true_when_disabled(self):
        assert await durable_redis_probe() is True

    async def test_probe_false_when_client_none(self):
        async def _none():
            return None

        instance = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_none)
        configure_durable(instance)
        try:
            assert await durable_redis_probe() is False
        finally:
            configure_durable(None)


# ───────────────────────────────────────────────────────────────
# The consumer: persist-then-ACK, dead-letter, reclaim
# ───────────────────────────────────────────────────────────────


class TestConsumer:
    async def test_persist_then_ack_after_flush(self):
        fake = FakeRedis()
        d = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_fake_client)
        with (
            patch.object(writer_singleton, "write", AsyncMock()) as w,
            patch.object(writer_singleton, "flush", AsyncMock()) as f,
            patch.object(d, "_client", AsyncMock(return_value=fake)),
        ):
            await d.enqueue(_event(host="consumer-test"))
            batch = await fake.xreadgroup(
                d.cfg.consumer_group, d.cfg.consumer_name, {d.cfg.stream: ">"}
            )
            assert batch and batch[0][1]
            await d._process(fake, batch[0][1])
            assert w.call_count == 1
            assert f.call_count == 1  # flush BEFORE ack
        assert len(fake.acked) == 1  # acked only after persist

    async def test_writer_failure_leaves_pending_no_ack(self):
        fake = FakeRedis()
        d = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_fake_client)
        with patch.object(d, "_client", AsyncMock(return_value=fake)):
            await d.enqueue(_event())
        batch = await fake.xreadgroup(
            d.cfg.consumer_group, d.cfg.consumer_name, {d.cfg.stream: ">"}
        )
        with (
            patch.object(writer_singleton, "write", AsyncMock(side_effect=RuntimeError("db down"))),
            patch.object(writer_singleton, "flush", AsyncMock()),
        ):
            await d._process(fake, batch[0][1])
        assert fake.acked == set()  # NOT acked — redelivery later
        assert len(fake.pending) == 1

    async def test_poison_payload_dead_lettered_and_acked(self):
        fake = FakeRedis()
        d = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_fake_client)
        await fake.xadd(d.cfg.stream, {"payload": "not-json-at-all"})
        batch = await fake.xreadgroup(
            d.cfg.consumer_group, d.cfg.consumer_name, {d.cfg.stream: ">"}
        )
        with patch.object(writer_singleton, "write", AsyncMock()) as w:
            await d._process(fake, batch[0][1])
        assert w.call_count == 0
        assert len(fake.streams[d.cfg.dead_letter_stream]) == 1
        assert len(fake.acked) == 1  # the poison entry is acked (DLQ'd)

    async def test_exhausted_deliveries_dead_lettered(self):
        fake = FakeRedis()
        d = DurableIngest(
            DurableIngestConfig(enabled=True, max_deliveries=2),
            client_factory=_fake_client,
        )
        await fake.xadd(d.cfg.stream, {"payload": _event().model_dump_json()})
        entry_id = fake.streams[d.cfg.stream][0][0]
        fake.pending[entry_id] = 5  # delivered 5 times (>= max)
        with patch.object(writer_singleton, "write", AsyncMock()):
            await d._deadletter_exhausted(fake)
        assert len(fake.streams[d.cfg.dead_letter_stream]) == 1
        assert entry_id in fake.acked
        assert fake.streams[d.cfg.dead_letter_stream][0][1]["attempts"] == "5"

    async def test_reclaim_processes_orphans(self):
        fake = FakeRedis()
        d = DurableIngest(
            DurableIngestConfig(enabled=True, claim_idle_seconds=1),
            client_factory=_fake_client,
        )
        with (
            patch.object(writer_singleton, "write", AsyncMock()) as w,
            patch.object(writer_singleton, "flush", AsyncMock()),
        ):
            await fake.xadd(d.cfg.stream, {"payload": _event(host="orphan").model_dump_json()})
            # Simulate a crashed consumer's pending entry (delivered once).
            fake.delivered.add(fake.streams[d.cfg.stream][0][0])
            fake.pending[fake.streams[d.cfg.stream][0][0]] = 1
            await d._reclaim(fake)
            assert w.call_count == 1

    async def test_run_loop_exits_on_stop(self):
        import asyncio

        d = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_fake_client)
        stop = asyncio.Event()
        stop.set()  # exit immediately
        await d.run(stop)  # must return promptly

    async def test_run_survives_redis_outage_then_processes(self):
        import asyncio

        # The consumer waits while Redis is down, then processes once back.
        fake = FakeRedis()
        state = {"up": False}

        async def flaky():
            return fake if state["up"] else None

        d = DurableIngest(DurableIngestConfig(enabled=True, read_block_ms=10), client_factory=flaky)
        stop = asyncio.Event()
        await fake.xadd(d.cfg.stream, {"payload": _event(host="outage").model_dump_json()})
        with (
            patch.object(writer_singleton, "write", AsyncMock()) as w,
            patch.object(writer_singleton, "flush", AsyncMock()),
            # Shrink the outage backoff (production waits 5s between probes).
            patch.object(
                DurableIngest,
                "_wait",
                staticmethod(lambda stop, timeout: asyncio.sleep(0.01)),
            ),
        ):
            task = asyncio.create_task(d.run(stop))
            await asyncio.sleep(0.05)  # first pass: Redis "down"
            assert w.call_count == 0
            state["up"] = True
            for _ in range(60):
                await asyncio.sleep(0.01)
                if w.call_count > 0:
                    break
            stop.set()
            await task
        assert w.call_count == 1

    async def test_enqueue_roundtrip_payload(self):
        fake = FakeRedis()
        d = DurableIngest(DurableIngestConfig(enabled=True), client_factory=_fake_client)
        with patch.object(d, "_client", AsyncMock(return_value=fake)):
            await d.enqueue(_event(host="rt"))
        stored = fake.streams[d.cfg.stream][0][1]["payload"]
        from src.ingestion.schemas import NormalizedEvent

        parsed = NormalizedEvent.model_validate_json(stored)
        assert parsed.host_name == "rt"


# ───────────────────────────────────────────────────────────────
# The API contract in durable mode
# ───────────────────────────────────────────────────────────────


class TestApiFailClosed:
    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.auth import get_ingest_client
        from src.api.ingest import router

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        app.dependency_overrides[get_ingest_client] = lambda: {
            "username": "test",
            "kind": "service",
        }
        return TestClient(app)

    def _payload(self) -> dict:
        return {
            "@timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "host_name": "s1",
            "source": "syslog",
            "event_category": "process",
            "event_type": "start",
        }

    def test_durable_mode_redis_down_503(self, client):
        async def _probe_false():
            return False

        with (
            patch("src.ingestion.durable.durable_mode", return_value=True),
            patch("src.ingestion.durable.durable_redis_probe", _probe_false),
        ):
            resp = client.post("/api/v1/ingest", json=[self._payload()])
        assert resp.status_code == 503
        assert "fail-closed" in resp.json()["detail"]

    def test_durable_mode_redis_up_202(self, client):
        async def _enqueue_ok(event):
            return None

        async def _probe_true():
            return True

        with (
            patch("src.ingestion.durable.durable_mode", return_value=True),
            patch("src.ingestion.durable.durable_redis_probe", _probe_true),
            patch("src.ingestion.durable.persist_event", _enqueue_ok),
        ):
            resp = client.post("/api/v1/ingest", json=[self._payload()])
        assert resp.status_code == 202

    def test_disabled_mode_unchanged(self, client):
        from src.services.writer import writer as ws

        with (
            patch("src.ingestion.durable.durable_mode", return_value=False),
            patch.object(ws, "write", AsyncMock()),
            patch.object(ws, "flush", AsyncMock()),
        ):
            resp = client.post("/api/v1/ingest", json=[self._payload()])
        assert resp.status_code == 202
