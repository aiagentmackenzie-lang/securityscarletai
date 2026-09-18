"""Phase-5 runtime-resilience tests (F-03 / F-10 / F-16 / F-17 / F-18 / F-20).

- F-03: reverse DNS runs OFF the event loop (bounded thread pool).
- F-10: correlation runs capped + coalesced + INSERT-dedup (24h window, covering the lookback).
- F-16: WS broadcasts honor per-connection filters; client registry capped.
- F-17: fire-and-forget tasks kept referenced (module-level registry).
- F-20: a missing sigma selection parses as FALSE (fail-safe), never TRUE.
"""

from __future__ import annotations

import asyncio  # noqa: F401 — used via pytest-asyncio
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
os.environ.setdefault("API_SECRET_KEY", "x" * 64)
os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)


# ───────────────────────────────────────────────────────────────
# F-03 — reverse DNS off the loop
# ───────────────────────────────────────────────────────────────


class TestReverseDnsOffLoop:
    @pytest.mark.asyncio
    async def test_async_variant_returns_enrichment(self, monkeypatch):
        from src.enrichment import pipeline

        monkeypatch.setattr(
            pipeline,
            "_resolve_reverse",
            lambda ip: {"dns": {"reverse": "host.example.com"}},
        )
        out = await pipeline.enrich_dns_reverse_async("8.8.8.8")
        assert out == {"dns": {"reverse": "host.example.com"}}

    @pytest.mark.asyncio
    async def test_private_ip_skips_lookup_entirely(self, monkeypatch):
        from src.enrichment import pipeline

        called = {"n": 0}

        def boom(ip):
            called["n"] += 1
            raise AssertionError("must not resolve private ips")

        monkeypatch.setattr(pipeline, "_resolve_reverse", boom)
        out = await pipeline.enrich_dns_reverse_async("10.0.0.5")
        assert out == {}
        assert called["n"] == 0  # never touched the resolver

    def test_executor_is_bounded(self):
        from src.enrichment.pipeline import (
            _DNS_EXECUTOR_MAX_WORKERS,
            _get_dns_executor,
        )

        ex = _get_dns_executor()
        assert ex._max_workers == _DNS_EXECUTOR_MAX_WORKERS
        assert _DNS_EXECUTOR_MAX_WORKERS <= 8  # bounded, not dozens


# ───────────────────────────────────────────────────────────────
# F-20 — missing selection parses FALSE
# ───────────────────────────────────────────────────────────────


class TestSigmaMissingSelection:
    def test_missing_selection_is_false_not_true(self):
        from src.detection.sigma import SigmaParser

        parser = SigmaParser()
        out = parser._parse_selection("nonexistent_selection", {"title": "x"})
        assert out == "FALSE"


# ───────────────────────────────────────────────────────────────
# F-16 — WS broadcast filters + registry cap
# ───────────────────────────────────────────────────────────────


from starlette.websockets import WebSocketState


class _FakeWS:
    """Minimal WebSocket stand-in for broadcast tests."""

    def __init__(self) -> None:
        self.client_state = WebSocketState.CONNECTED
        self.sent: list[dict] = []

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)


@pytest.fixture()
def ws_module():
    import src.api.websocket as websocket

    websocket._connected_clients.clear()
    websocket._client_filters.clear()
    yield websocket
    websocket._connected_clients.clear()
    websocket._client_filters.clear()


def _event(
    host: str = "web-server-01", severity: str = "high", category: str = "process"
) -> "NormalizedEvent":  # noqa: F821
    from src.ingestion.schemas import NormalizedEvent

    return NormalizedEvent(
        **{
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "host_name": host,
            "source": "osquery",
            "event_category": category,
            "event_type": "process_create",
            "severity": severity,
            "raw_data": {},
        }
    )


class TestWSBroadcastFilters:
    @pytest.mark.asyncio
    async def test_host_filter_blocks_non_matching(self, ws_module):
        from src.api.websocket import broadcast_event

        ws = _FakeWS()
        async with ws_module._clients_lock:
            ws_module._connected_clients.append(ws)
            ws_module._client_filters[ws] = {
                "host_filter": "db-prod",
                "category_filter": None,
                "severity_filter": None,
            }

        await broadcast_event(_event(host="web-server-01"))
        assert ws.sent == []  # filtered out

        await broadcast_event(_event(host="db-prod-02"))
        assert len(ws.sent) == 1  # matching host delivered

    @pytest.mark.asyncio
    async def test_no_filters_receives_everything(self, ws_module):
        from src.api.websocket import broadcast_event

        ws = _FakeWS()
        async with ws_module._clients_lock:
            ws_module._connected_clients.append(ws)
            ws_module._client_filters[ws] = {
                "host_filter": None,
                "category_filter": None,
                "severity_filter": None,
            }
        await broadcast_event(_event())
        assert len(ws.sent) == 1

    def test_registry_cap_constant(self, ws_module):
        from src.api.websocket import MAX_WEBSOCKET_CLIENTS

        assert MAX_WEBSOCKET_CLIENTS <= 200  # sane hard cap exists


# ───────────────────────────────────────────────────────────────
# F-10 — correlation cap + coalescing + dedup
# ───────────────────────────────────────────────────────────────


class TestCorrelationBounds:
    def test_semaphore_and_task_registry_wiring(self):
        import inspect

        from src.api import ingest
        from src.detection import correlation as corr

        # AUD-016: ingest no longer re-exports the correlation guard — the
        # cap lives ONCE in src.detection.correlation and the ingest path
        # delegates to the shared trigger.
        assert isinstance(corr._correlation_semaphore, asyncio.Semaphore)
        assert corr.CORRELATION_MAX_CONCURRENT == 2
        assert isinstance(ingest._post_process_tasks, set)
        src = inspect.getsource(ingest)
        assert "_post_process_tasks.add(task)" in src  # F-17 strong ref
        assert "task.add_done_callback(_post_process_tasks.discard)" in src
        # F-18: both ips participate in the write-back predicate — since W2.2
        # the write-back is the SHARED builder (used by the durable consumer
        # too), so the predicate lives there; the ingest module must DELEGATE
        # to it (no drift between the two paths).
        from src.enrichment import pipeline as _ep

        shared = inspect.getsource(_ep)
        assert "source_ip::text" in shared
        assert "destination_ip::text" in shared
        assert "write_back_enrichment(batch_events)" in src

    @pytest.mark.asyncio
    async def test_correlation_dedupe_skips_insert(self):
        """A duplicate (rule, trigger, payload) inside the 24h dedup window is
        not persisted twice — this was unbounded per batch before F-10."""
        from src.detection import correlation as corr

        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        conn.fetchval = AsyncMock(return_value=1)  # dupe found
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool = MagicMock()
        pool.acquire = MagicMock(return_value=acquirer)

        match = {
            "correlation_rule": "payload_callback",
            "severity": "high",
            "host_name": "h",
            "title": "t",
            "trigger_event_id": 42,
            "mitre_tactics": [],
            "mitre_techniques": [],
        }

        no_matches = AsyncMock(return_value=[])

        async def mock_detect_correlations_stub(*args, **kwargs):
            return []

        # run_all resolves detectors through the module registry (AUD-039) —
        # patch the REGISTRY; patch-by-name would silently not apply.
        registry_override = {name: no_matches for name in corr.CORRELATION_DETECTORS}
        registry_override["payload_callback"] = AsyncMock(return_value=[match])
        with (
            patch.object(corr, "get_pool", AsyncMock(return_value=pool)),
            patch.dict(corr.CORRELATION_DETECTORS, registry_override),
            patch.object(corr, "create_alert", AsyncMock()),
        ):
            result = await corr.run_all_correlations(
                as_of=datetime(2026, 8, 28, tzinfo=timezone.utc), persist=True
            )

        assert result["total_matches"] == 1
        assert result["persisted"] == 0  # dupe suppressed
        conn.execute.assert_not_called()  # INSERT never ran

    @pytest.mark.asyncio
    async def test_non_dupe_still_persists(self):
        from src.detection import correlation as corr

        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        conn.fetchval = AsyncMock(return_value=None)  # no dupe
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool = MagicMock()
        pool.acquire = MagicMock(return_value=acquirer)

        match = {
            "correlation_rule": "payload_callback",
            "severity": "high",
            "host_name": "h",
            "title": "t",
            "trigger_event_id": 7,
            "mitre_tactics": [],
            "mitre_techniques": [],
        }

        no_matches = AsyncMock(return_value=[])

        # run_all resolves detectors through the module registry (AUD-039) —
        # patch the REGISTRY; patch-by-name would silently not apply.
        registry_override = {name: no_matches for name in corr.CORRELATION_DETECTORS}
        registry_override["payload_callback"] = AsyncMock(return_value=[match])
        with (
            patch.object(corr, "get_pool", AsyncMock(return_value=pool)),
            patch.dict(corr.CORRELATION_DETECTORS, registry_override),
            patch.object(corr, "create_alert", AsyncMock()),
        ):
            result = await corr.run_all_correlations(
                as_of=datetime(2026, 8, 28, tzinfo=timezone.utc), persist=True
            )

        assert result["persisted"] == 1
        conn.execute.assert_awaited_once()


class TestSharedCoalescingTrigger:
    """The coalescing state moved to src.detection.correlation so the
    scheduler's sweep shares the SAME inflight guard as the ingest path."""

    @pytest.mark.asyncio
    async def test_ingest_and_sweep_share_one_semaphore(self):
        from src.api import ingest
        from src.detection import correlation as corr

        # AUD-016: the sharing is now BY DELEGATION — ingest's trigger IS
        # the correlation module's own (single inflight guard, single cap).
        assert ingest.trigger_correlation_coalesced is corr.trigger_correlation_coalesced
        assert isinstance(corr._correlation_semaphore, asyncio.Semaphore)

    @pytest.mark.asyncio
    async def test_second_call_while_inflight_is_coalesced(self):
        """A request arriving during an in-flight run skips (the shared
        trigger's core contract, now also exercised by the sweep)."""
        from src.detection import correlation as corr

        started = asyncio.Event()
        release = asyncio.Event()
        runs: list[int] = []

        async def fake_run_all(persist=False):
            runs.append(1)
            started.set()
            await release.wait()

        with (
            patch.object(corr, "run_all_correlations", fake_run_all),
            patch.object(corr, "get_pool", AsyncMock()),
        ):
            first = asyncio.create_task(corr.trigger_correlation_coalesced())
            await asyncio.wait_for(started.wait(), timeout=2)
            second = asyncio.create_task(corr.trigger_correlation_coalesced())
            await asyncio.sleep(0.05)
            release.set()
            await asyncio.wait_for(asyncio.gather(first, second), timeout=5)

        assert len(runs) == 1  # the second call was coalesced away
        assert corr._correlation_inflight is False  # state resets after the run


class TestDedupWindowCoversLookback:
    """2026-09-12 live finding: at a 15-min dedup window the SAME finding
    re-persisted every 15 min while its source events stayed in the 24h
    lookback (1,048 copies of the real host's credential_theft_exfil
    findings in 71 minutes). A finding is one finding per lookback
    lifetime."""

    @pytest.mark.asyncio
    async def test_identical_finding_from_20_min_ago_is_still_deduped(self):
        from src.detection import correlation as corr

        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        # The dupe probe now finds the 20-minute-old copy (the old 15-min
        # window would have let it through and re-persisted).
        conn.fetchval = AsyncMock(return_value=1)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool = MagicMock()
        pool.acquire = MagicMock(return_value=acquirer)

        match = {
            "correlation_rule": "credential_theft_exfil",
            "severity": "high",
            "host_name": "h",
            "title": "t",
            "trigger_event_id": None,
            "mitre_tactics": [],
            "mitre_techniques": [],
        }
        persisted: list = []

        async def fake_execute(q, *a):
            persisted.append(1)
            return "INSERT 0 1"

        conn.execute = fake_execute

        async def no_matches(*args, **kwargs):
            return []

        # run_all resolves detectors through the module registry (AUD-039) —
        # patch the REGISTRY; patch-by-name would silently not apply.
        registry_override = {name: no_matches for name in corr.CORRELATION_DETECTORS}
        registry_override["credential_theft_exfil"] = AsyncMock(return_value=[match])
        with (
            patch.object(corr, "get_pool", AsyncMock(return_value=pool)),
            patch.dict(corr.CORRELATION_DETECTORS, registry_override),
            patch.object(corr, "create_alert", AsyncMock()),
        ):
            result = await corr.run_all_correlations(persist=True)

        assert result["persisted"] == 0  # the 20-min-old identical finding was deduped
        assert persisted == []
        # and the dedup query really uses the 24h window:
        assert "'24 hours'" in conn.fetchval.call_args[0][0]
