"""Phase-5 runtime-resilience tests (F-03 / F-10 / F-16 / F-17 / F-18 / F-20).

- F-03: reverse DNS runs OFF the event loop (bounded thread pool).
- F-10: correlation runs capped + coalesced + INSERT-dedup (15-min window).
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


def _event(host: str = "web-server-01", severity: str = "high",
           category: str = "process") -> "NormalizedEvent":  # noqa: F821
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

        assert isinstance(ingest._correlation_semaphore, asyncio.Semaphore)
        assert ingest.CORRELATION_MAX_CONCURRENT == 2
        assert isinstance(ingest._post_process_tasks, set)
        src = inspect.getsource(ingest)
        assert "_post_process_tasks.add(task)" in src  # F-17 strong ref
        assert "task.add_done_callback(_post_process_tasks.discard)" in src
        # F-18: both ips participate in the write-back predicate
        assert "source_ip::text" in src
        assert "destination_ip::text" in src

    @pytest.mark.asyncio
    async def test_correlation_dedupe_skips_insert(self):
        """A duplicate (rule, trigger, payload) inside the 15-min window is
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

        with patch.object(
            corr, "get_pool", AsyncMock(return_value=pool)
        ), patch.object(
            corr, "detect_payload_callback", AsyncMock(return_value=[match])
        ), patch.object(
            corr, "detect_brute_force_then_success", no_matches
        ), patch.object(
            corr, "detect_persistence_activated", no_matches
        ), patch.object(
            corr, "detect_data_exfiltration", no_matches
        ), patch.object(
            corr, "detect_privilege_escalation_chain", no_matches
        ), patch.object(
            corr, "detect_credential_theft_exfil", no_matches
        ), patch.object(
            corr, "detect_defense_evasion_cleanup", no_matches
        ), patch.object(corr, "create_alert", AsyncMock()):
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

        with patch.object(
            corr, "get_pool", AsyncMock(return_value=pool)
        ), patch.object(
            corr, "detect_payload_callback", AsyncMock(return_value=[match])
        ), patch.object(
            corr, "detect_brute_force_then_success", no_matches
        ), patch.object(
            corr, "detect_persistence_activated", no_matches
        ), patch.object(
            corr, "detect_data_exfiltration", no_matches
        ), patch.object(
            corr, "detect_privilege_escalation_chain", no_matches
        ), patch.object(
            corr, "detect_credential_theft_exfil", no_matches
        ), patch.object(
            corr, "detect_defense_evasion_cleanup", no_matches
        ), patch.object(corr, "create_alert", AsyncMock()):
            result = await corr.run_all_correlations(
                as_of=datetime(2026, 8, 28, tzinfo=timezone.utc), persist=True
            )

        assert result["persisted"] == 1
        conn.execute.assert_awaited_once()
