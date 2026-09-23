"""
Tests for Threat Intelligence v2.

Tests the threat intel clients, caching, enrichment, and stats.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.intel.threat_intel import (
    FEED_REFRESH_INTERVAL_HOURS,
    AbuseIPDBClient,
    OTXClient,
    URLhausClient,
    _map_ioc_type,
)


class TestIOCTypeMapping:
    """Test IOC type mapping from OTX types to our enum."""

    def test_ipv4_mapping(self):
        assert _map_ioc_type("IPv4") == "ip"

    def test_ipv6_mapping(self):
        assert _map_ioc_type("IPv6") == "ip"

    def test_url_mapping(self):
        assert _map_ioc_type("URL") == "url"

    def test_md5_mapping(self):
        assert _map_ioc_type("FileHash-MD5") == "hash_md5"

    def test_sha256_mapping(self):
        assert _map_ioc_type("FileHash-SHA256") == "hash_sha256"

    def test_unknown_mapping(self):
        assert _map_ioc_type("unknown_type") == ""


class TestAbuseIPDBClient:
    """Test AbuseIPDB client."""

    @pytest.mark.asyncio
    async def test_check_ip_no_api_key(self):
        """Should return None when no API key is configured."""
        with patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = None
            client = AbuseIPDBClient()
            # Re-check settings directly since AbuseIPDBClient reads at module level
            result = await client.check_ip("1.2.3.4")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_blacklist_no_api_key(self):
        """Should return empty list when no API key."""
        with patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = None
            client = AbuseIPDBClient()
            result = await client.get_blacklist()
            assert result == []


class TestURLhausClient:
    """Test URLhaus client."""

    @pytest.mark.asyncio
    async def test_check_url_no_results(self):
        """Should return None when URLhaus has no results.

        AUD-052: the TI clients use the process-shared per-loop client —
        the mock shape is direct-call (constructor patched, request called
        on the client); __aenter__/__aexit__ never happen."""
        client = URLhausClient()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"query_status": "no_results"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = await client.check_url("https://example.com/safe")
            assert result is None
            # Per-request timeout is pinned (the shared client's constructor
            # default is only a fallback).
            assert mock_client.post.call_args.kwargs.get("timeout") == 10.0


class TestOTXClient:
    """Test OTX client."""

    @pytest.mark.asyncio
    async def test_get_pulse_indicators_no_api_key(self):
        """Should return empty list when no OTX API key."""
        client = OTXClient(api_key=None)
        with patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.otx_api_key = None
            result = await client.get_pulse_indicators("test-pulse-id")
            assert result == []

    # Note (AUD-054, Wave 7): the get_subscribed_pulses tests were deleted
    # WITH the dead function itself — refresh uses get_modified_pulses and
    # nothing else ever consumed the subscription list.


class TestThreatIntelConfig:
    """Test threat intel configuration constants."""

    def test_refresh_interval(self):
        """Feed refresh should be every 6 hours."""
        assert FEED_REFRESH_INTERVAL_HOURS == 6


class TestThreatIntelStats:
    """Test threat intel statistics."""

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Stats should return correct structure."""
        from unittest.mock import MagicMock

        from src.intel.threat_intel import get_threat_intel_stats

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_acquirer = AsyncMock()
        mock_acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquirer.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire = MagicMock(return_value=mock_acquirer)

        mock_conn.fetchval.return_value = 42
        mock_conn.fetch.side_effect = [
            [{"ioc_type": "ip", "count": 30}, {"ioc_type": "url", "count": 12}],
            [{"source": "urlhaus", "count": 20}, {"source": "abuseipdb", "count": 22}],
        ]

        with patch("src.intel.threat_intel.get_pool", return_value=mock_pool):
            stats = await get_threat_intel_stats()
            assert "total_indicators" in stats
            assert "by_type" in stats
            assert "by_source" in stats
            assert "last_refresh" in stats
            assert "feed_status" in stats


class TestAirGappedScheduler:
    """P4.3: THREAT_INTEL_ENABLED=false disables all external feed egress."""

    @pytest.mark.asyncio
    async def test_scheduler_disabled_does_not_start_or_refresh(self):
        """When THREAT_INTEL_ENABLED is false, start_threat_intel_scheduler
        returns early: no scheduler is started and refresh_all_feeds is not
        fired (no external calls to URLhaus/AbuseIPDB/OTX)."""
        from src.intel import threat_intel

        threat_intel._async_scheduler = None  # reset
        with patch.object(threat_intel.settings, "threat_intel_enabled", False):
            with patch.object(threat_intel, "refresh_all_feeds", AsyncMock()) as mock_refresh:
                await threat_intel.start_threat_intel_scheduler()
                mock_refresh.assert_not_awaited()
                assert threat_intel._async_scheduler is None

    @pytest.mark.asyncio
    async def test_scheduler_enabled_starts_and_refreshes(self):
        """When enabled (default), the scheduler starts and the initial
        refresh fires as a background task (existing behaviour preserved).

        C4: TI no longer OWNS a scheduler — its job rides the shared
        instance (default jobstore, NOT the reload-scoped detection one).
        """
        from src.intel import threat_intel
        from src.services import shared_scheduler as shared_mod

        threat_intel._async_scheduler = None  # reset
        mock_shared = MagicMock()
        mock_shared.running = False

        with patch.object(threat_intel.settings, "threat_intel_enabled", True):
            with patch.object(shared_mod, "_scheduler", mock_shared):
                with patch.object(threat_intel, "refresh_all_feeds", AsyncMock()) as mock_refresh:
                    with patch.object(threat_intel.asyncio, "create_task"):
                        await threat_intel.start_threat_intel_scheduler()
                        mock_shared.add_job.assert_called_once()
                        call = mock_shared.add_job.call_args
                        assert call.kwargs["id"] == "threat_intel_refresh"
                        # ops jobs use the DEFAULT store — a detection reload
                        # (which clears only the detection store) must never
                        # wipe the TI refresh.
                        assert call.kwargs.get("jobstore") is None
                        mock_shared.start.assert_called_once()
                        mock_refresh.assert_not_awaited()  # create_task wraps it

    @pytest.mark.asyncio
    async def test_scheduler_constructed_with_misfire_job_defaults(self):
        """W1-G (C4 home): the ONE shared scheduler carries the misfire
        defaults — the three per-module constructions are gone."""
        from unittest.mock import ANY

        from src.services import shared_scheduler as shared_mod

        with (
            patch.object(shared_mod, "_scheduler", None),
            patch.object(shared_mod, "AsyncIOScheduler") as mock_cls,
        ):
            sched = shared_mod.get_shared_scheduler()
            mock_cls.assert_called_once_with(
                jobstores={"detection": ANY},
                job_defaults={"misfire_grace_time": 60, "coalesce": True, "max_instances": 1},
            )
            assert sched is shared_mod._scheduler


class TestInitialRefreshTaskRef:
    """W2-E/B6 — the initial feed refresh is no longer an unreferenced
    fire-and-forget task: the module keeps the reference (F-17) and the
    done-callback discards + retrieves the exception."""

    @pytest.mark.asyncio
    async def test_initial_refresh_retained_and_exception_surfaced(self, monkeypatch):
        """Ref retained while in flight; a failing refresh LOGS its exception
        (retrieved — not swallowed, not 'never retrieved' loop noise) and the
        set entry is discarded on completion."""
        import asyncio

        from src.intel import threat_intel

        threat_intel._async_scheduler = None
        threat_intel._initial_refresh_tasks.clear()

        async def failing_refresh():
            await asyncio.sleep(0.01)
            raise RuntimeError("feed refresh exploded")

        events: list[tuple] = []

        class _Rec:
            @staticmethod
            def error(event, **kw):
                events.append((event, kw))

            @staticmethod
            def info(event, **kw):
                pass

        monkeypatch.setattr(threat_intel, "log", _Rec())

        # C4: no global AsyncIOScheduler patch — TI adds its job to the REAL
        # shared scheduler (fresh per test via the conftest reset).
        with (
            patch.object(threat_intel.settings, "threat_intel_enabled", True),
            patch.object(threat_intel, "refresh_all_feeds", failing_refresh),
        ):
            await threat_intel.start_threat_intel_scheduler()
            assert len(threat_intel._initial_refresh_tasks) == 1  # ref RETAINED

            await asyncio.sleep(0.1)  # let the task fail + done-callback run

        assert events == [
            (
                "threat_intel_initial_refresh_failed",
                {"error": "feed refresh exploded"},
            )
        ]  # exception SURFACED, not swallowed
        assert len(threat_intel._initial_refresh_tasks) == 0  # discarded after done
