"""
Tests for Threat Intelligence v2.

Tests the threat intel clients, caching, enrichment, and stats.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.intel.threat_intel import (
    AbuseIPDBClient,
    URLhausClient,
    OTXClient,
    _map_ioc_type,
    FEED_REFRESH_INTERVAL_HOURS,
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
        """Should return None when URLhaus has no results."""
        client = URLhausClient()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"query_status": "no_results"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = await client.check_url("https://example.com/safe")
            assert result is None


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

    @pytest.mark.asyncio
    async def test_get_subscribed_pulses_no_api_key(self):
        """Should return empty list when no OTX API key."""
        client = OTXClient(api_key=None)
        with patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.otx_api_key = None
            result = await client.get_subscribed_pulses()
            assert result == []


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
        from src.intel.threat_intel import get_threat_intel_stats
        from unittest.mock import MagicMock

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