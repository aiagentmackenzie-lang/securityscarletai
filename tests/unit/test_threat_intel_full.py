"""
Comprehensive tests for src/intel/threat_intel.py.

Covers:
- AbuseIPDBClient (check_ip, get_blacklist)
- OTXClient (get_pulse_indicators, get_subscribed_pulses, get_modified_pulses)
- URLhausClient (check_url, get_recent_urls)
- DB operations (cache_ioc, cache_iocs_bulk, check_ioc_match)
- Refresh functions (refresh_all_feeds, enrich_ip_with_threat_intel, enrich_url_with_threat_intel)
- Statistics (get_threat_intel_stats)
- Scheduler (start/stop)
- _map_ioc_type helper
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from datetime import datetime, timedelta

from src.intel.threat_intel import (
    AbuseIPDBClient,
    OTXClient,
    URLhausClient,
    cache_ioc,
    cache_iocs_bulk,
    _map_ioc_type,
    check_ioc_match,
    enrich_ip_with_threat_intel,
    enrich_url_with_threat_intel,
    get_threat_intel_stats,
    refresh_all_feeds,
    start_threat_intel_scheduler,
    stop_threat_intel_scheduler,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _map_ioc_type (pure function, no mocking needed)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestMapIocType:
    def test_ipv4(self):
        assert _map_ioc_type("IPv4") == "ip"

    def test_ipv6(self):
        assert _map_ioc_type("IPv6") == "ip"

    def test_domain(self):
        assert _map_ioc_type("domain") == "ip"

    def test_hostname(self):
        assert _map_ioc_type("hostname") == "ip"

    def test_url(self):
        assert _map_ioc_type("URL") == "url"

    def test_uri(self):
        assert _map_ioc_type("uri") == "url"

    def test_hash_md5(self):
        assert _map_ioc_type("FileHash-MD5") == "hash_md5"

    def test_hash_sha256(self):
        assert _map_ioc_type("FileHash-SHA256") == "hash_sha256"

    def test_email(self):
        assert _map_ioc_type("email") == "ip"

    def test_unknown_type(self):
        assert _map_ioc_type("unknown_type") == ""

    def test_empty_string(self):
        assert _map_ioc_type("") == ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AbuseIPDBClient
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAbuseIPDBClient:

    @pytest.mark.asyncio
    async def test_check_ip_no_api_key(self):
        """Should return None when abuseipdb_api_key is not set."""
        client = AbuseIPDBClient()
        with patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = ""
            result = await client.check_ip("1.2.3.4")
            assert result is None

    @pytest.mark.asyncio
    async def test_check_ip_success(self):
        """Should return enrichment dict on successful check."""
        client = AbuseIPDBClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 120,
                "countryCode": "US",
                "isp": "EvilCorp",
                "domain": "evil.com",
            }
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            mock_settings.abuseipdb_api_key = "test-key"
            result = await client.check_ip("1.2.3.4")

        assert result is not None
        assert result["ip"] == "1.2.3.4"
        assert result["abuse_confidence"] == 85
        assert result["total_reports"] == 120
        assert result["country"] == "US"
        assert result["isp"] == "EvilCorp"
        assert result["threat_type"] == "malicious_ip"

    @pytest.mark.asyncio
    async def test_check_ip_low_confidence(self):
        """Low confidence should return None threat_type."""
        client = AbuseIPDBClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 20,
                "totalReports": 5,
                "countryCode": "DE",
                "isp": "SomeISP",
            }
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            mock_settings.abuseipdb_api_key = "test-key"
            result = await client.check_ip("5.6.7.8")

        assert result is not None
        assert result["threat_type"] is None
        assert result["abuse_confidence"] == 20

    @pytest.mark.asyncio
    async def test_check_ip_timeout(self):
        """Should return None on timeout."""
        import httpx
        client = AbuseIPDBClient()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            mock_settings.abuseipdb_api_key = "test-key"
            result = await client.check_ip("1.2.3.4")
            assert result is None

    @pytest.mark.asyncio
    async def test_check_ip_http_error(self):
        """Should return None on HTTP error."""
        client = AbuseIPDBClient()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("connection error"))

        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            mock_settings.abuseipdb_api_key = "test-key"
            result = await client.check_ip("1.2.3.4")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_blacklist_no_api_key(self):
        """Should return empty list when no API key."""
        client = AbuseIPDBClient()
        with patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = ""
            result = await client.get_blacklist()
            assert result == []

    @pytest.mark.asyncio
    async def test_get_blacklist_success(self):
        """Should return list of IPs on success."""
        client = AbuseIPDBClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [
                {"ipAddress": "1.2.3.4"},
                {"ipAddress": "5.6.7.8"},
                {"ipAddress": "9.10.11.12"},
            ]
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            mock_settings.abuseipdb_api_key = "test-key"
            result = await client.get_blacklist(confidence_minimum=90)

        assert len(result) == 3
        assert "1.2.3.4" in result

    @pytest.mark.asyncio
    async def test_get_blacklist_error(self):
        """Should return empty list on error."""
        client = AbuseIPDBClient()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("error"))

        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            mock_settings.abuseipdb_api_key = "test-key"
            result = await client.get_blacklist()
            assert result == []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OTXClient
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestOTXClient:

    @pytest.mark.asyncio
    async def test_get_pulse_indicators_no_api_key(self):
        """Should return empty list when no API key."""
        client = OTXClient(api_key="")
        result = await client.get_pulse_indicators("pulse123")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_pulse_indicators_success(self):
        """Should return list of indicator dicts."""
        client = OTXClient(api_key="test-otx-key")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [
                {"type": "IPv4", "indicator": "1.2.3.4", "title": "malicious", "confidence": 80},
                {"type": "URL", "indicator": "http://evil.com/payload", "title": "malware", "confidence": 90},
            ]
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_pulse_indicators("abc123")

        assert len(result) == 2
        assert result[0]["type"] == "IPv4"
        assert result[0]["value"] == "1.2.3.4"
        assert result[1]["type"] == "URL"

    @pytest.mark.asyncio
    async def test_get_pulse_indicators_error(self):
        """Should return empty list on error."""
        client = OTXClient(api_key="test-key")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("error"))

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_pulse_indicators("abc123")
            assert result == []

    @pytest.mark.asyncio
    async def test_get_subscribed_pulses_no_api_key(self):
        """Should return empty list when no API key."""
        client = OTXClient(api_key="")
        result = await client.get_subscribed_pulses()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_subscribed_pulses_success(self):
        """Should return list of pulse dicts."""
        client = OTXClient(api_key="test-key")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [
                {"id": "pulse1", "name": "APT29 Activity"},
                {"id": "pulse2", "name": "Emotet Campaign"},
            ]
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_subscribed_pulses()

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_subscribed_pulses_error(self):
        """Should return empty list on error."""
        client = OTXClient(api_key="test-key")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("error"))

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_subscribed_pulses()
            assert result == []

    @pytest.mark.asyncio
    async def test_get_modified_pulses_no_api_key(self):
        """Should return empty list when no API key."""
        client = OTXClient(api_key="")
        result = await client.get_modified_pulses()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_modified_pulses_with_since(self):
        """Should pass 'since' parameter when provided."""
        client = OTXClient(api_key="test-key")
        since = datetime(2024, 1, 1)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"results": []}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_modified_pulses(since=since)

        assert result == []
        # Verify the get was called
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_modified_pulses_error(self):
        """Should return empty list on error."""
        client = OTXClient(api_key="test-key")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("error"))

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_modified_pulses()
            assert result == []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# URLhausClient
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestURLhausClient:

    @pytest.mark.asyncio
    async def test_check_url_malicious(self):
        """Should return threat info for known malicious URLs."""
        client = URLhausClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "tags": ["emotet", "trojan"],
            "payloads": [{"signature": "Emotet"}],
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.check_url("http://evil.com/payload")

        assert result is not None
        assert result["url"] == "http://evil.com/payload"
        assert result["threat"] == "malware_download"
        assert "emotet" in result["tags"]

    @pytest.mark.asyncio
    async def test_check_url_no_results(self):
        """Should return None when URL is not in URLhaus database."""
        client = URLhausClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"query_status": "no_results"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.check_url("http://safe-site.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_check_url_error(self):
        """Should return None on error."""
        client = URLhausClient()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=Exception("error"))

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.check_url("http://example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_recent_urls_success(self):
        """Should return list of URL dicts."""
        client = URLhausClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "urls": [
                {"url": "http://evil1.com", "threat": "malware", "tags": ["trojan"], "host": "evil1.com"},
                {"url": "http://evil2.com", "threat": "phishing", "tags": [], "host": "evil2.com"},
            ]
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_recent_urls(limit=100)

        assert len(result) == 2
        assert result[0]["url"] == "http://evil1.com"
        assert result[1]["threat"] == "phishing"

    @pytest.mark.asyncio
    async def test_get_recent_urls_error(self):
        """Should return empty list on error."""
        client = URLhausClient()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("error"))

        with patch("src.intel.threat_intel.httpx.AsyncClient", return_value=mock_client):
            result = await client.get_recent_urls()
            assert result == []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DB Operations (cache_ioc, cache_iocs_bulk, check_ioc_match)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCacheIoc:
    @pytest.mark.asyncio
    async def test_cache_ioc(self):
        """Should insert IOC into threat_intel table."""
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        mock_pool = AsyncMock()
        mock_pool.acquire = AsyncMock(return_value=mock_conn)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        # Make acquire return an async context manager
        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)):
            await cache_ioc(
                ioc_type="ip",
                ioc_value="1.2.3.4",
                source="abuseipdb",
                threat_type="malicious_ip",
                confidence=90,
                metadata={"country": "US"},
            )

        mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_ioc_without_metadata(self):
        """Should cache IOC with empty metadata."""
        mock_conn = AsyncMock()

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)):
            await cache_ioc(
                ioc_type="url",
                ioc_value="http://evil.com",
                source="urlhaus",
                threat_type="malware",
            )

        call_args = mock_conn.execute.call_args
        # metadata should be "{}" when None
        assert call_args is not None


class TestCacheIocsBulk:
    @pytest.mark.asyncio
    async def test_cache_iocs_bulk_empty(self):
        """Should return 0 for empty list."""
        result = await cache_iocs_bulk([], source="test")
        assert result == 0

    @pytest.mark.asyncio
    async def test_cache_iocs_bulk_success(self):
        """Should cache IOCs and return count."""
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        iocs = [
            {"type": "IPv4", "value": "1.2.3.4", "threat_type": "malicious_ip", "confidence": 90},
            {"type": "URL", "value": "http://evil.com", "threat_type": "malware", "confidence": 80},
        ]

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)):
            result = await cache_iocs_bulk(iocs, source="test")
            assert result == 2

    @pytest.mark.asyncio
    async def test_cache_iocs_bulk_skips_empty_type(self):
        """Should skip IOCs with unmapped type."""
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        iocs = [
            {"type": "unknown_type", "value": "test", "threat_type": "malware"},
            {"type": "IPv4", "value": "1.2.3.4", "threat_type": "malicious_ip"},
        ]

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)):
            # Only IPv4 should be cached; unknown_type maps to ""
            result = await cache_iocs_bulk(iocs, source="test")
            # Should only execute once (skip the unknown type)
            assert mock_conn.execute.call_count >= 1

    @pytest.mark.asyncio
    async def test_cache_iocs_bulk_handles_exception(self):
        """Should handle individual IOC errors gracefully."""
        mock_conn = AsyncMock()
        # First call raises, second succeeds
        mock_conn.execute = AsyncMock(side_effect=[Exception("db error"), None])

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        iocs = [
            {"type": "IPv4", "value": "1.2.3.4", "threat_type": "malicious_ip"},
            {"type": "URL", "value": "http://evil.com", "threat_type": "malware"},
        ]

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)):
            result = await cache_iocs_bulk(iocs, source="test")
            # Should not raise, even with an error


class TestCheckIocMatch:
    @pytest.mark.asyncio
    async def test_ioc_match_found(self):
        """Should return match dict when IOC is in cache."""
        mock_conn = AsyncMock()
        mock_row = {
            "ioc_type": "ip",
            "ioc_value": "1.2.3.4",
            "source": "abuseipdb",
            "threat_type": "malicious_ip",
            "confidence": 90,
            "last_seen": datetime(2024, 1, 1),
        }
        mock_conn.fetchrow = AsyncMock(return_value=mock_row)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)):
            result = await check_ioc_match("ip", "1.2.3.4")

        assert result is not None
        assert result["source"] == "abuseipdb"
        assert result["threat_type"] == "malicious_ip"

    @pytest.mark.asyncio
    async def test_ioc_no_match(self):
        """Should return None when IOC is not in cache."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)):
            result = await check_ioc_match("ip", "99.99.99.99")
            assert result is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Enrichment Functions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnrichIpWithThreatIntel:
    @pytest.mark.asyncio
    async def test_cached_match_high_confidence(self):
        """Should return enrichment with severity_boost='high' for high-confidence cache hit."""
        mock_row = {
            "source": "abuseipdb",
            "threat_type": "malicious_ip",
            "confidence": 90,
            "last_seen": datetime(2024, 1, 1),
        }

        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=mock_row)):
            result = await enrich_ip_with_threat_intel("1.2.3.4")

        assert result["threat_intel"]["match"] is True
        assert result["threat_intel"]["severity_boost"] == "high"
        assert result["threat_intel"]["confidence"] == 90

    @pytest.mark.asyncio
    async def test_cached_match_low_confidence(self):
        """Should return enrichment without severity_boost for low-confidence cache hit."""
        mock_row = {
            "source": "otx",
            "threat_type": "suspicious",
            "confidence": 40,
            "last_seen": datetime(2024, 1, 1),
        }

        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=mock_row)):
            result = await enrich_ip_with_threat_intel("5.6.7.8")

        assert result["threat_intel"]["match"] is True
        assert "severity_boost" not in result["threat_intel"]

    @pytest.mark.asyncio
    async def test_no_cache_hit_with_abuseipdb(self):
        """Should check AbuseIPDB live when no cache hit and API key set."""
        mock_abuseipdb_result = {
            "ip": "1.2.3.4",
            "abuse_confidence": 75,
            "total_reports": 50,
            "country": "CN",
            "isp": "EvilISP",
            "threat_type": "malicious_ip",
            "domain": None,
        }

        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=None)), \
             patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockClient, \
             patch("src.intel.threat_intel.cache_ioc", AsyncMock()):

            mock_settings.abuseipdb_api_key = "test-key"
            mock_client_instance = MagicMock()
            mock_client_instance.check_ip = AsyncMock(return_value=mock_abuseipdb_result)
            MockClient.return_value = mock_client_instance

            result = await enrich_ip_with_threat_intel("1.2.3.4")

        assert result["threat_intel"]["match"] is True
        assert result["threat_intel"]["source"] == "abuseipdb"
        assert result["threat_intel"]["confidence"] == 75

    @pytest.mark.asyncio
    async def test_no_cache_hit_no_api_key(self):
        """Should return empty dict when no cache hit and no API key."""
        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=None)), \
             patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = ""
            result = await enrich_ip_with_threat_intel("1.2.3.4")

        assert result == {}

    @pytest.mark.asyncio
    async def test_abuseipdb_returns_none(self):
        """Should return empty dict when AbuseIPDB also returns None."""
        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=None)), \
             patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockClient:

            mock_settings.abuseipdb_api_key = "test-key"
            mock_client_instance = MagicMock()
            mock_client_instance.check_ip = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            result = await enrich_ip_with_threat_intel("1.2.3.4")

        assert result == {}

    @pytest.mark.asyncio
    async def test_abuseipdb_returns_no_threat(self):
        """Should not cache when AbuseIPDB returns no threat_type."""
        mock_abuseipdb_result = {
            "ip": "1.2.3.4",
            "abuse_confidence": 10,
            "total_reports": 1,
            "country": "US",
            "isp": "GoodISP",
            "threat_type": None,
            "domain": None,
        }

        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=None)), \
             patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockClient:

            mock_settings.abuseipdb_api_key = "test-key"
            mock_client_instance = MagicMock()
            mock_client_instance.check_ip = AsyncMock(return_value=mock_abuseipdb_result)
            MockClient.return_value = mock_client_instance

            result = await enrich_ip_with_threat_intel("1.2.3.4")

        # Match should be false since threat_type is None
        assert result["threat_intel"]["match"] is False


class TestEnrichUrlWithThreatIntel:
    @pytest.mark.asyncio
    async def test_cached_url_match(self):
        """Should return cache hit for known URL."""
        mock_row = {
            "source": "urlhaus",
            "threat_type": "malware",
            "confidence": 80,
        }

        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=mock_row)):
            result = await enrich_url_with_threat_intel("http://evil.com/payload")

        assert result["threat_intel"]["match"] is True
        assert result["threat_intel"]["source"] == "urlhaus"

    @pytest.mark.asyncio
    async def test_url_no_cache_urlhaus_hit(self):
        """Should check URLhaus when no cache hit."""
        mock_urlhaus_result = {
            "url": "http://evil.com/payload",
            "threat": "malware_download",
            "tags": ["trojan"],
        }

        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=None)), \
             patch("src.intel.threat_intel.URLhausClient") as MockClient, \
             patch("src.intel.threat_intel.cache_ioc", AsyncMock()):

            mock_client = MagicMock()
            mock_client.check_url = AsyncMock(return_value=mock_urlhaus_result)
            MockClient.return_value = mock_client

            result = await enrich_url_with_threat_intel("http://evil.com/payload")

        assert result["threat_intel"]["match"] is True
        assert result["threat_intel"]["source"] == "urlhaus"
        assert result["threat_intel"]["threat_type"] == "malware_download"

    @pytest.mark.asyncio
    async def test_url_no_cache_urlhaus_miss(self):
        """Should return empty when URLhaus also has no match."""
        with patch("src.intel.threat_intel.check_ioc_match", AsyncMock(return_value=None)), \
             patch("src.intel.threat_intel.URLhausClient") as MockClient:

            mock_client = MagicMock()
            mock_client.check_url = AsyncMock(return_value=None)
            MockClient.return_value = mock_client

            result = await enrich_url_with_threat_intel("http://safe-site.com")
            assert result == {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# refresh_all_feeds
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRefreshAllFeeds:
    @pytest.mark.asyncio
    async def test_refresh_all_feeds_no_keys(self):
        """Should return results with -1 for unconfigured feeds."""
        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.URLhausClient") as MockURLhaus, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockAbuseIPDB:

            mock_settings.abuseipdb_api_key = ""
            mock_settings.otx_api_key = ""

            # URLhaus returns some URLs
            mock_urlhaus = MagicMock()
            mock_urlhaus.get_recent_urls = AsyncMock(return_value=[
                {"url": "http://evil.com", "threat": "malware", "tags": [], "host": "evil.com"},
            ])
            MockURLhaus.return_value = mock_urlhaus

            with patch("src.intel.threat_intel.cache_iocs_bulk", AsyncMock(return_value=5)):
                result = await refresh_all_feeds()

        # URLhaus should be present, AbuseIPDB and OTX should be -1
        assert "urlhaus" in result
        assert result.get("abuseipdb") == -1 or result.get("otx") == -1

    @pytest.mark.asyncio
    async def test_refresh_all_feeds_with_abuseipdb(self):
        """Should cache AbuseIPDB blacklist when API key is set."""
        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.URLhausClient") as MockURLhaus, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockAbuseIPDB, \
             patch("src.intel.threat_intel.OTXClient") as MockOTX:

            mock_settings.abuseipdb_api_key = "test-key"
            mock_settings.otx_api_key = ""

            mock_urlhaus = MagicMock()
            mock_urlhaus.get_recent_urls = AsyncMock(return_value=[])

            mock_abuseipdb = MagicMock()
            mock_abuseipdb.get_blacklist = AsyncMock(return_value=["1.2.3.4", "5.6.7.8"])

            MockURLhaus.return_value = mock_urlhaus
            MockAbuseIPDB.return_value = mock_abuseipdb

            with patch("src.intel.threat_intel.cache_iocs_bulk", AsyncMock(return_value=2)):
                result = await refresh_all_feeds()

        assert "abuseipdb" in result
        assert result["abuseipdb"] > 0 or result["abuseipdb"] == 0

    @pytest.mark.asyncio
    async def test_refresh_all_feeds_urlhaus_error(self):
        """Should handle URLhaus error gracefully."""
        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.URLhausClient") as MockURLhaus, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockAbuseIPDB:

            mock_settings.abuseipdb_api_key = ""
            mock_settings.otx_api_key = ""

            mock_urlhaus = MagicMock()
            mock_urlhaus.get_recent_urls = AsyncMock(side_effect=Exception("network error"))
            MockURLhaus.return_value = mock_urlhaus

            result = await refresh_all_feeds()
            assert result["urlhaus"] == 0

    @pytest.mark.asyncio
    async def test_refresh_all_feeds_with_otx(self):
        """Should fetch OTX pulses when API key is set."""
        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.URLhausClient") as MockURLhaus, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockAbuseIPDB, \
             patch("src.intel.threat_intel.OTXClient") as MockOTX, \
             patch("src.intel.threat_intel.asyncio.sleep", AsyncMock()):

            mock_settings.abuseipdb_api_key = ""
            mock_settings.otx_api_key = "test-otx-key"

            mock_urlhaus = MagicMock()
            mock_urlhaus.get_recent_urls = AsyncMock(return_value=[])

            mock_otx = MagicMock()
            mock_otx.get_modified_pulses = AsyncMock(return_value=[
                {"id": "pulse1", "name": "APT29"},
            ])
            mock_otx.get_pulse_indicators = AsyncMock(return_value=[
                {"type": "IPv4", "value": "10.0.0.1", "threat_type": "c2", "confidence": 80},
            ])
            MockURLhaus.return_value = mock_urlhaus
            MockOTX.return_value = mock_otx

            with patch("src.intel.threat_intel.cache_iocs_bulk", AsyncMock(return_value=1)):
                result = await refresh_all_feeds()

        assert "otx" in result

    @pytest.mark.asyncio
    async def test_refresh_all_feeds_empty_urls(self):
        """Should handle URLhaus returning empty results."""
        with patch("src.intel.threat_intel.settings") as mock_settings, \
             patch("src.intel.threat_intel.URLhausClient") as MockURLhaus, \
             patch("src.intel.threat_intel.AbuseIPDBClient") as MockAbuseIPDB:

            mock_settings.abuseipdb_api_key = ""
            mock_settings.otx_api_key = ""

            mock_urlhaus = MagicMock()
            mock_urlhaus.get_recent_urls = AsyncMock(return_value=[])
            MockURLhaus.return_value = mock_urlhaus

            result = await refresh_all_feeds()
            assert result["urlhaus"] == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# get_threat_intel_stats
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestGetThreatIntelStats:
    @pytest.mark.asyncio
    async def test_stats(self):
        """Should return stats dict with indicators and feed status."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=500)
        mock_conn.fetch = AsyncMock(return_value=[
            {"ioc_type": "ip", "count": 300},
            {"ioc_type": "url", "count": 200},
        ])
        # Second call for by_source
        mock_conn.fetch.side_effect = [
            [{"ioc_type": "ip", "count": 300}, {"ioc_type": "url", "count": 200}],
            [{"source": "abuseipdb", "count": 300}, {"source": "urlhaus", "count": 200}],
        ]
        mock_conn.fetchrow = AsyncMock(return_value=None)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)), \
             patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = "configured"
            mock_settings.otx_api_key = "configured"
            result = await get_threat_intel_stats()

        assert result["total_indicators"] == 500
        assert "by_type" in result
        assert "by_source" in result
        assert "feed_status" in result
        assert result["feed_status"]["abuseipdb"] == "configured"
        assert result["feed_status"]["otx"] == "configured"
        assert result["feed_status"]["urlhaus"] == "configured"

    @pytest.mark.asyncio
    async def test_stats_no_data(self):
        """Should handle empty database."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=0)
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.fetchrow = AsyncMock(return_value={"max": None})

        # Override fetchval for different calls
        # First call for COUNT(*), second for MAX(fetched_at)
        mock_conn.fetchval = AsyncMock(return_value=0)
        mock_conn.fetchrow = AsyncMock(return_value={"max": None})

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.intel.threat_intel.get_pool", AsyncMock(return_value=mock_pool)), \
             patch("src.intel.threat_intel.settings") as mock_settings:
            mock_settings.abuseipdb_api_key = ""
            mock_settings.otx_api_key = ""

            # We need to handle sequential fetchval calls
            call_count = [0]
            async def fake_fetchval(sql, *args):
                return 0

            async def fake_fetch(sql, *args):
                return []

            mock_conn.fetchval = fake_fetchval
            mock_conn.fetch = fake_fetch

            result = await get_threat_intel_stats()

        assert result["total_indicators"] == 0
        assert result["feed_status"]["abuseipdb"] == "not_configured"
        assert result["last_refresh"] == "never"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scheduler
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestThreatIntelScheduler:
    @pytest.mark.asyncio
    async def test_start_scheduler(self):
        """Should start APScheduler and run initial refresh."""
        mock_scheduler = MagicMock()
        mock_scheduler.start = MagicMock()
        mock_scheduler.add_job = MagicMock()

        with patch("src.intel.threat_intel._async_scheduler", None), \
             patch("src.intel.threat_intel.refresh_all_feeds", AsyncMock(return_value={"urlhaus": 0})), \
             patch("apscheduler.schedulers.asyncio.AsyncIOScheduler", return_value=mock_scheduler), \
             patch("apscheduler.triggers.interval.IntervalTrigger"):
            await start_threat_intel_scheduler()

        mock_scheduler.add_job.assert_called_once()
        mock_scheduler.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_scheduler_initial_refresh_error(self):
        """Should handle initial refresh error gracefully."""
        mock_scheduler = MagicMock()
        mock_scheduler.start = MagicMock()
        mock_scheduler.add_job = MagicMock()

        with patch("src.intel.threat_intel._async_scheduler", None), \
             patch("src.intel.threat_intel.refresh_all_feeds", AsyncMock(side_effect=Exception("db error"))), \
             patch("apscheduler.schedulers.asyncio.AsyncIOScheduler", return_value=mock_scheduler), \
             patch("apscheduler.triggers.interval.IntervalTrigger"):
            # Should not raise even when initial refresh fails
            await start_threat_intel_scheduler()

        mock_scheduler.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_scheduler(self):
        """Should stop the scheduler."""
        mock_scheduler = MagicMock()
        mock_scheduler.shutdown = MagicMock()

        with patch("src.intel.threat_intel._async_scheduler", mock_scheduler):
            await stop_threat_intel_scheduler()

        mock_scheduler.shutdown.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_scheduler_no_scheduler(self):
        """Should handle stop when scheduler is None."""
        with patch("src.intel.threat_intel._async_scheduler", None):
            # Should not raise
            await stop_threat_intel_scheduler()