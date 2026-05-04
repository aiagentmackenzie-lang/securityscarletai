"""
Tests for src/api/threat_intel.py endpoint logic.

Covers:
- threat_intel_stats
- refresh_threat_intel (success, error)
- lookup_ip (found, not found)
- lookup_url
- lookup_hash (MD5, SHA256, invalid)
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from src.api.threat_intel import (
    threat_intel_stats,
    refresh_threat_intel,
    lookup_ip,
    lookup_url,
    lookup_hash,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# threat_intel_stats
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestThreatIntelStats:
    @pytest.mark.asyncio
    async def test_stats(self):
        mock_stats = {
            "total_indicators": 500,
            "by_type": {"ip": 300, "url": 200},
            "by_source": {"abuseipdb": 300, "urlhaus": 200},
            "last_refresh": "2024-01-01T12:00:00",
            "feed_status": {
                "abuseipdb": "configured",
                "otx": "configured",
                "urlhaus": "configured",
            },
        }

        with patch("src.api.threat_intel.get_threat_intel_stats", AsyncMock(return_value=mock_stats)):
            result = await threat_intel_stats(user="admin")

        assert result["total_indicators"] == 500
        assert result["feed_status"]["abuseipdb"] == "configured"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# refresh_threat_intel
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRefreshThreatIntel:
    @pytest.mark.asyncio
    async def test_refresh_success(self):
        mock_results = {
            "urlhaus": 50,
            "abuseipdb": 30,
            "otx": 20,
        }

        with patch("src.api.threat_intel.refresh_all_feeds", AsyncMock(return_value=mock_results)):
            result = await refresh_threat_intel(user="admin")

        assert result["status"] == "completed"
        assert result["results"]["urlhaus"] == 50

    @pytest.mark.asyncio
    async def test_refresh_error(self):
        with patch("src.api.threat_intel.refresh_all_feeds", AsyncMock(side_effect=Exception("DB error"))):
            with pytest.raises(HTTPException) as exc_info:
                await refresh_threat_intel(user="admin")
            assert exc_info.value.status_code == 500


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# lookup_ip
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLookupIp:
    @pytest.mark.asyncio
    async def test_lookup_ip_found(self):
        mock_result = {
            "ioc_type": "ip",
            "ioc_value": "1.2.3.4",
            "source": "abuseipdb",
            "threat_type": "malicious_ip",
            "confidence": 90,
        }

        with patch("src.api.threat_intel.check_ioc_match", AsyncMock(return_value=mock_result)):
            result = await lookup_ip(ip_address="1.2.3.4", user="analyst1")

        assert result["ioc_value"] == "1.2.3.4"
        assert result["source"] == "abuseipdb"

    @pytest.mark.asyncio
    async def test_lookup_ip_not_found(self):
        with patch("src.api.threat_intel.check_ioc_match", AsyncMock(return_value=None)):
            result = await lookup_ip(ip_address="99.99.99.99", user="analyst1")

        assert result["match"] is False
        assert result["ip"] == "99.99.99.99"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# lookup_url
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLookupUrl:
    @pytest.mark.asyncio
    async def test_lookup_url_found(self):
        mock_result = {
            "ioc_type": "url",
            "ioc_value": "http://evil.com",
            "source": "urlhaus",
            "threat_type": "malware",
            "confidence": 80,
        }

        with patch("src.api.threat_intel.check_ioc_match", AsyncMock(return_value=mock_result)):
            result = await lookup_url(url="http://evil.com", user="analyst1")

        assert result["ioc_value"] == "http://evil.com"

    @pytest.mark.asyncio
    async def test_lookup_url_not_found(self):
        with patch("src.api.threat_intel.check_ioc_match", AsyncMock(return_value=None)):
            result = await lookup_url(url="http://safe.com", user="analyst1")

        assert result["match"] is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# lookup_hash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLookupHash:
    @pytest.mark.asyncio
    async def test_lookup_md5(self):
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"  # 32 chars
        mock_result = {
            "ioc_type": "hash_md5",
            "ioc_value": md5_hash,
            "source": "otx",
            "threat_type": "malware",
        }

        with patch("src.api.threat_intel.check_ioc_match", AsyncMock(return_value=mock_result)):
            result = await lookup_hash(hash_value=md5_hash, user="analyst1")

        assert result["ioc_value"] == md5_hash

    @pytest.mark.asyncio
    async def test_lookup_sha256(self):
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # 64 chars
        mock_result = {
            "ioc_type": "hash_sha256",
            "ioc_value": sha256_hash,
            "source": "otx",
        }

        with patch("src.api.threat_intel.check_ioc_match", AsyncMock(return_value=mock_result)):
            result = await lookup_hash(hash_value=sha256_hash, user="analyst1")

        assert result["ioc_value"] == sha256_hash

    @pytest.mark.asyncio
    async def test_lookup_hash_not_found(self):
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        with patch("src.api.threat_intel.check_ioc_match", AsyncMock(return_value=None)):
            result = await lookup_hash(hash_value=sha256_hash, user="analyst1")

        assert result["match"] is False
        assert result["hash"] == sha256_hash

    @pytest.mark.asyncio
    async def test_lookup_invalid_hash_length(self):
        with pytest.raises(HTTPException) as exc_info:
            await lookup_hash(hash_value="short", user="analyst1")
        assert exc_info.value.status_code == 400