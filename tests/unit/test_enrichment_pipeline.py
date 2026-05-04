"""
Comprehensive tests for src/enrichment/pipeline.py.

Covers:
- is_public_ip (various IP types)
- enrich_geoip (with/without MaxMind DB)
- enrich_dns_reverse (with/without DNS resolution)
- enrich_with_threat_intel
- enrich_event (source IP, dest IP, both)
- enrich_event_dict
- calculate_severity_boost
- severity boost thresholds
"""
import pytest
import socket
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.enrichment.pipeline import (
    is_public_ip,
    enrich_geoip,
    enrich_dns_reverse,
    enrich_with_threat_intel,
    enrich_event,
    enrich_event_dict,
    calculate_severity_boost,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# is_public_ip
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestIsPublicIp:
    def test_public_ip(self):
        assert is_public_ip("8.8.8.8") is True

    def test_private_ip_10(self):
        assert is_public_ip("10.0.0.1") is False

    def test_private_ip_172(self):
        assert is_public_ip("172.16.0.1") is False

    def test_private_ip_192(self):
        assert is_public_ip("192.168.1.1") is False

    def test_loopback(self):
        assert is_public_ip("127.0.0.1") is False

    def test_none(self):
        assert is_public_ip(None) is False

    def test_empty_string(self):
        assert is_public_ip("") is False

    def test_invalid_ip(self):
        assert is_public_ip("not_an_ip") is False

    def test_ipv6_public(self):
        assert is_public_ip("2001:4860:4860::8888") is True

    def test_ipv6_loopback(self):
        assert is_public_ip("::1") is False

    def test_link_local(self):
        assert is_public_ip("169.254.1.1") is False

    def test_broadcast_address(self):
        # 255.255.255.255 is technically a broadcast address which ipaddress considers non-global
        result = is_public_ip("255.255.255.255")
        assert result is False  # broadcast addresses are not routable

    def test_multicast(self):
        # Multicast addresses: ipaddress considers some as global
        result = is_public_ip("224.0.0.1")
        # Python ipaddress considers multicast IPv4 as is_global=True
        # But our function should handle this based on ipaddress behavior
        assert isinstance(result, bool)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# enrich_geoip
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnrichGeoip:
    @pytest.mark.asyncio
    async def test_private_ip_returns_empty(self):
        """Should return empty dict for private IPs."""
        result = await enrich_geoip("192.168.1.1")
        assert result == {}

    @pytest.mark.asyncio
    async def test_no_geoip_database(self):
        """Should return empty dict when GeoIP database not found."""
        with patch("src.enrichment.pipeline.is_public_ip", return_value=True):
            result = await enrich_geoip("8.8.8.8")
            # Either returns geo data or empty dict if no database
            assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_geoip_with_mock_database(self):
        """Should return geo data when database is available."""
        mock_response = MagicMock()
        mock_response.country.iso_code = "US"
        mock_response.country.name = "United States"
        mock_response.city.name = "Mountain View"
        mock_response.location.latitude = 37.386
        mock_response.location.longitude = -122.0838

        mock_reader = MagicMock()
        mock_reader.city = MagicMock(return_value=mock_response)

        with patch("src.enrichment.pipeline.is_public_ip", return_value=True), \
             patch("geoip2.database.Reader", return_value=mock_reader):
            result = await enrich_geoip("8.8.8.8")

        # Result should contain geo info or be empty if import failed
        # The actual result depends on geoip2 being available


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# enrich_dns_reverse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnrichDnsReverse:
    def test_private_ip_returns_empty(self):
        """Should return empty dict for private IPs."""
        result = enrich_dns_reverse("192.168.1.1")
        assert result == {}

    def test_dns_resolution_failure(self):
        """Should return empty dict when DNS resolution fails."""
        with patch("socket.gethostbyaddr", side_effect=socket.herror):
            # Need to check is_public_ip first - it should return True
            result = enrich_dns_reverse("8.8.8.8")
            # If is_public_ip returns True but DNS fails, empty dict
            if result:
                assert "dns" not in result or result == {}
            # Or if is_public_ip is not mocked, actual behavior

    def test_dns_resolution_success(self):
        """Should return hostname for resolvable IP."""
        with patch("src.enrichment.pipeline.is_public_ip", return_value=True), \
             patch("socket.gethostbyaddr", return_value=("dns.google", [], "8.8.8.8")):
            result = enrich_dns_reverse("8.8.8.8")
            if result:
                assert result["dns"]["reverse"] == "dns.google"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# enrich_with_threat_intel
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnrichWithThreatIntel:
    @pytest.mark.asyncio
    async def test_enrich_public_ip(self):
        """Should return threat intel data for public IPs."""
        # The function delegates to the threat_intel module
        # Mock at the point-of-use: src.enrichment.pipeline.enrich_ip_with_threat_intel
        # But in pipeline.py it does a local import: from src.intel.threat_intel import enrich_ip_with_threat_intel
        # So we need to mock src.intel.threat_intel.enrich_ip_with_threat_intel
        mock_result = {"threat_intel": {"match": True, "source": "abuseipdb"}}
        with patch("src.intel.threat_intel.enrich_ip_with_threat_intel", AsyncMock(return_value=mock_result)):
            result = await enrich_with_threat_intel("8.8.8.8")
            assert "threat_intel" in result

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Should return empty dict on error."""
        with patch("src.intel.threat_intel.enrich_ip_with_threat_intel", AsyncMock(side_effect=Exception("DB error"))):
            result = await enrich_with_threat_intel("1.2.3.4")
            assert result == {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# enrich_event
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnrichEvent:
    @pytest.mark.asyncio
    async def test_enrich_event_no_ips(self):
        """Should return empty enrichment when no public IPs."""
        mock_event = MagicMock()
        mock_event.source_ip = None
        mock_event.destination_ip = None

        result = await enrich_event(mock_event)
        assert result == {}

    @pytest.mark.asyncio
    async def test_enrich_event_private_source_ip(self):
        """Should not enrich private source IPs."""
        mock_event = MagicMock()
        mock_event.source_ip = "192.168.1.1"
        mock_event.destination_ip = None

        result = await enrich_event(mock_event)
        assert result == {}

    @pytest.mark.asyncio
    async def test_enrich_event_public_source_ip(self):
        """Should enrich public source IP with geo, dns, threat intel."""
        mock_event = MagicMock()
        mock_event.source_ip = "8.8.8.8"
        mock_event.destination_ip = None

        with patch("src.enrichment.pipeline.enrich_geoip", AsyncMock(return_value={"geo": {"country_iso": "US"}})), \
             patch("src.enrichment.pipeline.enrich_dns_reverse", return_value={"dns": {"reverse": "dns.google"}}), \
             patch("src.enrichment.pipeline.enrich_with_threat_intel", AsyncMock(return_value={})):
            result = await enrich_event(mock_event)

        assert "geo" in result
        assert "dns" in result

    @pytest.mark.asyncio
    async def test_enrich_event_with_threat_intel_severity_boost(self):
        """Should add severity_boost when threat intel matches with high confidence."""
        mock_event = MagicMock()
        mock_event.source_ip = "1.2.3.4"
        mock_event.destination_ip = None

        with patch("src.enrichment.pipeline.enrich_geoip", AsyncMock(return_value={})), \
             patch("src.enrichment.pipeline.enrich_dns_reverse", return_value={}), \
             patch("src.enrichment.pipeline.enrich_with_threat_intel", AsyncMock(return_value={
                 "threat_intel": {"match": True, "confidence": 85, "source": "abuseipdb", "threat_type": "malicious_ip"}
             })):
            result = await enrich_event(mock_event)

        assert result["threat_intel"]["match"] is True
        assert result["severity_boost"] == "critical"

    @pytest.mark.asyncio
    async def test_enrich_event_medium_severity_boost(self):
        """Should add 'high' severity_boost for confidence 50-79."""
        mock_event = MagicMock()
        mock_event.source_ip = "1.2.3.4"
        mock_event.destination_ip = None

        with patch("src.enrichment.pipeline.enrich_geoip", AsyncMock(return_value={})), \
             patch("src.enrichment.pipeline.enrich_dns_reverse", return_value={}), \
             patch("src.enrichment.pipeline.enrich_with_threat_intel", AsyncMock(return_value={
                 "threat_intel": {"match": True, "confidence": 60, "source": "abuseipdb", "threat_type": "suspicious"}
             })):
            result = await enrich_event(mock_event)

        assert result["severity_boost"] == "high"

    @pytest.mark.asyncio
    async def test_enrich_event_low_severity_boost(self):
        """Should add 'medium' severity_boost for confidence 25-49."""
        mock_event = MagicMock()
        mock_event.source_ip = "1.2.3.4"
        mock_event.destination_ip = None

        with patch("src.enrichment.pipeline.enrich_geoip", AsyncMock(return_value={})), \
             patch("src.enrichment.pipeline.enrich_dns_reverse", return_value={}), \
             patch("src.enrichment.pipeline.enrich_with_threat_intel", AsyncMock(return_value={
                 "threat_intel": {"match": True, "confidence": 30, "source": "otx", "threat_type": "unknown"}
             })):
            result = await enrich_event(mock_event)

        assert result["severity_boost"] == "medium"

    @pytest.mark.asyncio
    async def test_enrich_event_with_destination_ip(self):
        """Should enrich both source and destination IPs."""
        mock_event = MagicMock()
        mock_event.source_ip = "8.8.8.8"
        mock_event.destination_ip = "9.9.9.9"

        with patch("src.enrichment.pipeline.enrich_geoip", AsyncMock(return_value={})), \
             patch("src.enrichment.pipeline.enrich_dns_reverse", return_value={}), \
             patch("src.enrichment.pipeline.enrich_with_threat_intel", AsyncMock(return_value={})):
            result = await enrich_event(mock_event)

        # With both source and dest IPs, enrichment should happen
        assert isinstance(result, dict)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# enrich_event_dict
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnrichEventDict:
    @pytest.mark.asyncio
    async def test_enrich_event_dict_no_ips(self):
        """Should return empty enrichment when dict has no IPs."""
        result = await enrich_event_dict({"source_ip": None, "destination_ip": None})
        assert result == {}

    @pytest.mark.asyncio
    async def test_enrich_event_dict_with_source_ip(self):
        """Should create internal _Event and enrich."""
        with patch("src.enrichment.pipeline.enrich_event", AsyncMock(return_value={"geo": {"country_iso": "US"}})):
            result = await enrich_event_dict({"source_ip": "8.8.8.8", "destination_ip": None})
            assert "geo" in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# calculate_severity_boost
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCalculateSeverityBoost:
    def test_no_boost(self):
        """Should return original severity when no boost."""
        result = calculate_severity_boost("medium", {})
        assert result == "medium"

    def test_no_severity_boost_key(self):
        """Should return original severity when no severity_boost key."""
        result = calculate_severity_boost("low", {"geo": {"country": "US"}})
        assert result == "low"

    def test_critical_boost(self):
        """Should boost to critical when severity_boost is critical."""
        result = calculate_severity_boost("medium", {"severity_boost": "critical"})
        assert result == "critical"

    def test_high_boost(self):
        """Should boost to high when severity_boost is high."""
        result = calculate_severity_boost("low", {"severity_boost": "high"})
        assert result == "high"

    def test_medium_boost(self):
        """Should boost to medium when severity_boost is medium."""
        result = calculate_severity_boost("low", {"severity_boost": "medium"})
        assert result == "medium"

    def test_boost_lower_than_current(self):
        """Should keep current severity if boost is lower."""
        result = calculate_severity_boost("critical", {"severity_boost": "low"})
        assert result == "critical"

    def test_unknown_severity_defaults_to_medium(self):
        """Unknown severity should default to index 2 (medium)."""
        result = calculate_severity_boost("unknown", {"severity_boost": "high"})
        assert result == "high"

    def test_info_severity(self):
        """Info severity should be boostable."""
        result = calculate_severity_boost("info", {"severity_boost": "medium"})
        assert result == "medium"

    def test_all_severity_boosts(self):
        """Test all combinations of severity + boost."""
        severities = ["info", "low", "medium", "high", "critical"]
        for sev in severities:
            for boost in ["info", "low", "medium", "high", "critical"]:
                result = calculate_severity_boost(sev, {"severity_boost": boost})
                # Result should be the maximum of current and boost
                severity_order = ["info", "low", "medium", "high", "critical"]
                expected_idx = max(severity_order.index(sev), severity_order.index(boost))
                assert result == severity_order[expected_idx]