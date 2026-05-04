"""
Tests for Enrichment Pipeline v2.

Tests GeoIP checks, threat intel enrichment, severity boosting,
and the enrichment pipeline composition.
"""
import pytest
from unittest.mock import AsyncMock, patch

from src.enrichment.pipeline import (
    is_public_ip,
    enrich_dns_reverse,
    calculate_severity_boost,
)


class TestPublicIPCheck:
    """Test public vs private IP detection."""

    def test_public_ip(self):
        assert is_public_ip("8.8.8.8") is True

    def test_private_ip_10(self):
        assert is_public_ip("10.0.0.1") is False

    def test_private_ip_192(self):
        assert is_public_ip("192.168.1.1") is False

    def test_private_ip_172(self):
        assert is_public_ip("172.16.0.1") is False

    def test_loopback(self):
        assert is_public_ip("127.0.0.1") is False

    def test_none(self):
        assert is_public_ip(None) is False

    def test_empty_string(self):
        assert is_public_ip("") is False

    def test_invalid_ip(self):
        assert is_public_ip("not_an_ip") is False

    def test_ipv6_public(self):
        # Google's public DNS
        assert is_public_ip("2001:4860:4860::8888") is True

    def test_link_local(self):
        assert is_public_ip("169.254.1.1") is False


class TestDNSReverseLookup:
    """Test DNS reverse lookup enrichment."""

    def test_reverse_dns_private_ip(self):
        """Private IPs should return empty dict."""
        result = enrich_dns_reverse("10.0.0.1")
        assert result == {}

    def test_reverse_dns_none(self):
        """None IP should return empty dict."""
        result = enrich_dns_reverse(None)
        assert result == {}

    def test_reverse_dns_empty(self):
        """Empty IP should return empty dict."""
        result = enrich_dns_reverse("")
        assert result == {}


class TestSeverityBoost:
    """Test severity boost calculation from enrichment data."""

    def test_no_boost(self):
        """No threat intel match should not boost severity."""
        result = calculate_severity_boost("medium", {})
        assert result == "medium"

    def test_no_threat_intel_key(self):
        """Missing threat_intel key should not boost."""
        result = calculate_severity_boost("low", {"geo": {"country": "US"}})
        assert result == "low"

    def test_threat_intel_no_match(self):
        """No threat intel match should not boost."""
        result = calculate_severity_boost("medium", {"threat_intel": {"match": False}})
        assert result == "medium"

    def test_high_confidence_boost(self):
        """High confidence threat match should boost to critical."""
        result = calculate_severity_boost("high", {
            "threat_intel": {"match": True, "confidence": 85},
            "severity_boost": "critical"
        })
        assert result == "critical"

    def test_medium_confidence_boost(self):
        """Medium confidence threat match should boost to high."""
        result = calculate_severity_boost("medium", {
            "threat_intel": {"match": True, "confidence": 60},
            "severity_boost": "high"
        })
        assert result == "high"

    def test_low_confidence_boost(self):
        """Low confidence threat match should boost to medium."""
        result = calculate_severity_boost("low", {
            "threat_intel": {"match": True, "confidence": 30},
            "severity_boost": "medium"
        })
        assert result == "medium"

    def test_boost_doesnt_lower(self):
        """Boost should never lower severity."""
        result = calculate_severity_boost("critical", {
            "severity_boost": "medium"
        })
        assert result == "critical"


class TestEnrichmentPipeline:
    """Test the main enrichment pipeline."""

    @pytest.mark.asyncio
    async def test_enrich_event_no_ips(self):
        """Event with no public IPs should return empty enrichment."""
        class _Event:
            source_ip = None
            destination_ip = None

        from src.enrichment.pipeline import enrich_event

        # Mock enrichment modules to avoid API calls
        with patch("src.enrichment.pipeline.enrich_geoip", new_callable=AsyncMock, return_value={}), \
             patch("src.enrichment.pipeline.enrich_with_threat_intel", new_callable=AsyncMock, return_value={}):
            result = await enrich_event(_Event())
            assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_enrich_event_dict(self):
        """Enriching from dict should work."""
        from src.enrichment.pipeline import enrich_event_dict

        with patch("src.enrichment.pipeline.enrich_geoip", new_callable=AsyncMock, return_value={}), \
             patch("src.enrichment.pipeline.enrich_with_threat_intel", new_callable=AsyncMock, return_value={}):
            result = await enrich_event_dict({"source_ip": None, "destination_ip": None})
            assert isinstance(result, dict)