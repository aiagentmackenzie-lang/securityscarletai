"""
Tests for Enrichment Pipeline v2.

Tests GeoIP checks, threat intel enrichment, severity boosting,
and the enrichment pipeline composition.
"""

from unittest.mock import AsyncMock, patch

import pytest

from src.enrichment.pipeline import (
    enrich_dns_reverse,
    is_public_ip,
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
        with (
            patch("src.enrichment.pipeline.enrich_geoip", new_callable=AsyncMock, return_value={}),
            patch(
                "src.enrichment.pipeline.enrich_with_threat_intel",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await enrich_event(_Event())
            assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_enrich_event_dict(self):
        """Enriching from dict should work."""
        from src.enrichment.pipeline import enrich_event_dict

        with (
            patch("src.enrichment.pipeline.enrich_geoip", new_callable=AsyncMock, return_value={}),
            patch(
                "src.enrichment.pipeline.enrich_with_threat_intel",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await enrich_event_dict({"source_ip": None, "destination_ip": None})
            assert isinstance(result, dict)
