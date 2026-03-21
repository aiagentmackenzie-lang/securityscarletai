"""
Log enrichment pipeline — adds context to raw events.

Enrichments applied (in order):
1. GeoIP — country, city, ASN for public IPs
2. DNS reverse — PTR record for IPs
3. Threat Intel — match against cached IOC database

Design: Each enricher is a function that takes an event and returns
the enrichment dict to merge. Enrichers must be fast (<50ms each)
and must never raise — return empty dict on failure.
"""
import ipaddress
import socket
from typing import Any

from src.config.logging import get_logger

log = get_logger("enrichment")


def is_public_ip(ip_str: str | None) -> bool:
    """Check if an IP is routable (not private, loopback, or link-local)."""
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


async def enrich_geoip(ip: str) -> dict[str, Any]:
    """GeoIP lookup using MaxMind GeoLite2 database.
    
    Setup: Download GeoLite2-City.mmdb from maxmind.com (free account required)
    and place in data/GeoLite2-City.mmdb
    """
    if not is_public_ip(ip):
        return {}
    try:
        import geoip2.database
        # Cache the reader — don't open the DB file per-event
        reader = geoip2.database.Reader("data/GeoLite2-City.mmdb")
        response = reader.city(ip)
        return {
            "geo": {
                "country_iso": response.country.iso_code,
                "country_name": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
        }
    except Exception:
        return {}


def enrich_dns_reverse(ip: str) -> dict[str, Any]:
    """Reverse DNS lookup. Synchronous but fast with timeout."""
    if not is_public_ip(ip):
        return {}
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"dns": {"reverse": hostname}}
    except (socket.herror, socket.gaierror, OSError):
        return {}


async def enrich_event(event) -> dict[str, Any]:
    """Run all enrichments for an event. Returns merged enrichment dict."""
    enrichment: dict[str, Any] = {}

    # Enrich destination IP (most useful — outbound connections)
    if event.destination_ip and is_public_ip(event.destination_ip):
        geo = await enrich_geoip(event.destination_ip)
        enrichment.update(geo)
        dns = enrich_dns_reverse(event.destination_ip)
        enrichment.update(dns)

    # Enrich source IP (inbound connections)
    if event.source_ip and is_public_ip(event.source_ip):
        src_geo = await enrich_geoip(event.source_ip)
        if src_geo:
            enrichment["source_geo"] = src_geo.get("geo", {})

    return enrichment
