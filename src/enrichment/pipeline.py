"""
Enrichment pipeline v2 — wires threat intel into event processing.

Enrichments applied (in order):
1. GeoIP — country, city, ASN for public IPs
2. DNS reverse — PTR record for IPs
3. Threat Intel — match against cached IOC database
4. Severity boost — increase severity if threat intel match

Designed to be called from the ingestion pipeline (writer.py)
for automatic enrichment of every incoming event.
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

    Requires GeoLite2-City.mmdb in data/ directory.
    Returns empty dict if not available.
    """
    if not is_public_ip(ip):
        return {}
    try:
        import geoip2.database
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
    except FileNotFoundError:
        log.debug("geoip_db_not_found")
        return {}
    except Exception as e:
        log.debug("geoip_lookup_failed", ip=ip, error=str(e))
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


async def enrich_with_threat_intel(ip: str) -> dict[str, Any]:
    """Enrich an IP with threat intel data from cache and live APIs."""
    from src.intel.threat_intel import enrich_ip_with_threat_intel
    try:
        return await enrich_ip_with_threat_intel(ip)
    except Exception as e:
        log.warning("threat_intel_enrichment_failed", ip=ip, error=str(e))
        return {}


async def enrich_event(event) -> dict[str, Any]:
    """
    Run all enrichments for an event.

    This is the main entry point called from the ingestion pipeline.
    Returns a merged enrichment dict to be stored in the event's
    enrichment JSONB column.

    Args:
        event: A LogEvent or similar object with source_ip, destination_ip attributes.
    """
    enrichment: dict[str, Any] = {}

    # ── Enrich source IP ──────────────────────────────────
    if event.source_ip and is_public_ip(event.source_ip):
        # GeoIP
        geo = await enrich_geoip(event.source_ip)
        if geo:
            enrichment.update(geo)

        # DNS reverse
        dns = enrich_dns_reverse(event.source_ip)
        if dns:
            enrichment.update(dns)

        # Threat Intel
        ti = await enrich_with_threat_intel(event.source_ip)
        if ti:
            enrichment.update(ti)

    # ── Enrich destination IP ──────────────────────────────────
    if event.destination_ip and is_public_ip(event.destination_ip):
        dest_enrichment: dict[str, Any] = {}

        # GeoIP
        geo = await enrich_geoip(event.destination_ip)
        if geo:
            dest_enrichment.update(geo)

        # DNS
        dns = enrich_dns_reverse(event.destination_ip)
        if dns:
            dest_enrichment.update(dns)

        # Threat Intel
        ti = await enrich_with_threat_intel(event.destination_ip)
        if ti:
            dest_enrichment.update(ti)

        # Store destination enrichment under separate key
        if dest_enrichment:
            # If source already had enrichment, namespace the dest enrichment
            if enrichment:
                enrichment["destination"] = dest_enrichment
            else:
                enrichment.update(dest_enrichment)

    # ── Severity boost ──────────────────────────────────────────
    # If threat intel found a match, boost the event severity
    if enrichment.get("threat_intel", {}).get("match"):
        ti_confidence = enrichment["threat_intel"].get("confidence", 0)
        if ti_confidence >= 80:
            enrichment["severity_boost"] = "critical"
        elif ti_confidence >= 50:
            enrichment["severity_boost"] = "high"
        elif ti_confidence >= 25:
            enrichment["severity_boost"] = "medium"

    return enrichment


async def enrich_event_dict(event_data: dict) -> dict:
    """
    Enrich an event from a dict (used when LogEvent object not available).

    Extracts IPs from dict and returns enrichment data.
    """
    source_ip = event_data.get("source_ip")
    destination_ip = event_data.get("destination_ip")

    class _Event:
        """Minimal event-like object for enrichment."""
        def __init__(self, source_ip, destination_ip):
            self.source_ip = source_ip
            self.destination_ip = destination_ip

    event = _Event(source_ip, destination_ip)
    return await enrich_event(event)


def calculate_severity_boost(event_severity: str, enrichment: dict) -> str:
    """
    Calculate the final severity for an event considering enrichment data.

    If threat intel found a match, bump the severity accordingly.
    """
    boost = enrichment.get("severity_boost")
    if not boost:
        return event_severity

    severity_order = ["info", "low", "medium", "high", "critical"]
    current_idx = severity_order.index(event_severity) if event_severity in severity_order else 2
    boost_idx = severity_order.index(boost) if boost in severity_order else 2

    # Take the higher of current and boost
    new_idx = max(current_idx, boost_idx)
    return severity_order[new_idx]
