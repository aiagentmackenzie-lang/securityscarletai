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
import asyncio
import ipaddress
import socket
import time
from typing import Any

from src.config.logging import get_logger

log = get_logger("enrichment")


# ───────────────────────────────────────────────────────────────
# Singleton GeoIP reader — initialized once, reused for all lookups
# ───────────────────────────────────────────────────────────────
_geoip_reader = None
_geoip_loaded = False
_geoip_last_attempt: float = 0.0
_GEOIP_RETRY_INTERVAL_SEC = 60.0  # Re-attempt init at most once per minute


def _get_geoip_reader():
    """Get or initialize the singleton GeoIP reader.

    Bug fix (Epic 9): the previous implementation set ``_geoip_loaded = True``
    BEFORE the try/except, so a single init failure (missing DB file, perms,
    locked FD) would permanently mark the singleton as loaded and we'd never
    retry for the rest of the process lifetime. We now track the last
    init attempt timestamp and allow periodic retry, but only after a
    minimum interval (default 60s) so we don't thrash the FS on every
    call when the DB is missing.
    """
    global _geoip_reader, _geoip_loaded, _geoip_last_attempt

    if _geoip_loaded:
        return _geoip_reader

    # Throttle retry attempts: if we tried recently and failed, skip until
    # the interval has elapsed.
    now = time.monotonic()
    if _geoip_last_attempt and (now - _geoip_last_attempt) < _GEOIP_RETRY_INTERVAL_SEC:
        return None
    _geoip_last_attempt = now

    try:
        import geoip2.database
        _geoip_reader = geoip2.database.Reader("data/GeoLite2-City.mmdb")
        _geoip_loaded = True
        log.info("geoip_db_loaded")
        return _geoip_reader
    except FileNotFoundError:
        log.debug("geoip_db_not_found")
        _geoip_reader = None
        # Do NOT set _geoip_loaded=True — we want to retry next time
        return None
    except Exception as e:
        log.debug("geoip_init_failed", error=str(e))
        _geoip_reader = None
        # Do NOT set _geoip_loaded=True — we want to retry next time
        return None


async def _geoip_retry_loop():
    """Background coroutine that periodically attempts to (re)open the
    GeoIP database. Useful if the operator drops the .mmdb file in after
    the API has already started — we'll pick it up on the next cycle.

    Runs forever; intended to be cancelled via ``asyncio.CancelledError``
    on shutdown. Failures are logged at debug and swallowed.
    """
    while True:
        await asyncio.sleep(_GEOIP_RETRY_INTERVAL_SEC)
        if _geoip_loaded:
            continue
        # Throttle: only attempt one init per cycle, and respect the
        # last-attempt gate in _get_geoip_reader.
        try:
            reader = _get_geoip_reader()
            if reader is not None:
                log.info("geoip_db_loaded_via_retry_loop")
        except Exception as e:  # pragma: no cover — defensive
            log.debug("geoip_retry_loop_error", error=str(e))


def close_geoip_reader():
    """Close the singleton GeoIP reader (call on shutdown)."""
    global _geoip_reader, _geoip_loaded, _geoip_last_attempt
    if _geoip_reader:
        try:
            _geoip_reader.close()
        except Exception as e:  # pragma: no cover — defensive
            log.exception("geoip_close_failed", error=str(e))  # Non-critical, best-effort close
    _geoip_reader = None
    _geoip_loaded = False
    _geoip_last_attempt = 0.0


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
    Uses singleton reader to avoid file handle leaks.
    """
    if not is_public_ip(ip):
        return {}

    reader = _get_geoip_reader()
    if reader is None:
        return {}

    try:
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

        # Always namespace destination enrichment under "destination" key
        # to prevent overwriting source IP enrichment data
        if dest_enrichment:
            enrichment["destination"] = dest_enrichment

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
