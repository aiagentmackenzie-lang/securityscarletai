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
from concurrent.futures import ThreadPoolExecutor
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


# F-03 (plan phase 5): socket.gethostbyaddr has NO timeout and blocks the
# event loop outright when called inline from the async ingest path — a slow
# resolver stalls EVERY request (event-loop DoS from attacker-chosen IPs).
# All reverse-DNS runs on a bounded thread pool instead, best-effort.
_DNS_EXECUTOR_MAX_WORKERS = 4
_dns_executor: ThreadPoolExecutor | None = None


def _get_dns_executor() -> ThreadPoolExecutor:
    global _dns_executor
    if _dns_executor is None:
        _dns_executor = ThreadPoolExecutor(
            max_workers=_DNS_EXECUTOR_MAX_WORKERS, thread_name_prefix="reverse-dns"
        )
    return _dns_executor


def _resolve_reverse(ip: str) -> dict[str, Any]:
    """Blocking body of the reverse lookup (runs on a pool thread)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"dns": {"reverse": hostname}}
    except (socket.herror, socket.gaierror, OSError):
        return {}


def enrich_dns_reverse(ip: str) -> dict[str, Any]:
    """Reverse DNS lookup — synchronous, for callers outside the loop."""
    if not is_public_ip(ip):
        return {}
    return _resolve_reverse(ip)


async def enrich_dns_reverse_async(ip: str) -> dict[str, Any]:
    """Async reverse DNS on a bounded pool thread.

    Per-call resolv timeout is NOT configurable in gethostbyaddr; the bound
    workers cap the concurrent blast radius and the event loop never blocks.
    Best-effort by design: a failed/timeout lookup yields no enrichment.
    """
    if not is_public_ip(ip):
        return {}
    return await asyncio.get_running_loop().run_in_executor(
        _get_dns_executor(), _resolve_reverse, ip
    )


async def enrich_with_threat_intel(
    ip: str, prefetched: dict[str, dict[str, Any] | None] | None = None
) -> dict[str, Any]:
    """Enrich an IP with threat intel data from cache and live APIs.

    W2-D/B5: ``prefetched`` is a batch-level {ip: cached-row-or-nothing}
    map from ONE check_ioc_matches query (see write_back_enrichment). When
    the ip is a key in the map, its cache verdict comes from the batch
    query — the per-IP cache round-trip is skipped. A miss still falls
    through to the live path (negative cache + budget), exactly like the
    single-IP path. ``None`` keeps the historical per-IP lookup.
    """
    from src.intel.threat_intel import enrich_ip_with_threat_intel

    try:
        return await enrich_ip_with_threat_intel(ip, prefetched=prefetched)
    except Exception as e:
        log.warning("threat_intel_enrichment_failed", ip=ip, error=str(e))
        return {}


async def enrich_event(
    event, ti_prefetch: dict[str, dict[str, Any] | None] | None = None
) -> dict[str, Any]:
    """
    Run all enrichments for an event.

    This is the main entry point called from the ingestion pipeline.
    Returns a merged enrichment dict to be stored in the event's
    enrichment JSONB column.

    Args:
        event: A LogEvent or similar object with source_ip, destination_ip attributes.
        ti_prefetch: W2-D/B5 batch-level {ip: cached-row-or-nothing} from ONE
            check_ioc_matches query — skips the per-IP cache round-trip.
    """
    enrichment: dict[str, Any] = {}

    # ── Enrich source IP ──────────────────────────────────
    if event.source_ip and is_public_ip(event.source_ip):
        # GeoIP
        geo = await enrich_geoip(event.source_ip)
        if geo:
            enrichment.update(geo)

        # DNS reverse (F-03: off-loop, bounded pool)
        dns = await enrich_dns_reverse_async(event.source_ip)
        if dns:
            enrichment.update(dns)

        # Threat Intel
        ti = await enrich_with_threat_intel(event.source_ip, prefetched=ti_prefetch)
        if ti:
            enrichment.update(ti)

    # ── Enrich destination IP ──────────────────────────────────
    if event.destination_ip and is_public_ip(event.destination_ip):
        dest_enrichment: dict[str, Any] = {}

        # GeoIP
        geo = await enrich_geoip(event.destination_ip)
        if geo:
            dest_enrichment.update(geo)

        # DNS (F-03: off-loop, bounded pool)
        dns = await enrich_dns_reverse_async(event.destination_ip)
        if dns:
            dest_enrichment.update(dns)

        # Threat Intel
        ti = await enrich_with_threat_intel(event.destination_ip, prefetched=ti_prefetch)
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


async def write_back_enrichment(events: list) -> None:
    """Persist + enrich + write back a batch of NormalizedEvent — the
    W1.8 shared-builder doctrine: the ingest post-process AND the W2.2
    durable consumer use THE SAME function (no drift). Flush first (the
    writer is batched, P1-07), then per-event enrichment keyed on the
    natural key plus BOTH endpoint ips (F-18: the tuple-only UPDATE could
    land one event's enrichment on a later, different-IP event sharing the
    same natural key — the inputs to enrichment ARE the ips). Best-effort:
    a failure here never affects ingestion.

    W2-D/B5: the cached-TI lookups are BATCHED — distinct public IPs across
    the batch are resolved with ONE check_ioc_matches query (per-IP cache
    round-trips previously scaled with the batch: a 1000-event batch cost
    up to 2000 fetchrows just to read the cache).
    """
    import json as _json

    from src.db.connection import get_pool
    from src.intel.threat_intel import check_ioc_matches
    from src.services.writer import writer

    # Persist the just-written batch so the enrichment write-back below
    # can find the rows.
    await writer.flush()

    # W2-D/B5: one batched cache query for all distinct public IPs in the
    # batch; the per-event path reads its verdicts from this map.
    distinct_ips: set[str] = set()
    for event_data in events:
        for ip in (event_data.source_ip, event_data.destination_ip):
            if ip and is_public_ip(ip):
                distinct_ips.add(ip)
    ti_prefetch = await check_ioc_matches("ip", sorted(distinct_ips))

    pool = await get_pool()
    async with pool.acquire() as conn:
        for event_data in events:
            try:
                enrichment = await enrich_event_dict(
                    event_data.model_dump(by_alias=True), ti_prefetch=ti_prefetch
                )
                if enrichment:
                    await conn.execute(
                        """UPDATE logs SET enrichment = $1::jsonb
                           WHERE time = $2 AND host_name = $3
                             AND source = $4 AND event_category = $5
                             AND event_type = $6
                             AND source_ip::text
                               = COALESCE($7::text, source_ip::text)
                             AND destination_ip::text
                               = COALESCE($8::text,
                                          destination_ip::text)""",
                        _json.dumps(enrichment),
                        event_data.timestamp,
                        event_data.host_name,
                        event_data.source,
                        event_data.event_category,
                        event_data.event_type,
                        event_data.source_ip,
                        event_data.destination_ip,
                    )
                    log.debug(
                        "ingest_enrichment_persisted",
                        host=event_data.host_name,
                        keys=list(enrichment.keys()),
                    )
            except Exception as e:  # pragma: no cover — defensive
                log.warning(
                    "ingest_enrichment_failed",
                    host=getattr(event_data, "host_name", None),
                    error=str(e),
                )


async def enrich_event_dict(
    event_data: dict, ti_prefetch: dict[str, dict[str, Any] | None] | None = None
) -> dict[str, Any]:
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
    return await enrich_event(event, ti_prefetch=ti_prefetch)
