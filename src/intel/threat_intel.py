"""
Threat intelligence feeds integration v2.

Features:
- Scheduled threat intel refresh (via APScheduler)
- AbuseIPDB IP reputation enrichment on ingest
- OTX pulse subscription and auto-ingestion
- URLhaus URL checking during enrichment
- Enrichment pipeline wired into ingestion
- Statistics endpoint

All external API calls use async httpx with proper timeouts and error handling.

P2.5 quota protection (live lookups):
- NEGATIVE CACHE: a clean (no-threat) AbuseIPDB result is remembered in Redis
  for 1h (key scarletai:v1:ti_neg:<ip>) so attacker-sprayed fresh IPs don't
  burn the daily quota on repeat lookups.
- HOURLY BUDGET: live calls are capped per hour (settings.abuseipdb_hourly_budget,
  default 500) via a Redis counter — when exhausted, live calls are SKIPPED and
  logged until the window rolls.
- FAIL-OPEN AVAILABILITY TRADEOFF (deliberate, written down): with Redis
  unavailable, neither mechanism can operate — lookups behave exactly as
  pre-P2.5 (live call, quota burn possible). Enrichment NEVER blocks or fails
  ingestion because of Redis/cache state: every cache/budget error is logged
  and treated as a miss.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, cast

import httpx

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("intel.feeds")

# Refresh interval for threat intel feeds (hours)
FEED_REFRESH_INTERVAL_HOURS = 6

# ───────────────────────────────────────────────────────────────
# Feed health tracking (Epic 9: honest stats)
# ───────────────────────────────────────────────────────────────
# Tracks the OUTCOME of the most recent refresh attempt per source.
# Read by get_threat_intel_stats() via _feed_status_for() so the API
# surfaces real health, not just "is the key set?".
#
# Values stored here (one of):
#   "ok"               — last refresh succeeded
#   "error"            — last refresh raised an exception
#   "never_refreshed"  — key IS set, but no successful refresh has run yet
#   "no_key"           — key is not set in settings
#
# The helper _feed_status_for() reconciles this stored outcome with
# the current settings (key may have been added/removed since the last
# refresh) and returns the right string to the API.
_feed_health: Dict[str, str] = {
    "abuseipdb": "never_refreshed",
    "otx":       "never_refreshed",
    "urlhaus":   "ok",   # URLhaus is always-OK (no key, no auth)
}

# ───────────────────────────────────────────────────────────────
# AbuseIPDB Client
# ───────────────────────────────────────────────────────────────

class AbuseIPDBClient:
    """AbuseIPDB API client — IP reputation checking."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    async def check_ip(self, ip: str) -> Optional[Dict]:
        """Check IP reputation against AbuseIPDB."""
        if not settings.abuseipdb_api_key:
            return None

        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/check",
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": True,
                    },
                    headers={
                        "Key": settings.abuseipdb_api_key,
                        "Accept": "application/json",
                    },
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})

                return {
                    "ip": ip,
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "threat_type": (
                        "malicious_ip"
                        if data.get("abuseConfidenceScore", 0) > 50
                        else None
                    ),
                }
            except httpx.TimeoutException:
                log.warning("abuseipdb_timeout", ip=ip)
                return None
            except Exception as e:
                log.warning("abuseipdb_check_failed", ip=ip, error=str(e))
                return None

    async def get_blacklist(self, confidence_minimum: int = 90) -> List[str]:
        """Get top abused IPs (returns list of IPs for bulk import)."""
        if not settings.abuseipdb_api_key:
            return []

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/blacklist",
                    params={
                        "confidenceMinimum": confidence_minimum,
                        "limit": 1000,
                    },
                    headers={
                        "Key": settings.abuseipdb_api_key,
                        "Accept": "application/json",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                return [ip.get("ipAddress") for ip in data.get("data", []) if ip.get("ipAddress")]
            except Exception as e:
                log.warning("abuseipdb_blacklist_failed", error=str(e))
                return []


# ───────────────────────────────────────────────────────────────
# OTX Client
# ───────────────────────────────────────────────────────────────

class OTXClient:
    """AlienVault Open Threat Exchange client."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.otx_api_key

    async def get_pulse_indicators(self, pulse_id: str) -> List[Dict]:
        """Get IOCs from a threat pulse."""
        if not self.api_key:
            return []

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/pulses/{pulse_id}/indicators",
                    headers={"X-OTX-API-KEY": self.api_key},
                )
                resp.raise_for_status()
                data = resp.json()

                indicators = []
                for ind in data.get("results", []):
                    indicators.append({
                        "type": ind.get("type"),  # IPv4, domain, hostname, URL, etc.
                        "value": ind.get("indicator"),
                        "threat_type": ind.get("title", "unknown"),
                        "confidence": ind.get("confidence", 50),
                        "pulse_name": pulse_id,
                    })

                return indicators
            except Exception as e:
                log.warning("otx_fetch_failed", pulse_id=pulse_id, error=str(e))
                return []

    async def get_subscribed_pulses(self) -> List[Dict]:
        """Get all pulses the user is subscribed to."""
        if not self.api_key:
            return []

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/pulses/subscribed",
                    headers={"X-OTX-API-KEY": self.api_key},
                    params={"limit": 100},
                )
                resp.raise_for_status()
                data = resp.json()
                return cast(List[Dict[str, Any]], data.get("results", []))
            except Exception as e:
                log.warning("otx_pulses_failed", error=str(e))
                return []

    async def get_modified_pulses(self, since: Optional[datetime] = None) -> List[Dict]:
        """Get pulses modified since a given date."""
        if not self.api_key:
            return []

        params: dict[str, Any] = {"limit": 100}
        if since:
            params["modified_since"] = since.isoformat()

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/pulses/subscribed",
                    headers={"X-OTX-API-KEY": self.api_key},
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                return cast(List[Dict[str, Any]], data.get("results", []))
            except Exception as e:
                log.warning("otx_modified_failed", error=str(e))
                return []


# ───────────────────────────────────────────────────────────────
# URLhaus Client
# ───────────────────────────────────────────────────────────────

class URLhausClient:
    """URLhaus malware URL database client."""

    BASE_URL = "https://urlhaus-api.abuse.ch"

    async def check_url(self, url: str) -> Optional[Dict]:
        """Check if URL is known malware."""
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/v1/url/",
                    data={"url": url},
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("query_status") == "no_results":
                    return None

                return {
                    "url": url,
                    "threat": data.get("threat", "unknown"),
                    "tags": data.get("tags", []),
                    "malware": (
                        data.get("payloads", [{}])[0].get(
                            "signature", "unknown"
                        )
                        if data.get("payloads")
                        else "unknown"
                    ),
                }
            except Exception as e:
                log.warning("urlhaus_check_failed", url=url, error=str(e))
                return None

    async def get_recent_urls(self, limit: int = 100) -> List[Dict]:
        """Get recent malicious URLs (no API key needed)."""
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/v1/urls/recent/",
                    params={"limit": limit},
                )
                resp.raise_for_status()
                data = resp.json()

                urls = []
                for entry in data.get("urls", []):
                    urls.append({
                        "url": entry.get("url"),
                        "threat": entry.get("threat"),
                        "tags": entry.get("tags", []),
                        "host": entry.get("host", ""),
                    })

                return urls
            except Exception as e:
                log.warning("urlhaus_fetch_failed", error=str(e))
                return []


# ───────────────────────────────────────────────────────────────
# Threat Intel Database Operations
# ───────────────────────────────────────────────────────────────

async def cache_ioc(
    ioc_type: str,
    ioc_value: str,
    source: str,
    threat_type: str,
    confidence: int = 80,
    metadata: Optional[dict] = None,
) -> None:
    """Cache a single IOC in the threat_intel table."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO threat_intel (
                ioc_type, ioc_value, source, threat_type, confidence, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (ioc_type, ioc_value, source) DO UPDATE
            SET last_seen = NOW(),
                fetched_at = NOW(),
                confidence = GREATEST(threat_intel.confidence, $5)
            """,
            ioc_type,
            ioc_value,
            source,
            threat_type,
            confidence,
            json.dumps(metadata) if metadata else "{}",
        )


async def cache_iocs_bulk(iocs: List[Dict], source: str) -> int:
    """Cache a batch of IOCs efficiently."""
    if not iocs:
        return 0

    pool = await get_pool()
    total_cached = 0

    async with pool.acquire() as conn:
        for ioc in iocs:
            try:
                ioc_type = _map_ioc_type(ioc.get("type", ""))
                ioc_value = ioc.get("value", ioc.get("url", ioc.get("ip", "")))
                if not ioc_type or not ioc_value:
                    continue

                await conn.execute(
                    """
                    INSERT INTO threat_intel (
                        ioc_type, ioc_value, source, threat_type, confidence, metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (ioc_type, ioc_value, source) DO UPDATE
                    SET last_seen = NOW(), fetched_at = NOW(),
                        confidence = GREATEST(threat_intel.confidence, $5)
                    """,
                    ioc_type,
                    ioc_value,
                    source,
                    ioc.get("threat_type", ioc.get("threat", "malware")),
                    ioc.get("confidence", 80),
                    json.dumps(ioc.get("metadata", {})),
                )
                total_cached += 1
            except Exception as e:
                log.warning("ioc_cache_failed", value=ioc.get("value", ""), error=str(e))

    return total_cached


def _map_ioc_type(otx_type: str) -> str:
    """Map OTX indicator types to our ioc_type enum."""
    mapping = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "uri": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA256": "hash_sha256",
        "email": "email",
    }
    return mapping.get(otx_type, "")


# ───────────────────────────────────────────────────────────────
# Scheduled Threat Intel Refresh
# ───────────────────────────────────────────────────────────────

async def refresh_all_feeds() -> Dict[str, int]:
    """
    Refresh all threat intel feeds.

    Returns:
        Dictionary with feed names and count of new IOCs cached.
    """
    results = {}

    # URLhaus — always available (no API key needed)
    urlhaus = URLhausClient()
    try:
        urls = await urlhaus.get_recent_urls(limit=200)
        if urls:
            iocs = []
            for u in urls:
                iocs.append({
                    "type": "url",
                    "value": u.get("url"),
                    "threat_type": u.get("threat", "malware"),
                    "confidence": 75,
                    "metadata": {"tags": u.get("tags", []), "host": u.get("host", "")},
                })
            count = await cache_iocs_bulk(iocs, source="urlhaus")
            results["urlhaus"] = count
        else:
            results["urlhaus"] = 0
        _feed_health["urlhaus"] = "ok"
    except Exception as e:
        log.error("urlhaus_refresh_failed", error=str(e))
        results["urlhaus"] = 0
        _feed_health["urlhaus"] = "error"

    # AbuseIPDB — requires API key
    abuseipdb = AbuseIPDBClient()
    if settings.abuseipdb_api_key:
        try:
            blacklist = await abuseipdb.get_blacklist(confidence_minimum=90)
            if blacklist:
                iocs = [{
                    "type": "IPv4",
                    "value": ip,
                    "threat_type": "malicious_ip",
                    "confidence": 90,
                } for ip in blacklist]
                count = await cache_iocs_bulk(iocs, source="abuseipdb")
                results["abuseipdb"] = count
            else:
                results["abuseipdb"] = 0
            _feed_health["abuseipdb"] = "ok"
        except Exception as e:
            log.error("abuseipdb_refresh_failed", error=str(e))
            results["abuseipdb"] = 0
            _feed_health["abuseipdb"] = "error"
    else:
        results["abuseipdb"] = -1  # Not configured
        _feed_health["abuseipdb"] = "no_key"

    # OTX — requires API key
    otx = OTXClient()
    if settings.otx_api_key:
        try:
            # Get pulses modified in last 6 hours
            since = datetime.now(timezone.utc) - timedelta(hours=FEED_REFRESH_INTERVAL_HOURS)
            pulses = await otx.get_modified_pulses(since=since)

            total_indicators = 0
            for pulse in pulses[:10]:  # Limit to 10 pulses per refresh
                pulse_id = pulse.get("id", "")
                indicators = await otx.get_pulse_indicators(pulse_id)
                if indicators:
                    count = await cache_iocs_bulk(indicators, source="otx")
                    total_indicators += count

                # Rate limit
                await asyncio.sleep(1)

            results["otx"] = total_indicators
            _feed_health["otx"] = "ok"
        except Exception as e:
            log.error("otx_refresh_failed", error=str(e))
            results["otx"] = 0
            _feed_health["otx"] = "error"
    else:
        results["otx"] = -1  # Not configured
        _feed_health["otx"] = "no_key"

    total = sum(v for v in results.values() if v > 0)
    log.info("threat_intel_refresh_complete", total_cached=total, details=results)
    return results


# ───────────────────────────────────────────────────────────────
# IOC Matching (for enrichment pipeline)
# ───────────────────────────────────────────────────────────────

async def check_ioc_match(ioc_type: str, ioc_value: str) -> Optional[Dict]:
    """Check if an IOC matches cached threat intel data."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM threat_intel
            WHERE ioc_type = $1 AND ioc_value = $2
            ORDER BY confidence DESC, last_seen DESC
            LIMIT 1
            """,
            ioc_type,
            ioc_value,
        )

        if row:
            return dict(row)
        return None


# ───────────────────────────────────────────────────────────────
# P2.5 — AbuseIPDB quota protection (negative cache + hourly budget)
# ───────────────────────────────────────────────────────────────

_TI_NEG_TTL_SECONDS = 3600  # clean-IP memory window
_TI_NEG_KEY = "scarletai:v1:ti_neg:"
_TI_BUDGET_KEY = "scarletai:v1:ti_budget:abuseipdb:"
_BUDGET_WINDOW_SECONDS = 3600


async def _ti_redis_client():
    """Shared async Redis client (may be None when Redis is down)."""
    from src.api.redis_client import _get_client

    return await _get_client()


async def _abuseipdb_negative_hit(ip: str) -> bool:
    """True when this IP was confirmed CLEAN within the negative-cache TTL."""
    try:
        client = await _ti_redis_client()
        if client is None:
            return False
        return bool(await client.exists(f"{_TI_NEG_KEY}{ip}"))
    except Exception as e:
        log.debug("ti_negative_cache_check_failed", error=str(e))
        return False


async def _abuseipdb_negative_set(ip: str) -> None:
    """Remember that this IP is clean (no threat) for the TTL window."""
    try:
        client = await _ti_redis_client()
        if client is None:
            return
        await client.setex(f"{_TI_NEG_KEY}{ip}", _TI_NEG_TTL_SECONDS, "1")
    except Exception as e:
        log.debug("ti_negative_cache_set_failed", error=str(e))


async def _abuseipdb_budget_consume() -> bool:
    """Consume one slot of the hourly live-call budget.

    Returns False when the budget is exhausted (caller must skip the live
    call). Fail-open: with Redis unavailable there is no accounting, so the
    call is allowed (same availability tradeoff as every Redis consumer).
    """
    try:
        import time as _time

        client = await _ti_redis_client()
        if client is None:
            return True
        hour_bucket = int(_time.time() // _BUDGET_WINDOW_SECONDS)
        key = f"{_TI_BUDGET_KEY}{hour_bucket}"
        count = int(await client.incr(key) or 0)
        if count == 1:
            await client.expire(key, _BUDGET_WINDOW_SECONDS)
        if count > settings.abuseipdb_hourly_budget:
            return False
        return True
    except Exception as e:
        log.debug("ti_budget_check_failed", error=str(e))
        return True


async def enrich_ip_with_threat_intel(ip: str) -> Dict[str, Any]:
    """
    Enrich an IP address with threat intel data.

    Checks local cache first, then falls back to the AbuseIPDB API if
    available — BEHIND the P2.5 quota protection (negative cache + hourly
    budget). Returns enrichment dict to merge into the event.
    """
    enrichment: Dict[str, Any] = {}

    # Check local cache first
    cached = await check_ioc_match("ip", ip)
    if cached:
        enrichment["threat_intel"] = {
            "match": True,
            "source": cached.get("source", "unknown"),
            "threat_type": cached.get("threat_type"),
            "confidence": cached.get("confidence", 0),
            "last_seen": str(cached.get("last_seen", "")),
        }
        # If high-confidence match, also check AbuseIPDB for more details
        if cached.get("confidence", 0) >= 80:
            enrichment["threat_intel"]["severity_boost"] = "high"

    # If no cache hit and we have AbuseIPDB key, check live — but never
    # without the P2.5 quota guards (a sprayed fresh IP used to cost a live
    # call EVERY time; now repeats are free within the TTL window and the
    # hourly budget caps the volumetric cost).
    elif settings.abuseipdb_api_key:
        if await _abuseipdb_negative_hit(ip):
            log.debug("ti_negative_cache_hit", ip=ip)
            return enrichment
        if not await _abuseipdb_budget_consume():
            log.warning(
                "abuseipdb_hourly_budget_exhausted",
                ip=ip,
                budget=settings.abuseipdb_hourly_budget,
            )
            return enrichment

        abuseipdb = AbuseIPDBClient()
        result = await abuseipdb.check_ip(ip)
        if result:
            enrichment["threat_intel"] = {
                "match": result.get("threat_type") is not None,
                "source": "abuseipdb",
                "threat_type": result.get("threat_type"),
                "confidence": result.get("abuse_confidence", 0),
                "country": result.get("country"),
                "isp": result.get("isp"),
            }
            # Cache for future lookups
            if result.get("threat_type"):
                await cache_ioc(
                    "ip", ip, "abuseipdb",
                    result["threat_type"],
                    result.get("abuse_confidence", 0),
                )
            else:
                # P2.5: clean result — negative-cache so repeats skip the API
                await _abuseipdb_negative_set(ip)

    return enrichment


async def enrich_url_with_threat_intel(url: str) -> Dict[str, Any]:
    """Enrich a URL with URLhaus threat intel data."""
    enrichment: Dict[str, Any] = {}

    # Check local cache first
    cached = await check_ioc_match("url", url)
    if cached:
        enrichment["threat_intel"] = {
            "match": True,
            "source": cached.get("source", "unknown"),
            "threat_type": cached.get("threat_type"),
            "confidence": cached.get("confidence", 0),
        }
    else:
        # Check URLhaus live
        urlhaus = URLhausClient()
        result = await urlhaus.check_url(url)
        if result:
            enrichment["threat_intel"] = {
                "match": True,
                "source": "urlhaus",
                "threat_type": result.get("threat", "unknown"),
                "confidence": 80,
                "tags": result.get("tags", []),
            }
            # Cache for future lookups
            await cache_ioc("url", url, "urlhaus", result.get("threat", "malware"), 80)

    return enrichment


# ───────────────────────────────────────────────────────────────
# Statistics
# ───────────────────────────────────────────────────────────────

async def get_threat_intel_stats() -> Dict[str, Any]:
    """Get threat intel statistics for the API endpoint."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM threat_intel")
        by_type = await conn.fetch(
            "SELECT ioc_type, COUNT(*) as count FROM threat_intel GROUP BY ioc_type"
        )
        by_source = await conn.fetch(
            "SELECT source, COUNT(*) as count FROM threat_intel GROUP BY source"
        )
        last_refresh = await conn.fetchval(
            "SELECT MAX(fetched_at) FROM threat_intel"
        )

        return {
            "total_indicators": total or 0,
            "by_type": {row["ioc_type"]: row["count"] for row in by_type},
            "by_source": {row["source"]: row["count"] for row in by_source},
            "last_refresh": str(last_refresh) if last_refresh else "never",
            "feed_status": {
                # Epic 9: honest stats. Values:
                #   "ok"              — last refresh succeeded
                #   "error"           — last refresh raised
                #   "no_key"          — API key not configured
                #   "never_refreshed" — key set but no refresh has run yet
                "abuseipdb": _feed_status_for("abuseipdb", settings.abuseipdb_api_key),
                "otx":       _feed_status_for("otx",       settings.otx_api_key),
                "urlhaus":   _feed_status_for("urlhaus",   "urlhaus"),  # always non-empty
            },
            "feed_keys": {  # Operator-facing: was a key ever configured?
                "abuseipdb": bool(settings.abuseipdb_api_key),
                "otx":       bool(settings.otx_api_key),
                "urlhaus":   True,
            },
        }


def _feed_status_for(source: str, api_key: str | None) -> str:
    """Compute the current health string for a feed, reconciling the
    most recent refresh outcome with the current settings.

    Precedence (most important first):
      1. If the key is currently missing -> "no_key"
      2. If the stored state is "no_key" (stale from a refresh run when
         no key was set) and the key is now set -> "never_refreshed"
      3. Otherwise return the stored state (ok/error/never_refreshed),
         defaulting to "never_refreshed" if no refresh has ever run.
    """
    if source != "urlhaus" and not api_key:
        return "no_key"
    stored = _feed_health.get(source, "never_refreshed")
    if stored == "no_key":
        # Refresh ran when no key was set, but a key is now configured.
        # The stored state is stale; treat as never refreshed.
        return "never_refreshed"
    return stored


# ───────────────────────────────────────────────────────────────
# Scheduled refresh setup (called from main.py lifespan)
# ───────────────────────────────────────────────────────────────

_async_scheduler = None


async def start_threat_intel_scheduler():
    """Start the periodic threat intel refresh (every 6 hours).

    Air-gapped / no-egress mode (THREAT_INTEL_ENABLED=false): the scheduler is
    NOT started and refresh_all_feeds is NOT fired, so no external feed calls
    (URLhaus/AbuseIPDB/OTX) are made. IOC enrichment still matches the local
    threat_intel cache; pre-load IOCs offline before going dark. See
    docs/AIR-GAPPED.md.
    """
    if not settings.threat_intel_enabled:
        log.info("threat_intel_disabled_air_gapped_mode")
        return

    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    global _async_scheduler
    _async_scheduler = AsyncIOScheduler()

    _async_scheduler.add_job(
        refresh_all_feeds,
        trigger=IntervalTrigger(hours=FEED_REFRESH_INTERVAL_HOURS),
        id="threat_intel_refresh",
        replace_existing=True,
    )

    # P2-17: don't block API startup on the initial refresh (up to ~90s of
    # external HTTP to URLhaus/AbuseIPDB/OTX on a cold/no-network boot). Fire it
    # as a background task so the health check passes immediately; the
    # scheduled 6h refresh keeps it current.
    asyncio.create_task(refresh_all_feeds())

    _async_scheduler.start()
    log.info("threat_intel_scheduler_started", interval_hours=FEED_REFRESH_INTERVAL_HOURS)


async def stop_threat_intel_scheduler():
    """Stop the threat intel scheduler."""
    global _async_scheduler
    if _async_scheduler:
        _async_scheduler.shutdown()
        log.info("threat_intel_scheduler_stopped")

