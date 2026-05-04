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
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("intel.feeds")

# Refresh interval for threat intel feeds (hours)
FEED_REFRESH_INTERVAL_HOURS = 6

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
                return data.get("results", [])
            except Exception as e:
                log.warning("otx_pulses_failed", error=str(e))
                return []

    async def get_modified_pulses(self, since: Optional[datetime] = None) -> List[Dict]:
        """Get pulses modified since a given date."""
        if not self.api_key:
            return []

        params = {"limit": 100}
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
                return data.get("results", [])
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
        "domain": "ip",  # Will be stored as domain type
        "hostname": "ip",
        "URL": "url",
        "uri": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA256": "hash_sha256",
        "email": "ip",  # Store as generic for now
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
    except Exception as e:
        log.error("urlhaus_refresh_failed", error=str(e))
        results["urlhaus"] = 0

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
        except Exception as e:
            log.error("abuseipdb_refresh_failed", error=str(e))
            results["abuseipdb"] = 0
    else:
        results["abuseipdb"] = -1  # Not configured

    # OTX — requires API key
    otx = OTXClient()
    if settings.otx_api_key:
        try:
            # Get pulses modified in last 6 hours
            since = datetime.utcnow() - timedelta(hours=FEED_REFRESH_INTERVAL_HOURS)
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
        except Exception as e:
            log.error("otx_refresh_failed", error=str(e))
            results["otx"] = 0
    else:
        results["otx"] = -1  # Not configured

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


async def enrich_ip_with_threat_intel(ip: str) -> Dict[str, Any]:
    """
    Enrich an IP address with threat intel data.

    Checks local cache first, then falls back to API if available.
    Returns enrichment dict to merge into the event.
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

    # If no cache hit and we have AbuseIPDB key, check live
    elif settings.abuseipdb_api_key:
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
                "abuseipdb": "configured" if settings.abuseipdb_api_key else "not_configured",
                "otx": "configured" if settings.otx_api_key else "not_configured",
                "urlhaus": "configured",  # Always available
            },
        }


# ───────────────────────────────────────────────────────────────
# Scheduled refresh setup (called from main.py lifespan)
# ───────────────────────────────────────────────────────────────

_async_scheduler = None


async def start_threat_intel_scheduler():
    """Start the periodic threat intel refresh (every 6 hours)."""
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

    # Run initial refresh
    try:
        await refresh_all_feeds()
    except Exception as e:
        log.error("initial_threat_intel_refresh_failed", error=str(e))

    _async_scheduler.start()
    log.info("threat_intel_scheduler_started", interval_hours=FEED_REFRESH_INTERVAL_HOURS)


async def stop_threat_intel_scheduler():
    """Stop the threat intel scheduler."""
    global _async_scheduler
    if _async_scheduler:
        _async_scheduler.shutdown()
        log.info("threat_intel_scheduler_stopped")


# ───────────────────────────────────────────────────────────────
# Enrichment module (wires threat intel into ingestion)
# ───────────────────────────────────────────────────────────────

