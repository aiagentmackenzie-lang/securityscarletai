"""
Threat intelligence feeds integration.

Fetches IOCs from free APIs:
- AbuseIPDB (malicious IP reputation)
- AlienVault OTX (community threat intel)
- URLhaus (malicious URLs)
"""
from typing import Dict, List, Optional

import httpx

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("intel.feeds")


class AbuseIPDBClient:
    """AbuseIPDB API client."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    async def check_ip(self, ip: str) -> Optional[Dict]:
        """Check IP reputation."""
        if not settings.abuseipdb_api_key:
            return None

        async with httpx.AsyncClient() as client:
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
                    timeout=10,
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
                    "threat_type": "malicious_ip" if data.get("abuseConfidenceScore", 0) > 50 else None,
                }
            except Exception as e:
                log.warning("abuseipdb_check_failed", ip=ip, error=str(e))
                return None

    async def get_blacklist(self, confidence_minimum: int = 90) -> List[str]:
        """Get top abused IPs (simplified - returns list of IPs)."""
        # In production, use /blacklist endpoint
        log.info("fetching_abuseipdb_blacklist")
        return []  # Placeholder


class OTXClient:
    """AlienVault Open Threat Exchange client."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    async def get_pulse_indicators(self, pulse_id: str) -> List[Dict]:
        """Get IOCs from a threat pulse."""
        if not settings.otx_api_key:
            return []

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/pulses/{pulse_id}/indicators",
                    headers={"X-OTX-API-KEY": settings.otx_api_key},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()

                indicators = []
                for ind in data.get("results", []):
                    indicators.append({
                        "type": ind.get("type"),  # IPv4, domain, etc.
                        "value": ind.get("indicator"),
                        "threat_type": ind.get("title", "unknown"),
                        "confidence": ind.get("confidence", 50),
                    })

                return indicators
            except Exception as e:
                log.warning("otx_fetch_failed", pulse_id=pulse_id, error=str(e))
                return []


class URLhausClient:
    """URLhaus malware URL database client."""

    BASE_URL = "https://urlhaus-api.abuse.ch"

    async def check_url(self, url: str) -> Optional[Dict]:
        """Check if URL is known malware."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/v1/url/",
                    data={"url": url},
                    timeout=10,
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("query_status") == "no_results":
                    return None

                return {
                    "url": url,
                    "threat": data.get("threat", "unknown"),
                    "tags": data.get("tags", []),
                    "malware": data.get("payloads", [{}])[0].get("signature", "unknown"),
                }
            except Exception as e:
                log.warning("urlhaus_check_failed", url=url, error=str(e))
                return None

    async def get_recent_urls(self, limit: int = 100) -> List[Dict]:
        """Get recent malicious URLs (no API key needed)."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/v1/urls/recent/",
                    params={"limit": limit},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()

                urls = []
                for entry in data.get("urls", []):
                    urls.append({
                        "url": entry.get("url"),
                        "threat": entry.get("threat"),
                        "tags": entry.get("tags", []),
                    })

                return urls
            except Exception as e:
                log.warning("urlhaus_fetch_failed", error=str(e))
                return []


async def fetch_and_cache_iocs() -> int:
    """
    Fetch IOCs from all sources and cache in database.
    
    Returns:
        Number of IOCs cached
    """
    urlhaus = URLhausClient()

    total_cached = 0

    # Fetch URLhaus URLs
    urls = await urlhaus.get_recent_urls(limit=100)

    pool = await get_pool()
    async with pool.acquire() as conn:
        for url_data in urls:
            try:
                await conn.execute(
                    """
                    INSERT INTO threat_intel (
                        ioc_type, ioc_value, source, threat_type, confidence
                    ) VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (ioc_type, ioc_value, source) DO UPDATE
                    SET last_seen = NOW(), fetched_at = NOW()
                    """,
                    "url",
                    url_data["url"],
                    "urlhaus",
                    url_data.get("threat", "malware"),
                    80,  # Default confidence
                )
                total_cached += 1
            except Exception as e:
                log.warning("ioc_cache_failed", url=url_data.get("url"), error=str(e))

    log.info("iocs_fetched", count=total_cached)
    return total_cached


async def check_ioc_match(ioc_type: str, ioc_value: str) -> Optional[Dict]:
    """Check if an IOC matches cached threat intel."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM threat_intel
            WHERE ioc_type = $1 AND ioc_value = $2
            LIMIT 1
            """,
            ioc_type,
            ioc_value,
        )

        if row:
            return dict(row)
        return None
