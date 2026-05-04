"""
Threat intelligence API endpoints.

Statistics, manual refresh, and IOC queries.
"""

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_role, verify_bearer_token
from src.config.logging import get_logger
from src.intel.threat_intel import (
    check_ioc_match,
    get_threat_intel_stats,
    refresh_all_feeds,
)

router = APIRouter(tags=["threat-intel"], prefix="/threat-intel")
log = get_logger("api.threat_intel")


@router.get("/stats")
async def threat_intel_stats(
    user: str = Depends(verify_bearer_token),
):
    """Get threat intelligence statistics."""
    return await get_threat_intel_stats()


@router.post("/refresh")
async def refresh_threat_intel(
    user: str = Depends(require_role("admin")),
):
    """Manually trigger a threat intel feed refresh. Admin only."""
    try:
        results = await refresh_all_feeds()
        return {"status": "completed", "results": results}
    except Exception as e:
        log.error("manual_refresh_failed", error=str(e))
        raise HTTPException(
            status_code=500, detail=str(e)
        ) from None


@router.get("/lookup/ip/{ip_address}")
async def lookup_ip(
    ip_address: str,
    user: str = Depends(verify_bearer_token),
):
    """Look up an IP address in cached threat intel data."""
    result = await check_ioc_match("ip", ip_address)
    if result:
        return result
    return {"match": False, "ip": ip_address}


@router.get("/lookup/url")
async def lookup_url(
    url: str = Query(..., description="URL to check"),
    user: str = Depends(verify_bearer_token),
):
    """Look up a URL in cached threat intel data."""
    result = await check_ioc_match("url", url)
    if result:
        return result
    return {"match": False, "url": url}


@router.get("/lookup/hash/{hash_value}")
async def lookup_hash(
    hash_value: str,
    user: str = Depends(verify_bearer_token),
):
    """Look up a file hash in cached threat intel data."""
    # Determine hash type by length
    if len(hash_value) == 32:
        hash_type = "hash_md5"
    elif len(hash_value) == 64:
        hash_type = "hash_sha256"
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid hash length (expected MD5=32 or SHA256=64)",
        )

    result = await check_ioc_match(hash_type, hash_value)
    if result:
        return result
    return {"match": False, "hash": hash_value, "type": hash_type}
