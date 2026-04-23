"""
Health check endpoints — self-observability for the SIEM.
"""
from fastapi import APIRouter

from src.config.logging import get_logger
from src.db.connection import get_pool

router = APIRouter(tags=["health"])
log = get_logger("api.health")


@router.get("/health")
async def health_check():
    """Basic liveness check."""
    checks = {"api": "ok", "database": "unknown", "ollama": "unknown"}

    # Database
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)}"
        log.error("health_check_db_failed", error=str(e))

    # Ollama (non-blocking check)
    try:
        import httpx

        from src.config.settings import settings
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            checks["ollama"] = "ok" if resp.status_code == 200 else f"status {resp.status_code}"
    except Exception:
        checks["ollama"] = "unreachable"

    overall = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}
