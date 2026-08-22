"""
Health check endpoints — self-observability for the SIEM.

Returns a structured `ollama_status` block: "healthy" | "degraded" |
"unavailable". Replaces the boolean `ollama` key with a richer shape
for monitoring/alerting.

Backward compat: `checks["ollama"]` is still populated with the same
string values as before so existing tests/monitors don't break.
"""
import time
from typing import Any, cast

from fastapi import APIRouter

from src.ai.ollama_client import validate_ollama_model
from src.config.logging import get_logger
from src.db.connection import get_pool

router = APIRouter(tags=["health"])
log = get_logger("api.health")

# P2-34: cache the Ollama probe (a 5s HTTP GET to /api/tags) so /health stays
# cheap for monitoring polling. Refreshed at most once per _OLLAMA_CACHE_TTL.
_OLLAMA_CACHE: dict[str, Any] = {"result": None, "ts": 0.0}
_OLLAMA_CACHE_TTL = 60.0


async def _cached_ollama_check() -> tuple[bool, str | None, str | None]:
    now = time.time()
    cached = _OLLAMA_CACHE["result"]
    if cached is not None and now - _OLLAMA_CACHE["ts"] < _OLLAMA_CACHE_TTL:
        return cast(tuple[bool, str | None, str | None], cached)
    try:
        result = await validate_ollama_model()
    except Exception as e:
        result = (False, None, str(e))
    _OLLAMA_CACHE["result"] = result
    _OLLAMA_CACHE["ts"] = now
    return result


def _derive_status(available: bool, error: str | None) -> str:
    """Map (available, error) to one of: healthy | degraded | unavailable."""
    if available:
        return "healthy"
    if error and "unreachable" in error.lower():
        return "unavailable"
    if error and "model" in error.lower():
        return "degraded"
    return "unavailable"


@router.get("/health")
async def health_check():
    """Basic liveness check with rich Ollama status."""
    checks = {"api": "ok", "database": "unknown"}

    # Database
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = "error"  # H-16 fix: don't expose internal details
        log.error("health_check_db_failed", error=str(e))

    # Ollama (rich status block, but maintain backward-compat string in checks)
    ollama_status_value = "unavailable"
    ollama_model_check = None
    ollama_error = None
    try:
        available, model_name, error = await _cached_ollama_check()
        ollama_status_value = _derive_status(available, error)
        ollama_model_check = model_name
        ollama_error = error
    except Exception as e:
        ollama_status_value = "unavailable"
        ollama_error = str(e)
        log.warning("health_check_ollama_failed", error=str(e))

    # Backward compat: keep `checks["ollama"]` populated with the same
    # string values as before. Old tests / monitors expect this key.
    if ollama_status_value == "healthy":
        checks["ollama"] = "ok"
    elif ollama_status_value == "degraded":
        checks["ollama"] = "error"  # historical mapping
    else:
        checks["ollama"] = "unreachable"

    ollama_block = {
        "ollama_status": ollama_status_value,
        "model": ollama_model_check,
        "error": ollama_error,
    }

    overall = (
        "healthy"
        if all(v in ("ok",) for v in checks.values()) and ollama_status_value == "healthy"
        else "degraded"
    )
    return {
        "status": overall,
        "checks": checks,
        "ollama_status": ollama_status_value,
        "ollama": ollama_block,
    }
