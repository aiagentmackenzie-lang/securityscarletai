"""
AI cost and usage tracker.

Records every LLM call (success, fallback, or error) to the `ai_usage`
table. Non-blocking on failure — if the DB is down, we log and continue.
The user-facing AI feature must never break because the cost tracker
can't write.
"""
from datetime import datetime, timezone
from typing import Any, Optional

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.cost_tracker")


async def record_usage(
    user: Optional[str],
    endpoint: str,
    model: str,
    tokens_in: int,
    tokens_out: int,
    latency_ms: int,
    prompt_version: Optional[str] = None,
    source: Optional[str] = None,
    fallback_used: bool = False,
    warning: Optional[str] = None,
) -> bool:
    """Record a single LLM call. Returns True on successful insert.

    Args:
        user: The authenticated user (or None for system calls)
        endpoint: e.g. "ai.explain", "ai.chat", "ai.investigate"
        model: Model identifier, e.g. "mistral:7b" or "template_library"
        tokens_in: Prompt tokens (0 for templates)
        tokens_out: Completion tokens (0 for templates)
        latency_ms: Wall-clock latency in milliseconds
        prompt_version: e.g. "v1.0.0" — which prompt produced this output
        source: "ollama" or "template_library" or "error"
        fallback_used: True if the call fell back from Ollama
        warning: Optional warning string (e.g. "Ollama not responding")

    Returns:
        True on success, False on any DB error (errors are logged, never raised)
    """
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO ai_usage (
                    user_id, endpoint, model, tokens_in, tokens_out,
                    latency_ms, prompt_version, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                user or "system",
                endpoint,
                model,
                tokens_in,
                tokens_out,
                latency_ms,
                prompt_version,
                datetime.now(tz=timezone.utc),
            )
        log.info(
            "ai_usage_recorded",
            user=user,
            endpoint=endpoint,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            prompt_version=prompt_version,
            source=source,
            fallback_used=fallback_used,
        )
        return True
    except Exception as e:
        # Never raise — the AI feature must not break if cost tracking fails
        log.error(
            "ai_usage_record_failed",
            error=str(e),
            endpoint=endpoint,
            model=model,
        )
        return False


async def get_usage_summary(
    user: Optional[str] = None,
    since_hours: int = 24,
) -> dict[str, Any]:
    """Get a usage summary for diagnostics.

    Args:
        user: Filter by user, or None for all users
        since_hours: Time window

    Returns:
        Dict with call_count, total_tokens, fallback_count, avg_latency_ms
    """
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) AS call_count,
                    COALESCE(SUM(tokens_in), 0) AS total_tokens_in,
                    COALESCE(SUM(tokens_out), 0) AS total_tokens_out,
                    COALESCE(AVG(latency_ms), 0)::int AS avg_latency_ms,
                    COUNT(*) FILTER (
                        WHERE model = 'template_library' OR model LIKE 'template%'
                    ) AS fallback_count
                FROM ai_usage
                WHERE created_at > NOW() - ($2 || ' hours')::interval
                  AND ($1::text IS NULL OR user_id = $1)
                """,
                user,
                str(since_hours),
            )
            if row is None:
                return {
                    "call_count": 0,
                    "total_tokens_in": 0,
                    "total_tokens_out": 0,
                    "avg_latency_ms": 0,
                    "fallback_count": 0,
                }
            return dict(row)
    except Exception as e:
        log.warning("ai_usage_summary_failed", error=str(e))
        return {
            "call_count": 0,
            "total_tokens_in": 0,
            "total_tokens_out": 0,
            "avg_latency_ms": 0,
            "fallback_count": 0,
            "error": str(e),
        }
