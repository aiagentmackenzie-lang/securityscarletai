"""
Async PostgreSQL connection pool using asyncpg.
Singleton pool — initialize once at startup, share everywhere.
Includes retry with exponential backoff for deployment robustness.
"""
import asyncio

import asyncpg

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("db.connection")

_pool: asyncpg.Pool | None = None
_pool_lock = asyncio.Lock()

# Retry config for cold-start / rolling deploys
DB_RETRY_MAX_ATTEMPTS = 5
DB_RETRY_BASE_DELAY = 1.0  # seconds


async def get_pool() -> asyncpg.Pool:
    """Get or create the connection pool (race-safe with asyncio.Lock)."""
    global _pool
    if _pool is None:
        async with _pool_lock:
            # Double-check after acquiring lock
            if _pool is None:
                for attempt in range(1, DB_RETRY_MAX_ATTEMPTS + 1):
                    try:
                        log.info("creating_pool", host=settings.db_host, db=settings.db_name, attempt=attempt)
                        _pool = await asyncpg.create_pool(
                            host=settings.db_host,
                            port=settings.db_port,
                            database=settings.db_name,
                            user=settings.db_user,
                            password=settings.db_password,
                            min_size=settings.db_pool_min,
                            max_size=settings.db_pool_max,
                            command_timeout=30,
                        )
                        log.info("pool_created", host=settings.db_host, db=settings.db_name)
                        break
                    except (asyncpg.PostgresError, OSError, ConnectionError) as e:
                        if attempt == DB_RETRY_MAX_ATTEMPTS:
                            log.error("pool_creation_failed", error=str(e), attempts=DB_RETRY_MAX_ATTEMPTS)
                            raise
                        delay = DB_RETRY_BASE_DELAY * (2 ** (attempt - 1))
                        log.warning("pool_creation_retry", error=str(e), attempt=attempt, delay=delay)
                        await asyncio.sleep(delay)
    return _pool


async def close_pool() -> None:
    """Close the pool on shutdown."""
    global _pool
    async with _pool_lock:
        if _pool:
            await _pool.close()
            _pool = None
            log.info("pool_closed")
