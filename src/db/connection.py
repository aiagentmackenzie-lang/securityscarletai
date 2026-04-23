"""
Async PostgreSQL connection pool using asyncpg.
Singleton pool — initialize once at startup, share everywhere.
"""
import asyncpg

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("db.connection")

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    """Get or create the connection pool."""
    global _pool
    if _pool is None:
        log.info("creating_pool", host=settings.db_host, db=settings.db_name)
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
    return _pool


async def close_pool() -> None:
    """Close the pool on shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        log.info("pool_closed")
