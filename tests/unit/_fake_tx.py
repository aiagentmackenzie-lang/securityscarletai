"""Test helper: give a mock asyncpg connection a working transaction().

Production code that needs the advisory-lock/dedup check to be serialized
wraps it in `async with conn.transaction():` (SS-018). An `AsyncMock()`
connection has no `transaction` attribute, so attribute access returns an
AsyncMock whose call returns a coroutine — `async with` then fails with
"coroutine object does not support the asynchronous context manager protocol".

`with_tx(conn)` installs a no-op async context manager on the mock so the
existing unit tests exercise the real code path without a database.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock


def with_tx(conn):
    """Install a no-op async context manager as `conn.transaction`."""
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    tx.start = AsyncMock(return_value=None)
    tx.commit = AsyncMock(return_value=None)
    tx.rollback = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=tx)
    return conn
