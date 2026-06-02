"""
Unit-test conftest.

Currently:
- Replaces src.api.rate_limit.limiter's storage with an in-memory backend
  so tests run without a live Redis. This matches the "service stays up
  if Redis flaps" degradation policy of the production code.

  slowapi's Limiter has TWO storage references:
    - self._storage (slowapi-internal)
    - self.limiter.storage (the underlying limits.strategies storage)
  Both must be swapped, otherwise tests hit real Redis.
- Provides a fresh in-memory storage for each test (function scope) so
  test order doesn't matter.
"""
from __future__ import annotations

import pytest
from limits.storage import MemoryStorage

from src.api import rate_limit as _rl


@pytest.fixture(autouse=True)
def _inmem_rate_limit_storage():
    """Force the rate limiter to use in-memory storage for the duration of one test.

    Also disables slowapi's header injection, which requires a starlette.Response
    object to be passed through. In tests that call the endpoint directly
    (without going through FastAPI's middleware chain), the function returns
    a Pydantic model, not a Response, and slowapi's _inject_headers crashes.
    """
    original_slowapi_storage = _rl.limiter._storage  # noqa: SLF001
    original_strategy_storage = _rl.limiter.limiter.storage
    original_headers_enabled = _rl.limiter._headers_enabled
    mem = MemoryStorage()
    _rl.limiter._storage = mem  # noqa: SLF001
    _rl.limiter.limiter.storage = mem
    _rl.limiter._headers_enabled = False
    try:
        yield
    finally:
        _rl.limiter._storage = original_slowapi_storage  # noqa: SLF001
        _rl.limiter.limiter.storage = original_strategy_storage
        _rl.limiter._headers_enabled = original_headers_enabled
