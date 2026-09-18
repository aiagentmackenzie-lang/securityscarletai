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
  P2.1: the limiter now also carries an in-memory FALLBACK strategy
  (in_memory_fallback_enabled=True) used when the primary storage dies.
  Its storage must be swapped too, so a fallback episode inside a test
  stays deterministic and never touches real Redis.
- Provides a fresh in-memory storage for each test (function scope) so
  test order doesn't matter.
- Forces src.api.redis_client OFFLINE by default (2026-09-03): unit tests
  must never talk to a real Redis, and with the compose demo stack
  running, localhost:6379 ANSWERS — the lazy reconnect in _get_client()
  then satisfied "_client = None" premises and unit tests both failed on
  shared state and leaked test keys (scarletai:v1:ti_neg:* / ti_budget)
  into the RUNNING SIEM's redis (three distinct tests hit this in one
  session). Tests that need Redis behavior fake it explicitly (the
  fake_redis fixtures patch _client; auth tests patch the _from_url
  seam) — both override this fixture because pytest instantiates autouse
  fixtures first.
"""

from __future__ import annotations

import pytest
from limits.storage import MemoryStorage

from src.api import rate_limit as _rl


@pytest.fixture(autouse=True)
def _no_real_db(monkeypatch):
    """Unit tests must NEVER touch a live Postgres (2026-09-11 lesson).

    Found live: an endpoint test whose module delegates to a service module
    left the service's own ``get_pool`` import unpatched, so the real pool
    connected to the standing SIEM volume (localhost:5433) and wrote test
    rows into its audit chain. The Redis fixture below closes the same hole
    for Redis; this closes it for Postgres.

    The guard patches the SOURCE module (src.db.connection.get_pool) to
    raise. Tests that need a fake DB patch the name in THEIR module under
    test (``patch("src.api.<mod>.get_pool", ...)``), which shadows this
    seam -- the convention every existing test already follows. A unit test
    that genuinely needs the source seam must opt out explicitly.
    """

    # async def, DELIBERATELY (do not collapse to a sync raise): any module
    # first-imported while this fixture is active binds _refuse as its
    # get_pool (from-import copy). A SYNC _refuse made later patch() calls
    # see a non-async target and build a MagicMock, so `await get_pool()` in
    # the module-under-test returned a bare AsyncMock -> TypeError — an
    # import-order landmine that flipped whole targeted suites red purely on
    # which test imported src.api.response first (LRN-20260911-004 class).
    # An ASYNC _refuse keeps every binding awaitable-shaped: patch() detects
    # a coroutine function and builds the correct AsyncMock, and unpatched
    # use still raises loudly (at the await, same failure, same message).

    async def _refuse(*_args, **_kwargs):
        raise RuntimeError(
            "unit tests must not create a real DB pool -- patch the module-"
            "under-test's get_pool (see tests/unit/conftest.py _no_real_db)"
        )

    monkeypatch.setattr("src.db.connection.get_pool", _refuse)
    yield


@pytest.fixture(autouse=True)
def _reset_shared_http_clients():
    """Clear the per-loop shared httpx.AsyncClient cache around each test.

    The shared client (src/config/http_client.py, AUD-028) is keyed by the
    RUNNING event loop. pytest-asyncio gives each test a fresh function-
    scoped loop, so entries cannot normally cross tests — this fixture is
    belt-and-braces: it guarantees a test's patched httpx.AsyncClient class
    is the one that constructs the client, even if a future loop-reuse
    config change makes loops outlive a single test (the same class of
    cross-test bleed the Redis/DB fixtures close).
    """
    from src.config import http_client as _hc

    _hc._clients.clear()  # noqa: SLF001 — the cache IS the fixture seam
    yield
    _hc._clients.clear()  # noqa: SLF001


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
    fallback_limiter = _rl.limiter._fallback_limiter
    original_fallback_storage = fallback_limiter.storage if fallback_limiter is not None else None
    mem = MemoryStorage()
    _rl.limiter._storage = mem  # noqa: SLF001
    _rl.limiter.limiter.storage = mem
    if fallback_limiter is not None:  # noqa: SLF001
        fallback_limiter.storage = mem  # noqa: SLF001
    _rl.limiter._headers_enabled = False
    try:
        yield
    finally:
        _rl.limiter._storage = original_slowapi_storage  # noqa: SLF001
        _rl.limiter.limiter.storage = original_strategy_storage
        if fallback_limiter is not None and original_fallback_storage is not None:  # noqa: SLF001
            fallback_limiter.storage = original_fallback_storage  # noqa: SLF001
        _rl.limiter._headers_enabled = original_headers_enabled


@pytest.fixture(autouse=True)
def _redis_offline_by_default(monkeypatch):
    """Force src.api.redis_client offline for the duration of one test.

    The rate-limiter fixture above enforces "no live Redis" for the slowapi
    limiter; this closes the same hole for the redis_client singleton. With
    a live Redis on localhost:6379 (compose demo stack), _get_client()'s
    lazy reconnect satisfied tests' "_client = None" premise: tests failed
    on shared state from prior runs and leaked test keys into the running
    SIEM's redis (three distinct tests hit this in one session). Here the
    connect seam fails deterministically -> the production fail-open paths
    (F-08/P2.1/P2.5) run instead, which is what "redis down" tests actually
    mean to exercise.

    The stub raises on ping() (NOT inside _from_url itself): _get_client()'s
    except handler calls candidate.aclose(), so raising before assignment
    would NameError there. _SLEEP is stubbed so the 3-attempt retry round
    costs no wall time. Tests wanting Redis fake _client (fake_redis
    fixtures) or patch _from_url themselves — both override this fixture,
    because pytest instantiates autouse fixtures before explicit ones.
    """
    from src.api import redis_client as _rc

    class _UnreachableClient:
        async def ping(self) -> None:
            raise ConnectionError("test: redis offline by default (unit conftest)")

        async def aclose(self) -> None:
            pass

    def _unreachable_from_url(*args, **kwargs):
        return _UnreachableClient()

    async def _instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(_rc, "_client", None)
    monkeypatch.setattr(_rc, "_last_failure_ts", 0.0)
    monkeypatch.setattr(_rc, "_from_url", _unreachable_from_url)
    monkeypatch.setattr(_rc, "_SLEEP", _instant_sleep)
    yield
