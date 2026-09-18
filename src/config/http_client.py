"""Process-shared httpx.AsyncClient (AUD-028 / AUD-052).

Every outbound HTTP call used to build a throwaway AsyncClient per call
(or, in the notification retry loop, per retry ATTEMPT) — no connection
reuse, a fresh TCP/TLS handshake per attempt. This module provides ONE
client per running event loop, created lazily on first use and reused for
the loop's lifetime.

Why per-loop (not a single global): httpx transports bind their sockets
to the event loop that created them. A single module-global client would
break pytest (new event loop per test) and any future multi-loop
deployment; a per-loop cache is correct in both. WeakKeyDictionary drops
the entry when the loop (and its transport sockets) are collected — no
leak, no cross-test bleed.

Timeouts are per-REQUEST: every caller passes its own timeout on the
request, so one client serves callers with different deadlines. The
constructor default is only a fallback.

Callers must NOT close the shared client and must NOT use it as a context
manager (`async with` closes it on exit) — the client lives and dies with
the loop. In prod that is the process lifetime: exactly the reuse we want.
In unit tests the httpx.AsyncClient constructor is the patch seam (tests
patch the class; the helper's cache is cleared per test by the conftest's
_reset_shared_http_clients fixture).
"""

import asyncio
import weakref

import httpx

from src.config.logging import get_logger

log = get_logger("config.http_client")

_clients: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, httpx.AsyncClient]" = (
    weakref.WeakKeyDictionary()
)


def get_shared_async_client(default_timeout: float = 10.0) -> httpx.AsyncClient:
    """Return the shared AsyncClient for the RUNNING event loop (lazy, one per loop).

    There is no await between the cache check and the assignment, so two
    coroutines on the same loop can never race the creation (single-threaded
    loop, atomic dict operations).
    """
    loop = asyncio.get_running_loop()
    client = _clients.get(loop)
    if client is None:
        client = httpx.AsyncClient(timeout=default_timeout)
        _clients[loop] = client
        log.debug("shared_http_client_created", loop_id=id(loop))
    return client
