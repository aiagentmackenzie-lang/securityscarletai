"""Route-tree walker for fastapi >= 0.141 / starlette 1.x.

fastapi 0.141+ wraps include_router() results in
fastapi.routing._IncludedRouter objects: the mount prefix lives in
.include_context.prefix and the UNPREFIXED APIRoutes live in
.original_router.routes. Walking app.routes and reading .path directly
(now with the pre-1.x flattening) misses them — tests asserting route
registration must resolve EFFECTIVE paths the way requests see them.

Used by the router-wiring tests (users/metrics/ops-honesty/api-main).
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def iter_route_paths(routes: list[Any], prefix: str = "") -> Iterator[str]:
    """Yield effective (fully-prefixed) paths for a fastapi route tree."""
    for r in routes:
        if type(r).__name__ == "_IncludedRouter":
            sub = prefix + (getattr(r.include_context, "prefix", "") or "")
            yield from iter_route_paths(r.original_router.routes, sub)
        elif getattr(r, "path", None) is not None:
            yield prefix + r.path
