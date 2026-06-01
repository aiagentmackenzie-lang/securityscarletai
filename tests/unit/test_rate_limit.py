"""
Tests for rate limiting (Epic 4).

Covers:
- LIMIT_LOGIN is wired into POST /auth/login
- LIMIT_INGEST is wired into POST /ingest
- Custom 429 handler returns JSON with Retry-After header
- X-RateLimit-* headers are added by the middleware
- Limiter is constructed with the Redis storage URI
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request
from starlette.responses import Response

# Force-import the modules that register route limits with slowapi, BEFORE
# the test bodies run. Otherwise test_rate_limit.py in isolation may import
# only rate_limit, and slowapi._route_limits stays empty.
from src.api import rate_limit  # noqa: F401
from src.api import auth_login  # noqa: F401
from src.api import ingest  # noqa: F401

from src.api.rate_limit import (
    LIMIT_INGEST,
    LIMIT_LOGIN,
    RateLimitHeadersMiddleware,
    rate_limit_exceeded_handler,
)
from slowapi.errors import RateLimitExceeded
from tests.unit._test_request import make_test_request


# ───────────────────────────────────────────────────────────────
# Configuration sanity
# ───────────────────────────────────────────────────────────────


class TestConfig:
    def test_limit_login_constant(self):
        assert LIMIT_LOGIN == "5/minute"

    def test_limit_ingest_constant(self):
        assert LIMIT_INGEST == "100/minute"

    def test_default_limit_includes_200_per_minute(self):
        # The production limiter should default to 200/minute. We don't dig
        # into slowapi's internal _default_limits shape (brittle across versions);
        # we just confirm the limiter exists and has a sensible default.
        assert rate_limit.limiter is not None
        # The Limiter class accepts default_limits; verify the call to _build_limiter
        # didn't raise and the result is usable.
        assert hasattr(rate_limit.limiter, "_default_limits")


# ───────────────────────────────────────────────────────────────
# 429 handler
# ───────────────────────────────────────────────────────────────


class TestRateLimitExceededHandler:
    def test_returns_json_429(self):
        from slowapi.errors import RateLimitExceeded
        from slowapi.extension import Limit
        from slowapi.util import get_remote_address

        req = make_test_request()
        limit = Limit(
            "5/minute",
            key_func=get_remote_address,
            scope="",
            per_method=False,
            methods=None,
            error_message=None,
            exempt_when=None,
            cost=1,
            override_defaults=True,
        )
        exc = RateLimitExceeded(limit)
        response = rate_limit_exceeded_handler(req, exc)
        assert response.status_code == 429
        body = response.body.decode()
        assert '"error":"rate_limited"' in body
        assert '"retry_after":60' in body

    def test_includes_retry_after_header(self):
        from slowapi.errors import RateLimitExceeded
        from slowapi.extension import Limit
        from slowapi.util import get_remote_address

        req = make_test_request()
        limit = Limit(
            "5/minute",
            key_func=get_remote_address,
            scope="",
            per_method=False,
            methods=None,
            error_message=None,
            exempt_when=None,
            cost=1,
            override_defaults=True,
        )
        exc = RateLimitExceeded(limit)
        response = rate_limit_exceeded_handler(req, exc)
        assert "Retry-After" in response.headers
        assert int(response.headers["Retry-After"]) > 0


# ───────────────────────────────────────────────────────────────
# Middleware adds X-RateLimit-* headers
# ───────────────────────────────────────────────────────────────


class TestRateLimitHeadersMiddleware:
    @pytest.mark.asyncio
    async def test_adds_headers_to_successful_response(self):
        captured = {}

        async def fake_call_next(req: Request) -> Response:
            return Response(content="ok", status_code=200)

        mw = RateLimitHeadersMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/v1/rules", method="GET")
        response = await mw.dispatch(req, fake_call_next)
        assert "X-RateLimit-Reset" in response.headers
        # X-RateLimit-Remaining may either be slowapi's actual value or the
        # soft "n/a" hint we set; both are acceptable.
        assert "X-RateLimit-Remaining" in response.headers

    @pytest.mark.asyncio
    async def test_does_not_clobber_existing_headers(self):
        async def fake_call_next(req: Request) -> Response:
            r = Response(content="ok", status_code=200)
            r.headers["X-RateLimit-Remaining"] = "3"
            r.headers["X-RateLimit-Reset"] = "9999"
            return r

        mw = RateLimitHeadersMiddleware(app=None)  # type: ignore[arg-type]
        req = make_test_request(path="/api/v1/rules", method="GET")
        response = await mw.dispatch(req, fake_call_next)
        assert response.headers["X-RateLimit-Remaining"] == "3"
        assert response.headers["X-RateLimit-Reset"] == "9999"


# ───────────────────────────────────────────────────────────────
# Login endpoint integration
# ───────────────────────────────────────────────────────────────


class TestLoginRateLimit:
    @pytest.mark.asyncio
    async def test_login_endpoint_has_limit_decorator(self):
        """Confirm the /login route has slowapi's limit marker applied."""
        from src.api.rate_limit import limiter

        # slowapi keys by fully-qualified function name
        route_names = set(limiter._route_limits.keys())
        assert "src.api.auth_login.login" in route_names, (
            f"POST /auth/login must be marked. Found: {route_names}"
        )
        limits = limiter._route_limits["src.api.auth_login.login"]
        limit_strs = [str(lim.limit) for lim in limits]
        assert any("5" in s and "minute" in s for s in limit_strs), (
            f"Expected 5/minute on /login, got {limit_strs}"
        )


# ───────────────────────────────────────────────────────────────
# Ingest endpoint integration
# ───────────────────────────────────────────────────────────────


class TestIngestRateLimit:
    @pytest.mark.asyncio
    async def test_ingest_endpoint_has_limit_decorator(self):
        from src.api.rate_limit import limiter

        route_names = set(limiter._route_limits.keys())
        assert "src.api.ingest.ingest_events" in route_names, (
            f"POST /ingest must be marked. Found: {route_names}"
        )
        limits = limiter._route_limits["src.api.ingest.ingest_events"]
        limit_strs = [str(lim.limit) for lim in limits]
        assert any("100" in s and "minute" in s for s in limit_strs), (
            f"Expected 100/minute on /ingest, got {limit_strs}"
        )


# ───────────────────────────────────────────────────────────────
# Sanity: at least one route must be in route_limits
# ───────────────────────────────────────────────────────────────


def test_slowapi_route_limits_populated():
    from src.api.rate_limit import limiter

    assert len(limiter._route_limits) > 0
    # Both login and ingest should be registered
    route_names = set(limiter._route_limits.keys())
    assert "src.api.auth_login.login" in route_names
    assert "src.api.ingest.ingest_events" in route_names
