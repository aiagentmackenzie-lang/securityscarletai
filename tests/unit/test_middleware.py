"""
Tests for API middleware.

Covers:
- RequestValidationMiddleware body size check (P2.2: stream-cap — aborts
  mid-stream at the cap, never buffers unbounded bodies; garbage
  Content-Length headers 4xx instead of 500)
- RequestValidationMiddleware content-type enforcement
- AuditLogMiddleware logging of state-changing requests
"""

from unittest.mock import MagicMock

import pytest
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse

from src.api.middleware import AuditLogMiddleware, RequestValidationMiddleware, limiter


class TestRequestValidationMiddleware:
    """Test request validation middleware."""

    def test_max_body_size_defined(self):
        """Middleware should have a MAX_BODY_SIZE constant."""
        assert RequestValidationMiddleware.MAX_BODY_SIZE > 0

    def test_max_body_size_1mb(self):
        """Default max body size should be 1MB."""
        assert RequestValidationMiddleware.MAX_BODY_SIZE == 1_000_000


class TestAuditLogMiddleware:
    """Test audit log middleware."""

    def test_audit_middleware_instantiable(self):
        """Should instantiate without error."""
        mw = AuditLogMiddleware(app=MagicMock())
        assert mw is not None


class TestRateLimiter:
    """Test rate limiter configuration."""

    def test_limiter_exists(self):
        """Rate limiter should be configured."""
        assert limiter is not None
        # Limiter is a slowapi.Limiter instance
        assert type(limiter).__name__ == "Limiter"


class TestMiddlewareIntegration:
    """Integration tests with FastAPI TestClient."""

    @pytest.fixture
    def client(self):
        """Create a test client with middleware."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        @app.post("/ingest")
        async def ingest():
            return {"accepted": 0}

        @app.post("/api/v1/test")
        async def test_endpoint():
            return {"ok": True}

        app.add_middleware(RequestValidationMiddleware)

        return TestClient(app)

    def test_get_request_passes(self, client):
        """GET requests should pass through without body size check."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_post_request_normal_size_passes(self, client):
        """Normal-sized POST requests should pass."""
        response = client.post("/api/v1/test", json={"data": "test"})
        assert response.status_code == 200

    def test_post_ingest_requires_json_content_type(self, client):
        """Ingest endpoint should require application/json content-type."""
        response = client.post(
            "/ingest",
            content="not json",
            headers={"content-type": "text/plain"},
        )
        assert response.status_code == 415

    def test_post_ingest_json_passes(self, client):
        """Ingest endpoint should accept application/json."""
        response = client.post(
            "/ingest",
            json={"data": "test"},
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200

    def test_post_over_content_length_limit_413(self, client):
        """A declared Content-Length over 1MB must 413 before the body is read."""
        response = client.post("/api/v1/test", content=b"x" * 1_100_000)
        assert response.status_code == 413


def _make_stream_request(
    method: str = "POST",
    path: str = "/api/v1/test",
    headers: list[tuple[bytes, bytes]] | None = None,
    messages: list[dict] | None = None,
):
    """Build a real starlette Request whose receive() replays `messages`.

    Returns (request, consumed_count_getter, call_next_spy) so tests can
    assert EXACTLY how much of the stream the middleware pulled before
    aborting — the heart of the P2.2 memory-DoS fix.
    """
    remaining = list(messages or [])
    consumed: list[dict] = []

    async def receive():
        if not remaining:
            return {"type": "http.request", "body": b"", "more_body": False}
        msg = remaining.pop(0)
        consumed.append(msg)
        return msg

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": ("10.1.2.3", 55555),
        "server": ("testserver", 80),
    }
    request = StarletteRequest(scope, receive)
    return request, consumed


class TestStreamCapP2_2:
    """P2.2 — chunked bodies are capped DURING the stream (no full-buffer
    before the check), and garbage Content-Length headers 4xx instead of
    500ing on int()."""

    @pytest.fixture
    def mw(self):
        return RequestValidationMiddleware(app=MagicMock())  # type: ignore[arg-type]

    @staticmethod
    def _ok_call_next(request):
        async def _inner(req):
            return JSONResponse({"ok": True})

        return _inner

    def _ok(self):
        """call_next that never touches the request body — for 4xx-before-read tests."""
        return self._ok_call_next(None)

    @pytest.mark.asyncio
    async def test_chunked_body_over_limit_aborts_mid_stream(self, mw):
        """The 413 must fire BEFORE the third chunk is even read — the old
        code buffered every byte first."""
        big = b"x" * 700_000  # 2 chunks = 1.4MB > 1MB cap
        messages = [
            {"type": "http.request", "body": big, "more_body": True},
            {"type": "http.request", "body": big, "more_body": True},
            {"type": "http.request", "body": big, "more_body": False},
        ]
        request, consumed = _make_stream_request(messages=messages)
        called = {"next": False}

        async def call_next(req):
            called["next"] = True
            return JSONResponse({"ok": True})

        response = await mw.dispatch(request, call_next)
        assert response.status_code == 413
        # exactly 2 messages consumed: abort fired as soon as the cap was hit
        assert len(consumed) == 2
        # call_next must never have run for a rejected body
        assert called["next"] is False

    @pytest.mark.asyncio
    async def test_garbage_content_length_returns_400(self, mw):
        request, _ = _make_stream_request(
            headers=[(b"content-length", b"totally-not-a-number")],
            messages=[],
        )
        response = await mw.dispatch(request, self._ok())
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_negative_content_length_returns_400(self, mw):
        request, _ = _make_stream_request(
            headers=[(b"content-length", b"-5")],
            messages=[],
        )
        response = await mw.dispatch(request, self._ok())
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_multiple_content_length_values_returns_400(self, mw):
        """Conflicting Content-Length headers (smuggling primitive) → 400."""
        request, _ = _make_stream_request(
            headers=[(b"content-length", b"5, 5")],
            messages=[],
        )
        response = await mw.dispatch(request, self._ok())
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_chunked_body_under_limit_is_reinjected(self, mw):
        """A bounded chunked body must reach the endpoint intact (re-injected
        receive) — the endpoint sees the exact bytes that were streamed."""
        seen = {}

        async def call_next(req):
            body = await req.body()
            seen["size"] = len(body)
            seen["content"] = body
            return JSONResponse({"size": len(body)})

        request, _ = _make_stream_request(
            messages=[
                {"type": "http.request", "body": b"hello ", "more_body": True},
                {"type": "http.request", "body": b"chunked world", "more_body": False},
            ],
        )
        response = await mw.dispatch(request, call_next)
        assert response.status_code == 200
        assert seen["content"] == b"hello chunked world"
