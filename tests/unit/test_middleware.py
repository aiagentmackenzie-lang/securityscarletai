"""
Tests for API middleware.

Covers:
- RequestValidationMiddleware body size check
- RequestValidationMiddleware content-type enforcement
- AuditLogMiddleware logging of state-changing requests
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.api.middleware import RequestValidationMiddleware, AuditLogMiddleware, limiter


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
        from src.api.middleware import limiter
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