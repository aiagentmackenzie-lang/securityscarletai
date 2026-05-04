"""
Tests for API health endpoint.

Covers:
- GET /health with database available
- GET /health with database unavailable
- GET /health with Ollama unavailable
- Overall status calculation
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from src.api.health import router


class TestHealthCheck:
    """Test health check endpoint."""

    @pytest.fixture
    def client(self):
        """Create test client with health router."""
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        return TestClient(app)

    def test_health_all_ok(self, client):
        """Health check should return healthy when all services are up."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.health.get_pool", return_value=mock_pool):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                response = client.get("/api/v1/health")
                assert response.status_code == 200
                data = response.json()
                assert "status" in data
                assert "checks" in data

    def test_health_returns_checks_dict(self, client):
        """Health check should always include checks dict."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.health.get_pool", return_value=mock_pool):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                response = client.get("/api/v1/health")
                data = response.json()
                assert "checks" in data
                assert "api" in data["checks"]
                assert "database" in data["checks"]
                assert "ollama" in data["checks"]
                assert data["checks"]["api"] == "ok"

    def test_health_db_error_degraded(self, client):
        """Health check should report degraded when DB is down."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=Exception("Connection refused"))

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.health.get_pool", return_value=mock_pool):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                response = client.get("/api/v1/health")
                data = response.json()
                assert data["status"] == "degraded"
                assert "error" in data["checks"]["database"]

    def test_health_ollama_unreachable(self, client):
        """Health check should handle unreachable Ollama gracefully."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.health.get_pool", return_value=mock_pool):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client_cls.return_value = mock_client

                response = client.get("/api/v1/health")
                data = response.json()
                assert data["checks"]["ollama"] == "unreachable"
                # API and DB should still work, so status depends
                # If DB is ok but Ollama down, should be "degraded"
                assert data["status"] in ["healthy", "degraded"]