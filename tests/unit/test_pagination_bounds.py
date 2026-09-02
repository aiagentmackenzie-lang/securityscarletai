"""P2.3 — bounded pagination on the unbounded list endpoints.

Before this fix, /alerts, /cases, and /correlation/matches accepted ANY
limit — `?limit=10000000` pulled the whole table into memory per request
(a DoS primitive; logs.py/audit.py were already bounded, these weren't).

Contract under test (HTTP layer — validation is FastAPI's job, so these
go through TestClient with auth overridden, NOT direct calls):
- limit above the cap → 422
- limit below 1 / negative offset → 422
- boundary value (exactly the cap) → accepted (handler runs)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.alerts import router as alerts_router
from src.api.auth import get_current_user
from src.api.cases import router as cases_router
from src.api.correlation import router as correlation_router


def _empty_pool_patch(module: str):
    """Patch get_pool in `module` to return a pool whose acquire() context
    yields an AsyncMock connection (fetch/fetchrow return [])."""
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])

    class AsyncCtx:
        async def __aenter__(self):
            return mock_conn

        async def __aexit__(self, *args):
            return False

    mock_pool = AsyncMock()
    mock_pool.acquire = MagicMock(return_value=AsyncCtx())
    return patch(module + ".get_pool", AsyncMock(return_value=mock_pool))


def _make_client(router) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    demo_admin = {"sub": "tester", "role": "admin"}
    app.dependency_overrides[get_current_user] = lambda: demo_admin
    return TestClient(app, raise_server_exceptions=False)


class TestAlertsPaginationBounds:
    def test_limit_over_cap_422(self):
        client = _make_client(alerts_router)
        r = client.get("/api/v1/alerts", params={"limit": 10_000_000})
        assert r.status_code == 422

    def test_limit_zero_422(self):
        client = _make_client(alerts_router)
        r = client.get("/api/v1/alerts", params={"limit": 0})
        assert r.status_code == 422

    def test_negative_offset_422(self):
        client = _make_client(alerts_router)
        r = client.get("/api/v1/alerts", params={"offset": -1})
        assert r.status_code == 422

    def test_limit_at_cap_accepted(self):
        """limit=1000 (exactly the cap) passes validation and reaches the
        handler (empty pool mock → 200 [])."""
        client = _make_client(alerts_router)
        with _empty_pool_patch("src.api.alerts"):
            r = client.get("/api/v1/alerts", params={"limit": 1000})
        assert r.status_code == 200


class TestCasesPaginationBounds:
    def test_limit_over_cap_422(self):
        client = _make_client(cases_router)
        r = client.get("/api/v1/cases", params={"limit": 10_000_000})
        assert r.status_code == 422

    def test_limit_501_422(self):
        """Cases cap at 500 — one over must already fail."""
        client = _make_client(cases_router)
        r = client.get("/api/v1/cases", params={"limit": 501})
        assert r.status_code == 422

    def test_limit_at_cap_accepted(self):
        client = _make_client(cases_router)
        with _empty_pool_patch("src.api.cases"):
            r = client.get("/api/v1/cases", params={"limit": 500})
        assert r.status_code == 200


class TestCorrelationMatchesPaginationBounds:
    def test_limit_over_cap_422(self):
        client = _make_client(correlation_router)
        r = client.get("/api/v1/correlation/matches", params={"limit": 10_000_000})
        assert r.status_code == 422

    def test_limit_at_cap_accepted(self):
        client = _make_client(correlation_router)
        # the handler delegates to the correlation engine — patch it, not get_pool
        with patch(
            "src.api.correlation.list_matches", AsyncMock(return_value=[])
        ):
            r = client.get("/api/v1/correlation/matches", params={"limit": 1000})
        assert r.status_code == 200

    def test_negative_offset_422(self):
        client = _make_client(correlation_router)
        r = client.get("/api/v1/correlation/matches", params={"offset": -1})
        assert r.status_code == 422
