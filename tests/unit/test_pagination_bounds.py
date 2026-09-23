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
        # the handler delegates to the correlation engine — patch it, not get_pool.
        # AUD-049: the handler now calls BOTH list_matches (page) and
        # count_matches (filtered total) — both seams must be stubbed.
        with (
            patch("src.api.correlation.list_matches", AsyncMock(return_value=[])),
            patch("src.api.correlation.count_matches", AsyncMock(return_value=0)),
        ):
            r = client.get("/api/v1/correlation/matches", params={"limit": 1000})
        assert r.status_code == 200

    def test_negative_offset_422(self):
        client = _make_client(correlation_router)
        r = client.get("/api/v1/correlation/matches", params={"offset": -1})
        assert r.status_code == 422


class TestAlertsWindowBounds:
    """W4-H — bounded time windows on the stats/export endpoints. The old
    signatures accepted ANY hours value: every stats/export query scanned
    the whole table (and exports serialized it) for one request."""

    # HTTPBearer(auto_error) resolves BEFORE _check_role's body — so the
    # export requests also carry a dummy Bearer token; the patched
    # get_current_user (module global inside _check_role) does the "verify".
    _AUTH = {"Authorization": "Bearer rbac-bypass-token"}

    def test_stats_hours_over_year_422(self):
        client = _make_client(alerts_router)
        with patch("src.api.alerts.get_alert_stats", AsyncMock(return_value={"total_count": 0})):
            r = client.get("/api/v1/alerts/stats", params={"hours": 24 * 365 + 1})
        assert r.status_code == 422

    def test_stats_hours_zero_422(self):
        client = _make_client(alerts_router)
        with patch("src.api.alerts.get_alert_stats", AsyncMock(return_value={"total_count": 0})):
            r = client.get("/api/v1/alerts/stats", params={"hours": 0})
        assert r.status_code == 422

    def test_stats_hours_at_cap_accepted(self):
        client = _make_client(alerts_router)
        with patch("src.api.alerts.get_alert_stats", AsyncMock(return_value={"total_count": 0})):
            r = client.get("/api/v1/alerts/stats", params={"hours": 24 * 365})
        assert r.status_code == 200

    def test_export_csv_hours_over_30d_422(self):
        # require_role calls get_current_user INSIDE _check_role (module
        # global lookup at call time) — patch the auth module, not the
        # dependency override, or the request 403s before validation.
        client = _make_client(alerts_router)
        analyst = AsyncMock(return_value={"sub": "tester", "role": "analyst"})
        with (
            patch("src.api.auth.get_current_user", analyst),
            patch("src.api.alerts.export_alerts_csv", AsyncMock(return_value="id\n")),
        ):
            r = client.get(
                "/api/v1/alerts/export/csv",
                params={"hours": 24 * 30 + 1},
                headers=self._AUTH,
            )
        assert r.status_code == 422

    def test_export_csv_hours_at_cap_accepted(self):
        client = _make_client(alerts_router)
        analyst = AsyncMock(return_value={"sub": "tester", "role": "analyst"})
        with (
            patch("src.api.auth.get_current_user", analyst),
            patch("src.api.alerts.export_alerts_csv", AsyncMock(return_value="id\n")),
        ):
            r = client.get(
                "/api/v1/alerts/export/csv",
                params={"hours": 24 * 30},
                headers=self._AUTH,
            )
        assert r.status_code == 200

    def test_export_stix_hours_over_30d_422(self):
        client = _make_client(alerts_router)
        analyst = AsyncMock(return_value={"sub": "tester", "role": "analyst"})
        with (
            patch("src.api.auth.get_current_user", analyst),
            patch("src.api.alerts.export_alerts_stix", AsyncMock(return_value={"type": "bundle"})),
        ):
            r = client.get(
                "/api/v1/alerts/export/stix",
                params={"hours": 24 * 30 + 1},
                headers=self._AUTH,
            )
        assert r.status_code == 422

    def test_export_stix_hours_at_cap_accepted(self):
        client = _make_client(alerts_router)
        analyst = AsyncMock(return_value={"sub": "tester", "role": "analyst"})
        with (
            patch("src.api.auth.get_current_user", analyst),
            patch("src.api.alerts.export_alerts_stix", AsyncMock(return_value={"type": "bundle"})),
        ):
            r = client.get(
                "/api/v1/alerts/export/stix",
                params={"hours": 24 * 30},
                headers=self._AUTH,
            )
        assert r.status_code == 200
