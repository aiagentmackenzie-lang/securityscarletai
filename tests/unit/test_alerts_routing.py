"""Routing-level regression tests for the alerts API.

The P4.2 suppression routes shipped declared AFTER ``GET /{alert_id}``; FastAPI
matches in declaration order, so ``GET /api/v1/alerts/suppressions`` was
captured as ``alert_id="suppressions"`` and returned 422 forever. The handler
unit tests (test_alerts_full.py) call the functions directly and never exercise
routing, so the bug was invisible until a real dashboard hit the HTTP surface.

These tests mount the alerts router in a TestClient — the layer that would have
caught it.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from src.api.alerts import router as alerts_router


@pytest.fixture
def client() -> TestClient:
    """TestClient for the alerts router with auth overridden (demo admin)."""
    app = FastAPI()
    app.include_router(alerts_router, prefix="/api/v1")

    demo_admin = {"sub": "tester", "role": "admin"}

    from src.api.auth import get_current_user

    app.dependency_overrides[get_current_user] = lambda: demo_admin

    for route in alerts_router.routes:
        if not isinstance(route, APIRoute):
            continue
        for dep in route.dependant.dependencies:
            if dep.call.__name__ == "_check_role":
                app.dependency_overrides[dep.call] = lambda: demo_admin

    return TestClient(app, raise_server_exceptions=False)


class TestSuppressionRouting:
    """GET /alerts/suppressions must never be shadowed by /{alert_id}."""

    def test_route_order_suppressions_before_alert_id(self):
        """Cheap static guard: literal routes declared before the {alert_id}
        catch-all. Catches a future refactor re-ordering them without HTTP."""
        paths = [
            r.path
            for r in alerts_router.routes
            if isinstance(r, APIRoute)
        ]  # router-level paths carry the /alerts prefix
        assert paths.index("/alerts/suppressions") < paths.index(
            "/alerts/{alert_id}"
        ), (
            "GET /suppressions declared after GET /{alert_id} — the literal "
            "path will be shadowed and 422 (regression of "
            "fix/suppressions-route-shadowing)"
        )

    def test_list_suppressions_via_http_is_200_not_422(self, client):
        """The exact call the dashboard makes: GET /api/v1/alerts/suppressions."""
        with patch(
            "src.api.alerts.list_suppression_rules",
            AsyncMock(return_value=[]),
        ):
            resp = client.get("/api/v1/alerts/suppressions")

        assert resp.status_code == 200, (
            f"expected 200, got {resp.status_code}: {resp.text[:200]}"
        )
        assert resp.json() == []

    def test_alert_id_route_still_works(self, client):
        """The catch-all /{alert_id} must still resolve integers normally."""
        row = {
            "id": 7,
            "time": "2026-08-25T08:08:03.417031+00:00",
            "rule_id": None,
            "rule_name": "Test Rule",
            "severity": "high",
            "status": "new",
            "host_name": "host-01",
            "description": "d",
            "mitre_tactics": [],
            "mitre_techniques": [],
            "evidence": "[]",
            "ai_summary": None,
            "risk_score": 1.0,
            "assigned_to": None,
            "resolved_at": None,
            "resolution_note": None,
            "case_id": None,
            "notes": "[]",
            "created_at": "2026-08-25T09:51:03.438013+00:00",
            "updated_at": "2026-08-25T09:51:03.438013+00:00",
        }
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=row)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            resp = client.get("/api/v1/alerts/7")

        assert resp.status_code == 200
        assert resp.json()["id"] == 7

    def test_suppressions_id_route_still_scoped(self, client):
        """/suppressions/5 must NOT match /{alert_id} — it toggles instead."""
        with patch(
            "src.api.alerts.set_suppression_enabled",
            AsyncMock(return_value=True),
        ):
            resp = client.patch(
                "/api/v1/alerts/suppressions/5", json={"enabled": False}
            )

        assert resp.status_code == 200
        assert resp.json() == {"id": 5, "enabled": False, "status": "updated"}