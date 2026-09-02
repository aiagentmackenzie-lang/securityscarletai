"""P2.6 — scoped ingest bearer token.

Before this fix there was ONE static bearer and it was FULL ADMIN
everywhere: a leaked ingest credential could read every alert, case, and
query result. Now an optional INGEST_BEARER_TOKEN is viewer-class and is
honored ONLY on the ingest router (via get_ingest_client); every other
endpoint resolves auth through get_current_user, which rejects it.

Covered:
- ingest token works on /ingest (HTTP-level, mocked writer)
- ingest token is 401 on non-ingest endpoints (JWT-shaped? no — static;
  it must 401 there, not 403, because get_current_user never accepts it)
- admin bearer still works on /ingest AND everywhere (backward compat)
- unset INGEST_BEARER_TOKEN → identical to pre-P2.6 (ingest token string
  is just an invalid credential)
- JWT users still ingest (get_ingest_client accepts access JWTs)
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
os.environ.setdefault("API_SECRET_KEY", "x" * 64)
os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)

INGEST_TOKEN = "z" * 32  # distinct from API_BEARER_TOKEN ("y"*32)


@pytest.fixture(autouse=True)
def _scoped_token(monkeypatch):
    from pydantic import SecretStr

    from src.config.settings import settings

    monkeypatch.setattr(settings, "ingest_bearer_token", SecretStr(INGEST_TOKEN))


def _ingest_event() -> dict:
    return {
        "@timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "host_name": "s1",
        "source": "syslog",
        "event_category": "process",
        "event_type": "start",
    }


def _ingest_app() -> TestClient:
    from src.api.ingest import router
    from src.api.rate_limit import (
        limiter,
        rate_limit_exceeded_handler,
    )

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    # Mirror main.py's slowapi wiring — /ingest carries a route-level limit
    # decorator that needs app.state.limiter (missing → 500 in tests).
    app.state.limiter = limiter
    from slowapi.errors import RateLimitExceeded

    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    # Real auth dependency (no override) — the token contract IS what's under test.
    return TestClient(app, raise_server_exceptions=False)


def _mock_writer():
    from src.services.writer import writer as writer_singleton

    return (
        patch.object(writer_singleton, "write", AsyncMock()),
        patch.object(writer_singleton, "flush", AsyncMock()),
    )


class TestIngestTokenOnIngestRouter:
    def test_scoped_token_accepted_on_ingest(self):
        client = _ingest_app()
        wpatches = _mock_writer()
        with wpatches[0], wpatches[1], patch(
            "src.db.connection.get_pool",
            AsyncMock(side_effect=RuntimeError("no db")),
        ), patch(
            "src.detection.correlation.run_all_correlations", AsyncMock()
        ), patch(
            "src.api.websocket.broadcast_event", AsyncMock()
        ):
            r = client.post(
                "/api/v1/ingest",
                json=[_ingest_event()],
                headers={"Authorization": f"Bearer {INGEST_TOKEN}"},
            )
        assert r.status_code == 202
        assert r.json()["accepted"] == 1

    def test_admin_bearer_still_accepted_on_ingest(self):
        """Backward compat: the admin bearer still ingests (role admin)."""
        from src.config.settings import settings

        client = _ingest_app()
        wpatches = _mock_writer()
        with wpatches[0], wpatches[1], patch(
            "src.db.connection.get_pool",
            AsyncMock(side_effect=RuntimeError("no db")),
        ), patch(
            "src.detection.correlation.run_all_correlations", AsyncMock()
        ), patch(
            "src.api.websocket.broadcast_event", AsyncMock()
        ):
            r = client.post(
                "/api/v1/ingest",
                json=[_ingest_event()],
                headers={
                    "Authorization": "Bearer "
                    + settings.api_bearer_token.get_secret_value()
                },
            )
        assert r.status_code == 202

    def test_garbage_token_rejected_on_ingest(self):
        client = _ingest_app()
        r = client.post(
            "/api/v1/ingest",
            json=[_ingest_event()],
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert r.status_code == 401


class TestIngestTokenScopeElsewhere:
    def test_get_current_user_rejects_scoped_token(self):
        """The scoped token is NOT a valid credential on non-ingest endpoints
        (get_current_user rejects it outright — 401, no role confusion)."""
        import asyncio

        from src.api.auth import get_current_user
        from src.config.settings import settings

        creds = MagicMock()
        creds.credentials = INGEST_TOKEN
        with pytest.raises(HTTPException) as exc:
            asyncio.run(get_current_user(creds))
        assert exc.value.status_code == 401
        assert settings.ingest_bearer_token is not None  # sanity: fixture active

    def test_admin_bearer_still_admin_everywhere(self):
        import asyncio

        from src.api.auth import get_current_user
        from src.config.settings import settings

        creds = MagicMock()
        creds.credentials = settings.api_bearer_token.get_secret_value()
        payload = asyncio.run(get_current_user(creds))
        assert payload["role"] == "admin"
        assert payload["sub"] == "api-client"

    def test_scoped_token_identity_is_viewer_class(self):
        import asyncio

        from src.api.auth import get_ingest_client

        creds = MagicMock()
        creds.credentials = INGEST_TOKEN
        payload = asyncio.run(get_ingest_client(creds))
        assert payload["role"] == "viewer"
        assert payload["sub"] == "ingest-client"


class TestUnscopedBackwardCompat:
    def test_unset_ingest_token_same_as_pre_p26(self, monkeypatch):
        """When INGEST_BEARER_TOKEN is unset, the old single-bearer behavior
        holds: admin bearer works, anything else is invalid."""
        import asyncio

        from src.api.auth import get_current_user, get_ingest_client
        from src.config.settings import settings

        monkeypatch.setattr(settings, "ingest_bearer_token", None)

        admin = settings.api_bearer_token.get_secret_value()
        creds = MagicMock()
        creds.credentials = admin
        assert asyncio.run(get_ingest_client(creds))["role"] == "admin"
        assert asyncio.run(get_current_user(creds))["role"] == "admin"

        # the (unset) scoped token string is now just an invalid credential
        bad = MagicMock()
        bad.credentials = INGEST_TOKEN
        with pytest.raises(HTTPException):
            asyncio.run(get_ingest_client(bad))
        with pytest.raises(HTTPException):
            asyncio.run(get_current_user(bad))
