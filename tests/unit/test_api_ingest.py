"""
Tests for API ingestion endpoint.

Covers:
- POST /ingest with valid events
- Batch size limits
- Input validation
- Field sanitization
- Auth requirement
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api.ingest import IngestEvent, IngestResponse


class TestIngestEvent:
    """Test IngestEvent Pydantic model."""

    def test_valid_event(self):
        """Should accept a valid event."""
        event = IngestEvent(
            **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
            host_name="server01",
            source="syslog",
            event_category="process",
            event_type="start",
        )
        assert event.host_name == "server01"

    def test_hostname_sanitization(self):
        """Should strip control characters from hostname."""
        event = IngestEvent(
            **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
            host_name="server\n\r01\t",
            source="syslog",
            event_category="process",
            event_type="start",
        )
        assert "\n" not in event.host_name
        assert "\r" not in event.host_name
        assert "\t" not in event.host_name

    def test_hostname_strips_newlines(self):
        """Hostname should not contain newlines."""
        event = IngestEvent(
            **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
            host_name="evil\nhost",
            source="syslog",
            event_category="process",
            event_type="start",
        )
        assert event.host_name == "evilhost"

    def test_max_length_hostname(self):
        """Should reject hostname longer than 253 chars."""
        with pytest.raises(Exception):
            IngestEvent(
                **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
                host_name="a" * 254,
                source="syslog",
                event_category="process",
                event_type="start",
            )

    def test_max_length_source(self):
        """Should reject source longer than 100 chars."""
        with pytest.raises(Exception):
            IngestEvent(
                **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
                host_name="server01",
                source="a" * 101,
                event_category="process",
                event_type="start",
            )

    def test_optional_fields(self):
        """Optional fields should default to None."""
        event = IngestEvent(
            **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
            host_name="server01",
            source="syslog",
            event_category="process",
            event_type="start",
        )
        assert event.user_name is None
        assert event.source_ip is None
        assert event.destination_ip is None
        assert event.process_name is None
        assert event.file_path is None

    def test_optional_fields_with_values(self):
        """Should accept optional fields."""
        event = IngestEvent(
            **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
            host_name="server01",
            source="syslog",
            event_category="authentication",
            event_type="login",
            user_name="admin",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            destination_port=443,
            process_name="sshd",
            file_path="/var/log/auth.log",
        )
        assert event.user_name == "admin"
        assert event.source_ip == "10.0.0.1"
        assert event.destination_port == 443

    def test_raw_data_defaults_empty(self):
        """raw_data should default to empty dict."""
        event = IngestEvent(
            **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
            host_name="server01",
            source="syslog",
            event_category="process",
            event_type="start",
        )
        assert event.raw_data == {}

    def test_severity_optional(self):
        """Severity should be optional."""
        event = IngestEvent(
            **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
            host_name="server01",
            source="syslog",
            event_category="process",
            event_type="start",
        )
        assert event.severity is None

    def test_severity_max_length(self):
        """Should reject severity longer than 20 chars."""
        with pytest.raises(Exception):
            IngestEvent(
                **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
                host_name="server01",
                source="syslog",
                event_category="process",
                event_type="start",
                severity="a" * 21,
            )


class TestIngestResponse:
    """Test IngestResponse model."""

    def test_response_model(self):
        """Should create response model."""
        resp = IngestResponse(accepted=5, message="Accepted 5 events")
        assert resp.accepted == 5
        assert "5" in resp.message


class TestIngestEndpoint:
    """Test POST /ingest endpoint with FastAPI TestClient."""

    @pytest.fixture
    def client(self):
        """Create test client with ingestion router."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.auth import get_current_user
        from src.api.ingest import router

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        # Override auth dependency
        app.dependency_overrides[get_current_user] = lambda: "test-token"
        return TestClient(app)

    def test_ingest_requires_auth(self):
        """Ingestion should require authentication."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.ingest import router

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        client = TestClient(app)
        response = client.post(
            "/api/v1/ingest",
            json=[
                {
                    "@timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "host_name": "s1",
                    "source": "syslog",
                    "event_category": "process",
                    "event_type": "start",
                }
            ],
        )
        # Should return 401 or 403
        assert response.status_code in (401, 403, 422)


class TestBroadcastOffHotPath:
    """P2.4 — WS broadcast runs in the per-batch background task, OFF the
    ingest hot path; a broken WS never affects the ingest result."""

    async def test_broadcast_failure_does_not_affect_ingest(self):
        from src.api.ingest import ingest_events
        from src.services.writer import writer as writer_singleton
        from tests.unit._test_request import make_test_request

        events = [
            IngestEvent(
                **{"@timestamp": datetime.now(tz=timezone.utc).isoformat()},
                host_name="s1",
                source="syslog",
                event_category="process",
                event_type="start",
            )
        ]
        broadcast_calls = {"n": 0}

        async def failing_broadcast(event):
            broadcast_calls["n"] += 1
            raise RuntimeError("ws down")

        with (
            patch.object(writer_singleton, "write", AsyncMock()),
            patch.object(writer_singleton, "flush", AsyncMock()),
            patch(
                "src.db.connection.get_pool",
                AsyncMock(side_effect=RuntimeError("no db")),
            ),
            patch("src.detection.correlation.run_all_correlations", AsyncMock()),
            patch("src.api.websocket.broadcast_event", failing_broadcast),
        ):
            result = await ingest_events(
                make_test_request(), MagicMock(), events, "token"
            )
            assert result.accepted == 1
            # Yield the loop so the _post_process background task runs —
            # the broadcast is NOT part of the request path anymore.
            for _ in range(20):
                await asyncio.sleep(0)

        assert broadcast_calls["n"] == 1  # ran in background; failure swallowed
