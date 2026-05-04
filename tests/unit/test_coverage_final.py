"""
Additional coverage tests for remaining low-coverage modules.

Covers:
- src/api/ai.py (train, status, triage, ueba, explain endpoints)
- src/api/websocket.py (auth failure)
- src/api/auth.py (require_role)
- src/ai/alert_triage.py (get_triage_model)
- src/enrichment/pipeline.py (enrich_event with both IPs, dest-only)
- src/db/writer.py (LogWriter start/stop)
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/api/ai.py models and logic
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAiEndpointsModels:
    def test_train_request_model(self):
        from src.api.ai import TrainRequest, TrainResponse
        req = TrainRequest(min_samples=50)
        assert req.min_samples == 50

    def test_train_response_success(self):
        from src.api.ai import TrainResponse
        resp = TrainResponse(success=True, message="OK", samples=100, accuracy=0.95)
        assert resp.success is True
        assert resp.accuracy == 0.95

    def test_status_response_model(self):
        from src.api.ai import StatusResponse
        resp = StatusResponse(
            triage={"is_trained": True},
            ueba={"is_trained": False},
            ollama_available=True,
        )
        assert resp.ollama_available is True

    def test_triage_response_model(self):
        from src.api.ai import TriageResponse
        resp = TriageResponse(
            alert_id=1,
            prediction="true_positive",
            confidence=0.85,
            priority_score=75.0,
        )
        assert resp.prediction == "true_positive"

    def test_ueba_response_model(self):
        from src.api.ai import UEBAResponse
        resp = UEBAResponse(
            user_name="admin",
            anomaly_score=0.3,
            is_anomaly=False,
        )
        assert resp.user_name == "admin"

    def test_explain_response_model(self):
        from src.api.ai import ExplainResponse
        resp = ExplainResponse(
            alert_id=1,
            explanation="This alert indicates brute force activity.",
        )
        assert "brute force" in resp.explanation


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/api/ai.py endpoint logic
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAiTrainEndpoint:
    @pytest.mark.asyncio
    async def test_train_success(self):
        from src.api.ai import train_models, TrainRequest

        mock_triage = MagicMock()
        mock_triage.train = AsyncMock(return_value=True)
        mock_triage.training_samples = 100
        mock_triage.training_accuracy = 0.95

        mock_ueba = MagicMock()
        mock_ueba.train = AsyncMock(return_value=True)

        with patch("src.api.ai.get_triage_model", AsyncMock(return_value=mock_triage)), \
             patch("src.api.ai.get_ueba", AsyncMock(return_value=mock_ueba)):
            result = await train_models(
                request=TrainRequest(min_samples=50),
                _user={"sub": "analyst1", "role": "analyst"},
            )

        assert result.success is True
        assert result.samples == 100

    @pytest.mark.asyncio
    async def test_train_insufficient_data(self):
        from src.api.ai import train_models, TrainRequest

        mock_triage = MagicMock()
        mock_triage.train = AsyncMock(return_value=False)
        mock_triage.training_samples = 0
        mock_triage.training_accuracy = None

        mock_ueba = MagicMock()
        mock_ueba.train = AsyncMock(return_value=False)

        with patch("src.api.ai.get_triage_model", AsyncMock(return_value=mock_triage)), \
             patch("src.api.ai.get_ueba", AsyncMock(return_value=mock_ueba)):
            result = await train_models(
                request=TrainRequest(min_samples=50),
                _user={"sub": "analyst1", "role": "analyst"},
            )

        assert result.success is False


class TestAiStatusEndpoint:
    @pytest.mark.asyncio
    async def test_get_status(self):
        from src.api.ai import get_status

        mock_ueba = MagicMock()
        mock_ueba.get_status = MagicMock(return_value={"is_trained": False})

        with patch("src.api.ai.get_ueba", AsyncMock(return_value=mock_ueba)), \
             patch("src.ai.ollama_client.is_ollama_available", AsyncMock(return_value=True)):
            result = await get_status(_user={"sub": "analyst1", "role": "viewer"})

        assert result.ollama_available is True
        assert result.triage is not None
        assert result.ueba is not None


class TestAiTriageEndpoint:
    @pytest.mark.asyncio
    async def test_triage_alert_not_found(self):
        from src.api.ai import triage_alert
        from fastapi import HTTPException

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.ai.get_pool", AsyncMock(return_value=mock_pool)):
            with pytest.raises(HTTPException) as exc_info:
                await triage_alert(alert_id=9999, _user={"sub": "analyst1", "role": "analyst"})
            assert exc_info.value.status_code == 404


class TestAiExplainEndpoint:
    @pytest.mark.asyncio
    async def test_explain_alert_not_found(self):
        from src.api.ai import explain_alert_endpoint
        from fastapi import HTTPException

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.ai.get_pool", AsyncMock(return_value=mock_pool)):
            with pytest.raises(HTTPException) as exc_info:
                await explain_alert_endpoint(alert_id=9999, _user={"sub": "analyst1", "role": "analyst"})
            assert exc_info.value.status_code == 404


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/api/websocket.py endpoint logic
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWebSocketEndpoint:
    @pytest.mark.asyncio
    async def test_websocket_auth_failure(self):
        """WebSocket should close on auth failure."""
        from src.api.websocket import websocket_logs
        from fastapi import status as http_status

        mock_ws = AsyncMock()
        mock_ws.close = AsyncMock()

        with patch("src.api.websocket.verify_bearer_token", side_effect=Exception("Invalid token")):
            await websocket_logs(
                websocket=mock_ws,
                token="invalid_token",
                host_filter=None,
                category_filter=None,
                severity_filter=None,
            )

        mock_ws.close.assert_called_once_with(code=http_status.WS_1008_POLICY_VIOLATION)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/api/auth.py
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAuthFunctions:
    def test_require_role_viewer(self):
        from src.api.auth import require_role
        fn = require_role("viewer")
        assert callable(fn)

    def test_require_role_admin(self):
        from src.api.auth import require_role
        fn = require_role("admin")
        assert callable(fn)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/ai/alert_triage.py remaining
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestTriageRemaining:
    @pytest.mark.asyncio
    async def test_get_triage_model_creates_instance(self):
        from src.ai.alert_triage import get_triage_model, AlertTriageModel
        import src.ai.alert_triage as triage_mod
        triage_mod._triage_model = None

        with patch.object(AlertTriageModel, "_load_model", return_value=False), \
             patch.object(AlertTriageModel, "train", AsyncMock(return_value=False)):
            model = await get_triage_model()
            assert isinstance(model, AlertTriageModel)

        triage_mod._triage_model = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/enrichment/pipeline.py remaining
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnrichPipelineRemaining:
    @pytest.mark.asyncio
    async def test_enrich_event_both_ips(self):
        """Should enrich both source and dest when both are public."""
        from src.enrichment.pipeline import enrich_event

        mock_event = MagicMock()
        mock_event.source_ip = "8.8.8.8"
        mock_event.destination_ip = "9.9.9.9"

        with patch("src.enrichment.pipeline.enrich_geoip", AsyncMock(return_value={"geo": {"country_iso": "US"}})), \
             patch("src.enrichment.pipeline.enrich_dns_reverse", return_value={"dns": {"reverse": "dns.google"}}), \
             patch("src.intel.threat_intel.enrich_ip_with_threat_intel", AsyncMock(return_value={})):
            result = await enrich_event(mock_event)

        assert "geo" in result
        assert "dns" in result
        assert "destination" in result

    @pytest.mark.asyncio
    async def test_enrich_event_dest_only(self):
        """Should enrich when only dest IP is public."""
        from src.enrichment.pipeline import enrich_event

        mock_event = MagicMock()
        mock_event.source_ip = None
        mock_event.destination_ip = "9.9.9.9"

        with patch("src.enrichment.pipeline.enrich_geoip", AsyncMock(return_value={"geo": {"country_iso": "DE"}})), \
             patch("src.enrichment.pipeline.enrich_dns_reverse", return_value={}), \
             patch("src.intel.threat_intel.enrich_ip_with_threat_intel", AsyncMock(return_value={})):
            result = await enrich_event(mock_event)

        assert "geo" in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/db/writer.py
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLogWriter:
    def test_writer_init(self):
        from src.db.writer import LogWriter
        writer = LogWriter()
        assert writer is not None

    @pytest.mark.asyncio
    async def test_writer_start(self):
        from src.db.writer import LogWriter
        writer = LogWriter()
        with patch("src.db.writer.get_pool", AsyncMock()):
            await writer.start()

    @pytest.mark.asyncio
    async def test_writer_stop(self):
        from src.db.writer import LogWriter
        writer = LogWriter()
        # close_pool is an async function in connection.py, patch it
        with patch("src.db.connection.close_pool", AsyncMock()):
            await writer.stop()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/ingestion/schemas.py
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSchemas:
    def test_normalized_event_model(self):
        from src.ingestion.schemas import NormalizedEvent
        event = NormalizedEvent(
            **{"@timestamp": datetime(2024, 1, 1, tzinfo=timezone.utc)},
            host_name="server-01",
            source="syslog",
            event_category="process",
            event_type="create",
            raw_data={"test": True},
        )
        assert event.host_name == "server-01"
        assert event.raw_data == {"test": True}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# src/api/chat.py
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAiChatModels:
    def test_chat_request_model(self):
        from src.api.chat import ChatRequest
        req = ChatRequest(message="Hello", history=[])
        assert req.message == "Hello"

