"""
Tests for API AI endpoints models.

Covers:
- TrainRequest/TrainResponse models
- StatusResponse model
- TriageResponse model
- UEBAResponse model
- ExplainResponse model
"""
import pytest
from src.api.ai import (
    TrainRequest,
    TrainResponse,
    StatusResponse,
    TriageResponse,
    UEBAResponse,
    ExplainResponse,
)


class TestTrainRequest:
    """Test TrainRequest model."""

    def test_default_min_samples(self):
        req = TrainRequest()
        assert req.min_samples == 50

    def test_custom_min_samples(self):
        req = TrainRequest(min_samples=100)
        assert req.min_samples == 100


class TestTrainResponse:
    """Test TrainResponse model."""

    def test_success_response(self):
        resp = TrainResponse(
            success=True,
            message="Models trained successfully",
            samples=100,
            accuracy=0.92,
        )
        assert resp.success is True
        assert resp.samples == 100
        assert resp.accuracy == 0.92

    def test_failure_response(self):
        resp = TrainResponse(
            success=False,
            message="Insufficient data",
        )
        assert resp.success is False
        assert resp.samples is None
        assert resp.accuracy is None


class TestStatusResponse:
    """Test StatusResponse model."""

    def test_full_status(self):
        resp = StatusResponse(
            triage={"is_trained": True, "training_samples": 100},
            ueba={"is_trained": False},
            ollama_available=True,
        )
        assert resp.ollama_available is True
        assert resp.triage["is_trained"] is True

    def test_ollama_unavailable(self):
        resp = StatusResponse(
            triage={"is_trained": False},
            ueba={"is_trained": False},
            ollama_available=False,
        )
        assert resp.ollama_available is False


class TestTriageResponse:
    """Test TriageResponse model."""

    def test_full_response(self):
        resp = TriageResponse(
            alert_id=42,
            prediction="true_positive",
            confidence=0.85,
            priority_score=78.5,
            features={"severity_score": 0.8},
            reason="High severity, unusual process pattern",
        )
        assert resp.alert_id == 42
        assert resp.prediction == "true_positive"
        assert resp.confidence == 0.85

    def test_minimal_response(self):
        resp = TriageResponse(
            alert_id=1,
            prediction="unknown",
        )
        assert resp.confidence is None
        assert resp.priority_score is None


class TestUEBAResponse:
    """Test UEBAResponse model."""

    def test_anomaly_detected(self):
        resp = UEBAResponse(
            user_name="suspicious_user",
            anomaly_score=0.85,
            is_anomaly=True,
            features={"login_hour_of_day": 3.0},
        )
        assert resp.is_anomaly is True

    def test_no_anomaly(self):
        resp = UEBAResponse(
            user_name="normal_user",
            anomaly_score=0.15,
            is_anomaly=False,
        )
        assert resp.is_anomaly is False

    def test_error_response(self):
        resp = UEBAResponse(
            user_name="unknown_user",
            anomaly_score=None,
            is_anomaly=False,
            error="No data for user",
        )
        assert resp.error is not None


class TestExplainResponse:
    """Test ExplainResponse model."""

    def test_response(self):
        resp = ExplainResponse(
            alert_id=42,
            explanation="This alert indicates a brute force attack...",
        )
        assert resp.alert_id == 42
        assert "brute force" in resp.explanation