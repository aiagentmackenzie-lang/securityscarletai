"""
Tests for API chat endpoint.

Covers:
- ChatRequest validation
- ChatResponse model
- Auth requirement
"""
import pytest
from src.api.chat import ChatRequest, ChatResponse


class TestChatRequest:
    """Test ChatRequest validation."""

    def test_valid_request(self):
        req = ChatRequest(message="What happened on server01?")
        assert req.message == "What happened on server01?"
        assert req.session_id is None

    def test_min_length_validation(self):
        """Should reject empty message."""
        with pytest.raises(Exception):
            ChatRequest(message="")

    def test_max_length_validation(self):
        """Should reject message > 1000 chars."""
        with pytest.raises(Exception):
            ChatRequest(message="x" * 1001)

    def test_with_session_id(self):
        req = ChatRequest(message="test", session_id="abc123")
        assert req.session_id == "abc123"


class TestChatResponse:
    """Test ChatResponse model."""

    def test_success_response(self):
        resp = ChatResponse(
            response="I detected a brute force attack",
            context_used=True,
        )
        assert resp.context_used is True
        assert "brute force" in resp.response

    def test_response_with_warnings(self):
        resp = ChatResponse(
            response="Analysis complete",
            context_used=False,
            warnings=["Ollama unavailable, using fallback"],
        )
        assert len(resp.warnings) == 1


class TestApiHuntModels:
    """Test Hunt API models."""

    def test_hunt_execute_response(self):
        from src.api.hunt import HuntExecuteResponse
        resp = HuntExecuteResponse(success=True, hunt_id="brute_force_check")
        assert resp.success is True
        assert resp.hunt_id == "brute_force_check"

    def test_gap_analysis_response(self):
        from src.api.hunt import GapAnalysisResponse
        resp = GapAnalysisResponse(
            total_critical_techniques=50,
            covered_by_rules=30,
            covered_by_hunts=15,
            total_covered=35,
            coverage_percentage=70.0,
            gaps=["T1059", "T1078"],
            gap_hunts=[],
            rule_techniques=["T1110", "T1059"],
            hunt_techniques=["T1078"],
        )
        assert resp.coverage_percentage == 70.0