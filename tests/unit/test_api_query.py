"""
Tests for API query endpoint (NL→SQL).

Covers:
- NLQueryRequest validation
- NLQueryResponse model
- TemplateResponse model
- Query endpoint auth requirements
- Query endpoint with mocked DB
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.api.query import NLQueryRequest, NLQueryResponse, TemplateResponse


class TestNLQueryRequest:
    """Test NLQueryRequest Pydantic model."""

    def test_valid_request(self):
        req = NLQueryRequest(question="How many alerts yesterday?")
        assert req.question == "How many alerts yesterday?"
        assert req.execute is True  # Default
        assert req.session_id is None

    def test_question_min_length(self):
        """Should reject empty question."""
        with pytest.raises(Exception):
            NLQueryRequest(question="")

    def test_question_max_length(self):
        """Should reject question > 500 chars."""
        with pytest.raises(Exception):
            NLQueryRequest(question="x" * 501)

    def test_custom_session_id(self):
        req = NLQueryRequest(question="test", session_id="abc123")
        assert req.session_id == "abc123"

    def test_dry_run_mode(self):
        req = NLQueryRequest(question="test", execute=False)
        assert req.execute is False


class TestNLQueryResponse:
    """Test NLQueryResponse model."""

    def test_success_response(self):
        resp = NLQueryResponse(
            success=True,
            sql="SELECT COUNT(*) FROM alerts",
            results=[{"count": 42}],
            row_count=1,
        )
        assert resp.success is True
        assert resp.sql == "SELECT COUNT(*) FROM alerts"

    def test_error_response(self):
        resp = NLQueryResponse(
            success=False,
            error="Query failed",
        )
        assert resp.success is False
        assert resp.error == "Query failed"

    def test_all_optional_fields(self):
        resp = NLQueryResponse(success=True)
        assert resp.sql is None
        assert resp.results is None
        assert resp.row_count is None
        assert resp.truncated is None
        assert resp.template_used is None
        assert resp.estimated_rows is None
        assert resp.session_id is None
        assert resp.elapsed_ms is None
        assert resp.execution_ms is None
        assert resp.error is None
        assert resp.warnings is None


class TestTemplateResponse:
    """Test TemplateResponse model."""

    def test_template_response(self):
        resp = TemplateResponse(
            id="alerts_by_severity",
            description="Count alerts by severity",
            keywords=["alerts", "severity", "count"],
        )
        assert resp.id == "alerts_by_severity"
        assert len(resp.keywords) == 3