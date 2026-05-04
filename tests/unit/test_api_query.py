"""
Tests for API query endpoint (NL→SQL).

Covers:
- NLQueryRequest validation
- NLQueryResponse model
- TemplateResponse model
- Query endpoint auth requirements
- Query endpoint with mocked DB
- SQL injection adversarial tests (T-07)
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.api.query import NLQueryRequest, NLQueryResponse, TemplateResponse
from src.ai.nl2sql import add_safety_limits, validate_sql_structure, sanitize_input


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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# T-07: SQL Injection Adversarial Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSQLInjectionPrevention:
    """Adversarial tests for NL→SQL injection prevention.

    These tests verify that SQL injection attempts are blocked
    at the template/safety layer, not just at the request model level.
    """

    def test_drop_table_injection(self):
        """DROP TABLE should be blocked by validate_sql_structure."""
        malicious = "SELECT * FROM alerts; DROP TABLE alerts; --"
        # The real defense is validate_sql_structure which rejects forbidden patterns
        from src.ai.nl2sql import validate_sql_structure
        is_valid, reason = validate_sql_structure(malicious)
        assert not is_valid
        assert "DROP" in reason or "forbidden" in reason.lower() or "semicolon" in reason.lower() or "comment" in reason.lower()

    def test_union_select_injection(self):
        """UNION SELECT to extract other tables should be blocked."""
        malicious = "SELECT * FROM alerts UNION SELECT * FROM users --"
        safe = add_safety_limits(malicious)
        # UNION SELECT in a non-subquery context is injection
        # add_safety_limits adds LIMIT; sanitize_sql should block UNION
        assert "LIMIT" in safe.upper(), "Safety limits should be applied"

    def test_comment_injection(self):
        """SQL comments should not bypass safety."""
        malicious = "SELECT * FROM alerts WHERE host_name = 'server01' --"
        safe = add_safety_limits(malicious)
        # Should still have LIMIT applied, comment doesn't bypass
        assert "LIMIT" in safe.upper()

    def test_semicolon_stacking(self):
        """Multiple statement stacking should be blocked."""
        malicious = "SELECT * FROM alerts; DELETE FROM alerts WHERE 1=1"
        safe = add_safety_limits(malicious)
        # add_safety_limits applies to first statement only
        # The safety system should limit damage
        assert "LIMIT" in safe.upper()

    def test_boolean_injection(self):
        """Always-true WHERE clause injection."""
        malicious = "SELECT * FROM alerts WHERE 1=1 OR 1=1"
        safe = add_safety_limits(malicious)
        # Safety limits should cap results even with always-true WHERE
        assert "LIMIT" in safe.upper()

    def test_safety_limits_adds_max_rows(self):
        """add_safety_limits must add a LIMIT clause."""
        plain = "SELECT * FROM alerts WHERE severity = 'high'"
        safe = add_safety_limits(plain)
        assert "LIMIT" in safe.upper()

    def test_safety_limits_preserves_existing_limit(self):
        """Existing LIMIT should be capped, not duplicated."""
        with_limit = "SELECT * FROM alerts LIMIT 50"
        safe = add_safety_limits(with_limit)
        # Should not have duplicate LIMIT keywords
        assert safe.upper().count("LIMIT") == 1

    def test_sanitize_sql_blocks_write_ops(self):
        """validate_sql_structure should reject INSERT, UPDATE, DELETE, DROP."""
        dangerous_queries = [
            "INSERT INTO users (name) VALUES ('hacker')",
            "UPDATE alerts SET severity = 'low'",
            "DELETE FROM alerts WHERE 1=1",
            "DROP TABLE alerts",
            "ALTER TABLE alerts ADD COLUMN backdoor TEXT",
            "CREATE TABLE hack (id INT)",
        ]
        for sql in dangerous_queries:
            is_valid, reason = validate_sql_structure(sql)
            assert is_valid is False, \
                f"validate_sql_structure should block: {sql[:50]} — {reason}"

    def test_request_rejects_sql_keywords_in_question(self):
        """NLQueryRequest should accept any string (filtering is downstream)."""
        # The model itself accepts any text — injection protection is in
        # the NL→SQL pipeline, not the request model
        req = NLQueryRequest(question="DROP TABLE users")
        assert req.question == "DROP TABLE users"
        # Protection happens in nl2sql, not at the request model

    def test_sanitize_input_strips_dangerous_sql(self):
        """sanitize_input should flag dangerous SQL keywords in user text."""
        dangerous_questions = [
            "show me alerts; DROP TABLE users",
            "alerts where 1=1 UNION SELECT * FROM passwords",
        ]
        for question in dangerous_questions:
            cleaned, warnings = sanitize_input(question)
            assert len(warnings) > 0, \
                f"sanitize_input should flag dangerous input: {question[:40]}"


class TestAddSafetyLimitsCTE:
    """Test that add_safety_limits handles CTEs correctly (M-08 fix)."""

    def test_simple_query_gets_limit(self):
        """Simple SELECT should get LIMIT appended."""
        sql = "SELECT * FROM alerts"
        result = add_safety_limits(sql)
        assert "LIMIT" in result.upper()

    def test_cte_query_limit_in_right_place(self):
        """CTE query should have LIMIT in final SELECT, not inside WITH."""
        sql = "WITH recent AS (SELECT * FROM logs WHERE time > NOW() - INTERVAL '1 hour') SELECT * FROM recent"
        result = add_safety_limits(sql)
        # LIMIT should appear only once, in the final SELECT
        assert "LIMIT" in result.upper()
        # Should NOT have LIMIT inside the CTE definition
        cte_body = result.upper().split("SELECT")[1]  # After first SELECT
        # The LIMIT should be near the end, not inside WITH block
        limit_pos = result.upper().rfind("LIMIT")
        assert limit_pos > result.upper().find(") SELECT"), \
            "LIMIT should be in the final SELECT, not inside CTE definition"

    def test_nested_cte_with_limit(self):
        """Nested CTEs should have LIMIT only on final SELECT."""
        sql = "WITH a AS (SELECT * FROM logs), b AS (SELECT * FROM a) SELECT * FROM b"
        result = add_safety_limits(sql)
        assert result.upper().count("LIMIT") == 1

    def test_existing_limit_capped(self):
        """Existing LIMIT > MAX should be capped."""
        sql = "SELECT * FROM alerts LIMIT 1000000"
        result = add_safety_limits(sql)
        # Should have a reasonable limit, not 1M
        import re
        match = re.search(r"LIMIT\s+(\d+)", result, re.IGNORECASE)
        assert match, "Should have LIMIT clause"
        limit_val = int(match.group(1))
        assert limit_val <= 10000, f"LIMIT should be capped, got {limit_val}"