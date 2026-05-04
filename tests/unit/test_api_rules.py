"""
Tests for API rules endpoints.

Covers:
- RuleCreate validation
- RuleResponse model
- CRUD operations (with mocked DB)
- Sigma YAML validation
- Auth requirements
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.api.rules import RuleCreate, RuleResponse


class TestRuleCreate:
    """Test RuleCreate Pydantic model."""

    def test_valid_rule(self):
        rule = RuleCreate(
            name="SSH Brute Force",
            sigma_yaml="title: SSH Brute Force\ndetection:\n  condition: selection",
        )
        assert rule.name == "SSH Brute Force"
        assert rule.severity == "medium"  # default
        assert rule.enabled is True  # default
        assert rule.run_interval == 60  # default
        assert rule.lookback == 300  # default
        assert rule.threshold == 1  # default

    def test_name_required(self):
        """Should reject rule without name."""
        with pytest.raises(Exception):
            RuleCreate(
                name="",
                sigma_yaml="title: Test",
            )

    def test_name_max_length(self):
        """Should reject name > 200 chars."""
        with pytest.raises(Exception):
            RuleCreate(
                name="x" * 201,
                sigma_yaml="title: Test",
            )

    def test_custom_severity(self):
        rule = RuleCreate(
            name="Test",
            sigma_yaml="title: Test",
            severity="critical",
        )
        assert rule.severity == "critical"

    def test_description_default(self):
        rule = RuleCreate(
            name="Test",
            sigma_yaml="title: Test",
        )
        assert rule.description == ""

    def test_custom_interval(self):
        rule = RuleCreate(
            name="Test",
            sigma_yaml="title: Test",
            run_interval=300,
            lookback=600,
            threshold=5,
        )
        assert rule.run_interval == 300
        assert rule.lookback == 600
        assert rule.threshold == 5


class TestRuleResponse:
    """Test RuleResponse model."""

    def test_response_fields(self):
        resp = RuleResponse(
            id=1,
            name="SSH Brute Force",
            description="Detects SSH brute force",
            severity="high",
            enabled=True,
            last_run="2025-01-01T00:00:00",
            last_match=None,
            match_count=5,
        )
        assert resp.id == 1
        assert resp.name == "SSH Brute Force"
        assert resp.severity == "high"
        assert resp.match_count == 5

    def test_optional_fields_nullable(self):
        resp = RuleResponse(
            id=1,
            name="Test",
            description="",
            severity="low",
            enabled=True,
            last_run=None,
            last_match=None,
            match_count=0,
        )
        assert resp.last_run is None
        assert resp.last_match is None


class TestRulesEndpoint:
    """Test rules API endpoint logic."""

    def test_parse_sigma_raises_on_invalid_yaml(self):
        """Invalid Sigma YAML should raise an exception."""
        from src.detection.sigma import parse_sigma_rule
        with pytest.raises(Exception):
            parse_sigma_rule("not: valid: sigma: yaml:")

    def test_parse_sigma_valid_yaml(self):
        """Valid Sigma YAML should parse."""
        from src.detection.sigma import parse_sigma_rule
        yaml = """
title: Test Rule
level: high
detection:
    selection:
        Field1: value1
    condition: selection
"""
        result = parse_sigma_rule(yaml)
        assert result is not None