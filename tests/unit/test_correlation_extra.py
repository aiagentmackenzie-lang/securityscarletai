"""
Tests for the correlation engine (additional coverage).

Covers:
- CORRELATION_RULES definitions
- get_correlation_rule_info
- list_correlation_rules
- detect_* functions with mocked DB
- get_host_sessions with mocked DB
- run_all_correlations
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.detection.correlation import (
    CORRELATION_RULES,
    get_correlation_rule_info,
    list_correlation_rules,
    run_all_correlations,
)


class TestCorrelationRuleDefinitions:
    """Test correlation rule definitions."""

    def test_rule_count(self):
        """Should have 5 correlation rules."""
        assert len(CORRELATION_RULES) == 5

    def test_all_rule_names(self):
        """Should have expected rule names."""
        expected = {
            "brute_force_success",
            "payload_callback",
            "persistence_activated",
            "data_exfiltration",
            "privilege_escalation_chain",
        }
        assert set(CORRELATION_RULES.keys()) == expected

    def test_all_rules_have_title(self):
        for name, rule in CORRELATION_RULES.items():
            assert "title" in rule
            assert len(rule["title"]) > 0

    def test_all_rules_have_description(self):
        for name, rule in CORRELATION_RULES.items():
            assert "description" in rule
            assert len(rule["description"]) > 0

    def test_all_rules_have_mitre(self):
        for name, rule in CORRELATION_RULES.items():
            assert len(rule["mitre_tactics"]) > 0
            assert len(rule["mitre_techniques"]) > 0

    def test_brute_force_rule(self):
        rule = CORRELATION_RULES["brute_force_success"]
        assert rule["severity"] == "critical"
        assert "T1110" in rule["mitre_techniques"]

    def test_data_exfiltration_rule(self):
        rule = CORRELATION_RULES["data_exfiltration"]
        assert rule["severity"] == "high"
        assert "T1048" in rule["mitre_techniques"]

    def test_privilege_escalation_chain_rule(self):
        rule = CORRELATION_RULES["privilege_escalation_chain"]
        assert rule["severity"] == "critical"
        assert "T1548" in rule["mitre_techniques"]


class TestGetCorrelationRuleInfo:
    """Test get_correlation_rule_info function."""

    def test_existing_rule(self):
        result = get_correlation_rule_info("brute_force_success")
        assert result is not None
        assert result["title"] == "Brute Force → Successful Login"

    def test_nonexistent_rule(self):
        result = get_correlation_rule_info("nonexistent_rule")
        assert result is None

    def test_payload_callback(self):
        result = get_correlation_rule_info("payload_callback")
        assert result is not None
        assert "Payload" in result["title"] or "C2" in result["title"]


class TestListCorrelationRules:
    """Test list_correlation_rules function."""

    def test_returns_list(self):
        rules = list_correlation_rules()
        assert isinstance(rules, list)
        assert len(rules) == 5

    def test_each_rule_has_required_fields(self):
        rules = list_correlation_rules()
        required = {"name", "title", "description", "severity", "mitre_tactics", "mitre_techniques"}
        for rule in rules:
            assert required.issubset(set(rule.keys()))

    def test_rule_names_match_keys(self):
        rules = list_correlation_rules()
        rule_names = {r["name"] for r in rules}
        assert rule_names == set(CORRELATION_RULES.keys())


class TestDetectBruteForce:
    """Test brute force detection with mocked DB."""

    @pytest.mark.asyncio
    async def test_detect_brute_force_with_results(self):
        """Should detect brute force patterns."""
        from src.detection.correlation import detect_brute_force_then_success

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {
                "host_name": "server01",
                "source_ip": "10.0.0.5",
                "user_name": "admin",
                "success_time": "2025-01-01T12:30:00",
                "failed_count": 5,
            }
        ])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_brute_force_then_success()
            assert len(result) == 1
            assert result[0]["correlation_rule"] == "brute_force_success"
            assert "confidence" in result[0]

    @pytest.mark.asyncio
    async def test_detect_brute_force_no_results(self):
        """Should return empty list when no brute force detected."""
        from src.detection.correlation import detect_brute_force_then_success

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_brute_force_then_success()
            assert result == []


class TestRunAllCorrelations:
    """Test run_all_correlations function."""

    @pytest.mark.asyncio
    async def test_run_all_returns_results(self):
        """Should run all 5 correlation rules and return results."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await run_all_correlations()
            assert isinstance(result, dict)
            assert len(result) == 5  # All 5 rules should be present
            for rule_name in CORRELATION_RULES:
                assert rule_name in result

    @pytest.mark.asyncio
    async def test_run_all_with_error(self):
        """Should handle errors in individual rules gracefully."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        # First call succeeds, rest throw errors
        mock_conn.fetch = AsyncMock(side_effect=[
            [],  # brute force
            Exception("DB error"),
        ])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await run_all_correlations()
            # Results should still contain all rule names
            assert isinstance(result, dict)
            # Rules that errored should have empty lists
            for key in result:
                assert isinstance(result[key], list)