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

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.detection import correlation as corr
from src.detection.correlation import (
    CORRELATION_RULES,
    get_correlation_rule_info,
    list_correlation_rules,
    run_all_correlations,
)

# Shared point-in-time bound for detect_* tests (pattern from
# test_correlation_match_building.py — as_of-bound, no NOW()).
AS_OF = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _conn_returning(rows):
    """Build a mock asyncpg conn whose .fetch returns the given rows."""
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=rows)
    return conn


class TestCorrelationRuleDefinitions:
    """Test correlation rule definitions."""

    def test_rule_count(self):
        """Should have 8 correlation rules."""
        assert len(CORRELATION_RULES) == 8

    def test_all_rule_names(self):
        """Should have expected rule names."""
        expected = {
            "brute_force_success",
            "payload_callback",
            "persistence_activated",
            "data_exfiltration",
            "privilege_escalation_chain",
            "credential_theft_exfil",
            "defense_evasion_cleanup",
            "ai_verdict_block_sustained",
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
        assert len(rules) == 8

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
        from datetime import datetime, timezone

        from src.detection.correlation import detect_brute_force_then_success

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                {
                    "host_name": "server01",
                    "source_ip": "10.0.0.5",
                    "user_name": "admin",
                    "success_time": "2025-01-01T12:30:00",
                    "failed_count": 5,
                }
            ]
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_brute_force_then_success(
                mock_conn, datetime(2025, 1, 1, 12, 30, 0, tzinfo=timezone.utc)
            )
            assert len(result) == 1
            assert result[0]["correlation_rule"] == "brute_force_success"
            assert "confidence" in result[0]
            assert "correlation_id" in result[0]
            assert result[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_detect_brute_force_no_results(self):
        """Should return empty list when no brute force detected."""
        from datetime import datetime, timezone

        from src.detection.correlation import detect_brute_force_then_success

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await detect_brute_force_then_success(
                mock_conn, datetime(2025, 1, 1, 12, 30, 0, tzinfo=timezone.utc)
            )
            assert result == []


class TestDetectAiVerdictBlockSustained:
    """Test sustained AI-verdict BLOCK detection with mocked DB."""

    @pytest.mark.asyncio
    async def test_detect_sustained_blocks(self):
        """Should flag a (host, source, tenant) group above the threshold."""
        from datetime import datetime, timezone

        from src.detection.correlation import detect_ai_verdict_block_sustained

        row = {
            "host_name": "neuralguard-appliance",
            "source": "neuralguard",
            "tenant_id": "default",
            "block_count": 14,
            "last_block_time": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        }
        conn = _conn_returning([row])

        result = await detect_ai_verdict_block_sustained(conn, AS_OF)

        assert len(result) == 1
        m = result[0]
        assert m["correlation_rule"] == "ai_verdict_block_sustained"
        assert m["severity"] == "high"
        assert m["block_count"] == 14
        assert m["tenant_id"] == "default"
        assert isinstance(m["correlation_id"], str)
        assert "confidence" in m
        assert "mitre_techniques" in m

    @pytest.mark.asyncio
    async def test_no_results_below_threshold(self):
        """No groups at/above threshold -> empty list (SQL HAVING), no crash."""
        conn = _conn_returning([])

        result = await corr.detect_ai_verdict_block_sustained(conn, AS_OF)

        assert result == []

    @pytest.mark.asyncio
    async def test_confidence_scales_with_block_count_capped(self):
        """More blocks above threshold -> higher confidence, capped at 100."""
        low = {
            "host_name": "h",
            "source": "neuralguard",
            "tenant_id": "t1",
            "block_count": 10,
            "last_block_time": AS_OF,
        }
        high = {
            "host_name": "h",
            "source": "neuralguard",
            "tenant_id": "t1",
            "block_count": 500,
            "last_block_time": AS_OF,
        }

        m_low = (await corr.detect_ai_verdict_block_sustained(_conn_returning([low]), AS_OF))[0]
        m_high = (await corr.detect_ai_verdict_block_sustained(_conn_returning([high]), AS_OF))[0]

        assert m_low["confidence"] == 75  # at threshold = base
        assert m_high["confidence"] == 100  # capped
        assert m_high["confidence"] > m_low["confidence"]

    @pytest.mark.asyncio
    async def test_unknown_tenant_coalesced_in_match(self):
        """A NULL tenant row surfaces as 'unknown' from the SQL COALESCE."""
        row = {
            "host_name": "h",
            "source": "neuralguard",
            "tenant_id": "unknown",
            "block_count": 12,
            "last_block_time": AS_OF,
        }

        result = await corr.detect_ai_verdict_block_sustained(_conn_returning([row]), AS_OF)

        assert result[0]["tenant_id"] == "unknown"

    def test_rule_metadata(self):
        """The rule definition carries complete metadata."""
        rule = CORRELATION_RULES["ai_verdict_block_sustained"]
        assert rule["severity"] == "high"
        assert "T1190" in rule["mitre_techniques"]
        assert "TA0001" in rule["mitre_tactics"]


class TestRunAllCorrelations:
    """Test run_all_correlations function (Epic 2 contract)."""

    @pytest.mark.asyncio
    async def test_run_all_returns_results(self):
        """Should run all 8 correlation rules and return results."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await run_all_correlations()
            # New contract: dict with matches, total_matches, persisted, as_of, per_rule
            assert isinstance(result, dict)
            assert "matches" in result
            assert "total_matches" in result
            assert "persisted" in result
            assert "as_of" in result
            assert "per_rule" in result
            # All 8 rules should be present in per_rule
            assert len(result["per_rule"]) == 8
            for rule_name in CORRELATION_RULES:
                assert rule_name in result["per_rule"]

    @pytest.mark.asyncio
    async def test_run_all_with_error(self):
        """Should handle errors in individual rules gracefully."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        # All calls throw errors
        mock_conn.fetch = AsyncMock(side_effect=Exception("DB error"))

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await run_all_correlations()
            # Even with errors, the per_rule dict is populated
            assert isinstance(result, dict)
            assert isinstance(result["per_rule"], dict)
            # Rules that errored should have empty lists
            for key, val in result["per_rule"].items():
                assert isinstance(val, list)
                assert val == []
