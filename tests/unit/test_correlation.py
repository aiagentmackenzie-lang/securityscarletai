"""
Tests for Correlation Engine v3.

Tests correlation rule metadata and parameterized SQL safety.
The decorative sequences module was removed in P1.2b -- SEQUENCE_DEFINITIONS
had zero engine consumers; the live engine is the hand-written SQL in
src/detection/correlation.py.
"""

from src.detection.correlation import (
    CORRELATION_RULES,
    get_correlation_rule_info,
    list_correlation_rules,
)


class TestCorrelationRules:
    """Test correlation rule metadata."""

    def test_all_rules_have_metadata(self):
        """Each correlation rule must have complete metadata."""
        for name, info in CORRELATION_RULES.items():
            assert info["title"], f"Rule {name} missing title"
            assert info["description"], f"Rule {name} missing description"
            assert info["severity"] in ("low", "medium", "high", "critical"), (
                f"Rule {name} invalid severity: {info['severity']}"
            )
            assert len(info["mitre_tactics"]) > 0, f"Rule {name} missing tactics"
            assert len(info["mitre_techniques"]) > 0, f"Rule {name} missing techniques"
            assert 0 < info["confidence_base"] <= 100, (
                f"Rule {name} invalid confidence: {info['confidence_base']}"
            )

    def test_list_correlation_rules(self):
        """list_correlation_rules should return properly formatted list."""
        rules = list_correlation_rules()
        assert len(rules) >= 5
        for r in rules:
            assert "name" in r
            assert "title" in r
            assert "severity" in r

    def test_get_correlation_rule_info(self):
        """get_correlation_rule_info should return metadata."""
        info = get_correlation_rule_info("brute_force_success")
        assert info is not None
        assert info["severity"] == "critical"

    def test_get_correlation_rule_not_found(self):
        """get_correlation_rule_info should return None for unknown rules."""
        info = get_correlation_rule_info("nonexistent")
        assert info is None
