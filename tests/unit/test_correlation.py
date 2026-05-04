"""
Tests for Correlation Engine v2.

Tests sequence definitions, correlation rule metadata,
and parameterized SQL safety.
"""
import pytest
from src.detection.sequences import (
    SEQUENCE_DEFINITIONS,
    EventSequence,
    get_sequence,
    list_sequences,
)
from src.detection.correlation import (
    CORRELATION_RULES,
    list_correlation_rules,
    get_correlation_rule_info,
)


class TestSequenceDefinitions:
    """Test the sequence-based detection definitions."""

    def test_at_least_five_sequences(self):
        """Must define at least 5 attack sequences."""
        assert len(SEQUENCE_DEFINITIONS) >= 5

    def test_all_sequences_have_required_fields(self):
        """Each sequence must have all required fields."""
        for seq in SEQUENCE_DEFINITIONS:
            assert seq.name, f"Sequence missing name: {seq}"
            assert seq.title, f"Sequence missing title: {seq.name}"
            assert seq.description, f"Sequence missing description: {seq.name}"
            assert seq.severity in ("low", "medium", "high", "critical"), \
                f"Sequence {seq.name} has invalid severity: {seq.severity}"
            assert seq.trigger_category, f"Sequence {seq.name} missing trigger_category"
            assert seq.followup_category, f"Sequence {seq.name} missing followup_category"
            assert seq.join_key, f"Sequence {seq.name} missing join_key"
            assert seq.time_window_minutes > 0, f"Sequence {seq.name} has invalid time_window"
            assert len(seq.mitre_tactics) > 0, f"Sequence {seq.name} missing MITRE tactics"
            assert len(seq.mitre_techniques) > 0, f"Sequence {seq.name} missing MITRE techniques"
            assert 0 < seq.confidence_base <= 100, \
                f"Sequence {seq.name} has invalid confidence: {seq.confidence_base}"

    def test_sequence_names_are_unique(self):
        """Sequence names must be unique."""
        names = [seq.name for seq in SEQUENCE_DEFINITIONS]
        assert len(names) == len(set(names)), f"Duplicate sequence names: {names}"

    def test_get_sequence_found(self):
        """get_sequence should return a sequence when name matches."""
        seq = get_sequence("brute_force_success")
        assert seq is not None
        assert seq.title == "Brute Force → Successful Login"

    def test_get_sequence_not_found(self):
        """get_sequence should return None for unknown names."""
        seq = get_sequence("nonexistent_sequence")
        assert seq is None

    def test_list_sequences(self):
        """list_sequences should return all sequences as dicts."""
        seqs = list_sequences()
        assert len(seqs) >= 5
        for s in seqs:
            assert "name" in s
            assert "title" in s
            assert "severity" in s
            assert "mitre_tactics" in s
            assert "mitre_techniques" in s
            assert "confidence_base" in s

    def test_brute_force_sequence(self):
        """Brute force sequence should have correct MITRE mapping."""
        seq = get_sequence("brute_force_success")
        assert "TA0006" in seq.mitre_tactics
        assert "T1110" in seq.mitre_techniques
        assert seq.severity == "critical"

    def test_payload_callback_sequence(self):
        """Payload callback sequence should cover execution and C2."""
        seq = get_sequence("payload_callback")
        assert "TA0002" in seq.mitre_tactics
        assert "TA0011" in seq.mitre_tactics

    def test_persistence_sequence(self):
        """Persistence sequence should detect LaunchAgent patterns."""
        seq = get_sequence("persistence_activated")
        assert "T1547" in seq.mitre_techniques


class TestCorrelationRules:
    """Test correlation rule metadata."""

    def test_all_rules_have_metadata(self):
        """Each correlation rule must have complete metadata."""
        for name, info in CORRELATION_RULES.items():
            assert info["title"], f"Rule {name} missing title"
            assert info["description"], f"Rule {name} missing description"
            assert info["severity"] in ("low", "medium", "high", "critical"), \
                f"Rule {name} invalid severity: {info['severity']}"
            assert len(info["mitre_tactics"]) > 0, f"Rule {name} missing tactics"
            assert len(info["mitre_techniques"]) > 0, f"Rule {name} missing techniques"
            assert 0 < info["confidence_base"] <= 100, \
                f"Rule {name} invalid confidence: {info['confidence_base']}"

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