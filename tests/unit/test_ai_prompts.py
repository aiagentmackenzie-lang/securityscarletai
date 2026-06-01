"""
Tests for src/ai/prompts.py (Agent A, Epic 1).

Covers:
- Version constants exist and are non-empty
- Jinja2 templates render with expected fields
- Renderer returns (text, version, version_hash)
- Version hash is stable for same input
- all_versions() returns all prompt versions
"""

import pytest

from src.ai.prompts import (
    ALERT_EXPLANATION_PROMPT_VERSION,
    ALERT_SUMMARY_PROMPT_VERSION,
    CHAT_SYSTEM_PROMPT_VERSION,
    INVESTIGATION_STEPS_PROMPT_VERSION,
    all_versions,
    render_alert_explanation,
    render_alert_summary,
    render_chat,
    render_investigation_steps,
)


class TestVersionConstants:
    def test_alert_explanation_version_is_semver(self):
        v = ALERT_EXPLANATION_PROMPT_VERSION
        assert v.startswith("v")
        parts = v[1:].split(".")
        assert len(parts) == 3
        for p in parts:
            assert p.isdigit()

    def test_all_version_constants_present(self):
        assert ALERT_EXPLANATION_PROMPT_VERSION
        assert ALERT_SUMMARY_PROMPT_VERSION
        assert INVESTIGATION_STEPS_PROMPT_VERSION
        assert CHAT_SYSTEM_PROMPT_VERSION

    def test_all_versions_returns_dict(self):
        versions = all_versions()
        assert "alert_explanation" in versions
        assert "alert_summary" in versions
        assert "investigation_steps" in versions
        assert "chat" in versions


class TestRenderAlertExplanation:
    def test_basic_render(self):
        text, version, version_hash = render_alert_explanation(
            rule_name="Brute Force SSH",
            rule_description="Multiple failed logins",
            severity="high",
            host_name="server-01",
            mitre_techniques=["T1110"],
            evidence_str="",
            related_logs_count=10,
        )
        assert "Brute Force SSH" in text
        assert "server-01" in text
        assert "T1110" in text
        assert "10" in text
        assert version == ALERT_EXPLANATION_PROMPT_VERSION
        assert len(version_hash) == 16  # sha256 truncated to 16 chars

    def test_render_with_no_mitre(self):
        text, version, _ = render_alert_explanation(
            rule_name="Custom Alert",
            rule_description="Custom",
            severity="low",
            host_name="ws-01",
            mitre_techniques=None,
        )
        assert "N/A" in text  # mitre fallback

    def test_render_with_evidence(self):
        text, _, _ = render_alert_explanation(
            rule_name="Test",
            rule_description="Test",
            severity="medium",
            host_name="host",
            evidence_str='{"key": "value"}',
            related_logs_count=0,
        )
        assert "key" in text
        assert "value" in text

    def test_hash_is_stable(self):
        """Same inputs should produce the same hash."""
        kwargs = dict(
            rule_name="X",
            rule_description="Y",
            severity="z",
            host_name="h",
            mitre_techniques=["T1"],
            evidence_str="",
            related_logs_count=0,
        )
        _, _, h1 = render_alert_explanation(**kwargs)
        _, _, h2 = render_alert_explanation(**kwargs)
        assert h1 == h2


class TestRenderAlertSummary:
    def test_basic_render(self):
        text, version, h = render_alert_summary(
            alert_summaries="- [HIGH] Brute Force on ws-01",
            truncated_count=2,
        )
        assert "Brute Force" in text
        assert "ws-01" in text
        assert "2" in text
        assert version == ALERT_SUMMARY_PROMPT_VERSION
        assert len(h) == 16

    def test_zero_truncated(self):
        text, _, _ = render_alert_summary(
            alert_summaries="- x", truncated_count=0,
        )
        # Should not say "and 0 more alerts"
        assert "0 more" not in text


class TestRenderInvestigationSteps:
    def test_basic(self):
        text, version, h = render_investigation_steps(
            alert_type="brute_force", host_name="ws-01",
        )
        assert "brute_force" in text
        assert "ws-01" in text
        assert version == INVESTIGATION_STEPS_PROMPT_VERSION

    def test_with_user(self):
        text, _, _ = render_investigation_steps(
            alert_type="x", host_name="h", user_name="alice",
        )
        assert "alice" in text

    def test_without_user(self):
        text, _, _ = render_investigation_steps(
            alert_type="x", host_name="h", user_name=None,
        )
        # Should not crash, and user_name shouldn't appear
        assert "User:" not in text


class TestRenderChat:
    def test_basic(self):
        text, version, h = render_chat(
            context="5 critical alerts",
            sanitized_message="What should I do?",
        )
        assert "5 critical alerts" in text
        assert "What should I do?" in text
        assert version == CHAT_SYSTEM_PROMPT_VERSION
        assert len(h) == 16


class TestPromptsImportSafety:
    """The prompts module should import cleanly and not call any DB."""

    def test_imports_without_db(self):
        from src.ai import prompts
        assert prompts is not None
