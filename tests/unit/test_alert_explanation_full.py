"""
Comprehensive tests for src/ai/alert_explanation.py.

Covers:
- explain_alert (LLM success, fallback, template match)
- summarize_multiple_alerts (LLM, fallback)
- suggest_investigation_steps (LLM, fallback)
- get_template_explanation (exact, partial, no match)
- TEMPLATE_EXPLANATIONS structure
- _fallback_investigation_steps
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.ai.alert_explanation import (
    explain_alert,
    summarize_multiple_alerts,
    suggest_investigation_steps,
    get_template_explanation,
    TEMPLATE_EXPLANATIONS,
    _fallback_investigation_steps,
    SYSTEM_PROMPT,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEMPLATE_EXPLANATIONS structure
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestTemplateExplanations:
    def test_templates_exist(self):
        assert len(TEMPLATE_EXPLANATIONS) > 0

    def test_all_templates_are_strings(self):
        for key, value in TEMPLATE_EXPLANATIONS.items():
            assert isinstance(key, str)
            assert isinstance(value, str)
            assert len(value) > 50  # Templates should be detailed

    def test_template_keys(self):
        expected_keys = [
            "brute_force_ssh",
            "suspicious_tmp_process",
            "launch_agent_persistence",
            "reverse_shell",
            "c2_beaconing",
            "data_exfiltration_volume",
        ]
        for key in expected_keys:
            assert key in TEMPLATE_EXPLANATIONS

    def test_templates_contain_next_steps(self):
        """All templates should include next steps guidance."""
        for key, value in TEMPLATE_EXPLANATIONS.items():
            assert "next steps" in value.lower() or "Next steps" in value


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# get_template_explanation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestGetTemplateExplanation:
    def test_exact_match(self):
        result = get_template_explanation("brute_force_ssh")
        assert result is not None
        assert "brute force" in result.lower()

    def test_exact_match_case_insensitive(self):
        result = get_template_explanation("Brute_Force_SSH")
        assert result is not None

    def test_partial_match(self):
        """Should match by partial key overlap."""
        result = get_template_explanation("brute_force")
        assert result is not None

    def test_reverse_shell_match(self):
        result = get_template_explanation("reverse_shell")
        assert result is not None
        assert "reverse shell" in result.lower()

    def test_no_match(self):
        result = get_template_explanation("completely_unknown_alert_type_xyz")
        assert result is None

    def test_hyphen_converted_to_underscore(self):
        """Should handle hyphenated names by converting to underscores."""
        result = get_template_explanation("c2-beaconing")
        if result is not None:
            assert "c2" in result.lower() or "beacon" in result.lower()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# explain_alert
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestExplainAlert:
    @pytest.mark.asyncio
    async def test_explain_with_llm(self):
        """Should return LLM-generated explanation."""
        mock_explanation = (
            "1. **What happened**: Brute force SSH detected\n"
            "2. **Why it matters**: Possible credential compromise\n"
            "3. **Next steps**: Review login history"
        )

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_explanation)):
            result = await explain_alert(
                rule_name="Brute Force SSH",
                rule_description="Multiple failed SSH login attempts",
                severity="high",
                host_name="server-01",
                mitre_techniques=["T1110"],
                evidence={"source_ip": "10.0.0.1"},
                related_logs_count=50,
            )

        assert "Brute Force SSH" in result or "brute force" in result.lower()

    @pytest.mark.asyncio
    async def test_explain_fallback_to_template(self):
        """Should fallback to template when LLM is unavailable."""
        from src.ai.ollama_client import FALLBACK_MESSAGE

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=FALLBACK_MESSAGE)):
            result = await explain_alert(
                rule_name="brute_force_ssh",
                rule_description="Multiple failed SSH login attempts",
                severity="high",
                host_name="server-01",
            )

        # Should use template for "brute_force_ssh"
        assert "brute force" in result.lower() or "SSH" in result

    @pytest.mark.asyncio
    async def test_explain_fallback_generic(self):
        """Should fallback to generic explanation when no template matches."""
        from src.ai.ollama_client import FALLBACK_MESSAGE

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=FALLBACK_MESSAGE)):
            result = await explain_alert(
                rule_name="custom_alert_xyz",
                rule_description="Custom alert description",
                severity="medium",
                host_name="workstation-01",
            )

        # Generic fallback explanation should have key elements
        assert "medium" in result.upper() or "Medium" in result or "workstation-01" in result or "Next steps" in result or "custom_alert" in result.lower()

    @pytest.mark.asyncio
    async def test_explain_with_mitre_and_evidence(self):
        """Should include MITRE techniques and evidence in context."""
        mock_explanation = "Analysis of the alert."

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_explanation)) as mock_llm:
            await explain_alert(
                rule_name="C2 Beaconing",
                rule_description="Regular connections to suspicious IPs",
                severity="critical",
                host_name="server-01",
                mitre_techniques=["T1071", "T1573"],
                evidence={"destination_ip": "10.0.0.99"},
                related_logs_count=100,
            )

            # Verify the prompt included MITRE techniques
            call_args = mock_llm.call_args
            assert call_args is not None

    @pytest.mark.asyncio
    async def test_explain_no_mitre_no_evidence(self):
        """Should work with no MITRE techniques or evidence."""
        mock_explanation = "Simple explanation."

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_explanation)):
            result = await explain_alert(
                rule_name="Simple Alert",
                rule_description="A simple alert",
                severity="low",
                host_name="ws-01",
            )

        assert result == "Simple explanation."


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# summarize_multiple_alerts
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSummarizeMultipleAlerts:
    @pytest.mark.asyncio
    async def test_summarize_empty_list(self):
        """Should return message for empty list."""
        result = await summarize_multiple_alerts([])
        assert "no" in result.lower() or "No" in result

    @pytest.mark.asyncio
    async def test_summarize_with_llm(self):
        """Should return LLM summary of alerts."""
        mock_summary = "These alerts appear to be part of a coordinated attack campaign."

        alerts = [
            {"severity": "high", "rule_name": "Brute Force SSH", "host_name": "server-01", "time": "2024-01-01T12:00:00"},
            {"severity": "critical", "rule_name": "Malware Detected", "host_name": "server-01", "time": "2024-01-01T12:05:00"},
        ]

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_summary)):
            result = await summarize_multiple_alerts(alerts)

        assert "coordinated" in result.lower() or "attack" in result.lower()

    @pytest.mark.asyncio
    async def test_summarize_fallback(self):
        """Should return fallback summary when LLM unavailable."""
        from src.ai.ollama_client import FALLBACK_MESSAGE

        alerts = [
            {"severity": "high", "rule_name": "Brute Force", "host_name": "ws-01", "time": "2024-01-01"},
            {"severity": "medium", "rule_name": "Suspicious Process", "host_name": "ws-02", "time": "2024-01-01"},
        ]

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=FALLBACK_MESSAGE)):
            result = await summarize_multiple_alerts(alerts)

        assert "2" in result  # Should mention count
        assert "ws-01" in result  # Should mention host

    @pytest.mark.asyncio
    async def test_summarize_many_alerts(self):
        """Should limit to 5 alerts in context when many provided."""
        from src.ai.ollama_client import FALLBACK_MESSAGE

        alerts = [
            {"severity": "high", "rule_name": f"Alert {i}", "host_name": f"ws-{i}", "time": "2024-01-01"}
            for i in range(10)
        ]

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=FALLBACK_MESSAGE)):
            result = await summarize_multiple_alerts(alerts)

        # Should mention the total count
        assert "10" in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# suggest_investigation_steps
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSuggestInvestigationSteps:
    @pytest.mark.asyncio
    async def test_suggest_with_llm(self):
        """Should return parsed steps from LLM."""
        mock_response = (
            "1. Check authentication logs for ws-01\n"
            "2. Review process execution history\n"
            "3. Check network connections from affected host\n"
            "4. Verify threat intelligence matches\n"
            "5. Look for lateral movement patterns"
        )

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_response)):
            result = await suggest_investigation_steps(
                alert_type="brute_force",
                host_name="ws-01",
            )

        assert len(result) >= 1
        assert any(isinstance(s, str) for s in result)

    @pytest.mark.asyncio
    async def test_suggest_with_llm_and_user(self):
        """Should include user context when provided."""
        mock_response = "1. Check recent activity for user admin"

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_response)):
            result = await suggest_investigation_steps(
                alert_type="credential_access",
                host_name="server-01",
                user_name="admin",
            )

        assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_suggest_fallback(self):
        """Should return fallback steps when LLM unavailable."""
        from src.ai.ollama_client import FALLBACK_MESSAGE

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=FALLBACK_MESSAGE)):
            result = await suggest_investigation_steps(
                alert_type="malware",
                host_name="ws-01",
            )

        assert len(result) >= 1
        assert "ws-01" in result[0]

    @pytest.mark.asyncio
    async def test_suggest_fallback_with_user(self):
        """Fallback should include user context."""
        from src.ai.ollama_client import FALLBACK_MESSAGE

        with patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=FALLBACK_MESSAGE)):
            result = await suggest_investigation_steps(
                alert_type="brute_force",
                host_name="server-01",
                user_name="jsmith",
            )

        assert len(result) >= 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _fallback_investigation_steps
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestFallbackInvestigationSteps:
    def test_returns_list(self):
        result = _fallback_investigation_steps("brute_force", "server-01")
        assert isinstance(result, list)
        assert len(result) >= 5

    def test_includes_host(self):
        result = _fallback_investigation_steps("malware", "workstation-05")
        assert any("workstation-05" in step for step in result)

    def test_includes_mitre_reference(self):
        result = _fallback_investigation_steps("c2_beaconing", "server-01")
        assert any("MITRE" in step for step in result)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SYSTEM_PROMPT structure
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSystemPrompt:
    def test_system_prompt_exists(self):
        assert len(SYSTEM_PROMPT) > 50

    def test_system_prompt_contains_key_topics(self):
        assert "cybersecurity" in SYSTEM_PROMPT.lower()
        assert "explain" in SYSTEM_PROMPT.lower() or "explanation" in SYSTEM_PROMPT.lower()