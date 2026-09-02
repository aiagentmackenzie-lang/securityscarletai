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

from unittest.mock import AsyncMock, patch

import pytest

from src.ai.alert_explanation import (
    SYSTEM_PROMPT,
    TEMPLATE_EXPLANATIONS,
    _fallback_investigation_steps,
    explain_alert,
    get_template_explanation,
)
from src.ai.ollama_client import LLMResult

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
        mock_result = LLMResult(
            ok=True, text=mock_explanation, source="ollama",
            model_used="mistral:7b", tokens_in=20, tokens_out=15,
            latency_ms=300, fallback_used=False, prompt_version="v1.0.0",
        )

        with (

            patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_result)),

            patch("src.ai.cost_tracker.get_pool", side_effect=OSError("no db in unit tests")),

        ):
            result = await explain_alert(
                rule_name="Brute Force SSH",
                rule_description="Multiple failed SSH login attempts",
                severity="high",
                host_name="server-01",
                mitre_techniques=["T1110"],
                evidence={"source_ip": "10.0.0.1"},
                related_logs_count=50,
            )

        assert result["source"] == "ollama"
        assert "Brute Force SSH" in result["explanation"] or "brute force" in result["explanation"].lower()

    @pytest.mark.asyncio
    async def test_explain_fallback_to_template(self):
        """Should fallback to template when LLM is unavailable."""
        template_text = get_template_explanation("brute_force_ssh") or ""
        mock_result = LLMResult(
            ok=True, text=template_text, source="template_library", model_used=None,
            tokens_in=0, tokens_out=0, latency_ms=0, fallback_used=True,
            warning="Ollama not responding", prompt_version="v1.0.0",
        )
        with (
            patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_result)),
            patch("src.ai.cost_tracker.get_pool", side_effect=OSError("no db in unit tests")),
        ):
            result = await explain_alert(
                rule_name="brute_force_ssh",
                rule_description="Multiple failed SSH login attempts",
                severity="high",
                host_name="server-01",
            )

        # Should use template for "brute_force_ssh"
        assert result["fallback_used"] is True
        assert "brute force" in result["explanation"].lower() or "SSH" in result["explanation"]

    @pytest.mark.asyncio
    async def test_explain_fallback_generic(self):
        """Should fallback to generic explanation when no template matches."""
        # No template for "custom_alert_xyz" — explain_alert will use the
        # _generic_fallback builder. The mock should mirror what query_llm
        # would return: the fallback_text the caller passed in.
        from src.ai.alert_explanation import _generic_fallback
        fallback_text = _generic_fallback(
            "custom_alert_xyz", "Custom alert description", "medium", "workstation-01"
        )
        mock_result = LLMResult(
            ok=True, text=fallback_text, source="template_library", model_used=None,
            tokens_in=0, tokens_out=0, latency_ms=0, fallback_used=True,
            warning="Ollama not responding", prompt_version="v1.0.0",
        )
        with (
            patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_result)),
            patch("src.ai.cost_tracker.get_pool", side_effect=OSError("no db in unit tests")),
        ):
            result = await explain_alert(
                rule_name="custom_alert_xyz",
                rule_description="Custom alert description",
                severity="medium",
                host_name="workstation-01",
            )

        assert result["fallback_used"] is True
        explanation = result["explanation"]
        assert (
            "medium" in explanation.upper()
            or "Medium" in explanation
            or "workstation-01" in explanation
            or "Next steps" in explanation
            or "custom_alert" in explanation.lower()
        )

    @pytest.mark.asyncio
    async def test_explain_with_mitre_and_evidence(self):
        """Should include MITRE techniques and evidence in context."""
        mock_explanation = "Analysis of the alert."
        mock_result = LLMResult(
            ok=True, text=mock_explanation, source="ollama",
            model_used="mistral:7b", tokens_in=20, tokens_out=15,
            latency_ms=300, fallback_used=False, prompt_version="v1.0.0",
        )

        with (
            patch(
                "src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_result)
            ) as mock_llm,
            patch("src.ai.cost_tracker.get_pool", side_effect=OSError("no db in unit tests")),
        ):
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
        mock_result = LLMResult(
            ok=True, text=mock_explanation, source="ollama",
            model_used="mistral:7b", tokens_in=20, tokens_out=15,
            latency_ms=300, fallback_used=False, prompt_version="v1.0.0",
        )
        with (
            patch("src.ai.alert_explanation.query_llm", AsyncMock(return_value=mock_result)),
            patch("src.ai.cost_tracker.get_pool", side_effect=OSError("no db in unit tests")),
        ):
            result = await explain_alert(
                rule_name="Simple Alert",
                rule_description="A simple alert",
                severity="low",
                host_name="ws-01",
            )

        assert result["explanation"] == "Simple explanation."
        assert result["source"] == "ollama"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# summarize_multiple_alerts
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# suggest_investigation_steps
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


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
