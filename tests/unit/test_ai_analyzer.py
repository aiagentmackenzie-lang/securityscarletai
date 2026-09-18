"""
Tests for AI alert analysis (Ollama integration).

Covers:
- build_prompt() — prompt construction
- analyze_alert() — success, failures, parse errors
- enrich_alert() — DB updates
- Ollama unavailability handling

Updated: now tests against shared ollama_client.query_llm() instead of raw httpx.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.ai.ollama_client import FALLBACK_MESSAGE, LLMResult
from src.detection.ai_analyzer import (
    _parse_json_response,
    analyze_alert,
    build_prompt,
    enrich_alert,
)


def _llm_result(
    text: str, fallback: bool = False, source: str | None = None, error: str | None = None
) -> LLMResult:
    """Build a realistic LLMResult matching query_llm's real contract.

    analyze_alert passes NO fallback_text, so a REAL outage arrives as
    source='error' (ok=False, text='') — not as a template fallback. The
    default here still models the template shape for backward-compat pins;
    pass source='error' for the honest outage shape (AUD-029).
    """
    return LLMResult(
        ok=not fallback and source != "error",
        text=text,
        source=source if source is not None else ("template_library" if fallback else "ollama"),
        model_used=None,
        tokens_in=0,
        tokens_out=0,
        latency_ms=0,
        fallback_used=fallback,
        warning="Ollama not responding — using local analysis rules" if fallback else None,
        error=error,
    )


class _LogRecorder:
    """House pattern (see test_api_main): structlog writes via
    PrintLoggerFactory — caplog can't see it; capture via the module
    logger seam."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def info(self, event: str, **kw) -> None:
        self.events.append((event, kw))

    def warning(self, event: str, **kw) -> None:
        self.events.append((event, kw))

    def error(self, event: str, **kw) -> None:
        self.events.append((event, kw))


class TestBuildPrompt:
    """Test build_prompt for Ollama."""

    def test_prompt_contains_rule_name(self):
        """Prompt should include the rule name."""
        prompt = build_prompt(
            rule_name="SSH Brute Force",
            severity="high",
            host_name="server01",
            evidence={"source_ip": "10.0.0.5"},
        )
        assert "SSH Brute Force" in prompt

    def test_prompt_contains_severity(self):
        """Prompt should include severity."""
        prompt = build_prompt(
            rule_name="Test Rule",
            severity="critical",
            host_name="host1",
            evidence={},
        )
        assert "critical" in prompt

    def test_prompt_contains_host(self):
        """Prompt should include the hostname."""
        prompt = build_prompt(
            rule_name="Test",
            severity="low",
            host_name="web-prod-01",
            evidence={},
        )
        assert "web-prod-01" in prompt

    def test_prompt_contains_evidence(self):
        """Prompt should include evidence JSON."""
        evidence = {"source_ip": "1.2.3.4", "process": "bash"}
        prompt = build_prompt(
            rule_name="Test",
            severity="medium",
            host_name="host",
            evidence=evidence,
        )
        assert "1.2.3.4" in prompt
        assert "bash" in prompt

    def test_prompt_requests_json_format(self):
        """Prompt should request JSON response format."""
        prompt = build_prompt("R", "h", "H", {})
        assert "JSON" in prompt or "json" in prompt

    def test_prompt_truncates_large_evidence(self):
        """Large evidence should be truncated to avoid token overflow."""
        large_evidence = {"data": "x" * 3000}
        prompt = build_prompt("R", "h", "H", large_evidence)
        # Evidence string should be truncated to ~2000 chars
        assert len(prompt) < 5000

    def test_prompt_contains_risk_score_spec(self):
        """Prompt should specify risk score format."""
        prompt = build_prompt("R", "h", "H", {})
        assert "risk_score" in prompt

    def test_prompt_contains_verdict_spec(self):
        """Prompt should specify verdict format."""
        prompt = build_prompt("R", "h", "H", {})
        assert "verdict" in prompt


class TestParseJsonResponse:
    """Test JSON parsing helper."""

    def test_parses_plain_json(self):
        result = _parse_json_response('{"summary": "test", "risk_score": 50}')
        assert result == {"summary": "test", "risk_score": 50}

    def test_parses_markdown_wrapped_json(self):
        result = _parse_json_response('```json\n{"summary": "test"}\n```')
        assert result == {"summary": "test"}

    def test_parses_markdown_no_lang_json(self):
        result = _parse_json_response('```\n{"summary": "test"}\n```')
        assert result == {"summary": "test"}

    def test_returns_none_on_invalid(self):
        result = _parse_json_response("not json at all {{{")
        assert result is None

    def test_returns_none_on_empty(self):
        result = _parse_json_response("")
        assert result is None


class TestAnalyzeAlert:
    """Test analyze_alert with mocked query_llm."""

    @pytest.mark.asyncio
    async def test_successful_analysis(self):
        """Should parse valid query_llm response."""
        analysis_json = json.dumps(
            {
                "summary": "SSH brute force detected",
                "risk_score": 75,
                "verdict": "threat",
                "response": ["Block IP", "Notify admin"],
                "reasoning": "Multiple failed logins from same IP",
            }
        )

        with patch("src.detection.ai_analyzer.query_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = _llm_result(analysis_json)

            result = await analyze_alert(
                alert_id=1,
                rule_name="SSH Brute Force",
                severity="high",
                host_name="server01",
                evidence={"source_ip": "10.0.0.5"},
            )

        assert result is not None
        assert result["verdict"] == "threat"
        assert result["risk_score"] == 75

    @pytest.mark.asyncio
    async def test_ollama_fallback_returned(self):
        """Should return None when query_llm returns a template fallback
        (source != 'ollama' — the honest-source branch, AUD-029)."""
        with patch("src.detection.ai_analyzer.query_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = _llm_result(FALLBACK_MESSAGE, fallback=True)

            result = await analyze_alert(
                alert_id=2,
                rule_name="Test",
                severity="low",
                host_name="host",
                evidence={},
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_ollama_outage_error_source_attributed_honestly(self):
        """AUD-029: analyze_alert passes no fallback_text, so an outage
        arrives as source='error' with text='' — the failure must be
        attributed to the LLM being down (ai_analyzer_ollama_unavailable),
        NEVER misattributed as ai_parse_failed."""
        recorder = _LogRecorder()
        with (
            patch("src.detection.ai_analyzer.query_llm", new_callable=AsyncMock) as mock_llm,
            patch("src.detection.ai_analyzer.log", recorder),
        ):
            mock_llm.return_value = _llm_result(
                "", source="error", error="connect error: connection refused"
            )
            result = await analyze_alert(
                alert_id=2,
                rule_name="Test",
                severity="low",
                host_name="host",
                evidence={},
            )

        assert result is None
        events = [e for e, _ in recorder.events]
        assert "ai_analyzer_ollama_unavailable" in events
        assert "ai_parse_failed" not in events

    @pytest.mark.asyncio
    async def test_parse_failure_only_attributed_to_parsing_for_real_llm_output(self):
        """With source='ollama' and unparseable text, ai_parse_failed fires
        — and only then (the misattribution channel is closed by the
        source branch above)."""
        recorder = _LogRecorder()
        with (
            patch("src.detection.ai_analyzer.query_llm", new_callable=AsyncMock) as mock_llm,
            patch("src.detection.ai_analyzer.log", recorder),
        ):
            mock_llm.return_value = _llm_result("not valid json at all {{{")
            result = await analyze_alert(
                alert_id=2,
                rule_name="Test",
                severity="low",
                host_name="host",
                evidence={},
            )

        assert result is None
        events = [e for e, _ in recorder.events]
        assert "ai_parse_failed" in events
        assert "ai_analyzer_ollama_unavailable" not in events

    @pytest.mark.asyncio
    async def test_json_in_markdown_code_block(self):
        """Should parse JSON wrapped in markdown code blocks."""
        analysis = {
            "summary": "Suspicious activity",
            "risk_score": 50,
            "verdict": "suspicious",
            "response": ["Investigate"],
            "reasoning": "Unusual pattern",
        }
        raw = f"```json\n{json.dumps(analysis)}\n```"

        with patch("src.detection.ai_analyzer.query_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = _llm_result(raw)

            result = await analyze_alert(4, "R", "h", "H", {})

        assert result is not None
        assert result["verdict"] == "suspicious"

    @pytest.mark.asyncio
    async def test_markdown_no_lang_json_response(self):
        """Should parse JSON wrapped in generic markdown code block."""
        analysis = {
            "summary": "test",
            "risk_score": 30,
            "verdict": "benign",
            "response": [],
            "reasoning": "ok",
        }
        raw = f"```\n{json.dumps(analysis)}\n```"

        with patch("src.detection.ai_analyzer.query_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = _llm_result(raw)

            result = await analyze_alert(5, "R", "h", "H", {})

        assert result is not None
        assert result["verdict"] == "benign"

    @pytest.mark.asyncio
    async def test_invalid_json_response(self):
        """Should return None on invalid JSON."""
        with patch("src.detection.ai_analyzer.query_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = _llm_result("not valid json at all {{{")

            result = await analyze_alert(5, "R", "h", "H", {})

        assert result is None


class TestEnrichAlert:
    """Test enrich_alert with mocked DB."""

    @pytest.mark.asyncio
    async def test_enrich_writes_to_db(self):
        """Should write AI analysis to the alert in DB."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        analysis = {
            "summary": "Brute force detected",
            "risk_score": 80,
            "verdict": "threat",
            "reasoning": "Multiple failed logins",
            "response": ["Block IP", "Notify admin"],
        }

        with patch("src.detection.ai_analyzer.get_pool", return_value=mock_pool):
            await enrich_alert(alert_id=42, analysis=analysis)

        mock_conn.execute.assert_called_once()
        call_args = mock_conn.execute.call_args
        assert "UPDATE alerts" in call_args[0][0]
        assert call_args[0][1] == analysis.get("summary", "")

    @pytest.mark.asyncio
    async def test_enrich_none_analysis_skips(self):
        """Should not update DB if analysis is None."""
        mock_pool = AsyncMock()

        with patch("src.detection.ai_analyzer.get_pool", return_value=mock_pool):
            await enrich_alert(alert_id=42, analysis=None)

        # No DB calls should have been made
        mock_pool.acquire.assert_not_called()

    @pytest.mark.asyncio
    async def test_enrich_writes_risk_score(self):
        """Should write the risk_score from analysis."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        analysis = {"summary": "test", "risk_score": 85}

        with patch("src.detection.ai_analyzer.get_pool", return_value=mock_pool):
            await enrich_alert(alert_id=1, analysis=analysis)

        call_args = mock_conn.execute.call_args[0]
        # Second param after SQL should be summary, third should be risk_score
        assert call_args[2] == 85

    @pytest.mark.asyncio
    async def test_enrich_persists_verdict_reasoning_response(self):
        """AUD-030: verdict / reasoning / response steps must be persisted,
        not discarded (the LLM was paid for them; the alert detail API
        reads alerts with SELECT *, so these ride along)."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        analysis = {
            "summary": "C2 beaconing",
            "risk_score": 90,
            "verdict": "threat",
            "reasoning": "regular interval egress to one IP",
            "response": ["Block the C2 IP", "Isolate the host"],
        }

        with patch("src.detection.ai_analyzer.get_pool", return_value=mock_pool):
            await enrich_alert(alert_id=7, analysis=analysis)

        call_args = mock_conn.execute.call_args[0]
        sql = call_args[0]
        assert "ai_verdict" in sql and "ai_reasoning" in sql and "ai_response" in sql
        assert call_args[3] == "threat"
        assert call_args[4] == "regular interval egress to one IP"
        assert json.loads(call_args[5]) == ["Block the C2 IP", "Isolate the host"]
        assert call_args[6] == 7  # alert id is the LAST param

    @pytest.mark.asyncio
    async def test_enrich_partial_analysis_binds_nulls(self):
        """An analysis without verdict/reasoning/response binds NULLs —
        the columns are additive, never fabricated."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.ai_analyzer.get_pool", return_value=mock_pool):
            await enrich_alert(alert_id=8, analysis={"summary": "s", "risk_score": 40})

        call_args = mock_conn.execute.call_args[0]
        assert call_args[3] is None
        assert call_args[4] is None
        assert call_args[5] is None
