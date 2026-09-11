"""Tests for the AI-usage detection domain (V0.4/5 item 3): the closed kind
mapping, the event shape, producer wiring, and the Sigma rule quality for
the ai/ rules.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from src.ingestion.ai_usage import (
    AI_USAGE_CATEGORY,
    AI_USAGE_SOURCE,
    build_ai_usage_event,
)
from src.ingestion.schemas import NormalizedEvent

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# The closed mapping
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestKindMapping:
    def test_unknown_kind_rejected(self):
        with pytest.raises(ValueError, match="closed table"):
            build_ai_usage_event("delete_everything")

    def test_agent_run_lifecycle_tokens(self):
        start = build_ai_usage_event("agent_run_start", actor="analyst1")
        assert start.event_action == "ai_agent_run"
        assert start.event_type == "start"
        end = build_ai_usage_event("agent_run_end", actor="analyst1")
        assert end.event_action == "ai_agent_run"
        assert end.event_type == "end"

    def test_mcp_tokens_and_tool_mapping(self):
        call = build_ai_usage_event("mcp_tool_call", actor="mcp:s1", tool="hunt")
        assert call.event_action == "mcp_tool_call"
        assert call.event_type == "info"
        assert call.process_name == "hunt"  # the documented tool slot
        assert call.user_name == "mcp:s1"

        denied = build_ai_usage_event("mcp_tool_denied", actor="mcp:s1", tool="x")
        assert denied.event_action == "mcp_tool_denied"

    def test_injection_token(self):
        event = build_ai_usage_event("prompt_injection_detected", actor="analyst1")
        assert event.event_action == "ai_prompt_injection"
        assert event.event_category == "ai"

    def test_source_and_category_contract(self):
        event = build_ai_usage_event("agent_run_start", host_name="h1")
        assert event.source == AI_USAGE_SOURCE == "ai_usage"
        assert event.event_category == AI_USAGE_CATEGORY == "ai"

    def test_vocabulary_tokens_exist_in_schemas(self):
        """Drift-guard: the AI tokens must be part of the closed ingest
        vocabulary in src.ingestion.schemas (single source of truth)."""
        from src.ingestion import schemas as vocabulary

        assert vocabulary.EVENT_ACTION_AI_AGENT_RUN == "ai_agent_run"
        assert vocabulary.EVENT_ACTION_MCP_TOOL_CALL == "mcp_tool_call"
        assert vocabulary.EVENT_ACTION_MCP_TOOL_DENIED == "mcp_tool_denied"
        assert vocabulary.EVENT_ACTION_AI_PROMPT_INJECTION == "ai_prompt_injection"

    def test_shipper_line_shape_round_trip(self):
        from src.ingestion.ai_usage import event_to_shipper_line
        from src.ingestion.schemas import parse_normalized_line

        event = build_ai_usage_event("mcp_tool_denied", actor="mcp:s", tool="hunt")
        line = event_to_shipper_line(event)
        parsed = parse_normalized_line(line)
        assert parsed is not None
        assert parsed.event_action == "mcp_tool_denied"
        assert parsed.event_category == "ai"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Producers wire into the real pipes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAgentPathEmission:
    @pytest.mark.asyncio
    async def test_api_emits_agent_run_end_event(self):
        from src.agents.investigator import AgentRunResult
        from src.api.agents import _emit_ai_usage

        result = AgentRunResult(
            run_id=9,
            objective="o",
            status="completed",
            actor="ai:m",
            requested_by="analyst1",
            alert_id=None,
            plan={},
            steps=[],
            verdict_draft={"verdict": "needs_review"},
            hitl_state="required",
            error=None,
        )
        written: list[NormalizedEvent] = []

        class _FakeWriter:
            async def write(self, event):
                written.append(event)

        with patch("src.services.writer.writer", _FakeWriter()):
            await _emit_ai_usage(result)

        assert len(written) == 1
        assert written[0].event_action == "ai_agent_run"
        assert written[0].event_type == "end"
        assert written[0].user_name == "analyst1"
        assert written[0].raw_data["detail"]["run_id"] == 9

    @pytest.mark.asyncio
    async def test_emission_failure_never_raises(self):
        from src.agents.investigator import AgentRunResult
        from src.api.agents import _emit_ai_usage

        result = AgentRunResult(
            run_id=1,
            objective="o",
            status="failed",
            actor="ai:m",
            requested_by="u",
            alert_id=None,
            plan={},
            steps=[],
            verdict_draft=None,
            hitl_state="not_applicable",
            error=None,
        )

        class _BrokenWriter:
            async def write(self, event):
                raise RuntimeError("db down")

        with patch("src.services.writer.writer", _BrokenWriter()):
            await _emit_ai_usage(result)  # must not raise


class TestMcpEmission:
    @pytest.mark.asyncio
    async def test_mcp_tool_call_emitted_through_ingest(self):
        from src.mcp_server import app as app_module

        posted: list[list[dict]] = []

        fake_client = MagicMock()
        fake_response = MagicMock()
        fake_response.raise_for_status = MagicMock()

        async def _post(url, json=None, headers=None):
            posted.append(json)
            return fake_response

        fake_client.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client.__aexit__ = AsyncMock(return_value=False)
        fake_client.post = _post

        fake_settings = MagicMock()
        fake_settings.ai_usage_ingest_url = "http://api:8000/api/v1/ingest"
        fake_settings.ingest_bearer_token = SecretStr("ingest-tok")
        fake_settings.api_bearer_token = SecretStr("api-tok")

        with (
            patch("src.ingestion.ai_usage.httpx.AsyncClient", MagicMock(return_value=fake_client)),
            patch("src.ingestion.ai_usage.settings", fake_settings),
        ):
            await app_module._emit_tool_event(
                kind="mcp_tool_call",
                actor="mcp:sess-1",
                tool="hunt",
                session="sess-1",
                detail={"latency_ms": 5},
            )

        assert len(posted) == 1
        event = posted[0][0]
        assert event["event_action"] == "mcp_tool_call"
        assert event["event_category"] == "ai"
        assert event["source"] == "ai_usage"
        assert event["user_name"] == "mcp:sess-1"
        assert event["process_name"] == "hunt"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# The rules exist and target the right vocabulary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAiSigmaRules:
    def test_four_ai_rules_load_through_the_engine(self):
        from pathlib import Path

        from src.detection.sigma import load_rules_from_directory

        rules_dir = Path("rules/sigma")
        rules = load_rules_from_directory(rules_dir)
        ai_rules = [r for r in rules if (r.logsource_category or "") == "ai"]
        assert len(ai_rules) >= 4
        names = {r.title for r in ai_rules}
        assert "AI Prompt Injection Attempt" in names
        assert "MCP Tool Denial Burst" in names
        assert "MCP Tool Call High Volume" in names
        assert "AI Agent Run Burst" in names

    def test_ai_category_counts_as_ingested(self):
        from src.detection.coverage import INGESTED_CATEGORIES

        assert "ai" in INGESTED_CATEGORIES

    def test_denial_burst_compiles_to_count_by_actor(self):
        """The burst rule must compile to an aggregation over the flat actor
        column -- a rule that compiled to something else would be a
        decoration (the exact class the rule-quality gate exists to kill)."""
        from src.detection.sigma import sigma_to_sql

        yaml_text = Path("rules/sigma/ai/mcp_tool_denial_burst.yml").read_text()
        sql, _params = sigma_to_sql(yaml_text)
        assert "COUNT" in sql.upper()
        assert "user_name" in sql
        assert "event_action" in sql


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# The generator's pairs match the rule thresholds
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestMatrixPairs:
    def test_true_pairs_exceed_rule_thresholds(self):
        from scripts.generate_ai_usage_events import _events

        scenarios = dict(_events())
        assert len(scenarios["mcp_tool_denied_burst"]) >= 15  # > 10
        assert len(scenarios["mcp_tool_call_volume"]) >= 60  # > 50
        assert len(scenarios["agent_run_burst"]) >= 25  # > 20
        assert len(scenarios["ai_prompt_injection"]) >= 1
        # Quiet pairs below thresholds
        assert len(scenarios["mcp_tool_denied_quiet"]) <= 10
        assert len(scenarios["mcp_tool_call_quiet"]) <= 50

    def test_every_matrix_event_maps_into_the_closed_vocabulary(self):
        from scripts.generate_ai_usage_events import _events

        for _name, events in _events():
            for event in events:
                assert event.event_action in {
                    "ai_agent_run",
                    "mcp_tool_call",
                    "mcp_tool_denied",
                    "ai_prompt_injection",
                }
                assert event.source == "ai_usage"
