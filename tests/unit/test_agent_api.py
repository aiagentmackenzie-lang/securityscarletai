"""Tests for the agentic SOC API (V0.4/5 item 1): the investigate endpoint,
the operator kill switch, the HITL gate transitions, run reads, and the
agent_investigation decision-record type.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from tests.unit._test_request import make_test_request

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _user(role: str = "analyst", username: str = "analyst1") -> dict:
    return {"sub": username, "role": role}


def _pool_and_conn():
    pool = AsyncMock()
    conn = AsyncMock()
    acq = AsyncMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq)
    return pool, conn


def _run_row(hitl_state: str = "required", **overrides):
    row = {
        "id": 7,
        "objective": "investigate failed logins",
        "alert_id": None,
        "status": "completed",
        "actor": "ai:test-model",
        "requested_by": "analyst1",
        "plan": {"hypotheses": ["h"], "queries": ["q"]},
        "steps": [{"index": 0, "kind": "plan"}],
        "verdict_draft": {"verdict": "true_positive", "requires_hitl": True},
        "hitl_state": hitl_state,
        "hitl_actor": None,
        "hitl_note": None,
        "error": None,
        "created_at": datetime(2026, 9, 11, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 9, 11, tzinfo=timezone.utc),
    }
    row.update(overrides)
    return row


def _agent_result(status="completed"):
    from src.agents.investigator import AgentRunResult

    return AgentRunResult(
        run_id=7,
        objective="objective",
        status=status,
        actor="ai:test-model",
        requested_by="analyst1",
        alert_id=None,
        plan={"queries": ["q1"]},
        steps=[{"index": 0, "kind": "plan"}],
        verdict_draft=(
            {"verdict": "true_positive", "confidence": 0.8, "requires_hitl": True}
            if status == "completed"
            else None
        ),
        hitl_state="required" if status == "completed" else "not_applicable",
        error=None,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POST /agent/investigate
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestInvestigateEndpoint:
    @pytest.mark.asyncio
    async def test_runs_and_returns_draft_with_hitl_note(self):
        from src.api.agents import InvestigateRequest, investigate

        body = InvestigateRequest(objective="investigate failed logins", alert_id=None)
        user = _user()
        request = make_test_request(path="/api/v1/agent/investigate")

        async def _fake_run(objective, **kwargs):
            assert kwargs["requested_by"] == "analyst1"
            from src.agents.investigator import AgentRunResult

            return AgentRunResult(
                run_id=7,
                objective=objective,
                status="completed",
                actor="ai:m",
                requested_by="analyst1",
                alert_id=None,
                plan={},
                steps=[],
                verdict_draft={"verdict": "false_positive", "requires_hitl": True},
                hitl_state="required",
                error=None,
            )

        with patch("src.api.agents.run_investigation", _fake_run):
            result = await investigate(request, MagicMock(), body, user)

        assert result["id"] == 7
        assert result["verdict_draft"]["requires_hitl"] is True
        assert "DRAFT" in result["hitl"]
        assert "human-only" in result["hitl"]

    @pytest.mark.asyncio
    async def test_kill_switch_returns_423(self):
        from src.api.agents import InvestigateRequest, investigate

        body = InvestigateRequest(objective="objective")
        request = make_test_request(path="/api/v1/agent/investigate")

        with patch("src.api.agents.settings") as mock_settings:
            mock_settings.agent_enabled = False
            with pytest.raises(HTTPException) as exc_info:
                await investigate(request, MagicMock(), body, _user())

        assert exc_info.value.status_code == 423

    @pytest.mark.asyncio
    async def test_empty_after_sanitization_returns_400(self):
        from src.api.agents import InvestigateRequest, investigate

        body = InvestigateRequest(objective="   ")
        request = make_test_request(path="/api/v1/agent/investigate")

        async def _raise(*args, **kwargs):
            raise ValueError("objective is empty after sanitization")

        with patch("src.api.agents.run_investigation", _raise):
            with pytest.raises(HTTPException) as exc_info:
                await investigate(request, MagicMock(), body, _user())

        assert exc_info.value.status_code == 400


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GET /agent/runs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRunReads:
    @pytest.mark.asyncio
    async def test_unknown_status_refused(self):
        from src.api.agents import list_runs

        with pytest.raises(HTTPException) as exc_info:
            await list_runs(run_status="exploded", _user=_user())

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_lists_runs(self):
        from src.api.agents import list_runs

        pool, conn = _pool_and_conn()
        conn.fetch.return_value = [_run_row()]
        conn.fetchval.return_value = 1

        with patch("src.api.agents.get_pool", AsyncMock(return_value=pool)):
            result = await list_runs(_user=_user())

        assert result["total"] == 1
        assert result["runs"][0]["id"] == 7

    @pytest.mark.asyncio
    async def test_unknown_run_404(self):
        from src.api.agents import get_run

        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = None

        with patch("src.api.agents.get_pool", AsyncMock(return_value=pool)):
            with pytest.raises(HTTPException) as exc_info:
                await get_run(999, _user=_user())

        assert exc_info.value.status_code == 404


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POST /agent/runs/{id}/hitl -- the HITL gate
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestHitlGate:
    @pytest.mark.asyncio
    async def test_records_human_decision(self):
        from src.api.agents import HitlDecisionRequest, hitl_decision

        body = HitlDecisionRequest(decision="confirmed", note="evidence checked by me")
        pool, conn = _pool_and_conn()
        conn.fetchrow.side_effect = [
            _run_row(),  # the state check
            {"id": 7, "hitl_state": "confirmed", "hitl_actor": "analyst1"},
        ]

        with (
            patch("src.api.agents.get_pool", AsyncMock(return_value=pool)),
            patch("src.agents.investigator.get_pool", AsyncMock(return_value=pool)),
        ):
            result = await hitl_decision(7, body, _user())

        assert result["hitl_state"] == "confirmed"
        assert "human verdict to a case" in result["note"]

    @pytest.mark.asyncio
    async def test_already_decided_draft_cannot_be_re_decided(self):
        from src.api.agents import HitlDecisionRequest, hitl_decision

        body = HitlDecisionRequest(decision="rejected", note="changing my mind again")
        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = _run_row(hitl_state="confirmed")

        with patch("src.api.agents.get_pool", AsyncMock(return_value=pool)):
            with pytest.raises(HTTPException) as exc_info:
                await hitl_decision(7, body, _user())

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_failed_run_without_draft_cannot_be_decided(self):
        from src.api.agents import HitlDecisionRequest, hitl_decision

        body = HitlDecisionRequest(decision="confirmed", note="no draft ever existed")
        pool, conn = _pool_and_conn()
        conn.fetchrow.return_value = _run_row(hitl_state="not_applicable")

        with patch("src.api.agents.get_pool", AsyncMock(return_value=pool)):
            with pytest.raises(HTTPException) as exc_info:
                await hitl_decision(7, body, _user())

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_unknown_decision_token_rejected_by_schema(self):
        from pydantic import ValidationError

        from src.api.agents import HitlDecisionRequest

        with pytest.raises(ValidationError):
            HitlDecisionRequest(decision="auto_execute", note="trying to bypass the gate")

    @pytest.mark.asyncio
    async def test_short_note_rejected_by_schema(self):
        from pydantic import ValidationError

        from src.api.agents import HitlDecisionRequest

        with pytest.raises(ValidationError):
            HitlDecisionRequest(decision="confirmed", note="ok")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Decision records: the agent's drafts surface as governed decisions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDecisionRecords:
    @pytest.mark.asyncio
    async def test_agent_investigation_in_closed_type_set(self):
        from src.api.decisions import DECISION_TYPES

        assert "agent_investigation" in DECISION_TYPES

    @pytest.mark.asyncio
    async def test_agent_drafts_surface_with_actor_kind_ai(self):
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        ts = datetime.now(tz=timezone.utc)

        def _fetch(sql, *args, **kwargs):
            if "agent_investigations" in sql:
                return [
                    {
                        "id": 7,
                        "created_at": ts,
                        "updated_at": ts,
                        "objective": "investigate failed logins",
                        "alert_id": 3,
                        "status": "completed",
                        "actor": "ai:test-model",
                        "requested_by": "analyst1",
                        "verdict_draft": {
                            "verdict": "true_positive",
                            "confidence": 0.82,
                            "rationale": "sustained failures then success",
                        },
                        "hitl_state": "required",
                    }
                ]
            return []

        conn.fetch.side_effect = _fetch

        with patch("src.api.decisions.get_pool", AsyncMock(return_value=pool)):
            with patch("src.api.decisions.settings") as s:
                s.ollama_model = "test-model"
                result = await list_decisions(decision_type="agent_investigation", user=_user())

        assert result["total_returned"] >= 1
        rec = result["decisions"][0]
        assert rec["actor_kind"] == "ai"
        assert rec["decision_type"] == "agent_investigation"
        assert "true_positive" in rec["summary"]
        assert rec["evidence"]["hitl_state"] == "required"
