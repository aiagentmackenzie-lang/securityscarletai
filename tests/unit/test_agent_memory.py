"""W1.6 agentic memory -- unit gates.

Covers the few-shot exemplar retrieval (same-shape, self-excluded, bounded,
PII-conscious), the exemplar block formatting, the dead-end validation
(verbatim plan membership, closed statuses, caps), the outcome linkage
(draft vs final disposition, unmeasured-when-no-human-verdict honesty),
the aggregate agreement stats, and the outcome endpoint wiring.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.agents.memory import (
    MAX_EXEMPLAR_RATIONALE_CHARS,
    MAX_EXEMPLARS,
    agreement_stats,
    fetch_adjudicated_exemplars,
    format_exemplars_block,
    link_outcome,
    outcome_for_alert,
    validate_hypotheses_assessed,
)


def _pool_mock(conn):
    mock_pool = MagicMock()
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire = MagicMock(return_value=acquirer)
    return mock_pool


def _fetch_conn(rows_by_marker):
    """Conn mock dispatching fetch/fetchrow by a distinctive SQL marker."""
    conn = AsyncMock()

    async def fetch(sql, *params):
        for marker, rows in rows_by_marker.items():
            if marker in sql:
                return rows
        raise AssertionError(f"unexpected query: {sql[:120]}")

    conn.fetch = AsyncMock(side_effect=fetch)
    return conn


AS_OF = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


class TestExemplars:
    @pytest.mark.asyncio
    async def test_fetch_same_rule_shape_excluding_self(self):
        rows = [
            {
                "id": 5,
                "rule_name": "Reverse Shell",
                "severity": "critical",
                "host_name": "host-a",
                "disposition": "true_positive",
                "rationale": "C2 egress observed" + "x" * 500,
            },
            {
                "id": 9,
                "rule_name": "Reverse Shell",
                "severity": "medium",
                "host_name": "host-b",
                "disposition": "false_positive",
                "rationale": None,
            },
        ]
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=rows)
        with patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)):
            exemplars = await fetch_adjudicated_exemplars("Reverse Shell", exclude_alert_id=7, k=2)
        # The rule_name and exclude id were bound as parameters.
        params = conn.fetch.await_args.args
        assert params[1] == "Reverse Shell"
        assert params[2] == 7
        # PII-conscious: rationale is truncated to the bound.
        assert len(exemplars[0]["rationale"]) <= MAX_EXEMPLAR_RATIONALE_CHARS
        assert exemplars[0]["disposition"] == "true_positive"
        assert exemplars[1]["disposition"] == "false_positive"

    @pytest.mark.asyncio
    async def test_k_capped(self):
        rows = [
            {
                "id": i,
                "rule_name": "R",
                "severity": "low",
                "host_name": "h",
                "disposition": "benign",
                "rationale": None,
            }
            for i in range(10)
        ]
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=rows)
        with patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)):
            exemplars = await fetch_adjudicated_exemplars("R", k=10)
        assert len(exemplars) == MAX_EXEMPLARS

    def test_format_exemplars_block_empty_note(self):
        assert format_exemplars_block([]) == "(no past adjudicated alerts of this rule shape)"

    def test_format_exemplars_block_entries(self):
        block = format_exemplars_block(
            [
                {
                    "disposition": "true_positive",
                    "host_name": "h1",
                    "rationale": "reverse shell to 1.2.3.4",
                },
            ]
        )
        assert "true_positive" in block
        assert "h1" in block
        assert "reverse shell" in block.lower()


class TestDeadEndValidation:
    def test_verbatim_membership_enforced(self):
        plan = ["brute force from one source", "persistence via launchd"]
        raw = [
            {
                "hypothesis": "brute force from one source",
                "status": "ruled_out",
                "evidence": "single attempt only",
            },
            {"hypothesis": "INVENTED hypothesis", "status": "supported"},  # dropped
        ]
        assessed = validate_hypotheses_assessed(raw, plan)
        assert len(assessed) == 1
        assert assessed[0]["status"] == "ruled_out"

    def test_closed_status_vocabulary(self):
        raw = [
            {"hypothesis": "h", "status": "supported"},
            {"hypothesis": "h", "status": "RULED_OUT"},  # case-normalized
            {"hypothesis": "h", "status": "UNRESOLVED"},  # AUD-027: accepted, case-normalized
            {"hypothesis": "h", "status": "bogus"},  # dropped
        ]
        assessed = validate_hypotheses_assessed(raw, ["h"])
        assert [a["status"] for a in assessed] == ["supported", "ruled_out", "unresolved"]

    def test_unresolved_dead_end_record_is_kept(self):
        """AUD-027: the verdict prompt documents supported/ruled_out/
        unresolved; 'unresolved' hypotheses (honest dead ends) must be
        kept, not silently dropped."""
        raw = [
            {
                "hypothesis": "data staged in /tmp",
                "status": "unresolved",
                "evidence": "insufficient log retention to decide",
            },
        ]
        assessed = validate_hypotheses_assessed(raw, ["data staged in /tmp"])
        assert len(assessed) == 1
        assert assessed[0]["status"] == "unresolved"
        assert assessed[0]["evidence"] == "insufficient log retention to decide"

    def test_cap_and_malformed_entries(self):
        plan = [f"h{i}" for i in range(3)]
        raw = [
            "junk",
            {"h0": None},
            {"hypothesis": "h0", "status": "supported"},
            {"h1": None},
            {"hypothesis": "h1", "status": "supported"},
            5,
            None,
        ]
        assessed = validate_hypotheses_assessed(raw, plan)
        assert len(assessed) == 2
        assert assessed[0]["hypothesis"] == "h0"

    def test_empty_plan_yields_empty(self):
        assert validate_hypotheses_assessed([{"h": "x", "status": "supported"}], []) == []
        assert validate_hypotheses_assessed(None, ["h"]) == []


class TestOutcomeLinkage:
    @pytest.mark.asyncio
    async def test_outcome_for_alert_precedence(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"disposition": "false_positive"})
        with patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)):
            outcome = await outcome_for_alert(3)
        assert outcome == {"alert_id": 3, "disposition": "false_positive"}

        conn.fetchrow = AsyncMock(return_value=None)
        with patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)):
            assert await outcome_for_alert(404) is None

    @pytest.mark.asyncio
    async def test_link_outcome_measured_and_unmeasured(self):
        # Measured: confirmed run, alert disposition exists -> agreement bool.
        run_row = {
            "id": 1,
            "alert_id": 3,
            "verdict_draft": '{"verdict": "true_positive"}',
            "hitl_state": "confirmed",
            "hitl_actor": "analyst",
            "created_at": AS_OF,
        }
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=run_row)
        with (
            patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)),
            patch(
                "src.agents.memory.outcome_for_alert",
                AsyncMock(return_value={"alert_id": 3, "disposition": "true_positive"}),
            ),
        ):
            linkage = await link_outcome(1)
        assert linkage["draft_verdict"] == "true_positive"
        assert linkage["final_disposition"] == "true_positive"
        assert linkage["agreement"] is True

        # Unmeasured: no human disposition yet -> agreement None (honest).
        with (
            patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)),
            patch(
                "src.agents.memory.outcome_for_alert",
                AsyncMock(return_value={"alert_id": 3, "disposition": None}),
            ),
        ):
            linkage = await link_outcome(1)
        assert linkage["agreement"] is None
        assert "unmeasured" not in linkage  # the value IS None, not a note

    @pytest.mark.asyncio
    async def test_link_outcome_missing_run_or_draft(self):
        local_row = {
            "id": 1,
            "alert_id": 3,
            "verdict_draft": None,
            "hitl_state": "confirmed",
            "hitl_actor": "analyst",
            "created_at": AS_OF,
        }
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        with patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)):
            assert await link_outcome(99) is None

        conn.fetchrow = AsyncMock(return_value=local_row)
        with patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)):
            assert await link_outcome(1) is None


class TestAgreementStats:
    @pytest.mark.asyncio
    async def test_unmeasured_when_no_confirmed_runs(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        with patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)):
            stats = await agreement_stats(720)
        assert stats["measured"] == 0
        assert stats["agreement_rate"] is None  # unmeasured, never a fake 0
        assert "unmeasured" in stats["note"]

    @pytest.mark.asyncio
    async def test_measured_rate(self):
        runs = [
            {
                "id": 1,
                "alert_id": 3,
                "verdict_draft": '{"verdict": "true_positive"}',
            },
            {
                "id": 2,
                "alert_id": 4,
                "verdict_draft": '{"verdict": "false_positive"}',
            },
        ]
        outcomes = {
            3: {"alert_id": 3, "disposition": "true_positive"},
            4: {"alert_id": 4, "disposition": "false_positive"},
        }
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=runs)

        async def _outcome(alert_id):
            return outcomes.get(alert_id)

        with (
            patch("src.agents.memory.get_pool", return_value=_pool_mock(conn)),
            patch("src.agents.memory.outcome_for_alert", AsyncMock(side_effect=_outcome)),
        ):
            stats = await agreement_stats(720)
        assert stats["measured"] == 2
        assert stats["agreed"] == 2
        assert stats["agreement_rate"] == 1.0


class TestOutcomeEndpoint:
    @pytest.mark.asyncio
    async def test_endpoint_wiring(self):
        from src.api.agents import get_run_outcome

        linkage = {
            "run_id": 1,
            "draft_verdict": "true_positive",
            "final_disposition": "true_positive",
            "agreement": True,
        }
        with patch("src.agents.memory.link_outcome", AsyncMock(return_value=linkage)):
            from src.api.agents import get_run_outcome

            with patch("src.api.agents._require_agent_enabled"):
                result = await get_run_outcome(1, _user={"sub": "a"})
        assert result == linkage

    @pytest.mark.asyncio
    async def test_endpoint_404_without_linkage(self):
        from src.api.agents import get_run_outcome

        with (
            patch("src.agents.memory.link_outcome", AsyncMock(return_value=None)),
            patch("src.api.agents._require_agent_enabled"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await get_run_outcome(99, _user={"sub": "a"})
        assert exc_info.value.status_code == 404
