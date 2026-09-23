"""
Tests for the governed decision-records view (V0.4): assembly of AI triage
decisions, correlation matches, verdicts, response actions, and policy
refusals into one read-only governed surface.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _pool_and_conn():
    pool = AsyncMock()
    conn = AsyncMock()
    acq = AsyncMock()
    acq.__aenter__ = AsyncMock(return_value=conn)
    acq.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq)
    return pool, conn


def _user(role: str = "analyst", username: str = "testuser") -> dict:
    return {"sub": username, "role": role}


class TestListDecisions:
    @pytest.mark.asyncio
    async def test_assembles_all_five_decision_types(self):
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        ts = datetime.now(tz=timezone.utc)

        def _fetch(sql, *args, **kwargs):
            if "ai_summary IS NOT NULL" in sql:
                return [
                    {
                        "id": 1,
                        "created_at": ts,
                        "updated_at": ts,
                        "host_name": "h1",
                        "rule_name": "Sigma rule",
                        "severity": "high",
                        "ai_summary": "Suspicious process chain",
                        "risk_score": 87.0,
                    }
                ]
            if "correlation_matches" in sql:
                return [
                    {
                        "id": 2,
                        "created_at": ts,
                        "correlation_rule": "brute_force",
                        "severity": "high",
                        "match_data": {"events": 5},
                    }
                ]
            if "event_type = 'verdict'" in sql:
                return [
                    {
                        "id": 3,
                        "created_at": ts,
                        "actor": "analyst1",
                        "payload": {"verdict": "true_positive", "rationale": "confirmed"},
                        "case_id": 7,
                        "alert_id": 1,
                    }
                ]
            if "response_actions" in sql:
                return [
                    {
                        "id": 3,
                        "case_id": 7,
                        "action_type": "quarantine_host",
                        "policy_effect": "approval_required",
                        "status": "verified",
                        "requested_by": "analyst1",
                        "approved_by": "admin1",
                        "justification": "host compromised",
                        "executed_at": ts,
                        "verified_at": ts,
                        "evidence": {"verification": {"verified": True}},
                        "created_at": ts,
                    }
                ]
            if "response.refused" in sql:
                return [
                    {
                        "id": 4,
                        "created_at": ts,
                        "actor": "analyst2",
                        "target_type": "response_action",
                        "target_id": None,
                        "new_values": {"action_type": "pf_block_ip", "reason": "no case"},
                    }
                ]
            return []

        conn.fetch.side_effect = _fetch

        with (
            patch("src.api.decisions.get_pool", return_value=pool),
            patch("src.api.decisions.settings") as settings_mock,
        ):
            settings_mock.ollama_model = "mistral:7b"
            result = await list_decisions(user=_user())

        types = {d["decision_type"] for d in result["decisions"]}
        assert types == {
            "ai_triage",
            "correlation",
            "verdict",
            "response_action",
            "policy_refusal",
        }
        # Newest-first chronological ordering across all sources
        ts_list = [d["ts"] for d in result["decisions"]]
        assert ts_list == sorted(ts_list, key=lambda t: t, reverse=True)
        # Actor kinds are tagged for the governed view
        kinds = {d["actor_kind"] for d in result["decisions"]}
        assert kinds == {"ai", "rule", "human", "system"}

    @pytest.mark.asyncio
    async def test_filter_by_decision_type(self):
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        conn.fetch.side_effect = None
        conn.fetch.return_value = [
            {
                "id": 2,
                "created_at": datetime.now(tz=timezone.utc),
                "correlation_rule": "brute_force",
                "severity": "high",
                "match_data": {"events": 5},
            }
        ]

        with (
            patch("src.api.decisions.get_pool", return_value=pool),
            patch("src.api.decisions.settings") as settings_mock,
        ):
            settings_mock.ollama_model = "mistral:7b"
            result = await list_decisions(decision_type="correlation", user=_user())

        assert all(d["decision_type"] == "correlation" for d in result["decisions"])
        # Only the correlation query ran
        assert conn.fetch.await_count == 1

    @pytest.mark.asyncio
    async def test_unknown_decision_type_rejected(self):
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        with patch("src.api.decisions.get_pool", return_value=pool):
            with pytest.raises(Exception) as exc_info:
                await list_decisions(decision_type="vibes", user=_user())
        assert "unknown decision_type" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_actor_filter_applies_after_merge(self):
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        ts = datetime.now(tz=timezone.utc)

        def _fetch(sql, *a, **kw):
            if "event_type = 'verdict'" in sql:
                return [
                    {
                        "id": 1,
                        "created_at": ts,
                        "actor": "analyst1",
                        "payload": {"verdict": "benign", "rationale": "operator artifact"},
                        "case_id": 1,
                        "alert_id": None,
                    },
                    {
                        "id": 2,
                        "created_at": ts,
                        "actor": "analyst2",
                        "payload": {"verdict": "true_positive", "rationale": "confirmed"},
                        "case_id": 8,
                        "alert_id": None,
                    },
                ]
            return []

        conn.fetch.side_effect = _fetch

        with (
            patch("src.api.decisions.get_pool", return_value=pool),
            patch("src.api.decisions.settings") as settings_mock,
        ):
            settings_mock.ollama_model = "mistral:7b"
            result = await list_decisions(decision_type="verdict", actor="analyst1", user=_user())

        assert len(result["decisions"]) == 1
        assert result["decisions"][0]["actor"] == "analyst1"

    @pytest.mark.asyncio
    async def test_no_mutation_endpoints_exist(self):
        """The governed decision view is read-only: no POST/PATCH/DELETE
        routes may exist on the decisions router."""
        from src.api.decisions import router

        for route in router.routes:
            methods = {m for m in route.methods if m not in ("HEAD", "OPTIONS")}
            assert methods == {"GET"}, f"{route.path} must be read-only"


_SINCE = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_UNTIL = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)

# (decision_type, the time column that type's records actually sort on)
_WINDOW_CASES = [
    ("ai_triage", "updated_at"),
    ("correlation", "created_at"),
    ("verdict", "created_at"),
    ("response_action", "created_at"),
    ("policy_refusal", "created_at"),
    ("agent_investigation", "updated_at"),
]


def _capture_fetch(conn, calls):
    def _capture(sql, *args, **kw):
        calls.append((" ".join(sql.split()), tuple(args)))
        return []

    conn.fetch.side_effect = _capture


class TestDecisionWindowFiltering:
    """W4-D: the since/until window must reach EVERY decision-type query,
    on the column each type sorts on -- not just policy_refusal."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("decision_type,column", _WINDOW_CASES)
    async def test_window_reaches_every_type(self, decision_type, column):
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        calls: list[tuple[str, tuple]] = []
        _capture_fetch(conn, calls)

        with patch("src.api.decisions.get_pool", return_value=pool):
            await list_decisions(
                decision_type=decision_type, since=_SINCE, until=_UNTIL, user=_user()
            )

        assert len(calls) == 1
        sql, params = calls[0]
        # The window conditions ride the SQL with the timestamptz cast
        assert f"{column} >= $1::timestamptz" in sql
        assert f"{column} < $2::timestamptz" in sql
        # The params carry since/until first, LIMIT last (index shifts)
        assert params[0] == _SINCE
        assert params[1] == _UNTIL
        assert f"LIMIT ${len(params)}" in sql
        assert params[-1] == 100  # default limit + offset

    @pytest.mark.asyncio
    async def test_since_only_orders_before_limit(self):
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        calls: list[tuple[str, tuple]] = []
        _capture_fetch(conn, calls)

        with patch("src.api.decisions.get_pool", return_value=pool):
            await list_decisions(decision_type="correlation", since=_SINCE, user=_user())

        sql, params = calls[0]
        assert "created_at >= $1::timestamptz" in sql
        assert "created_at <" not in sql
        assert params == (_SINCE, 100)
        assert "LIMIT $2" in sql

    @pytest.mark.asyncio
    @pytest.mark.parametrize("decision_type", [c[0] for c in _WINDOW_CASES])
    async def test_no_window_keeps_unfiltered_shape(self, decision_type):
        """Regression guard: without since/until every query keeps the
        unfiltered LIMIT-$1 shape (params carry only the limit)."""
        from src.api.decisions import list_decisions

        pool, conn = _pool_and_conn()
        calls: list[tuple[str, tuple]] = []
        _capture_fetch(conn, calls)

        with patch("src.api.decisions.get_pool", return_value=pool):
            await list_decisions(decision_type=decision_type, user=_user())

        assert len(calls) == 1
        sql, params = calls[0]
        assert "::timestamptz" not in sql
        assert params == (100,)
        assert "LIMIT $1" in sql
