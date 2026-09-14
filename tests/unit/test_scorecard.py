"""V0.7b rule lifecycle scorecard -- unit gates.

Covers the read-only detection-engineering loop: metric assembly
(sigma + correlation kinds), disposition precedence (labels > status >
case verdict), FP-ratio math, retirement advice (never_fired / stale /
all_false_positive), ordering stability, and the API contract.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.detection.scorecard import (
    RETIREMENT_MIN_DISPOSITIONS,
    compute_rule_scorecard,
)

AS_OF = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
WINDOW_START = AS_OF - timedelta(hours=720)


def _mock_conn(rules, sigma_metrics, corr_metrics):
    """Conn mock dispatching by query shape: rules registry vs the two
    grouped metric scans (sigma by rule_id, correlation by rule_name)."""
    mock_conn = AsyncMock()

    async def fetch(sql, *params):
        if "FROM rules" in sql:
            return rules
        # The two metric scans bind 3 params: as_of, window_start, verdict tokens.
        assert len(params) == 3, f"metric query binds 3 params, got {len(params)}"
        assert isinstance(params[0], datetime)
        assert isinstance(params[1], datetime)
        assert isinstance(params[2], list)
        if "a.rule_id IS NOT NULL" in sql:
            return sigma_metrics
        if "a.rule_id IS NULL" in sql:
            return corr_metrics
        raise AssertionError(f"unexpected query: {sql[:120]}")

    mock_conn.fetch = AsyncMock(side_effect=fetch)
    return mock_conn


def _pool_mock(conn):
    mock_pool = MagicMock()
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire = MagicMock(return_value=acquirer)
    return mock_pool


def _metric_row(key, lifetime, window, last_fired, disp, tp, fp, benign=0, nr=0):
    return {
        "rule_key": key,
        "lifetime_fires": lifetime,
        "window_fires": window,
        "last_fired": last_fired,
        "dispositions": disp,
        "true_positives": tp,
        "false_positives": fp,
        "benign": benign,
        "needs_review": nr,
    }


class TestScorecardShape:
    @pytest.mark.asyncio
    async def test_empty_everything(self):
        conn = _mock_conn([], [], [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            result = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        assert result["summary"]["total_rules"] == 0
        assert result["rules"] == []
        assert result["retirement_advice"] == []
        assert result["summary"]["sigma_rules"] == 0
        assert result["summary"]["correlation_chains"] == 0

    @pytest.mark.asyncio
    async def test_sigma_and_correlation_kinds_joined(self):
        created = AS_OF - timedelta(days=40)
        rules = [
            {
                "id": 1,
                "name": "Reverse Shell Pattern Detected",
                "severity": "critical",
                "mitre_techniques": ["T1059"],
                "enabled": True,
                "match_count": 12,
                "last_match": WINDOW_START - timedelta(days=1),
                "last_run": AS_OF - timedelta(minutes=5),
                "created_at": created,
            }
        ]
        sigma = [_metric_row(1, 5, 2, AS_OF - timedelta(days=1), 3, 2, 1)]
        corr = [
            _metric_row(
                "brute_force_success",
                8,
                8,
                AS_OF - timedelta(minutes=30),
                4,
                4,
                0,
            )
        ]
        conn = _mock_conn(rules, sigma, corr)
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            result = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)

        assert result["summary"]["total_rules"] == 2
        assert result["summary"]["sigma_rules"] == 1
        assert result["summary"]["correlation_chains"] == 1

        by_name = {r["name"]: r for r in result["rules"]}
        rs = by_name["Reverse Shell Pattern Detected"]
        assert rs["kind"] == "sigma"
        assert rs["window_fires"] == 2
        assert rs["lifetime_fires"] == 5
        assert rs["matcher_hits_lifetime"] == 12  # matcher hits, NOT alerts
        assert rs["age_days"] == 40
        assert rs["dispositions"] == 3
        assert rs["fp_ratio"] == pytest.approx(1 / 3)

        rc = by_name["brute_force_success"]
        assert rc["kind"] == "correlation"
        assert rc["enabled"] is True  # chains are code-defined
        assert rc["fp_ratio"] == 0.0

    @pytest.mark.asyncio
    async def test_ordering_stable_kind_then_fires_desc_then_name(self):
        created = AS_OF - timedelta(days=40)
        rules = [
            {
                "id": i,
                "name": f"Rule {i}",
                "severity": "medium",
                "mitre_techniques": [],
                "enabled": True,
                "match_count": 0,
                "last_match": None,
                "last_run": None,
                "created_at": created,
            }
            for i in range(1, 4)
        ]
        sigma = [
            _metric_row(1, 1, 0, AS_OF - timedelta(days=10), 0, 0, 0),
            _metric_row(2, 1, 5, AS_OF - timedelta(days=1), 0, 0, 0),
            _metric_row(3, 1, 5, AS_OF - timedelta(days=2), 0, 0, 0),
        ]
        conn = _mock_conn(rules, sigma, [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            r1 = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
            r2 = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        order = [r["id"] for r in r1["rules"]]
        assert order == [2, 3, 1]  # fires desc, id/name tiebreak
        assert r1["rules"] == r2["rules"]  # snapshot regression: stable


class TestRetirementAdvice:
    @pytest.mark.asyncio
    async def test_never_fired_rule_flagged(self):
        created = AS_OF - timedelta(days=60)
        rules = [
            {
                "id": 1,
                "name": "Dead Rule",
                "severity": "medium",
                "mitre_techniques": [],
                "enabled": True,
                "match_count": 0,
                "last_match": None,
                "last_run": AS_OF - timedelta(days=1),
                "created_at": created,
            },
            {
                "id": 2,
                "name": "Young Rule",
                "severity": "medium",
                "mitre_techniques": [],
                "enabled": True,
                "match_count": 0,
                "last_match": None,
                "last_run": AS_OF - timedelta(days=1),
                "created_at": AS_OF - timedelta(days=2),  # too young
            },
        ]
        sigma = [_metric_row(1, 0, 0, None, 0, 0, 0)]
        conn = _mock_conn(rules, sigma, [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            result = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        advice_names = [a["name"] for a in result["retirement_advice"]]
        assert advice_names == ["Dead Rule"]
        reasons = advice_names and result["retirement_advice"][0]["reasons"]
        assert any(r["reason"] == "never_fired" for r in reasons)

    @pytest.mark.asyncio
    async def test_all_false_positive_rule_flagged(self):
        created = AS_OF - timedelta(days=40)
        rules = [
            {
                "id": 1,
                "name": "Noisy Rule",
                "severity": "medium",
                "mitre_techniques": [],
                "enabled": True,
                "match_count": 50,
                "last_match": AS_OF - timedelta(days=1),
                "last_run": AS_OF - timedelta(days=1),
                "created_at": created,
            }
        ]
        sigma = [
            _metric_row(
                1,
                RETIREMENT_MIN_DISPOSITIONS,
                2,
                AS_OF - timedelta(days=1),
                RETIREMENT_MIN_DISPOSITIONS,
                0,
                RETIREMENT_MIN_DISPOSITIONS,
            )
        ]
        conn = _mock_conn(rules, sigma, [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            result = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        advice = result["retirement_advice"]
        assert len(advice) == 1
        reasons = {r["reason"] for r in advice[0]["reasons"]}
        assert "all_false_positive" in reasons

    @pytest.mark.asyncio
    async def test_stale_rule_flagged(self):
        created = AS_OF - timedelta(days=40)
        rules = [
            {
                "id": 1,
                "name": "Went Quiet",
                "severity": "medium",
                "mitre_techniques": [],
                "enabled": True,
                "match_count": 3,
                "last_match": AS_OF - timedelta(days=40),
                "last_run": AS_OF - timedelta(days=1),
                "created_at": created,
            }
        ]
        # last fired BEFORE the window start -> stale
        sigma = [_metric_row(1, 3, 0, WINDOW_START - timedelta(days=1), 1, 1, 0)]
        conn = _mock_conn(rules, sigma, [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            result = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        advice = result["retirement_advice"]
        assert len(advice) == 1
        assert any(r["reason"] == "stale" for r in advice[0]["reasons"])

    @pytest.mark.asyncio
    async def test_advice_is_advisory_not_action(self):
        # The summary carries the doctrine: retirement advice never acts.
        conn = _mock_conn([], [], [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            result = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        assert "HITL" in result["summary"]["note"]
        assert "never automatic" in result["summary"]["note"]


class TestDispositionPrecedence:
    @pytest.mark.asyncio
    async def test_verdict_tokens_bound_as_param(self):
        # The lateral case-verdict lookup is bounded to the closed verdict
        # vocabulary (param $3) -- an arbitrary payload value never joins.
        conn = _mock_conn([], [], [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        for c in conn.fetch.call_args_list:
            if len(c.args) >= 4:
                tokens = c.args[3]
                assert set(tokens) == {"true_positive", "false_positive", "benign", "needs_review"}

    @pytest.mark.asyncio
    async def test_summary_counts_aggregate(self):
        created = AS_OF - timedelta(days=40)
        rules = [
            {
                "id": i,
                "name": f"Rule {i}",
                "severity": "medium",
                "mitre_techniques": [],
                "enabled": True,
                "match_count": 0,
                "last_match": None,
                "last_run": None,
                "created_at": created,
            }
            for i in (1, 2)
        ]
        sigma = [
            _metric_row(1, 4, 4, AS_OF - timedelta(hours=1), 2, 1, 1),
            _metric_row(2, 6, 6, AS_OF - timedelta(hours=2), 6, 2, 4),
        ]
        conn = _mock_conn(rules, sigma, [])
        with patch("src.detection.scorecard.get_pool", return_value=_pool_mock(conn)):
            result = await compute_rule_scorecard(window_hours=720, as_of=AS_OF)
        assert result["summary"]["dispositions_total"] == 8
        assert result["summary"]["false_positives_total"] == 5
        assert result["summary"]["retirement_candidates"] == 0  # ratio 0.5, not 1.0


class TestScorecardEndpoint:
    @pytest.mark.asyncio
    async def test_endpoint_wiring(self):
        from src.api.detection import detection_scorecard

        expected = {"summary": {}, "rules": [], "retirement_advice": []}
        with patch(
            "src.api.detection.compute_rule_scorecard",
            return_value=expected,
        ) as mock_fn:
            result = await detection_scorecard(window_hours=720, user={"sub": "analyst"})
        assert result == expected
        mock_fn.assert_awaited_once()
        kwargs = mock_fn.await_args.kwargs
        assert kwargs["window_hours"] == 720
        assert "as_of" in kwargs
