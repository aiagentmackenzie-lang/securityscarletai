"""W1.1 rule backtesting -- unit gates.

Covers the detection-engineering loop's backtest leg: production-compiler
reuse (compile_where + warnings capture), the simple-rule report (hits,
per-day, dedup-replay alert estimate, top values), the aggregation-rule
report (bucketed triggers, per-rule dedup), the FP projection with the
scorecard's disposition precedence, the sigmaforge honesty gates (fail-safe
compiles and empty corpora report unmeasured, never a fake 0), and the API
contract (XOR body validation, analyst+ role, audit, 400/404 mapping).
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.api.detection import BacktestRequest, detection_backtest
from src.detection.backtest import (
    DEDUP_WINDOW_SECONDS,  # noqa: F401 -- re-export check (kept in sync w/ alerts)
    MAX_BACKTEST_WINDOW_HOURS,
    run_backtest,
)

AS_OF = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

SIMPLE_RULE = """
title: Suspicious Python Execution
description: python spawned by curl parent
logsource:
    category: process
detection:
    selection:
        event_category: "process"
        process_name|contains: "python"
    condition: selection
timeframe: 1h
level: high
tags:
    - attack.execution
    - attack.t1059
"""

AGG_RULE = """
title: DNS Exfil Long Labels
description: many destinations per source
logsource:
    category: network
detection:
    selection:
        event_category: "network"
    condition: selection | count(destination_ip) by source_ip > 100
timeframe: 1h
level: medium
"""


def _pool_mock(conn):
    mock_pool = MagicMock()
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire = MagicMock(return_value=acquirer)
    return mock_pool


def _backtest_conn(
    *,
    corpus=10,
    per_day=None,
    islands=None,
    top_values=None,
    fp=None,
    agg_base=None,
    buckets=None,
):
    """Conn mock dispatching by query shape (scorecard-test pattern)."""
    conn = AsyncMock()

    async def fetch(sql, *params):
        if "FROM alerts a" in sql:
            assert fp is not None, f"unexpected fp query: {sql[:120]}"
            return fp
        if "WITH matched AS" in sql:
            assert islands is not None
            return islands
        if "date_trunc('day'" in sql:
            assert per_day is not None
            return per_day
        if "SELECT COUNT(*) AS n FROM logs WHERE time >" in sql:
            # corpus scan: binds window start + end, both datetimes
            assert len(params) == 2
            assert isinstance(params[0], datetime) and isinstance(params[1], datetime)
            return [{"n": corpus}]
        if "AS value, COUNT(*)" in sql:
            assert top_values is not None
            return top_values
        if "to_timestamp" in sql:
            assert buckets is not None
            return buckets
        if "SELECT COUNT(*) AS n FROM logs WHERE (" in sql:
            assert agg_base is not None
            return agg_base
        raise AssertionError(f"unexpected query: {sql[:160]}")

    conn.fetch = AsyncMock(side_effect=fetch)
    return conn


@pytest.fixture
def simple_per_day():
    from datetime import datetime as dt

    return [
        {"day": dt(2026, 9, 14), "n": 3},
        {"day": dt(2026, 9, 15), "n": 4},
    ]


class TestCompilation:
    @pytest.mark.asyncio
    async def test_compilation_block_simple_rule(self):
        conn = _backtest_conn(
            corpus=5,
            per_day=[],
            islands=[{"bursts": 0, "hosts": 0, "est_alerts": 0}],
            top_values=[],
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(SIMPLE_RULE, window_hours=24, as_of=AS_OF)
        comp = report["compilation"]
        assert comp["aggregation"] is False
        assert comp["group_by"] is None
        assert comp["threshold"] is None
        assert comp["timeframe_seconds"] == 3600
        assert comp["selected_fields"] == ["event_category", "process_name"]
        assert comp["warnings"] == []

    @pytest.mark.asyncio
    async def test_compilation_block_aggregation_rule(self):
        conn = _backtest_conn(corpus=5, agg_base=[{"n": 0}], per_day=[], buckets=[])
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(AGG_RULE, window_hours=24, as_of=AS_OF)
        comp = report["compilation"]
        assert comp["aggregation"] is True
        assert comp["group_by"] == "source_ip"
        assert comp["threshold"] == 100

    @pytest.mark.asyncio
    async def test_invalid_yaml_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid Sigma rule"):
            await run_backtest("title: [unclosed", window_hours=24, as_of=AS_OF)

    @pytest.mark.asyncio
    async def test_unknown_field_raises_value_error(self):
        bad = SIMPLE_RULE.replace("process_name|contains", "no_such_field|contains")
        with pytest.raises(ValueError, match="Invalid Sigma rule"):
            await run_backtest(bad, window_hours=24, as_of=AS_OF)

    @pytest.mark.asyncio
    async def test_fail_safe_selection_surfaces_as_warning(self):
        # A null selection value fails safe to FALSE (UnsupportedSigmaValue
        # path) -- the compiler logs it and the backtest MUST surface it
        # (sigmaforge gate).
        bad = """title: Broken Selection
detection:
    selection:
        event_category: "process"
        file_hash:
    condition: selection
"""
        conn = _backtest_conn(
            corpus=5, per_day=[], islands=[{"bursts": 0, "hosts": 0, "est_alerts": 0}]
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(bad, window_hours=24, as_of=AS_OF)
        assert report["compilation"]["warnings"], "fail-safe compile must warn"
        assert report["results"]["measured"] is False
        assert report["unmeasured_reasons"]
        assert report["projected_fp_ratio"]["measured"] is False

    @pytest.mark.asyncio
    async def test_unknown_modifier_surfaces_as_warning(self):
        bad = SIMPLE_RULE.replace("process_name|contains", "process_name|bogusmod")
        conn = _backtest_conn(
            corpus=5,
            per_day=[],
            islands=[{"bursts": 0, "hosts": 0, "est_alerts": 0}],
            top_values=[],
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(bad, window_hours=24, as_of=AS_OF)
        assert any("unknown modifier" in w for w in report["compilation"]["warnings"])
        # A narrower-than-intended compile still MEASURES (it is a valid,
        # just narrower, rule) -- but the ratio note stays honest.


class TestSimpleRuleBacktest:
    @pytest.mark.asyncio
    async def test_hits_per_day_and_estimate(self, simple_per_day):
        conn = _backtest_conn(
            corpus=50,
            per_day=simple_per_day,
            islands=[{"bursts": 3, "hosts": 2, "est_alerts": 5}],
            top_values=[{"value": "python3", "cnt": 6}, {"value": "python", "cnt": 1}],
            fp=None,
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(SIMPLE_RULE, window_hours=48, as_of=AS_OF)

        results = report["results"]
        assert results["total_rows"] == 7
        assert results["per_day"] == [
            {"day": "2026-09-14", "rows": 3},
            {"day": "2026-09-15", "rows": 4},
        ]
        assert results["estimated_alerts"] == 5
        assert results["hosts_affected"] == 2
        assert results["measured"] is True
        assert str(DEDUP_WINDOW_SECONDS) in results["estimate_method"]
        assert results["top_values"]["process_name"] == [
            {"value": "python3", "count": 6},
            {"value": "python", "count": 1},
        ]
        # event_category (the other selected column) got the same mocked rows
        assert results["top_values"]["event_category"][0]["count"] == 6
        assert report["rule"]["source"] == "draft"
        assert report["window"]["hours"] == 48

    @pytest.mark.asyncio
    async def test_draft_fp_ratio_unmeasured(self, simple_per_day):
        conn = _backtest_conn(
            corpus=10,
            per_day=simple_per_day,
            islands=[{"bursts": 1, "hosts": 1, "est_alerts": 1}],
            top_values=[],
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(SIMPLE_RULE, window_hours=48, as_of=AS_OF)
        assert report["projected_fp_ratio"]["measured"] is False
        assert "draft" in report["projected_fp_ratio"]["note"]

    @pytest.mark.asyncio
    async def test_existing_rule_fp_projection_measured(self, simple_per_day):
        conn = _backtest_conn(
            corpus=10,
            per_day=simple_per_day,
            islands=[{"bursts": 1, "hosts": 1, "est_alerts": 2}],
            top_values=[],
            fp=[
                {"alerts_lifetime": 9, "alerts_window": 3, "dispositions": 4, "false_positives": 1}
            ],
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(
                SIMPLE_RULE, window_hours=48, rule_id=7, rule_name="Py Rule", as_of=AS_OF
            )
        proj = report["projected_fp_ratio"]
        assert proj["measured"] is True
        assert proj["ratio"] == pytest.approx(0.25)
        assert proj["dispositions"] == 4
        assert proj["actual_alerts_lifetime"] == 9
        assert proj["actual_alerts_window"] == 3
        assert report["rule"]["rule_id"] == 7
        assert report["rule"]["rule_name"] == "Py Rule"
        assert report["rule"]["source"] == "existing"

    @pytest.mark.asyncio
    async def test_existing_rule_zero_dispositions_unmeasured(self, simple_per_day):
        conn = _backtest_conn(
            corpus=10,
            per_day=simple_per_day,
            islands=[{"bursts": 0, "hosts": 0, "est_alerts": 0}],
            top_values=[],
            fp=[
                {"alerts_lifetime": 3, "alerts_window": 0, "dispositions": 0, "false_positives": 0}
            ],
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(SIMPLE_RULE, window_hours=48, rule_id=7, as_of=AS_OF)
        assert report["projected_fp_ratio"]["measured"] is False
        assert "no adjudicated" in report["projected_fp_ratio"]["note"]

    @pytest.mark.asyncio
    async def test_zero_corpus_reports_unmeasured(self):
        conn = _backtest_conn(
            corpus=0, per_day=[], islands=[{"bursts": 0, "hosts": 0, "est_alerts": 0}]
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(SIMPLE_RULE, window_hours=24, as_of=AS_OF)
        assert report["results"]["measured"] is False
        assert report["results"]["total_rows"] == 0
        assert report["results"]["estimated_alerts"] == 0
        assert any("no logs in the window" in r for r in report["unmeasured_reasons"])

    @pytest.mark.asyncio
    async def test_window_clamped_to_30d(self):
        assert MAX_BACKTEST_WINDOW_HOURS == 720
        conn = _backtest_conn(
            corpus=1,
            per_day=[],
            islands=[{"bursts": 0, "hosts": 0, "est_alerts": 0}],
            top_values=[],
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(SIMPLE_RULE, window_hours=10_000, as_of=AS_OF)
        assert report["window"]["hours"] == 720

    @pytest.mark.asyncio
    async def test_zero_hits_with_data_is_measured_zero(self):
        # The honesty gate cuts BOTH ways: real zero data with a real corpus
        # is a valid measurement (not unmeasured).
        conn = _backtest_conn(
            corpus=500,
            per_day=[],
            islands=[{"bursts": 0, "hosts": 0, "est_alerts": 0}],
            top_values=[],
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(SIMPLE_RULE, window_hours=24, as_of=AS_OF)
        assert report["results"]["measured"] is True
        assert report["results"]["total_rows"] == 0
        assert "unmeasured_reasons" not in report


class TestAggregationBacktest:
    @pytest.mark.asyncio
    async def test_bucketed_triggers_and_dedup_replay(self, simple_per_day):
        from datetime import datetime as dt
        from datetime import timezone as tz

        # Three over-threshold buckets: T0, T0+10m (deduped), T0+20m (alert).
        t0 = dt(2026, 9, 15, 10, 0, 0, tzinfo=tz.utc)
        buckets = [
            {"bucket": t0, "grp": "10.0.0.5", "cnt": 150},
            {"bucket": dt(2026, 9, 15, 10, 10, 0, tzinfo=tz.utc), "grp": "10.0.0.5", "cnt": 120},
            {"bucket": dt(2026, 9, 15, 10, 20, 0, tzinfo=tz.utc), "grp": "10.0.0.9", "cnt": 101},
        ]
        conn = _backtest_conn(
            corpus=10, agg_base=[{"n": 400}], per_day=simple_per_day, buckets=buckets
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(AGG_RULE, window_hours=24, as_of=AS_OF)

        results = report["results"]
        assert results["total_rows"] == 400
        assert results["trigger_buckets_truncated"] is False
        assert len(results["trigger_buckets"]) == 3
        # t0 -> alert; t0+10m -> inside the 15m dedup (suppressed); t0+20m -> alert
        assert results["estimated_alerts"] == 2
        assert results["top_values"]["source_ip"][0] == {"value": "10.0.0.5", "count": 150}

    @pytest.mark.asyncio
    async def test_no_triggers_means_zero_estimate(self):
        conn = _backtest_conn(corpus=10, agg_base=[{"n": 5}], per_day=[], buckets=[])
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            report = await run_backtest(AGG_RULE, window_hours=24, as_of=AS_OF)
        assert report["results"]["estimated_alerts"] == 0
        assert report["results"]["trigger_buckets"] == []

    @pytest.mark.asyncio
    async def test_threshold_binds_as_param(self, simple_per_day):
        buckets = [
            {
                "bucket": datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc),
                "grp": "1.2.3.4",
                "cnt": 101,
            }
        ]
        conn = _backtest_conn(
            corpus=10, agg_base=[{"n": 5}], per_day=simple_per_day, buckets=buckets
        )
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            await run_backtest(AGG_RULE, window_hours=24, as_of=AS_OF)
        bucket_calls = [c for c in conn.fetch.call_args_list if "to_timestamp" in c.args[0]]
        assert bucket_calls, "bucket query must run"
        params = bucket_calls[0].args[1:]
        # where params + start + end + bucket_seconds + threshold + limit
        assert params[-3] == 3600  # timeframe bucket seconds
        assert params[-2] == 100  # the Sigma threshold
        assert params[-1] == 500  # MAX_TRIGGER_BUCKETS

    @pytest.mark.asyncio
    async def test_trigger_count_mirrors_the_runtime_field(self, simple_per_day):
        """AUD-082: the bucket query counts the rule's OWN count field, exactly
        like the runtime aggregation — COUNT(destination_ip) for
        `count(destination_ip) by ...`. The old hardcoded COUNT(*) let a
        NULL-field bucket cross the threshold in the report while the runtime's
        COUNT(field) can never fire it (count of all-NULL rows is 0)."""
        conn = _backtest_conn(corpus=10, agg_base=[{"n": 5}], per_day=simple_per_day, buckets=[])
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            await run_backtest(AGG_RULE, window_hours=24, as_of=AS_OF)
        bucket_sql = next(
            c.args[0] for c in conn.fetch.call_args_list if "to_timestamp" in c.args[0]
        )
        assert "COUNT(destination_ip) AS cnt" in bucket_sql
        assert "HAVING COUNT(destination_ip)" in bucket_sql
        assert "COUNT(*)" not in bucket_sql

    @pytest.mark.asyncio
    async def test_count_star_rule_keeps_count_star_triggers(self, simple_per_day):
        """AUD-082 mirror: a count(*) aggregation (data_exfiltration_volume
        shape) compiles COUNT(*) trigger buckets — unchanged."""
        star_rule = AGG_RULE.replace(
            "count(destination_ip) by source_ip > 100", "count(*) by host_name > 100"
        )
        conn = _backtest_conn(corpus=10, agg_base=[{"n": 5}], per_day=simple_per_day, buckets=[])
        with patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)):
            await run_backtest(star_rule, window_hours=24, as_of=AS_OF)
        bucket_sql = next(
            c.args[0] for c in conn.fetch.call_args_list if "to_timestamp" in c.args[0]
        )
        assert "COUNT(*) AS cnt" in bucket_sql
        assert "HAVING COUNT(*)" in bucket_sql


class TestEndpoint:
    @pytest.mark.asyncio
    async def test_backtest_wiring_and_audit(self, simple_per_day):
        report = {
            "rule": {"source": "existing", "sigma_title": "T"},
            "results": {"measured": True, "total_rows": 7, "estimated_alerts": 5},
        }
        conn = _backtest_conn(
            corpus=10,
            per_day=simple_per_day,
            islands=[{"bursts": 1, "hosts": 1, "est_alerts": 1}],
            top_values=[],
            fp=[
                {"alerts_lifetime": 2, "alerts_window": 2, "dispositions": 1, "false_positives": 0}
            ],
        )
        with (
            patch("src.detection.backtest.get_pool", return_value=_pool_mock(conn)),
            patch("src.api.detection.run_backtest", AsyncMock(return_value=report)),
            patch("src.api.detection.log_audit_action", new=AsyncMock()) as audit,
            patch(
                "src.api.rules.get_rule_by_id",
                AsyncMock(return_value={"name": "Py", "sigma_yaml": SIMPLE_RULE}),
            ),
        ):
            req = BacktestRequest(rule_id=7, window_hours=24)
            result = await detection_backtest(req, user={"sub": "analyst1"})

        assert result == report
        called = audit.await_args
        assert called.kwargs["action"] == "rule.backtest"
        assert called.kwargs["actor"] == "analyst1"
        assert called.kwargs["target_id"] == 7
        assert called.kwargs["new_values"]["total_rows"] == 7

    @pytest.mark.asyncio
    async def test_body_requires_exactly_one_source(self):
        with pytest.raises(ValueError):
            BacktestRequest(rule_id=1, sigma_yaml=SIMPLE_RULE)
        with pytest.raises(ValueError):
            BacktestRequest()

    @pytest.mark.asyncio
    async def test_unknown_rule_404(self):
        with patch("src.api.rules.get_rule_by_id", AsyncMock(return_value=None)):
            with pytest.raises(HTTPException) as exc_info:
                await detection_backtest(BacktestRequest(rule_id=99), user={"sub": "a"})
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_compiler_error_maps_to_400(self):
        with patch(
            "src.api.detection.run_backtest",
            AsyncMock(side_effect=ValueError("Invalid Sigma rule: bad field")),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await detection_backtest(BacktestRequest(sigma_yaml="title: x"), user={"sub": "a"})
        assert exc_info.value.status_code == 400
        assert "bad field" in exc_info.value.detail
