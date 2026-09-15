"""
Integration test for the detection engine.

Tests end-to-end: Sigma rule → scheduled execution → alert generation,
plus the W1.1 backtest legs (real compiler + real corpus).
Requires: PostgreSQL running with schema applied.
Run with: poetry run pytest tests/integration/test_detection.py -v -s
"""

from datetime import timedelta

import pytest

# Integration tests require a live PostgreSQL database.
# Run with: poetry run pytest tests/integration/ -v -s
# Skip automatically if DB is unavailable.
pytestmark = pytest.mark.integration

from src.db.connection import close_pool, get_pool
from src.detection.alerts import create_alert, get_alert_stats
from src.detection.backtest import run_backtest
from src.detection.sigma import sigma_to_sql

TEST_BRUTE_FORCE_RULE = """
title: Test Brute Force
description: Test rule for integration
timeframe: 1m
level: high
detection:
    selection:
        event_category: "authentication"
    condition: selection | count(host_name) by host_name > 2
"""

BACKTEST_SIMPLE_RULE = """
title: Backtest Probe Rule
description: W1.1 integration probe
detection:
    selection:
        event_category: "process"
        process_name|contains: "backtest-probe"
    condition: selection
timeframe: 1h
level: medium
"""

BACKTEST_AGG_RULE = """
title: Backtest Probe Aggregation
description: W1.1 aggregation probe
detection:
    selection:
        event_category: "network"
    condition: selection | count(destination_ip) by source_ip > 2
timeframe: 1h
level: medium
"""

_BACKTEST_HOSTS = "backtest-it-%"


@pytest.fixture
async def backtest_pool():
    """Throwaway rule + seeded logs for the backtest legs; nothing survives."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rule_id = await conn.fetchval(
            """INSERT INTO rules (name, sigma_yaml, severity)
            VALUES ('Backtest Probe Rule', $1, 'medium')
            ON CONFLICT (name) DO UPDATE SET sigma_yaml = EXCLUDED.sigma_yaml
            RETURNING id""",
            BACKTEST_SIMPLE_RULE,
        )
        agg_rule_id = await conn.fetchval(
            """INSERT INTO rules (name, sigma_yaml, severity)
            VALUES ('Backtest Probe Aggregation', $1, 'medium')
            ON CONFLICT (name) DO UPDATE SET sigma_yaml = EXCLUDED.sigma_yaml
            RETURNING id""",
            BACKTEST_AGG_RULE,
        )
        # Simple-rule corpus: probe-a has two matches 1h apart (two dedup
        # islands -> 2 alerts); probe-b two matches 10m apart (one island ->
        # ceil(600/900)+1... one island of span 0 -> 1 alert).
        for host, delta in (
            ("backtest-it-a", timedelta(minutes=120)),
            ("backtest-it-a", timedelta(minutes=60)),
            ("backtest-it-b", timedelta(minutes=95)),
            ("backtest-it-b", timedelta(minutes=85)),
        ):
            await conn.execute(
                """INSERT INTO logs (time, host_name, source, event_category, event_type,
                   process_name, raw_data, normalized)
                VALUES (NOW() - $1::interval, $2, 'osquery',
                        'process', 'start', 'backtest-probe-bin', '{}', '{}')""",
                delta,
                host,
            )
        # Aggregation corpus: source 10.99.0.7 hits 3 distinct destinations
        # inside ONE 1h bucket (over threshold 2); 10.99.0.8 hits only 2
        # (below threshold, must NOT trigger). Timestamps anchor to
        # date_trunc('hour', NOW()) - 30m + {5,15,25}m so all rows land in
        # the same hour bucket regardless of when the test runs (and always
        # in the past, within the 4h window).
        for src, dst, offset in (
            ("10.99.0.7", "8.8.8.8", timedelta(minutes=5)),
            ("10.99.0.7", "8.8.4.4", timedelta(minutes=15)),
            ("10.99.0.7", "1.1.1.1", timedelta(minutes=25)),
            ("10.99.0.8", "8.8.8.8", timedelta(minutes=10)),
            ("10.99.0.8", "8.8.4.4", timedelta(minutes=20)),
        ):
            await conn.execute(
                """INSERT INTO logs (time, host_name, source, event_category, event_type,
                   source_ip, destination_ip, raw_data, normalized)
                VALUES (date_trunc('hour', NOW()) - interval '30 minutes' + $1::interval,
                        'backtest-it-net', 'osquery', 'network', 'connection',
                        $2::inet, $3::inet, '{}', '{}')""",
                offset,
                src,
                dst,
            )
    yield pool, rule_id, agg_rule_id
    # Cleanup: alerts + labels cascade; logs by the marked hosts; rules.
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM alert_labels WHERE alert_id IN "
            "(SELECT id FROM alerts WHERE rule_name LIKE 'Backtest Probe%')"
        )
        await conn.execute("DELETE FROM alerts WHERE rule_name LIKE 'Backtest Probe%'")
        await conn.execute("DELETE FROM logs WHERE host_name LIKE $1", _BACKTEST_HOSTS)
        await conn.execute(
            "DELETE FROM rules WHERE name IN ('Backtest Probe Rule', 'Backtest Probe Aggregation')"
        )
    await close_pool()


@pytest.mark.asyncio
async def test_backtest_simple_counts_and_estimate(backtest_pool):
    """Backtest a simple rule end-to-end: real compiler + real corpus."""
    pool, rule_id, _ = backtest_pool
    report = await run_backtest(
        BACKTEST_SIMPLE_RULE, window_hours=4, rule_id=rule_id, rule_name="Backtest Probe Rule"
    )
    results = report["results"]
    assert results["measured"] is True
    assert results["total_rows"] == 4  # 2x backtest-it-a + 2x backtest-it-b
    assert sum(d["rows"] for d in results["per_day"]) == 4
    # probe-a: 120m and 60m ago = 1h gap > 15m dedup -> 2 islands;
    # probe-b: 95m/85m = 10m gap -> 1 island. 1h island spans -> 1 alert each.
    assert results["estimated_alerts"] == 3
    assert results["hosts_affected"] == 2
    assert results["top_values"]["process_name"][0]["value"] == "backtest-probe-bin"
    assert results["top_values"]["process_name"][0]["count"] == 4
    assert report["rule"]["source"] == "existing"


@pytest.mark.asyncio
async def test_backtest_aggregation_buckets(backtest_pool):
    """Aggregation rule: only the over-threshold group triggers."""
    pool, _, agg_rule_id = backtest_pool
    report = await run_backtest(
        BACKTEST_AGG_RULE,
        window_hours=4,
        rule_id=agg_rule_id,
        rule_name="Backtest Probe Aggregation",
    )
    results = report["results"]
    assert results["measured"] is True
    assert results["total_rows"] == 5  # all 5 seeded network rows match the base selection
    buckets = results["trigger_buckets"]
    assert buckets, "the 3-destination source must trigger"
    groups = {b["group"] for b in buckets}
    assert "10.99.0.7" in groups
    assert "10.99.0.8" not in groups  # 2 <= threshold 2 -> silent
    assert results["estimated_alerts"] >= 1


@pytest.mark.asyncio
async def test_backtest_fp_projection_from_dispositions(backtest_pool):
    """Projected FP ratio reads the SAME dispositions the scorecard reads."""
    pool, rule_id, _ = backtest_pool
    async with pool.acquire() as conn:
        a1 = await create_alert(
            rule_id=rule_id,
            rule_name="Backtest Probe Rule",
            severity="medium",
            host_name="backtest-it-a",
            description="one",
        )
        a2 = await create_alert(
            rule_id=rule_id,
            rule_name="Backtest Probe Rule",
            severity="medium",
            host_name="backtest-it-b",
            description="two",
        )
        await conn.execute(
            "INSERT INTO alert_labels (alert_id, label) VALUES ($1, 'false_positive')", a1
        )
        await conn.execute(
            "INSERT INTO alert_labels (alert_id, label) VALUES ($1, 'true_positive')", a2
        )
    try:
        report = await run_backtest(
            BACKTEST_SIMPLE_RULE,
            window_hours=24,
            rule_id=rule_id,
            rule_name="Backtest Probe Rule",
        )
        proj = report["projected_fp_ratio"]
        assert proj["measured"] is True
        assert proj["dispositions"] == 2
        assert proj["false_positives"] == 1
        assert proj["ratio"] == pytest.approx(0.5)
        # Window-vs-lifetime: the window bound is Python-clock vs DB-clock
        # racy at the microsecond level for alerts created DURING the test;
        # lifetime is the deterministic calibration number here.
        assert proj["actual_alerts_lifetime"] >= 2
    finally:
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM alert_labels WHERE alert_id IN ($1, $2)", a1, a2)
            await conn.execute("DELETE FROM alerts WHERE id IN ($1, $2)", a1, a2)


@pytest.fixture
async def db_pool():
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Insert test rule so FK constraints pass
        await conn.execute(
            """INSERT INTO rules (name, sigma_yaml, severity)
            VALUES ('Test Rule', 'title: Test\ndetection:\n  condition: selection', 'high')
            ON CONFLICT (name) DO NOTHING"""
        )
    yield pool
    # Cleanup test data
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM alerts WHERE rule_name LIKE '%Test%' OR rule_name LIKE '%Duplicate%' OR rule_name LIKE '%Stats Test%'"
        )
        await conn.execute("DELETE FROM rules WHERE name = 'Test Rule'")
    await close_pool()


@pytest.mark.asyncio
async def test_sigma_to_sql(db_pool):
    """Test: Sigma rule parses and generates valid SQL."""
    sql, params = sigma_to_sql(TEST_BRUTE_FORCE_RULE)

    assert "SELECT" in sql
    assert "GROUP BY" in sql
    assert "HAVING" in sql
    assert "authentication" in params


@pytest.mark.asyncio
async def test_alert_creation(db_pool):
    """Test: Create alert and verify in database."""
    # Get the test rule ID
    async with db_pool.acquire() as conn:
        rule_id = await conn.fetchval("SELECT id FROM rules WHERE name = 'Test Rule'")

    alert_id = await create_alert(
        rule_id=rule_id,
        rule_name="Test Rule",
        severity="high",
        host_name="test-host",
        description="Test alert",
        mitre_tactics=["TA0001"],
        mitre_techniques=["T1234"],
    )

    assert alert_id is not None

    # Verify in DB
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id)
        assert row["rule_name"] == "Test Rule"
        assert row["severity"] == "high"

        # Cleanup
        await conn.execute("DELETE FROM alerts WHERE id = $1", alert_id)


@pytest.mark.asyncio
async def test_alert_deduplication(db_pool):
    """Test: Duplicate alerts are suppressed within 5 minutes."""
    async with db_pool.acquire() as conn:
        rule_id = await conn.fetchval("SELECT id FROM rules WHERE name = 'Test Rule'")

    alert_id_1 = await create_alert(
        rule_id=rule_id,
        rule_name="Duplicate Test",
        severity="medium",
        host_name="dup-host",
        description="First alert",
    )

    alert_id_2 = await create_alert(
        rule_id=rule_id,
        rule_name="Duplicate Test",
        severity="medium",
        host_name="dup-host",
        description="Duplicate alert",
    )

    # Dedup contract (matches unit tests): the second call within the dedup
    # window returns -1 (suppressed) rather than the existing alert's id.
    assert alert_id_1 > 0
    assert alert_id_2 == -1

    # Cleanup
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM alerts WHERE id = $1", alert_id_1)


@pytest.mark.asyncio
async def test_alert_stats(db_pool):
    """Test: Alert statistics calculation."""
    async with db_pool.acquire() as conn:
        rule_id = await conn.fetchval("SELECT id FROM rules WHERE name = 'Test Rule'")

    # Create test alerts
    await create_alert(
        rule_id=rule_id,
        rule_name="Stats Test",
        severity="critical",
        host_name="stats-host",
        description="Critical alert",
    )

    stats = await get_alert_stats(1)

    assert "new_count" in stats
    assert "critical_count" in stats
    assert stats["critical_count"] >= 1


@pytest.mark.asyncio
async def test_backtest_channel_and_report_module_smoke(db_pool):
    """W1.7/W1.8 integration smoke: the notification-channel config parses
    (default-off -> no channels) and the shared posture builder runs against
    the live schema with the exact endpoint payload shape."""
    from src.detection.scheduler import SCHEDULES_CONFIG_PATH
    from src.response.scheduled_reports import (
        closed_cases_digest,
        load_schedules_file,
        posture_report_data,
    )

    # Fail-closed: the shipped config is default-off -> no schedules.
    assert load_schedules_file(SCHEDULES_CONFIG_PATH) == []

    payload = await posture_report_data(24)
    assert {"window_hours", "alerts", "mttr_seconds", "rule_scorecard_summary", "outliers"} <= set(
        payload
    )
    assert payload["alerts"]["total"] >= 0

    digest = await closed_cases_digest(24)
    assert {"window_hours", "closed_cases", "count"} <= set(digest)
