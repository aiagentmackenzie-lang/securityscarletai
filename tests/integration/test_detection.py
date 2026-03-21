"""
Integration test for the detection engine.

Tests end-to-end: Sigma rule → scheduled execution → alert generation.
Requires: PostgreSQL running with schema applied.
Run with: poetry run pytest tests/integration/test_detection.py -v -s
"""
import asyncio
import json
import pytest
from datetime import datetime, timezone

from src.detection.sigma import parse_sigma_rule, sigma_to_sql
from src.detection.alerts import create_alert, get_alert_stats
from src.db.connection import get_pool, close_pool
from src.db.writer import LogWriter
from src.ingestion.schemas import NormalizedEvent


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


@pytest.fixture
async def db_pool():
    pool = await get_pool()
    yield pool
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
    alert_id = await create_alert(
        rule_id=999,
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
    alert_id_1 = await create_alert(
        rule_id=999,
        rule_name="Duplicate Test",
        severity="medium",
        host_name="dup-host",
        description="First alert",
    )
    
    alert_id_2 = await create_alert(
        rule_id=999,
        rule_name="Duplicate Test",
        severity="medium",
        host_name="dup-host",
        description="Duplicate alert",
    )
    
    # Second call should return same ID (deduplicated)
    assert alert_id_1 == alert_id_2
    
    # Cleanup
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM alerts WHERE id = $1", alert_id_1)


@pytest.mark.asyncio
async def test_alert_stats(db_pool):
    """Test: Alert statistics calculation."""
    # Create test alerts
    await create_alert(
        rule_id=1,
        rule_name="Stats Test",
        severity="critical",
        host_name="stats-host",
        description="Critical alert",
    )
    
    stats = await get_alert_stats("1 hour")
    
    assert "new_count" in stats
    assert "critical_count" in stats
    assert stats["critical_count"] >= 1
    
    # Cleanup
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM alerts WHERE rule_name = 'Stats Test'")
