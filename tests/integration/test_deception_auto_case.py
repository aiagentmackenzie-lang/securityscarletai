"""Integration tests for the W1.5 deception doctrine (auto-case leg).

Requires: PostgreSQL running with schema applied. Run with the throwaway
PG (the integration gate): poetry run pytest tests/integration -v
"""

import pytest

pytestmark = pytest.mark.integration

from src.db.connection import close_pool, get_pool
from src.detection.alerts import create_alert


@pytest.fixture
async def deception_pool():
    """Live pool; closes it on teardown so each test gets a fresh loop."""
    pool = await get_pool()
    created: list[int] = []
    yield pool, created
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE alerts SET case_id = NULL WHERE id = ANY($1::int[])", created
            )
            await conn.execute(
                "DELETE FROM cases WHERE id IN (SELECT case_id FROM alerts WHERE id = ANY($1::int[]))",
                created,
            )
            await conn.execute("DELETE FROM alerts WHERE id = ANY($1::int[])", created)
    finally:
        await close_pool()


@pytest.mark.asyncio
async def test_critical_deception_alert_auto_creates_case(deception_pool):
    """A critical deception alert is a case by construction (W1.5)."""
    pool, created = deception_pool
    # The REAL rule title (rules.name stores the Sigma title) -- the doctrine
    # must match the actual pipeline naming, not a correlation-style stub.
    alert_id = await create_alert(
        rule_name="Deception Canary File Accessed",
        severity="critical",
        host_name="deception-it-a",
        description="canary file accessed (integration)",
    )
    assert alert_id > 0
    created.append(alert_id)
    async with pool.acquire() as conn:
        case_row = await conn.fetchrow(
            "SELECT c.id, c.severity, c.alert_ids FROM cases c "
            "JOIN alerts a ON a.case_id = c.id WHERE a.id = $1",
            alert_id,
        )
        assert case_row is not None, "critical deception alert must auto-create a case"
        assert case_row["severity"] == "critical"
        assert alert_id in (case_row["alert_ids"] or [])
        # The alert links back and carries the doctrine note.
        alert_row = await conn.fetchrow("SELECT case_id, notes FROM alerts WHERE id = $1", alert_id)
        assert alert_row["case_id"] == case_row["id"]
        notes_text = str(alert_row["notes"])
        assert "Auto-escalated to case" in notes_text


@pytest.mark.asyncio
async def test_high_deception_probe_no_auto_case(deception_pool):
    """Probes (high) alert + notify WITHOUT the auto-case doctrine."""
    pool, created = deception_pool
    alert_id = await create_alert(
        rule_name="Deception Service Probed",
        severity="high",
        host_name="deception-it-b",
        description="honeypot probe (integration)",
    )
    assert alert_id > 0
    created.append(alert_id)
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT case_id FROM alerts WHERE id = $1", alert_id)
        assert row is not None
        assert row["case_id"] is None, "high probes must not auto-create cases"


@pytest.mark.asyncio
async def test_non_deception_critical_no_auto_case(deception_pool):
    """The doctrine is deception-scoped: a critical NON-deception alert is not auto-cased."""
    pool, created = deception_pool
    alert_id = await create_alert(
        rule_name="Reverse Shell Pattern Detected",
        severity="critical",
        host_name="deception-it-c",
        description="critical non-deception (integration)",
    )
    assert alert_id > 0
    created.append(alert_id)
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT case_id FROM alerts WHERE id = $1", alert_id)
        assert row is not None
        assert row["case_id"] is None, "non-deception criticals must not auto-create cases"
