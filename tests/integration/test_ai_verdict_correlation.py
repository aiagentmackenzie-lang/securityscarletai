"""
Integration test: the AI-verdict correlation rule against live PostgreSQL.

NeuralGuard ingests verdict events (source=neuralguard,
event_category=intrusion_detection, event_action=verdict_block, tenant in
raw_data.neuralguard.tenant_id). The ai_verdict_block_sustained rule fires
when one (host_name, source, tenant_id) group records >= threshold BLOCK
verdicts inside the trailing window.

Validates the rule's real SQL — JSONB tenant extraction, GROUP BY/HAVING,
window bounds — which the mocked unit tests cannot.

Requires: PostgreSQL running with schema applied (local-prod stack: port 5433).
Run with: RUN_INTEGRATION_TESTS=1 poetry run pytest tests/integration/test_ai_verdict_correlation.py -v
"""

from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.integration

from src.db.connection import close_pool, get_pool
from src.detection.correlation import (
    detect_ai_verdict_block_sustained,
    run_all_correlations,
)

_TENANT_A = "it-test-tenant-a"
_TENANT_B = "it-test-tenant-b"
_HOST = "neuralguard-it-host"


def _block_event(tenant: str, at: datetime, i: int) -> dict:
    """A NeuralGuard-shaped verdict_block row for the logs table."""
    return {
        "time": at,
        "host_name": _HOST,
        "source": "neuralguard",
        "event_category": "intrusion_detection",
        "event_type": "info",
        "event_action": "verdict_block",
        "severity": "critical",
        "raw_data": '{"neuralguard": {"tenant_id": "%s", "request_id": "it-%s-%d"}}'
        % (tenant, tenant, i),
    }


async def _insert_events(conn, rows: list[dict]) -> None:
    """Insert events the same way the writer does — the ECS scalars also land
    in the NOT NULL `normalized` JSONB (writer: model_dump minus raw_data)."""
    import json

    values = []
    for r in rows:
        normalized = {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in r.items()
            if k != "raw_data"
        }
        values.append(
            (
                r["time"],
                r["host_name"],
                r["source"],
                r["event_category"],
                r["event_type"],
                r["event_action"],
                r["severity"],
                r["raw_data"],
                json.dumps(normalized),
            )
        )
    await conn.executemany(
        """INSERT INTO logs (time, host_name, source, event_category, event_type,
                             event_action, severity, raw_data, normalized)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb)""",
        values,
    )


@pytest.fixture
async def db_pool():
    pool = await get_pool()
    yield pool
    # Cleanup test data (keyed on the unique tenant ids so we never touch
    # real events — NeuralGuard's real tenants are never test-prefixed).
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM logs WHERE raw_data->'neuralguard'->>'tenant_id' IN ($1, $2)",
            _TENANT_A,
            _TENANT_B,
        )
        await conn.execute(
            "DELETE FROM correlation_matches WHERE match_data->>'tenant_id' IN ($1, $2)",
            _TENANT_A,
            _TENANT_B,
        )
    await close_pool()


@pytest.mark.asyncio
async def test_sustained_blocks_fire_the_rule(db_pool):
    """13 blocks in 5 minutes from tenant A -> exactly one match for that group."""
    now = datetime.now(timezone.utc)
    rows = [_block_event(_TENANT_A, now - timedelta(seconds=10 * i), i) for i in range(13)]
    # 3 blocks from a different tenant in the same window — below threshold
    # when the grouped count for tenant B stays under 10.
    rows += [_block_event(_TENANT_B, now - timedelta(seconds=10 * i), i) for i in range(3)]

    async with db_pool.acquire() as conn:
        await _insert_events(conn, rows)

        matches = await detect_ai_verdict_block_sustained(
            conn, now, block_threshold=10, time_window_minutes=5
        )

    mine = [m for m in matches if m["tenant_id"] == _TENANT_A]
    other = [m for m in matches if m["tenant_id"] == _TENANT_B]
    assert len(mine) == 1
    assert mine[0]["block_count"] == 13
    assert mine[0]["source"] == "neuralguard"
    assert mine[0]["severity"] == "high"
    assert mine[0]["correlation_rule"] == "ai_verdict_block_sustained"
    assert other == []  # 3 blocks < threshold of 10


@pytest.mark.asyncio
async def test_below_threshold_and_stale_blocks_do_not_fire(db_pool):
    """Few blocks in-window (and many old ones) -> no match."""
    now = datetime.now(timezone.utc)
    # 12 blocks but 2 hours old — outside the 5-minute window.
    old = [_block_event(_TENANT_A, now - timedelta(hours=2, seconds=i), i) for i in range(12)]
    # 2 fresh blocks — below threshold.
    fresh = [_block_event(_TENANT_B, now - timedelta(seconds=i), i) for i in range(2)]

    async with db_pool.acquire() as conn:
        await _insert_events(conn, old + fresh)

        matches = await detect_ai_verdict_block_sustained(
            conn, now, block_threshold=10, time_window_minutes=5
        )

    assert [m for m in matches if m["tenant_id"] in (_TENANT_A, _TENANT_B)] == []


@pytest.mark.asyncio
async def test_run_all_correlations_persists_matches(db_pool):
    """run_all_correlations(persist=True) must land the AI-verdict match in
    correlation_matches (the F-10 dedup + INSERT path, live against real
    Postgres — mocked tests cannot catch an unused-SQL-parameter bug there)."""
    now = datetime.now(timezone.utc)
    rows = [_block_event(_TENANT_A, now - timedelta(seconds=5 * i), i) for i in range(12)]

    async with db_pool.acquire() as conn:
        await _insert_events(conn, rows)

    result = await run_all_correlations(as_of=now, persist=True)

    assert result["persisted"] >= 1
    # Scope to THIS test's tenant — a live shared DB may legitimately hold
    # other sustained-block groups (e.g. live-fire demo data) in the window.
    ai_matches = [
        m
        for m in result["matches"]
        if m["correlation_rule"] == "ai_verdict_block_sustained" and m["tenant_id"] == _TENANT_A
    ]
    assert len(ai_matches) == 1

    # Second run, same data + same as_of → identical payload → the F-10 dedup
    # must SKIP the second persist (jsonb identity minus correlation_id).
    result2 = await run_all_correlations(as_of=now, persist=True)
    ai_matches_2 = [
        m
        for m in result2["matches"]
        if m["correlation_rule"] == "ai_verdict_block_sustained" and m["tenant_id"] == _TENANT_A
    ]
    assert len(ai_matches_2) == 1
    assert result2["persisted"] == 0

    import json as _json

    from src.detection.correlation import list_matches

    persisted = await list_matches(rule="ai_verdict_block_sustained", limit=50)
    ours = [
        p
        for p in persisted
        if (lambda md: _json.loads(md) if isinstance(md, str) else md or {})(p["match_data"]).get(
            "tenant_id"
        )
        == _TENANT_A
    ]
    assert len(ours) == 1
    assert ours[0]["severity"] == "high"
