"""DB-semantics regressions from the 2026-11-18 bug sweep.

Needs a real PostgreSQL with `src/db/schema.sql` applied (the throwaway
container described in the campaign brief):
    RUN_INTEGRATION_TESTS=1 DB_HOST=... poetry run pytest tests/integration/

Covered:
  SS-018  two connections racing the same (rule, host) produce ONE alert
  SS-049  reopening an alert clears resolved_at
  SS-036  check_audit_grants sees an INHERITED mutate privilege
  SS-037  the MCP scoped-role verifier sees the same inherited privilege
"""

from __future__ import annotations

import contextlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import asyncpg
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
async def _fresh_pool_per_test():
    """pytest-asyncio gives each test its own event loop; the module-global
    asyncpg pool would otherwise survive into the next test bound to a closed
    loop ("Event loop is closed" / InterfaceError)."""
    yield
    from src.db.connection import close_pool

    try:
        await close_pool()
    except Exception:
        pass


def _dsn(user: str | None = None, password: str | None = None) -> str:
    host = os.environ.get("DB_HOST", "127.0.0.1")
    port = os.environ.get("DB_PORT", "5432")
    name = os.environ.get("DB_NAME", "fix")
    user = user or os.environ.get("DB_USER", "postgres")
    password = password if password is not None else os.environ.get("DB_PASSWORD", "fix")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


class _SingleConnPool:
    """Minimal pool stand-in over one connection (enough for the verifier)."""

    def __init__(self, conn) -> None:
        self._conn = conn

    @contextlib.asynccontextmanager
    async def acquire(self):
        yield self._conn


# ───────────────────────────────────────────────────────────────
# SS-018 — dedup serialization
# ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_create_alert_yields_one_alert():
    from src.detection.alerts import create_alert

    host = f"sweepfix-{uuid.uuid4().hex[:8]}"
    rule_name = f"sweepfix rule {host}"

    import asyncio

    results = await asyncio.gather(
        create_alert(rule_id=None, rule_name=rule_name, severity="medium", host_name=host),
        create_alert(rule_id=None, rule_name=rule_name, severity="medium", host_name=host),
        return_exceptions=True,
    )
    ids = [r for r in results if isinstance(r, int) and r > 0]

    conn = await asyncpg.connect(_dsn())
    try:
        count = await conn.fetchval(
            "SELECT count(*) FROM alerts WHERE rule_name = $1 AND host_name = $2",
            rule_name,
            host,
        )
        await conn.execute(
            "DELETE FROM alerts WHERE rule_name = $1 AND host_name = $2", rule_name, host
        )
    finally:
        await conn.close()

    assert len(ids) == 1, f"expected exactly one created alert, got results={results}"
    assert count == 1, f"dedup failed: {count} alerts for one (rule, host)"


# ───────────────────────────────────────────────────────────────
# SS-049 — resolved_at on reopen
# ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reopen_clears_resolved_at():
    from src.db.connection import get_pool
    from src.detection.alerts import update_alert_status

    host = f"sweepfix-reopen-{uuid.uuid4().hex[:8]}"
    pool = await get_pool()
    async with pool.acquire() as conn:
        alert_id = await conn.fetchval(
            """
            INSERT INTO alerts (rule_name, severity, status, host_name, time)
            VALUES ('sweepfix reopen', 'low', 'new', $1, NOW())
            RETURNING id
            """,
            host,
        )
    try:
        await update_alert_status(alert_id, "resolved", updated_by="it")
        async with pool.acquire() as conn:
            resolved_at = await conn.fetchval(
                "SELECT resolved_at FROM alerts WHERE id = $1", alert_id
            )
        assert resolved_at is not None

        await update_alert_status(alert_id, "investigating", updated_by="it")
        async with pool.acquire() as conn:
            after = await conn.fetchval("SELECT resolved_at FROM alerts WHERE id = $1", alert_id)
    finally:
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM alerts WHERE host_name = $1", host)

    assert after is None, "reopening left a stale resolved_at (SS-049)"


# ───────────────────────────────────────────────────────────────
# SS-036 / SS-037 — inherited grants
# ───────────────────────────────────────────────────────────────


async def _drop_roles(conn, app_role: str) -> None:
    """Best-effort teardown: revoke, drop owned objects, drop both roles."""
    for role in (app_role, f"{app_role}_mutate"):
        for stmt in (
            f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}",
            f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}",
            f"REVOKE ALL ON SCHEMA public FROM {role}",
            f"DROP OWNED BY {role}",
            f"DROP ROLE IF EXISTS {role}",
        ):
            try:
                await conn.execute(stmt)  # noqa: S608 — test-local identities
            except Exception:
                pass


async def _harden_audit_owner_role(conn, app_role: str) -> None:
    """Give the app role direct INSERT/SELECT and an INHERITED UPDATE/DELETE."""
    await conn.execute(f"DROP ROLE IF EXISTS {app_role}_mutate")  # noqa: S608 — test-local role
    await conn.execute(f"DROP ROLE IF EXISTS {app_role}")  # noqa: S608
    await conn.execute(f"CREATE ROLE {app_role} LOGIN PASSWORD 'app-pw'")  # noqa: S608
    await conn.execute(f"CREATE ROLE {app_role}_mutate")  # noqa: S608
    await conn.execute(  # noqa: S608 — test-local identities, never user input
        f"GRANT SELECT, INSERT ON audit_logs, audit_log TO {app_role}"
    )
    await conn.execute(  # noqa: S608
        f"GRANT UPDATE, DELETE ON audit_logs TO {app_role}_mutate"
    )
    await conn.execute(f"GRANT {app_role}_mutate TO {app_role}")  # noqa: S608


@pytest.mark.asyncio
async def test_audit_check_detects_inherited_mutate_grant():
    from scripts.check_audit_grants import evaluate_audit_posture, fetch_audit_grant_report

    app_role = f"sweepfix_app_{uuid.uuid4().hex[:6]}"
    admin = await asyncpg.connect(_dsn())
    try:
        await _harden_audit_owner_role(admin, app_role)
        report = await fetch_audit_grant_report(_dsn(), app_role)
        enforced, problems = evaluate_audit_posture(report, app_role=app_role)

        # The DB agrees the role can mutate the audit trail...
        can_update = await admin.fetchval(
            "SELECT has_table_privilege($1, 'public.audit_logs', 'UPDATE')", app_role
        )
        # ...and the role can really do it (proven on the real table, rolled back).
        app_conn = await asyncpg.connect(_dsn(app_role, "app-pw"))
        try:
            async with app_conn.transaction():
                await app_conn.execute(
                    'UPDATE audit_logs SET "user" = "user" WHERE false'  # noqa: S608
                )
            mutation_succeeded = True
        finally:
            await app_conn.close()
    finally:
        await _drop_roles(admin, app_role)
        await admin.close()

    assert can_update is True
    assert mutation_succeeded is True
    assert enforced is False, "the verifier certified append-only while UPDATE succeeded (SS-036)"
    assert any("UPDATE" in p and "audit_logs" in p for p in problems)


@pytest.mark.asyncio
async def test_mcp_verifier_detects_inherited_mutate_grant():
    from src.mcp_server.tools import verify_scoped_role

    app_role = f"sweepfix_mcp_{uuid.uuid4().hex[:6]}"
    admin = await asyncpg.connect(_dsn())
    try:
        await _harden_audit_owner_role(admin, app_role)
        # Give the role the rest of the contract so only the inherited write
        # privilege can produce a violation.
        contract = [
            "logs",
            "alerts",
            "rules",
            "correlation_matches",
            "cases",
            "case_events",
            "response_actions",
        ]
        await admin.execute(
            f"GRANT SELECT ON {', '.join(contract)} TO {app_role}"  # noqa: S608
        )
        await admin.execute(  # noqa: S608
            f"GRANT SELECT, INSERT, UPDATE ON agent_investigations TO {app_role}"
        )
        await admin.execute(f"GRANT SELECT, INSERT ON ai_usage TO {app_role}")  # noqa: S608
        await admin.execute(  # noqa: S608
            f"GRANT {app_role}_mutate TO {app_role}"  # already inherited, idempotent
        )

        app_conn = await asyncpg.connect(_dsn(app_role, "app-pw"))
        try:
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(
                    "src.mcp_server.tools.get_pool",
                    AsyncMock(return_value=_single_pool(app_conn)),
                    raising=False,
                )
                violations = await verify_scoped_role(app_role)
        finally:
            await app_conn.close()
    finally:
        await _drop_roles(admin, app_role)
        await admin.close()

    assert any("audit_logs" in v and "UPDATE" in v for v in violations), (
        f"inherited UPDATE not detected: {violations}"
    )


def _single_pool(conn):
    return _SingleConnPool(conn)


# ───────────────────────────────────────────────────────────────
# Detector SQL sanity (SS-019 / SS-024 renumbered binds)
# ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "detector", ["payload_callback", "data_exfiltration", "credential_theft_exfil"]
)
async def test_external_gate_binds_resolve_on_a_real_server(detector):
    """The shared external-IP predicate must PREPARE and run (param counts and
    inet[] typing are only proven by the server)."""
    from src.detection import correlation as corr

    conn = await asyncpg.connect(_dsn())
    try:
        await conn.execute("SET statement_timeout = '15s'")
        result = await corr.CORRELATION_DETECTORS[detector](
            conn, datetime.now(tz=timezone.utc) - timedelta(minutes=1)
        )
    finally:
        await conn.close()
    assert isinstance(result, list)
