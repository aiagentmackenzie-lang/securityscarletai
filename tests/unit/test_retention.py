"""
Tests for data retention (P1-D).

Covers:
- The retention job deletes rows older than the configured window and leaves
  newer rows alone.
- retention_days == 0 skips the table (keep forever).
- Batched deletes drain a backlog across iterations.
- Failures are swallowed (a retention error never raises to the caller).
- The scheduler start/stop helpers wire APScheduler without error.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest


def _row(**kw):
    """A fake asyncpg Record-ish object for DELETE-return-ish tests."""
    return kw


class _FakeConn:
    """Fake asyncpg connection that 'deletes' rows older than cutoff from an
    in-memory list of dicts keyed by `id` with a `time`/`created_at` field.
    Also an async context manager (pool.acquire() returns this)."""

    def __init__(self, table: str, time_col: str, rows: list[dict]):
        self.table = table
        self.time_col = time_col
        self.rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, sql, cutoff, batch_size):
        # The CTE selects rows older than cutoff, LIMIT batch_size. Simulate
        # the DELETE: remove up to batch_size matching rows, return "DELETE N".
        matching = [r for r in self.rows if r[self.time_col] < cutoff]
        to_delete = matching[:batch_size]
        for r in to_delete:
            self.rows.remove(r)
        return f"DELETE {len(to_delete)}"


class _FakePool:
    def __init__(self, conn: _FakeConn):
        self._conn = conn

    def acquire(self):
        return self._conn  # _FakeConn is its own async context manager


def _make_rows(n_old: int, n_new: int, time_col: str = "time") -> list[dict]:
    now = datetime.now(tz=timezone.utc)
    rows = []
    for i in range(n_old):
        rows.append({"id": i, time_col: now - timedelta(days=100)})
    for i in range(n_new):
        rows.append({"id": 1000 + i, time_col: now - timedelta(hours=1)})
    return rows


class TestRunRetentionOnce:
    @pytest.mark.asyncio
    async def test_deletes_old_keeps_new(self, monkeypatch):
        import src.services.retention as r

        rows = _make_rows(n_old=5, n_new=3, time_col="time")
        conn = _FakeConn("logs", "time", rows)
        pool = _FakePool(conn)
        monkeypatch.setattr(r, "get_pool", AsyncMock(return_value=pool))
        monkeypatch.setattr(r.settings, "logs_retention_days", 30)
        monkeypatch.setattr(r.settings, "alerts_retention_days", 0)  # skip
        monkeypatch.setattr(r.settings, "audit_retention_days", 0)
        monkeypatch.setattr(r.settings, "correlation_retention_days", 0)
        monkeypatch.setattr(r.settings, "ai_usage_retention_days", 0)
        monkeypatch.setattr(r.settings, "retention_batch_size", 100)

        results = await r.run_retention_once()
        assert results["logs"] == 5
        # New rows survived.
        assert len(rows) == 3
        assert all(row["id"] >= 1000 for row in rows)

    @pytest.mark.asyncio
    async def test_zero_retention_skips_table(self, monkeypatch):
        import src.services.retention as r

        rows = _make_rows(n_old=5, n_new=0, time_col="time")
        conn = _FakeConn("logs", "time", rows)
        pool = _FakePool(conn)
        monkeypatch.setattr(r, "get_pool", AsyncMock(return_value=pool))
        monkeypatch.setattr(r.settings, "logs_retention_days", 0)
        monkeypatch.setattr(r.settings, "alerts_retention_days", 0)
        monkeypatch.setattr(r.settings, "audit_retention_days", 0)
        monkeypatch.setattr(r.settings, "correlation_retention_days", 0)
        monkeypatch.setattr(r.settings, "ai_usage_retention_days", 0)

        results = await r.run_retention_once()
        assert results["logs"] == -1  # sentinel: disabled
        assert len(rows) == 5  # nothing deleted

    @pytest.mark.asyncio
    async def test_batched_delete_drains_backlog(self, monkeypatch):
        import src.services.retention as r

        rows = _make_rows(n_old=12, n_new=0, time_col="time")
        conn = _FakeConn("logs", "time", rows)
        pool = _FakePool(conn)
        monkeypatch.setattr(r, "get_pool", AsyncMock(return_value=pool))
        monkeypatch.setattr(r.settings, "logs_retention_days", 30)
        monkeypatch.setattr(r.settings, "alerts_retention_days", 0)
        monkeypatch.setattr(r.settings, "audit_retention_days", 0)
        monkeypatch.setattr(r.settings, "correlation_retention_days", 0)
        monkeypatch.setattr(r.settings, "ai_usage_retention_days", 0)
        monkeypatch.setattr(r.settings, "retention_batch_size", 5)  # 12 -> 3 batches

        results = await r.run_retention_once()
        assert results["logs"] == 12
        assert len(rows) == 0

    @pytest.mark.asyncio
    async def test_delete_error_is_swallowed(self, monkeypatch):
        import src.services.retention as r

        class _ErrConn:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def execute(self, sql, cutoff, batch_size):
                raise RuntimeError("permission denied: cannot DELETE audit_logs")

        class _ErrPool:
            def acquire(self):
                return _ErrConn()

        monkeypatch.setattr(r, "get_pool", AsyncMock(return_value=_ErrPool()))
        monkeypatch.setattr(r.settings, "logs_retention_days", 30)
        monkeypatch.setattr(r.settings, "alerts_retention_days", 0)
        monkeypatch.setattr(r.settings, "audit_retention_days", 365)
        monkeypatch.setattr(r.settings, "correlation_retention_days", 0)
        monkeypatch.setattr(r.settings, "ai_usage_retention_days", 0)

        # Must not raise — a retention error must not crash the scheduler.
        results = await r.run_retention_once()
        assert results["logs"] == -2  # error sentinel
        assert results["audit_logs"] == -2


class TestParseRowcount:
    def test_delete_n(self):
        from src.services.retention import _parse_rowcount

        assert _parse_rowcount("DELETE 7") == 7
        assert _parse_rowcount("DELETE 0") == 0

    def test_garbage(self):
        from src.services.retention import _parse_rowcount

        assert _parse_rowcount("not a status") == 0
        assert _parse_rowcount("") == 0


class TestSchedulerLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop_scheduler(self, monkeypatch):
        import src.services.retention as r

        # APScheduler is a real dep; start then stop should not raise.
        await r.start_retention_scheduler()
        assert r._async_scheduler is not None
        await r.stop_retention_scheduler()
        # _async_scheduler remains set but shut down; the point is no raise.
