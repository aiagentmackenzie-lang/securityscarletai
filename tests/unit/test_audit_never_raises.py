"""SS-046: `log_audit_action`'s "never raises" contract must hold at the pool acquire.

The docstring promises audit can never break a mutation that already committed
(P2-23). The original implementation put `get_pool()` and `pool.acquire()`
OUTSIDE the try, so a DB outage / pool exhaustion raised before the guard and a
successful mutation returned 500 — the client retries and duplicates it.

These tests inject the failure at each seam and assert the absence of the
defect: no exception escapes, and the caller still gets None.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api.audit import log_audit_action


class TestLogAuditActionNeverRaises:
    @pytest.mark.asyncio
    async def test_pool_acquisition_failure_does_not_raise(self):
        """SS-046: `pool.acquire()` raising must be swallowed, not propagated."""
        pool = AsyncMock()
        pool.acquire = MagicMock(side_effect=RuntimeError("pool exhausted"))

        with patch("src.api.audit.get_pool", AsyncMock(return_value=pool)):
            result = await log_audit_action(actor="admin", action="alert.update", target_id=1)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_pool_failure_does_not_raise(self):
        """SS-046: a dead pool (get_pool raises) must not 500 the mutation."""
        with patch("src.api.audit.get_pool", AsyncMock(side_effect=OSError("db down"))):
            result = await log_audit_action(actor="system", action="case.create")

        assert result is None

    @pytest.mark.asyncio
    async def test_insert_failure_still_returns_none(self):
        """The pre-existing guarantee: an INSERT failure returns None."""
        conn = AsyncMock()
        conn.fetchval = AsyncMock(side_effect=RuntimeError("relation does not exist"))
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool = AsyncMock()
        pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.api.audit.get_pool", AsyncMock(return_value=pool)):
            result = await log_audit_action(actor="admin", action="rule.create")

        assert result is None

    @pytest.mark.asyncio
    async def test_failure_is_logged(self):
        """A swallowed audit failure must still be observable in the log."""
        with patch("src.api.audit.get_pool", AsyncMock(side_effect=OSError("db down"))):
            with patch("src.api.audit.log") as log:
                await log_audit_action(actor="admin", action="user.deactivate")

        assert log.error.called
        fields = log.error.call_args.kwargs
        assert fields["action"] == "user.deactivate"
        assert "audit_log_failed" in log.error.call_args.args
