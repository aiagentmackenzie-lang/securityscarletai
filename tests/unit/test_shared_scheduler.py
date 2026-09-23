"""Tests for the SHARED scheduler (C4/W2-E B6b consolidation).

The ONE AsyncIOScheduler (src/services/shared_scheduler.py) now serves all
three periodic domains — detection, retention, threat intel. The
consolidation hazard: detection's rules reload used remove_all_jobs(), which
on a shared instance would also wipe the ops jobs. The named-jobstore split
is the guard; these pins hold it.
"""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.services.shared_scheduler import (
    DETECTION_JOBSTORE,
    get_shared_scheduler,
    stop_shared_scheduler,
)


class TestSharedScheduler:
    @pytest.mark.asyncio
    async def test_one_instance_serves_all_domains(self):
        """C4: the registry is create-once, and a domain start (retention)
        lands its job on the instance detection started — no private
        scheduler instances anywhere."""
        from src.services.retention import (
            start_retention_scheduler,
            stop_retention_scheduler,
        )

        sched = get_shared_scheduler()
        assert get_shared_scheduler() is sched  # registry is create-once

        await start_retention_scheduler()
        try:
            # retention's job landed on the SAME instance detection uses.
            assert sched.get_job("retention_sweep") is not None
        finally:
            await stop_retention_scheduler()

    @pytest.mark.asyncio
    async def test_detection_reload_does_not_wipe_ops_jobs(self):
        """THE consolidation pin: reload_rules() removes ONLY the detection
        jobstore — an ops job sharing the instance (retention sweep) must
        survive, detection jobs get replaced."""
        import src.detection.scheduler as scheduler_mod

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"id": 1, "run_interval": timedelta(seconds=60)}])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        sched = get_shared_scheduler()

        with (
            patch("src.detection.scheduler.get_pool", return_value=mock_pool),
            patch("src.detection.scheduler.sigma_to_sql", return_value=("SELECT 1", [])),
            patch("src.api.ai.auto_train_check", AsyncMock()),
        ):
            await scheduler_mod.schedule_rules()  # starts the shared scheduler
            assert sched.running

            # An ops job lands in the DEFAULT store (retention's own start
            # does exactly this — simulated here without its settings deps).
            from apscheduler.triggers.interval import IntervalTrigger

            ops_marker = AsyncMock()
            sched.add_job(
                ops_marker,
                trigger=IntervalTrigger(hours=6),
                id="retention_sweep",
                replace_existing=True,
            )
            assert sched.get_job("retention_sweep") is not None

            # Detection rules reload — the consolidation hazard.
            await scheduler_mod.reload_rules()

            # Ops job SURVIVED the reload; detection job was replaced.
            assert sched.get_job("retention_sweep") is not None
            assert sched.get_job("rule_1") is not None
            # Store membership: detection-domain jobs sit in the detection
            # store, the ops job in the default store.
            detection_ids = {j.id for j in sched.get_jobs(jobstore=DETECTION_JOBSTORE)}
            default_ids = {j.id for j in sched.get_jobs(jobstore=None) if j.id != "rule_1"}
            assert "rule_1" in detection_ids
            assert "retention_sweep" not in detection_ids
            assert "retention_sweep" in default_ids

    @pytest.mark.asyncio
    async def test_stop_is_idempotent_across_domains(self):
        """Any domain's stop shuts the shared instance down; the rest no-op.

        APScheduler's AsyncIOScheduler.shutdown is DEFERRED
        (call_soon_threadsafe) — running stays True until the loop drains the
        callback, so the pin yields a tick before asserting. The idempotency
        guard in stop_shared_scheduler prevents the queued double-shutdown
        from raising SchedulerNotRunningError inside the loop callback."""
        import asyncio

        sched = get_shared_scheduler()
        sched.start()
        stop_shared_scheduler()
        await asyncio.sleep(0)  # drain the deferred shutdown callback
        assert not sched.running
        stop_shared_scheduler()  # second call — no raise, no double shutdown
        await asyncio.sleep(0)
        assert not sched.running
        stop_shared_scheduler()  # third call — no raise
