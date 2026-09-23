"""ONE AsyncIOScheduler for every periodic domain job (W2-E/B6b consolidation).

Three separate AsyncIOScheduler instances (detection / retention / threat
intel) meant three misfire surfaces, three shutdown paths, and three copies
of the same W1-G job defaults. One shared scheduler: one config, one boot,
one shutdown.

The consolidation hazard was detection's rules reload: reload_rules used to
call remove_all_jobs(), which on a shared instance would also wipe the ops
jobs (retention sweep, TI refresh). Guarded by NAMED JOBSTORES: every
detection job lands in the "detection" jobstore and reload removes exactly
that store; the ops jobs live in the default store and are never touched by
a reload.
"""

from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# All detection-domain jobs (rules, auto_train_check, scheduled reports) go
# here; reload_rules removes ONLY this store. Ops jobs (retention, TI) use
# the default store.
DETECTION_JOBSTORE = "detection"

# W1-G: explicit job_defaults on the ONE scheduler — APScheduler's defaults
# (~1s grace) silently SKIP jobs under a busy loop; a 60s grace + coalesce +
# max_instances=1 turns a transient misfire into a catch-up run. NOTE
# (W1-G follow-up): APScheduler logs via STDLIB logging — misfire warnings
# surface via logging.lastResort as plain stderr lines, NOT structlog JSON;
# no bridge exists (documented, out of scope).
_scheduler: AsyncIOScheduler | None = None
# One-shot stop guard: AsyncIOScheduler.shutdown is DEFERRED to the event
# loop (run_in_event_loop → call_soon_threadsafe), so ``running`` stays True
# until the loop drains the callback. Without this flag, two stop calls in
# the same tick would queue TWO shutdowns and the second would raise
# SchedulerNotRunningError inside the loop callback (unretrieved noise).
_stopped = False


def get_shared_scheduler() -> AsyncIOScheduler:
    """Create-once shared scheduler. Callers add jobs; each start site guards
    with ``if not scheduler.running`` (APScheduler raises
    SchedulerAlreadyRunningError on a second start)."""
    global _scheduler, _stopped
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(
            jobstores={DETECTION_JOBSTORE: MemoryJobStore()},
            job_defaults={"misfire_grace_time": 60, "coalesce": True, "max_instances": 1},
        )
        _stopped = False
    return _scheduler


def stop_shared_scheduler() -> None:
    """Idempotent shutdown — safe to call from EVERY domain's stop function
    (main.py's lifespan order then doesn't matter; the first stop wins, the
    rest are no-ops). The instance is kept for a potential re-start.

    One-shot per process lifetime: after the first stop the guard short-
    circuits (the deferred callback makes ``running`` unreliable for a tick,
    and re-arming without a real re-start would double-queue shutdowns).
    """
    global _stopped
    _stopped = True
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)
