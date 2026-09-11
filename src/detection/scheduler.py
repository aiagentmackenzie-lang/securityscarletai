"""
Detection rule scheduler using APScheduler.

Replaces Celery+Redis for single-machine deployments.
Schedules Sigma rules to run at configured intervals.

V0.3 hardening (live-fire finding, 2026-09-11): the scheduler froze the
whole API when a tick had >= pool-size rules with matches. Root cause:
run_rule HELD its pool connection across create_alert (which acquires a
SECOND connection) and the LLM enrichment (30s each, per match) -- with
every connection held awaiting another one, the pool dead-locked forever
(DB idle, CPU 0%, health hangs). Fixes:
  1. NO connection is held across alert creation or enrichment.
  2. LLM enrichment is fire-and-forget (bounded), never awaited in the
     scheduler path -- the ai_summary column was always documented as
     "filled async"; the awaited-inline version contradicted that.
  3. The rule query is bounded by RULE_QUERY_TIMEOUT -- a slow query
     fails the rule (fail-closed, logged) instead of wedging the tick.
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.alerts import create_alert
from src.detection.sigma import sigma_to_sql

log = get_logger("detection.scheduler")

scheduler = AsyncIOScheduler()

RULE_QUERY_TIMEOUT_SECONDS = 60
_ENRICH_MAX_CONCURRENT = 2
_enrich_semaphore = None  # created lazily inside the running loop
_enrich_tasks: set = set()  # F-17: keep fire-and-forget tasks GC-alive


def _get_enrich_semaphore():
    """Lazy semaphore bound to the running loop (recreated after restarts)."""
    global _enrich_semaphore
    if _enrich_semaphore is None:
        import asyncio

        _enrich_semaphore = asyncio.Semaphore(_ENRICH_MAX_CONCURRENT)
    return _enrich_semaphore


def _schedule_enrichment(alert_id: int, rule: dict, row: dict) -> None:
    """Fire-and-forget AI enrichment for one alert, bounded by a semaphore.

    The scheduler tick must NEVER block on the LLM: an Ollama call is up to
    30s per alert, and N matched alerts would hold the tick (and, in the
    old shape, its pool connection) for minutes. Failures are logged; the
    alert simply ships without ai_summary (documented async fill).
    """
    import asyncio

    from src.detection.ai_analyzer import analyze_alert, enrich_alert

    async def _run() -> None:
        async with _get_enrich_semaphore():
            analysis = await analyze_alert(
                alert_id=alert_id,
                rule_name=rule["name"],
                severity=rule["severity"],
                host_name=row.get("host_name", "unknown"),
                evidence=dict(row),
            )
            if analysis:
                await enrich_alert(alert_id, analysis)

    task = asyncio.create_task(_run())
    _enrich_tasks.add(task)
    task.add_done_callback(_enrich_tasks.discard)


async def run_rule(rule_id: int) -> None:
    """
    Execute a single detection rule against recent logs.

    Steps:
    1. Load rule from database
    2. Generate SQL from Sigma YAML
    3. Execute query (bounded -- a slow query fails the rule, never the API)
    4. Create alerts if matches found (NO connection held across this)
    """
    import asyncio

    log.info("running_rule", rule_id=rule_id)

    pool = await get_pool()
    async with pool.acquire() as conn:
        # Load rule
        rule = await conn.fetchrow("SELECT * FROM rules WHERE id = $1 AND enabled = TRUE", rule_id)

    if not rule:
        log.warning("rule_not_found_or_disabled", rule_id=rule_id)
        return

    try:
        # Parse Sigma and generate SQL
        sql, params = sigma_to_sql(rule["sigma_yaml"])

        # Execute detection query -- bounded: a slow/heavy query fails THIS
        # rule (fail-closed) instead of wedging a connection for minutes.
        async with pool.acquire() as conn:
            rows = await asyncio.wait_for(
                conn.fetch(sql, *params), timeout=RULE_QUERY_TIMEOUT_SECONDS
            )

        if rows:
            log.info("rule_matched", rule_id=rule_id, matches=len(rows))

            # Create alerts WITHOUT holding a connection: create_alert
            # acquires its own; enrichment is fire-and-forget (bounded). A
            # tick with many matching rules must never starve the pool.
            for row in rows:
                try:
                    alert_id = await create_alert(
                        rule_id=rule_id,
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        host_name=row.get("host_name", "unknown"),
                        description=f"Detection: {rule['description']}",
                        mitre_tactics=rule["mitre_tactics"],
                        mitre_techniques=rule["mitre_techniques"],
                        evidence=dict(row),
                        risk_score=None,
                    )
                    if alert_id:
                        _schedule_enrichment(alert_id, rule, row)
                except Exception as e:
                    log.error(
                        "rule_alert_create_failed",
                        rule_id=rule_id,
                        error=str(e),
                    )

        # Update rule stats (match + last_run in single update) -- short
        # acquisition, never held across alert/enrichment work.
        async with pool.acquire() as conn:
            if rows:
                await conn.execute(
                    "UPDATE rules SET last_match = NOW(), match_count = match_count + $1, "
                    "last_run = NOW() WHERE id = $2",
                    len(rows),
                    rule_id,
                )
            else:
                await conn.execute("UPDATE rules SET last_run = NOW() WHERE id = $1", rule_id)

    except asyncio.TimeoutError:
        log.error(
            "rule_query_timeout",
            rule_id=rule_id,
            timeout=RULE_QUERY_TIMEOUT_SECONDS,
        )
    except Exception as e:
        log.error("rule_execution_failed", rule_id=rule_id, error=str(e))


async def schedule_rules() -> None:
    """Schedule all enabled detection rules."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rules = await conn.fetch("SELECT id, run_interval FROM rules WHERE enabled = TRUE")

    for rule in rules:
        interval_seconds = rule["run_interval"].total_seconds()

        scheduler.add_job(
            run_rule,
            trigger=IntervalTrigger(seconds=interval_seconds),
            args=[rule["id"]],
            id=f"rule_{rule['id']}",
            replace_existing=True,
        )
        log.info("scheduled_rule", rule_id=rule["id"], interval=interval_seconds)

    # P2-25: schedule the triage auto-retrain check (runs hourly). Triggers a
    # retrain once >=100 alerts have been resolved since the last training run.
    # Lazy import to avoid a src.detection -> src.api import cycle at module load.
    from src.api.ai import auto_train_check

    scheduler.add_job(
        auto_train_check,
        trigger=IntervalTrigger(hours=1),
        id="auto_train_check",
        replace_existing=True,
    )
    log.info("scheduled_auto_train_check", interval_hours=1)

    # Idempotent start: reload_rules() (called after rule CRUD) re-enters
    # schedule_rules; scheduler.start() raises SchedulerAlreadyRunningError if
    # already running, which would 500 every rule mutation after the first.
    if not scheduler.running:
        scheduler.start()
    log.info("scheduler_started", rules_scheduled=len(rules))


async def stop_scheduler() -> None:
    """Stop the scheduler."""
    scheduler.shutdown()
    log.info("scheduler_stopped")


async def reload_rules() -> None:
    """Reload and reschedule all rules (call after rule CRUD operations)."""
    scheduler.remove_all_jobs()
    await schedule_rules()
    log.info("rules_reloaded")
