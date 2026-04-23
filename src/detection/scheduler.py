"""
Detection rule scheduler using APScheduler.

Replaces Celery+Redis for single-machine deployments.
Schedules Sigma rules to run at configured intervals.
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.alerts import create_alert
from src.detection.sigma import sigma_to_sql

log = get_logger("detection.scheduler")

scheduler = AsyncIOScheduler()


async def run_rule(rule_id: int) -> None:
    """
    Execute a single detection rule against recent logs.
    
    Steps:
    1. Load rule from database
    2. Generate SQL from Sigma YAML
    3. Execute query
    4. Create alerts if matches found
    """
    log.info("running_rule", rule_id=rule_id)

    pool = await get_pool()
    async with pool.acquire() as conn:
        # Load rule
        rule = await conn.fetchrow(
            "SELECT * FROM rules WHERE id = $1 AND enabled = TRUE",
            rule_id
        )

        if not rule:
            log.warning("rule_not_found_or_disabled", rule_id=rule_id)
            return

        try:
            # Parse Sigma and generate SQL
            sql, params = sigma_to_sql(rule["sigma_yaml"])

            # Execute detection query
            rows = await conn.fetch(sql, *params)

            if rows:
                log.info("rule_matched", rule_id=rule_id, matches=len(rows))

                # Create alerts for each match
                for row in rows:
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

                    # AI analysis on new alerts
                    if alert_id:
                        from src.detection.ai_analyzer import analyze_alert, enrich_alert
                        analysis = await analyze_alert(
                            alert_id=alert_id,
                            rule_name=rule["name"],
                            severity=rule["severity"],
                            host_name=row.get("host_name", "unknown"),
                            evidence=dict(row),
                        )
                        if analysis:
                            await enrich_alert(alert_id, analysis)

                # Update rule stats
                await conn.execute(
                    "UPDATE rules SET last_match = NOW(), match_count = match_count + $1 WHERE id = $2",
                    len(rows),
                    rule_id,
                )

                # Update rule stats
                await conn.execute(
                    "UPDATE rules SET last_match = NOW(), match_count = match_count + $1 WHERE id = $2",
                    len(rows),
                    rule_id
                )

            # Update last_run timestamp
            await conn.execute(
                "UPDATE rules SET last_run = NOW() WHERE id = $1",
                rule_id
            )

        except Exception as e:
            log.error("rule_execution_failed", rule_id=rule_id, error=str(e))


async def schedule_rules() -> None:
    """Schedule all enabled detection rules."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rules = await conn.fetch(
            "SELECT id, run_interval FROM rules WHERE enabled = TRUE"
        )

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
