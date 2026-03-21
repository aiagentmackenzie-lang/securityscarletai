"""
Correlation rules for multi-event patterns.

Uses SQL window functions to detect sequences across multiple log events.
"""
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("detection.correlation")


async def detect_brute_force_then_success(
    failed_threshold: int = 3,
    time_window: str = "5 minutes"
) -> list[dict]:
    """
    Detect: N failed logins followed by success from same source.
    
    Classic pattern for brute force attacks that succeeded.
    """
    sql = f"""
    WITH login_sequence AS (
        SELECT 
            host_name,
            source_ip,
            event_action,
            time,
            user_name,
            LAG(event_action, 1) OVER (
                PARTITION BY host_name, source_ip 
                ORDER BY time
            ) as prev_action,
            COUNT(*) FILTER (WHERE event_action LIKE '%%failed%%') 
                OVER (
                    PARTITION BY host_name, source_ip 
                    ORDER BY time 
                    RANGE BETWEEN INTERVAL '{time_window}' PRECEDING AND CURRENT ROW
                ) as failed_count
        FROM logs
        WHERE event_category = 'authentication'
          AND time > NOW() - INTERVAL '10 minutes'
    )
    SELECT 
        host_name,
        source_ip,
        user_name,
        time as success_time,
        failed_count
    FROM login_sequence
    WHERE event_action LIKE '%%success%%'
      AND failed_count >= {failed_threshold}
    ORDER BY time DESC
    """
    
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql)
        return [dict(row) for row in rows]


async def detect_multiple_processes_same_user(
    process_names: list[str],
    threshold: int = 5,
    time_window: str = "1 minute"
) -> list[dict]:
    """
    Detect: Multiple suspicious processes spawned by same user rapidly.
    
    Pattern: Malware spawning many processes.
    """
    placeholders = ", ".join(f"${i+1}" for i in range(len(process_names)))
    
    sql = f"""
    WITH process_spawns AS (
        SELECT 
            host_name,
            user_name,
            process_name,
            time,
            COUNT(*) OVER (
                PARTITION BY host_name, user_name
                ORDER BY time
                RANGE BETWEEN INTERVAL '{time_window}' PRECEDING AND CURRENT ROW
            ) as spawn_count
        FROM logs
        WHERE event_category = 'process'
          AND event_type = 'start'
          AND process_name IN ({placeholders})
          AND time > NOW() - INTERVAL '10 minutes'
    )
    SELECT DISTINCT
        host_name,
        user_name,
        MAX(spawn_count) as max_spawns
    FROM process_spawns
    WHERE spawn_count >= ${len(process_names) + 1}
    GROUP BY host_name, user_name
    """
    
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *process_names, threshold)
        return [dict(row) for row in rows]


async def detect_data_exfiltration_pattern(
    threshold_bytes: int = 100_000_000,  # 100 MB
    time_window: str = "1 hour"
) -> list[dict]:
    """
    Detect: Large outbound data transfer.
    
    Pattern: Data exfiltration to external IP.
    Note: Requires file size in logs (enrichment needed).
    """
    sql = f"""
    SELECT 
        host_name,
        destination_ip,
        COUNT(*) as connection_count,
        SUM(COALESCE((enrichment->>'bytes_sent')::bigint, 0)) as total_bytes
    FROM logs
    WHERE event_category = 'network'
      AND event_type = 'connection'
      AND destination_ip IS NOT NULL
      AND destination_ip NOT LIKE '10.%%'
      AND destination_ip NOT LIKE '192.168.%%'
      AND destination_ip NOT LIKE '172.16.%%'
      AND time > NOW() - INTERVAL '{time_window}'
    GROUP BY host_name, destination_ip
    HAVING SUM(COALESCE((enrichment->>'bytes_sent')::bigint, 0)) > {threshold_bytes}
    ORDER BY total_bytes DESC
    """
    
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql)
        return [dict(row) for row in rows]


async def run_all_correlations() -> dict[str, list[dict]]:
    """Run all correlation rules and return results."""
    results = {}
    
    try:
        results["brute_force_success"] = await detect_brute_force_then_success()
    except Exception as e:
        log.error("correlation_failed", rule="brute_force_success", error=str(e))
        results["brute_force_success"] = []
    
    try:
        suspicious_procs = ["bash", "python", "perl", "ruby"]
        results["process_spam"] = await detect_multiple_processes_same_user(suspicious_procs)
    except Exception as e:
        log.error("correlation_failed", rule="process_spam", error=str(e))
        results["process_spam"] = []
    
    log.info("correlations_complete", rules_run=len(results))
    return results
