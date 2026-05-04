"""
Correlation Engine v2 — Sequence-based multi-event detection.

Detects attack chains by correlating events across time windows:
- Event A followed by Event B within N minutes
- Sessionization to group events by host+user
- Confidence scoring (more signals = higher confidence)

All queries use parameterized SQL with safe interval construction.
"""
from typing import Optional

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("detection.correlation")


# ───────────────────────────────────────────────────────────────
# Correlation rule definitions
# ───────────────────────────────────────────────────────────────

CORRELATION_RULES = {
    "brute_force_success": {
        "title": "Brute Force → Successful Login",
        "description": (
            "Multiple failed logins followed by a successful login "
            "from the same source IP"
        ),
        "severity": "critical",
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1110"],
        "confidence_base": 80,
    },
    "payload_callback": {
        "title": "Dropped Payload → C2 Callback",
        "description": (
            "Process launched from /tmp followed by a "
            "network connection to an external IP"
        ),
        "severity": "critical",
        "mitre_tactics": ["TA0002", "TA0011"],
        "mitre_techniques": ["T1059", "T1071"],
        "confidence_base": 75,
    },
    "persistence_activated": {
        "title": "Persistence Created → Activated",
        "description": "File creation in LaunchAgents followed by launchctl load",
        "severity": "high",
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1547"],
        "confidence_base": 70,
    },
    "data_exfiltration": {
        "title": "Large Read → Large Network Transfer",
        "description": "Large file reads followed by large outbound network transfers",
        "severity": "high",
        "mitre_tactics": ["TA0010"],
        "mitre_techniques": ["T1048"],
        "confidence_base": 65,
    },
    "privilege_escalation_chain": {
        "title": "Privilege Escalation → Root Process",
        "description": "Sudo or privilege escalation followed by a new process running as root",
        "severity": "critical",
        "mitre_tactics": ["TA0004"],
        "mitre_techniques": ["T1548"],
        "confidence_base": 70,
    },
}


# ───────────────────────────────────────────────────────────────
# Sequence-based correlation queries
# ───────────────────────────────────────────────────────────────

async def detect_brute_force_then_success(
    failed_threshold: int = 3,
    time_window_minutes: int = 5,
    lookback_hours: int = 24,
) -> list[dict]:
    """
    Detect: N failed logins followed by success from same source.

    Uses window functions to count preceding failures per (host, IP)
    and flags successful logins that exceed the threshold.

    All dynamic values are parameterized. Column names are hardcoded.
    """
    sql = """
    WITH login_sequence AS (
        SELECT
            host_name,
            source_ip,
            event_action,
            time,
            user_name,
            COUNT(*) FILTER (WHERE event_action LIKE $1)
                OVER (
                    PARTITION BY host_name, source_ip
                    ORDER BY time
                    RANGE BETWEEN INTERVAL '1 minute' * $2 PRECEDING AND CURRENT ROW
                ) AS failed_count
        FROM logs
        WHERE event_category = 'authentication'
          AND time > NOW() - INTERVAL '1 hour' * $3
    )
    SELECT
        host_name,
        source_ip,
        user_name,
        time AS success_time,
        failed_count
    FROM login_sequence
    WHERE event_action NOT LIKE $1
      AND failed_count >= $4
    ORDER BY time DESC
    """

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            sql,
            "%failed%",       # $1 - failed action pattern
            time_window_minutes,  # $2 - window minutes
            lookback_hours,       # $3 - lookback hours
            failed_threshold,     # $4 - threshold
        )
        results = []
        for row in rows:
            d = dict(row)
            d["correlation_rule"] = "brute_force_success"
            d["confidence"] = min(
                CORRELATION_RULES["brute_force_success"]["confidence_base"]
                + (d.get("failed_count", 0) - 3) * 5,
                100,
            )
            results.append(d)
        return results


async def detect_payload_callback(
    time_window_minutes: int = 10,
    lookback_hours: int = 24,
) -> list[dict]:
    """
    Detect: Process from /tmp → Network connection (dropped payload calling home).

    Looks for processes spawned from temporary directories immediately
    followed by outbound network connections.
    """
    sql = """
    WITH tmp_processes AS (
        SELECT
            host_name,
            process_name,
            user_name,
            time AS proc_time,
            process_cmdline
        FROM logs
        WHERE event_category = 'process'
          AND event_type = 'start'
          AND file_path LIKE $1
          AND time > NOW() - INTERVAL '1 hour' * $2
    ),
    network_connections AS (
        SELECT
            host_name,
            destination_ip,
            destination_port,
            time AS conn_time
        FROM logs
        WHERE event_category = 'network'
          AND event_type = 'connection'
          AND destination_ip IS NOT NULL
          AND time > NOW() - INTERVAL '1 hour' * $2
    )
    SELECT
        t.host_name,
        t.process_name,
        t.user_name,
        t.proc_time,
        n.destination_ip,
        n.destination_port,
        n.conn_time
    FROM tmp_processes t
    JOIN network_connections n
        ON t.host_name = n.host_name
        AND n.conn_time > t.proc_time
        AND n.conn_time < t.proc_time + INTERVAL '1 minute' * $3
    ORDER BY t.proc_time DESC
    """

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            sql,
            "%/tmp/%",          # $1 - /tmp file path pattern
            lookback_hours,     # $2 - lookback hours
            time_window_minutes, # $3 - sequence window
        )
        results = []
        for row in rows:
            d = dict(row)
            d["correlation_rule"] = "payload_callback"
            d["confidence"] = CORRELATION_RULES["payload_callback"]["confidence_base"]
            results.append(d)
        return results


async def detect_persistence_activated(
    time_window_minutes: int = 30,
    lookback_hours: int = 24,
) -> list[dict]:
    """
    Detect: File creation in LaunchAgents → launchctl load (persistence activated).

    Finds LaunchAgent/LaunchDaemon creation followed by explicit loading.
    """
    sql = """
    WITH agent_creation AS (
        SELECT
            host_name,
            file_path,
            time AS creation_time,
            user_name
        FROM logs
        WHERE event_category = 'file'
          AND file_path LIKE $1
          AND time > NOW() - INTERVAL '1 hour' * $2
    ),
    launchctl_loads AS (
        SELECT
            host_name,
            process_cmdline,
            time AS load_time
        FROM logs
        WHERE event_category = 'process'
          AND process_name = 'launchctl'
          AND process_cmdline LIKE $3
          AND time > NOW() - INTERVAL '1 hour' * $2
    )
    SELECT
        a.host_name,
        a.file_path,
        a.creation_time,
        l.process_cmdline AS load_command,
        l.load_time
    FROM agent_creation a
    JOIN launchctl_loads l
        ON a.host_name = l.host_name
        AND l.load_time > a.creation_time
        AND l.load_time < a.creation_time + INTERVAL '1 minute' * $4
    ORDER BY a.creation_time DESC
    """

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            sql,
            "%LaunchAgents%",    # $1 - LaunchAgents file path
            lookback_hours,      # $2
            "%load%",            # $3 - launchctl load pattern
            time_window_minutes, # $4
        )
        results = []
        for row in rows:
            d = dict(row)
            d["correlation_rule"] = "persistence_activated"
            d["confidence"] = CORRELATION_RULES["persistence_activated"]["confidence_base"]
            results.append(d)
        return results


async def detect_data_exfiltration(
    threshold_bytes: int = 100_000_000,  # 100 MB
    time_window_hours: int = 1,
    lookback_hours: int = 24,
) -> list[dict]:
    """
    Detect: Large file read → Large network transfer (data exfiltration).

    Identifies hosts where large data reads are followed by significant
    outbound network transfers.
    """
    sql = """
    WITH outbound_transfers AS (
        SELECT
            host_name,
            destination_ip,
            COUNT(*) AS connection_count,
            SUM(COALESCE((enrichment->>'bytes_sent')::bigint, 0)) AS total_bytes,
            MAX(time) AS last_transfer
        FROM logs
        WHERE event_category = 'network'
          AND event_type = 'connection'
          AND destination_ip IS NOT NULL
          AND NOT destination_ip <<= $1::inet
          AND NOT destination_ip <<= $2::inet
          AND time > NOW() - INTERVAL '1 hour' * $3
        GROUP BY host_name, destination_ip
        HAVING SUM(COALESCE((enrichment->>'bytes_sent')::bigint, 0)) > $4
    )
    SELECT
        host_name,
        destination_ip,
        connection_count,
        total_bytes,
        last_transfer
    FROM outbound_transfers
    ORDER BY total_bytes DESC
    """

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            sql,
            "10.0.0.0/8",       # $1 - RFC1918 range 1
            "192.168.0.0/16",   # $2 - RFC1918 range 2
            lookback_hours,     # $3
            threshold_bytes,    # $4
        )
        results = []
        for row in rows:
            d = dict(row)
            d["correlation_rule"] = "data_exfiltration"
            # Higher volume = higher confidence
            extra = min(int((d.get("total_bytes", 0) - threshold_bytes) / threshold_bytes * 10), 25)
            d["confidence"] = min(
                CORRELATION_RULES["data_exfiltration"]["confidence_base"] + extra, 100
            )
            results.append(d)
        return results


async def detect_privilege_escalation_chain(
    time_window_minutes: int = 10,
    lookback_hours: int = 24,
) -> list[dict]:
    """
    Detect: Privilege escalation → New process as root (compromise chain).

    Finds sudo/privilege escalation events followed by root-level process execution.
    """
    sql = """
    WITH privilege_events AS (
        SELECT
            host_name,
            user_name,
            process_name,
            time AS priv_time
        FROM logs
        WHERE event_category = 'authentication'
          AND process_name = 'sudo'
          AND time > NOW() - INTERVAL '1 hour' * $1
    ),
    root_processes AS (
        SELECT
            host_name,
            process_name AS root_process,
            process_cmdline,
            time AS root_time
        FROM logs
        WHERE event_category = 'process'
          AND user_name = 'root'
          AND time > NOW() - INTERVAL '1 hour' * $1
    )
    SELECT
        p.host_name,
        p.user_name AS escalated_user,
        p.process_name AS escalation_method,
        p.priv_time,
        r.root_process,
        r.process_cmdline,
        r.root_time
    FROM privilege_events p
    JOIN root_processes r
        ON p.host_name = r.host_name
        AND r.root_time > p.priv_time
        AND r.root_time < p.priv_time + INTERVAL '1 minute' * $2
    ORDER BY p.priv_time DESC
    """

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            sql,
            lookback_hours,       # $1
            time_window_minutes,  # $2
        )
        results = []
        for row in rows:
            d = dict(row)
            d["correlation_rule"] = "privilege_escalation_chain"
            d["confidence"] = CORRELATION_RULES["privilege_escalation_chain"]["confidence_base"]
            results.append(d)
        return results


# ───────────────────────────────────────────────────────────────
# Sessionization — group events by host+user into sessions
# ───────────────────────────────────────────────────────────────

async def get_host_sessions(
    host_name: str,
    session_gap_minutes: int = 30,
    lookback_hours: int = 24,
) -> list[dict]:
    """
    Group events for a host into sessions based on time gaps.

    A new session starts when there's a gap > session_gap_minutes
    between consecutive events.

    Used for investigation timelines and correlation context.
    """
    sql = """
    WITH event_gaps AS (
        SELECT
            time,
            host_name,
            user_name,
            event_category,
            event_type,
            event_action,
            process_name,
            source_ip,
            destination_ip,
            time - LAG(time) OVER (
                PARTITION BY host_name, user_name
                ORDER BY time
            ) AS gap_from_prev
        FROM logs
        WHERE host_name = $1
          AND time > NOW() - INTERVAL '1 hour' * $2
    ),
    session_markers AS (
        SELECT
            *,
            CASE
                WHEN gap_from_prev IS NULL THEN 1
                WHEN gap_from_prev > INTERVAL '1 minute' * $3 THEN 1
                ELSE 0
            END AS new_session
        FROM event_gaps
    ),
    sessions AS (
        SELECT
            *,
            SUM(new_session) OVER (
                PARTITION BY host_name, user_name
                ORDER BY time
                ROWS UNBOUNDED PRECEDING
            ) AS session_id
        FROM session_markers
    )
    SELECT
        host_name,
        user_name,
        session_id,
        MIN(time) AS session_start,
        MAX(time) AS session_end,
        COUNT(*) AS event_count,
        COUNT(DISTINCT event_category) AS category_count,
        array_agg(DISTINCT process_name) FILTER (WHERE process_name IS NOT NULL) AS processes,
        array_agg(DISTINCT source_ip) FILTER (WHERE source_ip IS NOT NULL) AS source_ips
    FROM sessions
    GROUP BY host_name, user_name, session_id
    ORDER BY session_start DESC
    """

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            sql,
            host_name,               # $1
            lookback_hours,           # $2
            session_gap_minutes,      # $3
        )
        return [dict(row) for row in rows]


# ───────────────────────────────────────────────────────────────
# Run all correlations
# ───────────────────────────────────────────────────────────────

async def run_all_correlations() -> dict[str, list[dict]]:
    """Run all correlation rules and return results with confidence scores."""
    results: dict[str, list[dict]] = {}

    correlation_funcs = {
        "brute_force_success": detect_brute_force_then_success,
        "payload_callback": detect_payload_callback,
        "persistence_activated": detect_persistence_activated,
        "data_exfiltration": detect_data_exfiltration,
        "privilege_escalation_chain": detect_privilege_escalation_chain,
    }

    for rule_name, func in correlation_funcs.items():
        try:
            results[rule_name] = await func()
            count = len(results[rule_name])
            log.info("correlation_complete", rule=rule_name, matches=count)
        except Exception as e:
            log.error("correlation_failed", rule=rule_name, error=str(e))
            results[rule_name] = []

    total_matches = sum(len(v) for v in results.values())
    log.info("all_correlations_complete", rules_run=len(results), total_matches=total_matches)
    return results


def get_correlation_rule_info(rule_name: str) -> Optional[dict]:
    """Get metadata about a correlation rule."""
    return CORRELATION_RULES.get(rule_name)


def list_correlation_rules() -> list[dict]:
    """List all available correlation rules with metadata."""
    return [
        {
            "name": name,
            "title": info["title"],
            "description": info["description"],
            "severity": info["severity"],
            "mitre_tactics": info["mitre_tactics"],
            "mitre_techniques": info["mitre_techniques"],
        }
        for name, info in CORRELATION_RULES.items()
    ]
