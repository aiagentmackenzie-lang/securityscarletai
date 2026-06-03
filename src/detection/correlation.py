"""
Correlation Engine v3 — Event-driven, point-in-time safe.

Detects attack chains by correlating events across time windows.
Changes from v2:
- Every SQL query takes an `as_of` datetime and binds it as $1::timestamptz
  (or the relevant position). NO `NOW()` in query strings.
- Each rule function: `def rule(conn, as_of: datetime) -> list[dict]`
  with no hardcoded windows in the function body — windows are SQL params.
- run_all_correlations(as_of, persist) returns
  `{"matches": [...], "total_matches": N, "persisted": N}`
- When `persist=True`, writes each match into `correlation_matches` with
  a fresh correlation_id (uuid) and severity from CORRELATION_RULES.

Event-driven trigger (Agent B's responsibility — NOT implemented in this
sprint):
  After batch insert into `logs` (src/db/writer.py around line 124),
  call `asyncio.create_task(run_correlations_for_host(host))`. This file
  documents the seam in the run_all_correlations docstring; the actual
  trigger wiring is left to Agent B.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.alerts import create_alert

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
    "credential_theft_exfil": {
        "title": "Credential Access → External Connection",
        "description": (
            "Access to sensitive credential files followed by outbound "
            "network connection"
        ),
        "severity": "critical",
        "mitre_tactics": ["TA0006", "TA0010"],
        "mitre_techniques": ["T1555", "T1048"],
        "confidence_base": 80,
    },
    "defense_evasion_cleanup": {
        "title": "Suspicious Activity → Log Deletion",
        "description": "High-severity process execution followed by log file deletion",
        "severity": "high",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1070"],
        "confidence_base": 75,
    },
}


# ───────────────────────────────────────────────────────────────
# Per-rule correlation queries
#
# Each function:
#   - Takes (conn, as_of, **kwargs) — `as_of` is the point-in-time
#     boundary. Lookback windows are SQL parameters, not NOW() calls.
#   - Returns list of dicts, each with `correlation_rule` and
#     `correlation_id` (uuid4) populated.
# ───────────────────────────────────────────────────────────────


async def detect_brute_force_then_success(
    conn,
    as_of: datetime,
    failed_threshold: int = 3,
    time_window_minutes: int = 5,
    lookback_hours: int = 24,
) -> List[Dict[str, Any]]:
    """Detect: N failed logins followed by success from same source.

    SQL: window function counts preceding failures per (host, IP) and
    flags successful logins that exceed the threshold. All dynamic
    values are parameterized. Column names are hardcoded.
    """
    sql = """
    WITH login_sequence AS (
        SELECT
            host_name,
            source_ip,
            event_action,
            time,
            user_name,
            COUNT(*) FILTER (WHERE event_action LIKE $2)
                OVER (
                    PARTITION BY host_name, source_ip
                    ORDER BY time
                    RANGE BETWEEN INTERVAL '1 minute' * $3 PRECEDING AND CURRENT ROW
                ) AS failed_count
        FROM logs
        WHERE event_category = 'authentication'
          AND time > $1::timestamptz - INTERVAL '1 hour' * $4
          AND time <= $1::timestamptz
    )
    SELECT
        host_name,
        source_ip,
        user_name,
        time AS success_time,
        failed_count
    FROM login_sequence
    WHERE event_action LIKE $5
      AND failed_count >= $6
    ORDER BY time DESC
    """

    rows = await conn.fetch(
        sql,
        as_of,                  # $1 — point-in-time upper bound
        "%failed%",            # $2 — failed action pattern
        time_window_minutes,   # $3 — window minutes
        lookback_hours,        # $4 — lookback hours
        "%success%",           # $5 — success action pattern
        failed_threshold,      # $6 — threshold
    )
    results = []
    for row in rows:
        d = dict(row)
        d["correlation_rule"] = "brute_force_success"
        d["correlation_id"] = str(uuid.uuid4())
        d["severity"] = CORRELATION_RULES["brute_force_success"]["severity"]
        d["title"] = CORRELATION_RULES["brute_force_success"]["title"]
        d["mitre_tactics"] = CORRELATION_RULES["brute_force_success"]["mitre_tactics"]
        d["mitre_techniques"] = CORRELATION_RULES["brute_force_success"]["mitre_techniques"]
        d["confidence"] = min(
            CORRELATION_RULES["brute_force_success"]["confidence_base"]
            + (d.get("failed_count", 0) - 3) * 5,
            100,
        )
        results.append(d)
    return results


async def detect_payload_callback(
    conn,
    as_of: datetime,
    time_window_minutes: int = 10,
    lookback_hours: int = 24,
) -> List[Dict[str, Any]]:
    """Detect: Process from /tmp → Network connection (dropped payload)."""
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
          AND file_path LIKE $2
          AND time > $1::timestamptz - INTERVAL '1 hour' * $3
          AND time <= $1::timestamptz
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
          AND time > $1::timestamptz - INTERVAL '1 hour' * $3
          AND time <= $1::timestamptz
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
        AND n.conn_time < t.proc_time + INTERVAL '1 minute' * $4
    ORDER BY t.proc_time DESC
    """

    rows = await conn.fetch(
        sql,
        as_of,                  # $1
        "%/tmp/%",             # $2
        lookback_hours,        # $3
        time_window_minutes,   # $4
    )
    results = []
    for row in rows:
        d = dict(row)
        d["correlation_rule"] = "payload_callback"
        d["correlation_id"] = str(uuid.uuid4())
        d["severity"] = CORRELATION_RULES["payload_callback"]["severity"]
        d["title"] = CORRELATION_RULES["payload_callback"]["title"]
        d["mitre_tactics"] = CORRELATION_RULES["payload_callback"]["mitre_tactics"]
        d["mitre_techniques"] = CORRELATION_RULES["payload_callback"]["mitre_techniques"]
        d["confidence"] = CORRELATION_RULES["payload_callback"]["confidence_base"]
        results.append(d)
    return results


async def detect_persistence_activated(
    conn,
    as_of: datetime,
    time_window_minutes: int = 30,
    lookback_hours: int = 24,
) -> List[Dict[str, Any]]:
    """Detect: File creation in LaunchAgents → launchctl load."""
    sql = """
    WITH agent_creation AS (
        SELECT
            host_name,
            file_path,
            time AS creation_time,
            user_name
        FROM logs
        WHERE event_category = 'file'
          AND file_path LIKE $2
          AND time > $1::timestamptz - INTERVAL '1 hour' * $3
          AND time <= $1::timestamptz
    ),
    launchctl_loads AS (
        SELECT
            host_name,
            process_cmdline,
            time AS load_time
        FROM logs
        WHERE event_category = 'process'
          AND process_name = 'launchctl'
          AND process_cmdline LIKE $4
          AND time > $1::timestamptz - INTERVAL '1 hour' * $3
          AND time <= $1::timestamptz
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
        AND l.load_time < a.creation_time + INTERVAL '1 minute' * $5
    ORDER BY a.creation_time DESC
    """

    rows = await conn.fetch(
        sql,
        as_of,                  # $1
        "%LaunchAgents%",      # $2
        lookback_hours,        # $3
        "%load%",              # $4
        time_window_minutes,   # $5
    )
    results = []
    for row in rows:
        d = dict(row)
        d["correlation_rule"] = "persistence_activated"
        d["correlation_id"] = str(uuid.uuid4())
        d["severity"] = CORRELATION_RULES["persistence_activated"]["severity"]
        d["title"] = CORRELATION_RULES["persistence_activated"]["title"]
        d["mitre_tactics"] = CORRELATION_RULES["persistence_activated"]["mitre_tactics"]
        d["mitre_techniques"] = CORRELATION_RULES["persistence_activated"]["mitre_techniques"]
        d["confidence"] = CORRELATION_RULES["persistence_activated"]["confidence_base"]
        results.append(d)
    return results


async def detect_data_exfiltration(
    conn,
    as_of: datetime,
    threshold_bytes: int = 100_000_000,  # 100 MB
    time_window_hours: int = 1,
    lookback_hours: int = 24,
) -> List[Dict[str, Any]]:
    """Detect: Large outbound transfer (data exfiltration)."""
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
          AND NOT destination_ip <<= $2::inet
          AND NOT destination_ip <<= $3::inet
          AND NOT destination_ip <<= $4::inet
          AND time > $1::timestamptz - INTERVAL '1 hour' * $5
          AND time <= $1::timestamptz
        GROUP BY host_name, destination_ip
        HAVING SUM(COALESCE((enrichment->>'bytes_sent')::bigint, 0)) > $6
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

    rows = await conn.fetch(
        sql,
        as_of,                  # $1
        "10.0.0.0/8",          # $2 — RFC1918 range 1
        "192.168.0.0/16",      # $3 — RFC1918 range 2
        "172.16.0.0/12",       # $4 — RFC1918 range 3
        lookback_hours,        # $5
        threshold_bytes,       # $6
    )
    results = []
    for row in rows:
        d = dict(row)
        d["correlation_rule"] = "data_exfiltration"
        d["correlation_id"] = str(uuid.uuid4())
        d["severity"] = CORRELATION_RULES["data_exfiltration"]["severity"]
        d["title"] = CORRELATION_RULES["data_exfiltration"]["title"]
        d["mitre_tactics"] = CORRELATION_RULES["data_exfiltration"]["mitre_tactics"]
        d["mitre_techniques"] = CORRELATION_RULES["data_exfiltration"]["mitre_techniques"]
        # Higher volume = higher confidence
        extra = min(int((d.get("total_bytes", 0) - threshold_bytes) / threshold_bytes * 10), 25)
        d["confidence"] = min(
            CORRELATION_RULES["data_exfiltration"]["confidence_base"] + extra, 100
        )
        results.append(d)
    return results


async def detect_privilege_escalation_chain(
    conn,
    as_of: datetime,
    time_window_minutes: int = 10,
    lookback_hours: int = 24,
) -> List[Dict[str, Any]]:
    """Detect: Privilege escalation → New process as root."""
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
          AND time > $1::timestamptz - INTERVAL '1 hour' * $2
          AND time <= $1::timestamptz
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
          AND time > $1::timestamptz - INTERVAL '1 hour' * $2
          AND time <= $1::timestamptz
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
        AND r.root_time < p.priv_time + INTERVAL '1 minute' * $3
    ORDER BY p.priv_time DESC
    """

    rows = await conn.fetch(
        sql,
        as_of,                  # $1
        lookback_hours,        # $2
        time_window_minutes,   # $3
    )
    results = []
    for row in rows:
        d = dict(row)
        d["correlation_rule"] = "privilege_escalation_chain"
        d["correlation_id"] = str(uuid.uuid4())
        d["severity"] = CORRELATION_RULES["privilege_escalation_chain"]["severity"]
        d["title"] = CORRELATION_RULES["privilege_escalation_chain"]["title"]
        d["mitre_tactics"] = CORRELATION_RULES["privilege_escalation_chain"]["mitre_tactics"]
        d["mitre_techniques"] = CORRELATION_RULES["privilege_escalation_chain"]["mitre_techniques"]
        d["confidence"] = CORRELATION_RULES["privilege_escalation_chain"]["confidence_base"]
        results.append(d)
    return results


async def detect_credential_theft_exfil(
    conn,
    as_of: datetime,
    time_window_minutes: int = 15,
    lookback_hours: int = 24,
) -> List[Dict[str, Any]]:
    """Detect: SSH credential access → Outbound connection."""
    sql = """
    WITH cred_access AS (
        SELECT
            host_name,
            user_name,
            process_name,
            file_path,
            time AS access_time
        FROM logs
        WHERE event_category = 'file'
          AND file_path LIKE $2
          AND time > $1::timestamptz - INTERVAL '1 hour' * $3
          AND time <= $1::timestamptz
    ),
    outbound_connections AS (
        SELECT
            host_name,
            destination_ip,
            destination_port,
            time AS conn_time
        FROM logs
        WHERE event_category = 'network'
          AND event_type = 'connection'
          AND destination_ip IS NOT NULL
          AND NOT destination_ip <<= $4::inet
          AND NOT destination_ip <<= $5::inet
          AND NOT destination_ip <<= $6::inet
          AND time > $1::timestamptz - INTERVAL '1 hour' * $3
          AND time <= $1::timestamptz
    )
    SELECT
        c.host_name,
        c.user_name,
        c.file_path,
        c.access_time,
        o.destination_ip,
        o.conn_time
    FROM cred_access c
    JOIN outbound_connections o
        ON c.host_name = o.host_name
        AND o.conn_time > c.access_time
        AND o.conn_time < c.access_time + INTERVAL '1 minute' * $7
    ORDER BY c.access_time DESC
    """

    rows = await conn.fetch(
        sql,
        as_of,                  # $1
        "%.ssh%",              # $2
        lookback_hours,        # $3
        "10.0.0.0/8",          # $4
        "192.168.0.0/16",      # $5
        "172.16.0.0/12",       # $6
        time_window_minutes,   # $7
    )
    results = []
    for row in rows:
        d = dict(row)
        d["correlation_rule"] = "credential_theft_exfil"
        d["correlation_id"] = str(uuid.uuid4())
        d["severity"] = CORRELATION_RULES["credential_theft_exfil"]["severity"]
        d["title"] = CORRELATION_RULES["credential_theft_exfil"]["title"]
        d["mitre_tactics"] = CORRELATION_RULES["credential_theft_exfil"]["mitre_tactics"]
        d["mitre_techniques"] = CORRELATION_RULES["credential_theft_exfil"]["mitre_techniques"]
        d["confidence"] = CORRELATION_RULES["credential_theft_exfil"]["confidence_base"]
        results.append(d)
    return results


async def detect_defense_evasion_cleanup(
    conn,
    as_of: datetime,
    time_window_minutes: int = 30,
    lookback_hours: int = 24,
) -> List[Dict[str, Any]]:
    """Detect: High-severity process execution → Log file deletion."""
    sql = """
    WITH suspicious_procs AS (
        SELECT
            host_name,
            user_name,
            process_name,
            process_cmdline,
            time AS proc_time
        FROM logs
        WHERE event_category = 'process'
          AND event_type = 'start'
          AND severity = 'high'
          AND time > $1::timestamptz - INTERVAL '1 hour' * $2
          AND time <= $1::timestamptz
    ),
    log_deletions AS (
        SELECT
            host_name,
            process_cmdline AS deletion_cmd,
            time AS deletion_time
        FROM logs
        WHERE event_category = 'process'
          AND process_name = 'rm'
          AND process_cmdline ILIKE $3
          AND time > $1::timestamptz - INTERVAL '1 hour' * $2
          AND time <= $1::timestamptz
    )
    SELECT
        s.host_name,
        s.user_name,
        s.process_name AS suspicious_process,
        s.proc_time,
        l.deletion_cmd,
        l.deletion_time
    FROM suspicious_procs s
    JOIN log_deletions l
        ON s.host_name = l.host_name
        AND l.deletion_time > s.proc_time
        AND l.deletion_time < s.proc_time + INTERVAL '1 minute' * $4
    ORDER BY s.proc_time DESC
    """

    rows = await conn.fetch(
        sql,
        as_of,                  # $1
        lookback_hours,        # $2
        "%var/log%",           # $3
        time_window_minutes,   # $4
    )
    results = []
    for row in rows:
        d = dict(row)
        d["correlation_rule"] = "defense_evasion_cleanup"
        d["correlation_id"] = str(uuid.uuid4())
        d["severity"] = CORRELATION_RULES["defense_evasion_cleanup"]["severity"]
        d["title"] = CORRELATION_RULES["defense_evasion_cleanup"]["title"]
        d["mitre_tactics"] = CORRELATION_RULES["defense_evasion_cleanup"]["mitre_tactics"]
        d["mitre_techniques"] = CORRELATION_RULES["defense_evasion_cleanup"]["mitre_techniques"]
        d["confidence"] = CORRELATION_RULES["defense_evasion_cleanup"]["confidence_base"]
        results.append(d)
    return results


# ───────────────────────────────────────────────────────────────
# Sessionization — group events by host+user into sessions
# ───────────────────────────────────────────────────────────────


async def get_host_sessions(
    host_name: str,
    session_gap_minutes: int = 30,
    lookback_hours: int = 24,
    as_of: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Group events for a host into sessions based on time gaps."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
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
          AND time > $2::timestamptz - INTERVAL '1 hour' * $3
          AND time <= $2::timestamptz
    ),
    session_markers AS (
        SELECT
            *,
            CASE
                WHEN gap_from_prev IS NULL THEN 1
                WHEN gap_from_prev > INTERVAL '1 minute' * $4 THEN 1
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
            as_of,                  # $2
            lookback_hours,         # $3
            session_gap_minutes,    # $4
        )
        return [dict(row) for row in rows]


# ───────────────────────────────────────────────────────────────
# Run all correlations
# ───────────────────────────────────────────────────────────────


async def run_all_correlations(
    as_of: Optional[datetime] = None,
    persist: bool = False,
) -> Dict[str, Any]:
    """Run all correlation rules and return results.

    Args:
        as_of: Point-in-time upper bound. If None, defaults to
            `datetime.utcnow()`. All SQL queries use this as $1::timestamptz.
        persist: If True, write each match into `correlation_matches`
            with a fresh `correlation_id` (uuid).

    Returns:
        Dict with keys:
          - matches: list of match dicts (each with correlation_id)
          - total_matches: int
          - persisted: int (count written when persist=True)
          - as_of: the datetime used for the run (echoed back)
          - per_rule: dict of rule_name -> [match_dicts] (for API consumers)

    Event-driven trigger (Agent B):
        When `persist=True` and called from the ingestion path, this writes
        matches to `correlation_matches`. Manual `POST /correlation/run?persist=true`
        works for retro-hunting. The ingestion-path trigger lives in
        `src/api/ingest.py::_enrich_and_correlate()` (after the batch write),
        invoked as `await run_all_correlations(persist=True)` per the
        Epic 2 contract.
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)

    correlation_funcs = {
        "brute_force_success": detect_brute_force_then_success,
        "payload_callback": detect_payload_callback,
        "persistence_activated": detect_persistence_activated,
        "data_exfiltration": detect_data_exfiltration,
        "privilege_escalation_chain": detect_privilege_escalation_chain,
        "credential_theft_exfil": detect_credential_theft_exfil,
        "defense_evasion_cleanup": detect_defense_evasion_cleanup,
    }

    all_matches: List[Dict[str, Any]] = []
    per_rule: Dict[str, List[Dict[str, Any]]] = {}
    persisted_count = 0

    pool = await get_pool()
    async with pool.acquire() as conn:
        for rule_name, func in correlation_funcs.items():
            try:
                matches = await func(conn, as_of)
                per_rule[rule_name] = matches
                all_matches.extend(matches)
                log.info(
                    "correlation_complete",
                    rule=rule_name,
                    matches=len(matches),
                    as_of=as_of.isoformat(),
                )
            except Exception as e:
                log.error(
                    "correlation_failed",
                    rule=rule_name,
                    error=str(e),
                    as_of=as_of.isoformat(),
                )
                per_rule[rule_name] = []

    if persist and all_matches:
        async with pool.acquire() as conn:
            for match in all_matches:
                try:
                    await conn.execute(
                        """
                        INSERT INTO correlation_matches (
                            correlation_rule, severity, match_data,
                            trigger_event_id, seen, created_at
                        )
                        VALUES ($1, $2, $3::jsonb, $4, FALSE, $5::timestamptz)
                        """,
                        match["correlation_rule"],
                        match.get("severity", "medium"),
                        _serialize_match_data(match),
                        match.get("trigger_event_id"),
                        as_of,
                    )
                    persisted_count += 1
                except Exception as e:
                    log.error(
                        "correlation_persist_failed",
                        rule=match.get("correlation_rule"),
                        correlation_id=match.get("correlation_id"),
                        error=str(e),
                    )

    total_matches = len(all_matches)
    log.info(
        "all_correlations_complete",
        rules_run=len(correlation_funcs),
        total_matches=total_matches,
        persisted=persisted_count,
        as_of=as_of.isoformat(),
    )

    return {
        "matches": all_matches,
        "total_matches": total_matches,
        "persisted": persisted_count,
        "as_of": as_of.isoformat(),
        "per_rule": per_rule,
    }


def _serialize_match_data(match: Dict[str, Any]) -> str:
    """Serialize a match dict to JSON for storage in match_data JSONB.

    Handles datetime objects (which asyncpg cannot serialize natively).
    """
    import json
    from datetime import datetime as _dt
    from decimal import Decimal

    def _default(obj: Any) -> Any:
        if isinstance(obj, _dt):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        return str(obj)

    return json.dumps(match, default=_default)


# ───────────────────────────────────────────────────────────────
# Persistence helpers
# ───────────────────────────────────────────────────────────────


async def persist_match(
    match: Dict[str, Any],
    trigger_event_id: Optional[int] = None,
    as_of: Optional[datetime] = None,
) -> Optional[int]:
    """Persist a single correlation match. Returns the inserted row id, or None on error.

    Args:
        match: The match dict (must include correlation_rule, severity,
            and the rest of the match data).
        trigger_event_id: Optional FK to the logs row that triggered the
            correlation.
        as_of: Point-in-time timestamp for the created_at field. Defaults
            to datetime.utcnow() if not provided.
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row_id = await conn.fetchval(
                """
                INSERT INTO correlation_matches (
                    correlation_rule, severity, match_data,
                    trigger_event_id, seen, created_at
                )
                VALUES ($1, $2, $3::jsonb, $4, FALSE, $5::timestamptz)
                RETURNING id
                """,
                match.get("correlation_rule", "unknown"),
                match.get("severity", "medium"),
                _serialize_match_data(match),
                trigger_event_id,
                as_of,
            )
            return row_id
    except Exception as e:
        log.error(
            "persist_match_failed",
            error=str(e),
            rule=match.get("correlation_rule"),
        )
        return None


async def list_matches(
    rule: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    seen: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List persisted correlation matches with optional filters."""
    pool = await get_pool()
    conditions = []
    params: List[Any] = []
    idx = 1

    if rule:
        conditions.append(f"correlation_rule = ${idx}")
        params.append(rule)
        idx += 1
    if severity:
        conditions.append(f"severity = ${idx}")
        params.append(severity)
        idx += 1
    if since is not None:
        conditions.append(f"created_at >= ${idx}::timestamptz")
        params.append(since)
        idx += 1
    if until is not None:
        conditions.append(f"created_at <= ${idx}::timestamptz")
        params.append(until)
        idx += 1
    if seen is not None:
        conditions.append(f"seen = ${idx}")
        params.append(seen)
        idx += 1

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.extend([limit, offset])
    sql = f"""
        SELECT id, correlation_rule, severity, match_data, trigger_event_id,
               seen, created_at
        FROM correlation_matches
        {where_clause}
        ORDER BY created_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)
    return [dict(row) for row in rows]


async def mark_match_seen(match_id: int) -> bool:
    """Mark a correlation match as reviewed. Returns True if updated."""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE correlation_matches SET seen = TRUE WHERE id = $1",
                match_id,
            )
            # asyncpg returns "UPDATE N"
            return result.endswith(" 1")
    except Exception as e:
        log.error("mark_match_seen_failed", match_id=match_id, error=str(e))
        return False


# ───────────────────────────────────────────────────────────────
# Backwards-compat helpers
# ───────────────────────────────────────────────────────────────


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


# Backward-compat wrapper: old call signature `run_all_correlations(persist_alerts=...)`.
# This preserves any callers that still use the old shape.
async def run_all_correlations_legacy(persist_alerts: bool = False) -> dict:
    """Legacy compatibility: persist_alerts as first positional arg.

    Maps to the new run_all_correlations with persist=persist_alerts.
    Returns the OLD shape (dict[rule_name] -> matches) for compat.
    """
    result = await run_all_correlations(as_of=None, persist=persist_alerts)
    # Build the old shape: {rule_name: [matches]} and recreate alert side-effects
    legacy: Dict[str, List[Dict[str, Any]]] = result["per_rule"]
    if persist_alerts:
        for rule_name, matches in legacy.items():
            for match in matches:
                try:
                    await create_alert(
                        rule_id=None,
                        rule_name=rule_name,
                        severity=match.get("severity", "medium"),
                        host_name=match.get("host_name", ""),
                        description=match.get("title", ""),
                        mitre_tactics=match.get("mitre_tactics", []),
                        mitre_techniques=match.get("mitre_techniques", []),
                        evidence={"match": match},
                    )
                except Exception as e:
                    log.error(
                        "legacy_alert_create_failed",
                        rule=rule_name,
                        error=str(e),
                    )
    return legacy
