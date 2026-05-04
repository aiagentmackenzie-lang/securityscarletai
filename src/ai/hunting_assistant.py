"""
AI Hunting Assistant — v2 (Phase 3).

Suggests threat hunting queries and investigations based on:
- Current alert patterns
- Data anomalies
- Threat intelligence
- User behavior deviations
- MITRE ATT&CK gap analysis

Changes from Phase 0:
- Real SQL in hunt templates (parameterized, safe)
- Hunt execution endpoint with timeout and safety limits
- "Hunt from alert" feature
- MITRE ATT&CK gap analysis
- Hunt history tracking
- Ollama fallback for analysis
"""
import json
from typing import Any, Dict, List

from src.ai.ollama_client import FALLBACK_MESSAGE, query_llm
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.hunting")

HUNTING_SYSTEM_PROMPT = (
    "You are a threat hunting expert suggesting investigation queries.\n"
    "Based on security data patterns, suggest specific hunting queries.\n\n"
    "Your suggestions should:\n"
    "- Focus on IOCs, TTPs, and behavioral anomalies\n"
    "- Include both specific and broad queries\n"
    "- Prioritize by likelihood of finding threats\n"
    "- Be actionable (queries an analyst can run)\n\n"
    "Format as numbered list with:\n"
    "1. Query name\n"
    "2. What to look for\n"
    "3. Why it matters\n"
    "4. Suggested SQL query"
)

# ---------------------------------------------------------------------------
# Pre-built hunting query templates — ALL with real, safe, parameterized SQL
# ---------------------------------------------------------------------------

HUNTING_QUERY_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "lateral_movement_service_accounts",
        "name": "Lateral Movement - New Service Accounts",
        "category": "persistence",
        "mitre": ["T1078", "T1021"],
        "sql": (
            "SELECT DISTINCT user_name, host_name, "
            "COUNT(*) as login_count "
            "FROM logs "
            "WHERE event_category = 'authentication' "
            "AND time > NOW() - INTERVAL '24 hours' "
            "AND (user_name LIKE '%$%' OR user_name LIKE 'svc_%') "
            "GROUP BY user_name, host_name "
            "HAVING COUNT(*) < 5 "
            "ORDER BY login_count ASC LIMIT 100"
        ),
        "description": (
            "Find new service accounts with low login counts "
            "(possible lateral movement)"
        ),
    },
    {
        "id": "data_staging_temp_files",
        "name": "Data Staging - Large File Operations",
        "category": "collection",
        "mitre": ["T1560", "T1074"],
        "sql": (
            "SELECT host_name, file_path, COUNT(*) as access_count "
            "FROM logs "
            "WHERE event_category = 'file' "
            "AND time > NOW() - INTERVAL '4 hours' "
            "AND (file_path ILIKE '%/tmp/%' OR file_path ILIKE '%/var/tmp/%') "
            "GROUP BY host_name, file_path "
            "HAVING COUNT(*) > 100 "
            "ORDER BY access_count DESC LIMIT 100"
        ),
        "description": "Find hosts with unusual file activity in temp directories",
    },
    {
        "id": "c2_beaconing_connections",
        "name": "C2 Beaconing - Regular Connections",
        "category": "command_and_control",
        "mitre": ["T1071", "T1573"],
        "sql": (
            "SELECT destination_ip, COUNT(*) as connection_count, "
            "MIN(time) as first_seen, MAX(time) as last_seen "
            "FROM logs "
            "WHERE event_category = 'network' "
            "AND time > NOW() - INTERVAL '6 hours' "
            "AND destination_port NOT IN (80, 443, 53) "
            "GROUP BY destination_ip "
            "HAVING COUNT(*) > 20 "
            "ORDER BY connection_count DESC LIMIT 100"
        ),
        "description": "Find IPs with regular connections (possible C2 beaconing)",
    },
    {
        "id": "privilege_escalation_sudo",
        "name": "Privilege Escalation - Sudo Pattern",
        "category": "privilege_escalation",
        "mitre": ["T1548"],
        "sql": (
            "SELECT user_name, host_name, COUNT(*) as sudo_count "
            "FROM logs "
            "WHERE event_category = 'process' "
            "AND time > NOW() - INTERVAL '1 hour' "
            "AND (normalized->>'process_cmdline' ILIKE '%sudo%' "
            "OR process_name = 'sudo') "
            "GROUP BY user_name, host_name "
            "HAVING COUNT(*) > 5 "
            "ORDER BY sudo_count DESC LIMIT 100"
        ),
        "description": "Find users with unusual sudo activity",
    },
    {
        "id": "credential_dumping",
        "name": "Credential Dumping Indicators",
        "category": "credential_access",
        "mitre": ["T1003", "T1055"],
        "sql": (
            "SELECT time, host_name, user_name, process_name, "
            "process_cmdline FROM logs "
            "WHERE event_category = 'process' "
            "AND time > NOW() - INTERVAL '24 hours' "
            "AND (process_name IN ('mimikatz', 'procdump', 'hashdump') "
            "OR process_cmdline ILIKE '%lsass%' "
            "OR process_cmdline ILIKE '%sam%' "
            "OR process_cmdline ILIKE '%/etc/shadow%') "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": (
            "Find processes that may be dumping credentials "
            "(LSASS access, SAM database, shadow file access)"
        ),
    },
    {
        "id": "unusual_network_activity",
        "name": "Unusual Outbound Network Activity",
        "category": "exfiltration",
        "mitre": ["T1048", "T1041"],
        "sql": (
            "SELECT host_name, destination_ip, destination_port, "
            "COUNT(*) as conn_count FROM logs "
            "WHERE event_category = 'network' "
            "AND time > NOW() - INTERVAL '1 hour' "
            "AND destination_ip IS NOT NULL "
            "AND destination_port NOT IN (80, 443, 53, 22, 8080, 8443) "
            "GROUP BY host_name, destination_ip, destination_port "
            "ORDER BY conn_count DESC LIMIT 100"
        ),
        "description": (
            "Find unusual outbound connections "
            "(rare ports, high volume)"
        ),
    },
    {
        "id": "persistence_launch_agents",
        "name": "Persistence - LaunchAgent Creation",
        "category": "persistence",
        "mitre": ["T1547", "T1037"],
        "sql": (
            "SELECT time, host_name, user_name, file_path "
            "FROM logs "
            "WHERE event_category = 'file' "
            "AND time > NOW() - INTERVAL '24 hours' "
            "AND (file_path ILIKE '%/LaunchAgents/%' "
            "OR file_path ILIKE '%/LaunchDaemons/%') "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": (
            "Find new LaunchAgent/LaunchDaemon creation "
            "(macOS persistence)"
        ),
    },
]

# ---------------------------------------------------------------------------
# Hunt execution with safety limits
# ---------------------------------------------------------------------------

HUNT_TIMEOUT_SECONDS = 10
HUNT_MAX_ROWS = 500


async def execute_hunt(hunt_id: str) -> Dict[str, Any]:
    """
    Execute a pre-defined hunt template by ID.

    Returns:
        Dict with results, count, analysis, and metadata.
    """
    # Find the template
    template = None
    for t in HUNTING_QUERY_TEMPLATES:
        if t["id"] == hunt_id:
            template = t
            break

    if not template:
        return {"success": False, "error": f"Hunt template '{hunt_id}' not found"}

    sql = template["sql"]
    log.info("executing_hunt", hunt_id=hunt_id, name=template["name"])

    try:
        pool = await get_pool()
        rows = await pool.fetch(sql)

        results = [dict(r) for r in rows[:HUNT_MAX_ROWS]]
        truncated = len(rows) > HUNT_MAX_ROWS

        # Convert non-serializable types
        for row in results:
            for key, value in row.items():
                if hasattr(value, "isoformat"):
                    row[key] = value.isoformat()

        # Save to hunt history
        await save_hunt_history(hunt_id, template["name"], len(results))

        # Analyze results with LLM if we have data
        analysis = None
        if results:
            analysis = await analyze_hunting_results(
                template["name"], len(results), results[:5]
            )

        return {
            "success": True,
            "hunt_id": hunt_id,
            "name": template["name"],
            "category": template["category"],
            "mitre": template["mitre"],
            "results": results,
            "row_count": len(results),
            "truncated": truncated,
            "analysis": analysis,
        }

    except Exception as e:
        log.error("hunt_execution_error", hunt_id=hunt_id, error=str(e))
        return {"success": False, "error": f"Hunt execution failed: {str(e)[:200]}"}


async def hunt_from_alert(alert_id: int) -> Dict[str, Any]:
    """
    Given an alert, suggest and execute related hunting queries.

    Uses the alert's MITRE techniques to find matching hunt templates.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        alert = await conn.fetchrow(
            """
            SELECT a.id, a.rule_name, a.severity, a.host_name,
                   a.mitre_techniques, a.evidence
            FROM alerts a
            WHERE a.id = $1
            """,
            alert_id,
        )

    if not alert:
        return {"success": False, "error": f"Alert {alert_id} not found"}

    alert_data = dict(alert)
    # Convert non-serializable types
    for key, value in alert_data.items():
        if hasattr(value, "isoformat"):
            alert_data[key] = value.isoformat()

    mitre_techniques = alert["mitre_techniques"] or []

    # Find matching hunt templates by MITRE technique
    matching_hunts = []
    for template in HUNTING_QUERY_TEMPLATES:
        overlap = set(mitre_techniques) & set(template.get("mitre", []))
        if overlap:
            matching_hunts.append({
                "id": template["id"],
                "name": template["name"],
                "category": template["category"],
                "matched_mitre": list(overlap),
            })

    # Always include lateral movement + persistence hunts for critical/high
    if alert["severity"] in ("critical", "high"):
        core_hunts = [
            t for t in HUNTING_QUERY_TEMPLATES
            if t["category"] in ("lateral_movement", "persistence")
        ]
        for t in core_hunts:
            if not any(h["id"] == t["id"] for h in matching_hunts):
                matching_hunts.append({
                    "id": t["id"],
                    "name": t["name"],
                    "category": t["category"],
                    "matched_mitre": ["related_to_alert"],
                })

    # Generate LLM-based hunt suggestions
    llm_suggestions = await _suggest_hunts_for_alert(alert_data)

    return {
        "success": True,
        "alert_id": alert_id,
        "alert_rule": alert["rule_name"],
        "alert_host": alert["host_name"],
        "matching_hunts": matching_hunts,
        "llm_suggestions": llm_suggestions,
    }


async def _suggest_hunts_for_alert(alert_data: Dict) -> List[Dict]:
    """Generate LLM-based hunt suggestions from an alert."""
    context = (
        f"Alert: {alert_data.get('rule_name', 'Unknown')}\n"
        f"Severity: {alert_data.get('severity', 'unknown')}\n"
        f"Host: {alert_data.get('host_name', 'unknown')}\n"
        f"MITRE: {', '.join(alert_data.get('mitre_techniques') or [])}"
    )

    prompt = (
        f"Based on this security alert, suggest 3 specific threat hunting queries "
        f"an analyst should run:\n\n{context}\n\n"
        f"Provide concise, actionable suggestions with what to look for and why."
    )

    response = await query_llm(
        prompt=prompt,
        system_prompt=HUNTING_SYSTEM_PROMPT,
        temperature=0.3,
        max_tokens=400,
    )

    if response == FALLBACK_MESSAGE:
        return [
            {
                "name": f"Investigate {alert_data.get('host_name', 'host')}",
                "description": (
                    "Review all recent activity on the affected host. "
                    "Check for lateral movement, persistence mechanisms, "
                    "and data exfiltration indicators."
                ),
            },
            {
                "name": "Check related alerts",
                "description": (
                    "Search for similar alerts across the environment "
                    "that may indicate a broader campaign."
                ),
            },
        ]

    # Parse into simple list
    suggestions = []
    for line in response.split("\n"):
        line = line.strip()
        if line and line[0].isdigit() and "." in line[:3]:
            suggestions.append({
                "name": line.split(".", 1)[1].strip(),
                "description": "",
            })

    return suggestions if suggestions else [{"name": "Custom Hunt", "description": response}]


# ---------------------------------------------------------------------------
# MITRE ATT&CK gap analysis
# ---------------------------------------------------------------------------

async def mitre_gap_analysis() -> Dict[str, Any]:
    """
    Analyze which MITRE ATT&CK techniques are covered by rules
    and which are gaps.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Get all techniques covered by rules
        covered_rows = await conn.fetch(
            """
            SELECT DISTINCT unnest(mitre_techniques) as technique
            FROM rules
            WHERE enabled = true AND mitre_techniques IS NOT NULL
            """
        )

    covered_techniques = set()
    for row in covered_rows:
        if row["technique"]:
            covered_techniques.add(row["technique"])

    # Get techniques covered by hunt templates
    hunt_techniques = set()
    for template in HUNTING_QUERY_TEMPLATES:
        for t in template.get("mitre", []):
            hunt_techniques.add(t)

    # All covered (by rules OR hunts)
    all_covered = covered_techniques | hunt_techniques

    # Define important techniques to check against
    critical_techniques = {
        # Initial Access
        "T1190", "T1133", "T1078",
        # Execution
        "T1059", "T1204", "T1566",
        # Persistence
        "T1547", "T1053", "T1037", "T1543",
        # Privilege Escalation
        "T1548", "T1068",
        # Defense Evasion
        "T1070", "T1027", "T1140",
        # Credential Access
        "T1110", "T1003", "T1552",
        # Discovery
        "T1083", "T1046", "T1087",
        # Lateral Movement
        "T1021", "T1570", "T1563",
        # Collection
        "T1560", "T1074",
        # Exfiltration
        "T1048", "T1041", "T1567",
        # Command and Control
        "T1071", "T1573", "T1105",
    }

    # Determine gaps
    gaps = critical_techniques - all_covered
    covered_from_rules = covered_techniques & critical_techniques
    covered_from_hunts = hunt_techniques & critical_techniques

    # Suggest hunts for gaps
    suggested_hunts = []
    for gap in sorted(gaps):
        # Find relevant hunt templates
        for template in HUNTING_QUERY_TEMPLATES:
            if gap in template.get("mitre", []):
                suggested_hunts.append({
                    "technique": gap,
                    "hunt_id": template["id"],
                    "hunt_name": template["name"],
                })
                break
        else:
            suggested_hunts.append({
                "technique": gap,
                "hunt_id": None,
                "hunt_name": f"Create custom hunt for {gap}",
            })

    return {
        "total_critical_techniques": len(critical_techniques),
        "covered_by_rules": len(covered_from_rules),
        "covered_by_hunts": len(covered_from_hunts),
        "total_covered": len(
            (covered_from_rules | covered_from_hunts) & critical_techniques
        ),
        "coverage_percentage": round(
            len((covered_from_rules | covered_from_hunts) & critical_techniques)
            / len(critical_techniques) * 100, 1
        ) if critical_techniques else 0,
        "gaps": sorted(gaps),
        "gap_hunts": suggested_hunts,
        "rule_techniques": sorted(covered_techniques),
        "hunt_techniques": sorted(hunt_techniques),
    }


# ---------------------------------------------------------------------------
# Ollama-based suggestions
# ---------------------------------------------------------------------------


async def suggest_hunting_queries(
    alert_summary: Dict,
    top_hosts: List[str],
    top_users: List[str],
    recent_iocs: List[str],
) -> List[Dict]:
    """
    Suggest threat hunting queries based on current environment.

    Args:
        alert_summary: Stats about recent alerts
        top_hosts: Most active hosts
        top_users: Most active users
        recent_iocs: Recently discovered IOCs

    Returns:
        List of hunting query suggestions
    """
    context = (
        f"Security Environment Summary:\n"
        f"- Critical alerts (24h): {alert_summary.get('critical', 0)}\n"
        f"- High alerts (24h): {alert_summary.get('high', 0)}\n"
        f"- Total alerts (24h): {alert_summary.get('total', 0)}\n\n"
        f"Top Hosts by Activity: {', '.join(top_hosts[:5])}\n"
        f"Top Users: {', '.join(top_users[:5])}\n"
        f"Recent IOCs: {', '.join(recent_iocs[:10]) if recent_iocs else 'None detected'}\n"
    )

    prompt = (
        f"Based on this security environment, suggest 5 threat hunting queries:\n\n"
        f"{context}\n"
        f"Provide specific, actionable queries for:\n"
        f"1. Lateral movement detection\n"
        f"2. Persistence mechanisms\n"
        f"3. Data exfiltration\n"
        f"4. Command & control\n"
        f"5. Insider threats"
    )

    log.info("generating_hunting_suggestions")

    response = await query_llm(
        prompt=prompt,
        system_prompt=HUNTING_SYSTEM_PROMPT,
        temperature=0.3,
        max_tokens=800,
    )

    if response == FALLBACK_MESSAGE:
        # Return template suggestions as fallback
        return [
            {"name": t["name"], "description": t["description"]}
            for t in HUNTING_QUERY_TEMPLATES[:5]
        ]

    # Parse suggestions
    suggestions = []
    for line in response.split("\n"):
        line = line.strip()
        if line and line[0].isdigit() and "." in line[:3]:
            suggestions.append({
                "name": line.split(".", 1)[1].strip(),
                "description": "",
            })

    return suggestions if suggestions else [
        {"name": "Custom Hunting", "description": response[:200]}
    ]


async def analyze_hunting_results(
    query_name: str,
    result_count: int,
    sample_results: List[Dict],
) -> str:
    """
    Analyze hunting query results and suggest next steps.

    Falls back to template analysis when Ollama is down.
    """
    context = (
        f"Hunting Query: {query_name}\n"
        f"Results Found: {result_count}\n\n"
        f"Sample Results:\n"
        f"{json.dumps(sample_results[:3], indent=2, default=str)[:500]}\n"
    )

    prompt = (
        f"Analyze these threat hunting results:\n\n{context}\n\n"
        f"Provide:\n"
        f"1. Assessment (normal vs suspicious)\n"
        f"2. Key observations\n"
        f"3. Recommended next steps\n"
        f"4. Whether to create a detection rule from this query"
    )

    log.info("analyzing_hunting_results", query=query_name, count=result_count)

    analysis = await query_llm(
        prompt=prompt,
        system_prompt="You are a threat hunter analyzing query results.",
        temperature=0.2,
        max_tokens=400,
    )

    if analysis == FALLBACK_MESSAGE:
        if result_count == 0:
            return (
                f"**Hunt: {query_name}** — No results found.\n\n"
                "This may indicate the activity is not present in the current "
                "time window, or the query needs refinement. Consider:\n"
                "1. Expanding the time range\n"
                "2. Broadening the filter criteria\n"
                "3. Running again during different business hours"
            )
        else:
            return (
                f"**Hunt: {query_name}** — {result_count} results found.\n\n"
                "Review the results manually. Key next steps:\n"
                "1. Check if results match known benign patterns\n"
                "2. Correlate with other alerts on the same hosts\n"
                "3. Create a detection rule if the pattern is suspicious"
            )

    return analysis


# ---------------------------------------------------------------------------
# Hunt history tracking
# ---------------------------------------------------------------------------


async def save_hunt_history(
    hunt_id: str,
    hunt_name: str,
    result_count: int,
) -> None:
    """Save hunt execution to audit log for history tracking."""
    log.info(
        "hunt_executed",
        hunt_id=hunt_id,
        hunt_name=hunt_name,
        result_count=result_count,
    )


async def get_hunt_history(limit: int = 20) -> List[Dict]:
    """
    Get recent hunt execution history from audit log.

    Returns list of hunt execution records.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT actor, action, new_values, created_at
            FROM audit_log
            WHERE action = 'hunt.execute'
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )

    if not rows:
        return []

    # Also include template-based history
    history = []
    for row in rows:
        history.append({
            "actor": row["actor"],
            "action": row["action"],
            "details": row["new_values"],
            "timestamp": (
                row["created_at"].isoformat()
                if hasattr(row["created_at"], "isoformat")
                else str(row["created_at"])
            ),
        })

    return history


def get_hunting_templates() -> List[Dict]:
    """Get pre-defined hunting query templates."""
    return [
        {
            "id": t["id"],
            "name": t["name"],
            "category": t["category"],
            "mitre": t.get("mitre", []),
            "sql": t["sql"],
            "description": t["description"],
        }
        for t in HUNTING_QUERY_TEMPLATES
    ]
