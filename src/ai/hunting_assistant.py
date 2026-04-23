"""
AI Hunting Assistant.

Suggests threat hunting queries and investigations based on:
- Current alert patterns
- Data anomalies
- Threat intelligence
- User behavior deviations
"""
import json
from typing import Dict, List, Optional

from src.ai.ollama_client import query_llm
from src.config.logging import get_logger

log = get_logger("ai.hunting")


HUNTING_SYSTEM_PROMPT = """You are a threat hunting expert suggesting investigation queries.
Based on security data patterns, suggest specific hunting queries.

Your suggestions should:
- Focus on IOCs, TTPs, and behavioral anomalies
- Include both specific and broad queries
- Prioritize by likelihood of finding threats
- Be actionable (queries an analyst can run)

Format as numbered list with:
1. Query name
2. What to look for
3. Why it matters
4. Suggested query/SQL"""


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
    context = f"""Security Environment Summary:
- Critical alerts (24h): {alert_summary.get('critical', 0)}
- High alerts (24h): {alert_summary.get('high', 0)}
- Total alerts (24h): {alert_summary.get('total', 0)}

Top Hosts by Activity: {', '.join(top_hosts[:5])}
Top Users: {', '.join(top_users[:5])}
Recent IOCs: {', '.join(recent_iocs[:10]) if recent_iocs else 'None detected'}
"""

    prompt = f"""Based on this security environment, suggest 5 threat hunting queries:

{context}

Suggest specific hunting queries that would help find:
1. Lateral movement
2. Persistence mechanisms
3. Data exfiltration
4. Command & control
5. Insider threats

For each query, provide:
- Query name
- What to search for (in plain English)
- Why this query matters
- Suggested SQL or search syntax"""

    log.info("generating_hunting_suggestions")

    response = await query_llm(
        prompt=prompt,
        system_prompt=HUNTING_SYSTEM_PROMPT,
        temperature=0.3,
        max_tokens=800,
    )

    # Parse suggestions (simple structure)
    suggestions = []
    current = {}

    for line in response.split('\n'):
        line = line.strip()
        if not line:
            continue

        if line[0].isdigit() and '.' in line[:3]:
            if current:
                suggestions.append(current)
            current = {"name": line.split('.', 1)[1].strip(), "description": ""}
        elif line.startswith('-') or line.startswith('•'):
            if current:
                current["description"] += line[1:].strip() + " "
        elif 'sql' in line.lower() or 'select' in line.lower():
            if current:
                current["sql"] = line

    if current:
        suggestions.append(current)

    return suggestions if suggestions else [{"name": "Custom Hunting", "description": response}]


async def analyze_hunting_results(
    query_name: str,
    result_count: int,
    sample_results: List[Dict],
) -> str:
    """
    Analyze hunting query results and suggest next steps.
    
    Args:
        query_name: Name of the hunting query
        result_count: Number of results returned
        sample_results: Sample of results for analysis
    
    Returns:
        Analysis and recommendations
    """
    context = f"""Hunting Query: {query_name}
Results Found: {result_count}

Sample Results:
{json.dumps(sample_results[:3], indent=2, default=str)[:500]}
"""

    prompt = f"""Analyze these threat hunting results:

{context}

Provide:
1. Assessment (normal vs suspicious)
2. Key observations
3. Recommended next steps
4. Whether to create a detection rule from this query"""

    log.info("analyzing_hunting_results", query=query_name, count=result_count)

    analysis = await query_llm(
        prompt=prompt,
        system_prompt="You are a threat hunter analyzing query results.",
        temperature=0.2,
        max_tokens=400,
    )

    return analysis


# Pre-defined hunting queries (templates)
HUNTING_QUERY_TEMPLATES = [
    {
        "name": "Lateral Movement - New Service Accounts",
        "category": "persistence",
        "sql": """
            SELECT DISTINCT user_name, host_name, COUNT(*) as login_count
            FROM logs
            WHERE event_category = 'authentication'
              AND time > NOW() - INTERVAL '24 hours'
              AND user_name LIKE '%$%' OR user_name LIKE 'svc_%'
            GROUP BY user_name, host_name
            HAVING COUNT(*) < 5
            ORDER BY login_count ASC
        """,
        "description": "Find new service accounts with low login counts (possible lateral movement)",
    },
    {
        "name": "Data Staging - Large File Operations",
        "category": "collection",
        "sql": """
            SELECT host_name, file_path, COUNT(*) as access_count
            FROM logs
            WHERE event_category = 'file'
              AND time > NOW() - INTERVAL '4 hours'
              AND file_path LIKE '%/tmp/%' OR file_path LIKE '%/var/tmp/%'
            GROUP BY host_name, file_path
            HAVING COUNT(*) > 100
            ORDER BY access_count DESC
        """,
        "description": "Find hosts with unusual file activity in temp directories",
    },
    {
        "name": "C2 Beaconing - Regular Connections",
        "category": "command_and_control",
        "sql": """
            SELECT destination_ip, COUNT(*) as connection_count,
                   MIN(time) as first_seen, MAX(time) as last_seen
            FROM logs
            WHERE event_category = 'network'
              AND time > NOW() - INTERVAL '6 hours'
              AND destination_port NOT IN (80, 443, 53)
            GROUP BY destination_ip
            HAVING COUNT(*) > 20
            ORDER BY connection_count DESC
        """,
        "description": "Find IPs with regular connections (possible C2 beaconing)",
    },
    {
        "name": "Privilege Escalation - Sudo Pattern",
        "category": "privilege_escalation",
        "sql": """
            SELECT user_name, host_name, COUNT(*) as sudo_count
            FROM logs
            WHERE event_category = 'process'
              AND time > NOW() - INTERVAL '1 hour'
              AND (process_cmdline ILIKE '%sudo%' OR process_name = 'sudo')
            GROUP BY user_name, host_name
            HAVING COUNT(*) > 5
            ORDER BY sudo_count DESC
        """,
        "description": "Find users with unusual sudo activity",
    },
]


def get_hunting_templates() -> List[Dict]:
    """Get pre-defined hunting query templates."""
    return HUNTING_QUERY_TEMPLATES


async def suggest_custom_rule_from_hunt(
    hunt_query: str,
    results: List[Dict],
) -> Optional[Dict]:
    """
    Suggest a Sigma detection rule based on successful hunt.
    
    Takes hunting query results and generates a detection rule.
    """
    if not results:
        return None

    context = f"""Successful Hunting Query:
SQL: {hunt_query[:200]}

Results Sample:
{json.dumps(results[:2], indent=2, default=str)[:300]}

Suggest a Sigma detection rule YAML that would catch this activity automatically."""

    prompt = f"""Convert this hunting query into a Sigma detection rule:

{context}

Generate a Sigma rule YAML with:
- title
- description
- logsource (category: process/network/file)
- detection logic
- severity
- tags (MITRE ATT&CK)"""

    log.info("generating_rule_from_hunt")

    sigma_yaml = await query_llm(
        prompt=prompt,
        system_prompt="You are a detection engineer creating Sigma rules.",
        temperature=0.2,
        max_tokens=500,
    )

    # Extract YAML from response
    if 'title:' in sigma_yaml:
        return {"sigma_yaml": sigma_yaml}

    return None
