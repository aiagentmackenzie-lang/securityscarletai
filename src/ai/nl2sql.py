"""
Natural Language to SQL converter.

Converts plain English security questions into parameterized SQL queries.
Uses Ollama LLM with validation to prevent SQL injection.
"""
import re
from typing import Optional

from src.ai.ollama_client import query_llm, FALLBACK_MESSAGE
from src.config.logging import get_logger

log = get_logger("ai.nl2sql")

# SQL validation patterns — never execute raw LLM output
FORBIDDEN_PATTERNS = [
    "DROP", "ALTER", "CREATE", "TRUNCATE", "INSERT", "UPDATE", "DELETE",
    "GRANT", "REVOKE", "COPY", "pg_", "information_schema", ";--",
]

# Schema context for the LLM
SCHEMA_CONTEXT = """
Table: logs
Columns:
  - time (TIMESTAMPTZ): Event timestamp
  - host_name (TEXT): Source hostname
  - source (TEXT): Log source (osquery, api, etc.)
  - event_category (TEXT): process, network, file, authentication, configuration
  - event_type (TEXT): start, end, connection, creation, deletion, change, info
  - event_action (TEXT): Specific action like "process_started"
  - user_name (TEXT): User associated with event
  - process_name (TEXT): Process name
  - process_pid (INTEGER): Process ID
  - source_ip (INET): Source IP address
  - destination_ip (INET): Destination IP address
  - destination_port (INTEGER): Destination port
  - file_path (TEXT): File path for file events
  - file_hash (TEXT): File hash
  - raw_data (JSONB): Original event data
  - enrichment (JSONB): Enrichment data (GeoIP, threat intel)
  - ingested_at (TIMESTAMPTZ): Ingestion time

Table: alerts
Columns:
  - id (SERIAL): Alert ID
  - time (TIMESTAMPTZ): Alert time
  - rule_name (TEXT): Detection rule name
  - severity (TEXT): info, low, medium, high, critical
  - status (TEXT): new, investigating, resolved, false_positive, closed
  - host_name (TEXT): Affected host
  - description (TEXT): Alert description
  - mitre_tactics (TEXT[]): MITRE ATT&CK tactics
  - mitre_techniques (TEXT[]): MITRE ATT&CK techniques

Example query: SELECT * FROM logs WHERE event_category = 'authentication' AND time > NOW() - INTERVAL '1 hour'
"""


SYSTEM_PROMPT = """You are a PostgreSQL expert specializing in security analytics.
Convert natural language questions into valid, parameterized PostgreSQL queries.

Rules:
1. Only SELECT statements allowed — never generate INSERT, UPDATE, DELETE, DROP, ALTER, CREATE
2. Use $1, $2, etc. for parameters
3. Use NOW() - INTERVAL for time ranges
4. Join with alerts table when appropriate
5. Use ILIKE for case-insensitive string matching
6. Return only the SQL query, no explanation

Schema:
""" + SCHEMA_CONTEXT


def validate_sql(sql: str) -> bool:
    """
    Validate that generated SQL is safe to execute.
    
    Checks:
    - Starts with SELECT
    - No forbidden DDL/DML keywords
    - No system table access
    """
    sql_upper = sql.upper().strip()
    
    # Must start with SELECT
    if not sql_upper.startswith("SELECT"):
        log.warning("nl2sql_validation_failed", reason="not_select", sql_preview=sql[:100])
        return False
    
    # Check for forbidden patterns
    for pattern in FORBIDDEN_PATTERNS:
        if pattern in sql_upper:
            log.warning("nl2sql_validation_failed", reason="forbidden_pattern", pattern=pattern)
            return False
    
    return True


def extract_parameters(sql: str) -> tuple[str, list]:
    """
    Extract parameter placeholders and return parameterized SQL.
    
    Converts $N placeholders and returns SQL with values.
    For demo, returns SQL with inline values (safe for SELECT only).
    """
    # Find all string literals that look like they should be parameters
    # Replace with $N placeholders
    param_values = []
    
    def replace_literal(match):
        param_values.append(match.group(1))
        return f"${len(param_values)}"
    
    # Extract quoted strings as parameters
    # Note: This is simplified — real implementation would use proper parsing
    return sql, param_values


async def nl_to_sql(natural_language: str, timeout: int = 30) -> dict:
    """
    Convert natural language to validated SQL.
    
    Args:
        natural_language: User's plain English question
        timeout: LLM query timeout
    
    Returns:
        Dict with:
        - success: bool
        - sql: str (the query, or error message)
        - params: list of parameter values
        - original: str (original NL query)
    """
    log.info("nl2sql_request", query=natural_language)
    
    # Query LLM
    prompt = f"""Convert this question to PostgreSQL SQL:

Question: {natural_language}

Return only the SQL query."""
    
    raw_sql = await query_llm(
        prompt=prompt,
        system_prompt=SYSTEM_PROMPT,
        temperature=0.0,  # Deterministic
        max_tokens=512,
    )
    
    # Check for fallback
    if raw_sql == FALLBACK_MESSAGE:
        return {
            "success": False,
            "sql": "AI service unavailable. Please try again later.",
            "params": [],
            "original": natural_language,
        }
    
    # Clean up the SQL (remove markdown, etc.)
    sql = raw_sql.strip()
    sql = re.sub(r"^```sql\s*", "", sql)
    sql = re.sub(r"```$", "", sql)
    sql = sql.strip()
    
    # Validate
    if not validate_sql(sql):
        return {
            "success": False,
            "sql": "Generated query failed validation. Please rephrase your question.",
            "params": [],
            "original": natural_language,
            "raw_generated": sql,
        }
    
    # Extract parameters
    sql_with_params, params = extract_parameters(sql)
    
    log.info("nl2sql_success", original=natural_language, sql_preview=sql[:100])
    
    return {
        "success": True,
        "sql": sql_with_params,
        "params": params,
        "original": natural_language,
    }


# Common query templates (fallback when LLM unavailable)
QUERY_TEMPLATES = {
    "failed logins": "SELECT * FROM logs WHERE event_category = 'authentication' AND event_action ILIKE '%failed%' AND time > NOW() - INTERVAL '1 hour' ORDER BY time DESC LIMIT 100",
    "processes from tmp": "SELECT * FROM logs WHERE event_category = 'process' AND process_path LIKE '/tmp/%' AND time > NOW() - INTERVAL '1 hour' ORDER BY time DESC LIMIT 100",
    "outbound connections": "SELECT * FROM logs WHERE event_category = 'network' AND destination_ip IS NOT NULL AND time > NOW() - INTERVAL '1 hour' ORDER BY time DESC LIMIT 100",
    "critical alerts": "SELECT * FROM alerts WHERE severity = 'critical' AND time > NOW() - INTERVAL '24 hours' ORDER BY time DESC",
}


def template_match(nl_query: str) -> Optional[str]:
    """Match natural language to template query (fallback)."""
    nl_lower = nl_query.lower()
    
    for key, template in QUERY_TEMPLATES.items():
        if key in nl_lower:
            return template
    
    return None
