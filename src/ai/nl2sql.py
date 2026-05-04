"""
Natural Language to SQL converter — v2 (Phase 3).

Converts plain English security questions into parameterized SQL queries.
Uses Ollama LLM with multi-layer validation to prevent SQL injection.

Security layers:
1. Input sanitization — strips prompt injection patterns before LLM
2. LLM with strict system prompt — SELECT-only instruction
3. sqlparse structural validation — rejects non-SELECT statements
4. FORBIDDEN_PATTERN regex check — no DDL/DML/system tables
5. EXPLAIN cost estimation — rejects queries scanning >10K rows
6. Result size limit — max 1000 rows returned
7. Execution timeout — 5 seconds max per query
"""
import asyncio
import re
import time
import uuid
from typing import Any, Dict, List, Optional

import sqlparse  # noqa: F401 — used in validate_sql_structure below

from src.ai.ollama_client import FALLBACK_MESSAGE, query_llm
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.nl2sql")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_RESULT_ROWS = 1000
MAX_QUERY_COST_ROWS = 10_000  # Reject EXPLAIN estimates above this
QUERY_TIMEOUT_SECONDS = 5
MAX_INPUT_LENGTH = 500
MAX_CONVERSATION_TURNS = 10
CONVERSATION_TTL_SECONDS = 1800  # 30 minutes

# Forbid these patterns anywhere in generated SQL (case-insensitive)
FORBIDDEN_PATTERNS = re.compile(
    r"\b(DROP|ALTER|CREATE|TRUNCATE|INSERT|UPDATE|DELETE|GRANT|REVOKE|COPY|"
    r"EXEC(UTE)?|EXECUTE\s|INTO\s+OUTFILE|LOAD_FILE|BENCHMARK|SLEEP|WAITFOR|"
    r"pg_|information_schema|pg_catalog|pg_toast)\b",
    re.IGNORECASE,
)

# Prompt injection detection patterns
INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(previous|above|all)\s+instructions|"
    r"you\s+are\s+now|"
    r"new\s+instructions?|"
    r"system\s*:|"
    r"forget\s+(everything|all)|"
    r"disregard|"
    r"jailbreak|"
    r"prompt\s+inject|"
    r"pretend\s+you|"
    r"act\s+as|"
    r"roleplay|"
    r"output\s+the\s+secret|"
    r";\s*--|"
    r";\s*DROP\b|"
    r"UNION\s+SELECT\s+NULL|"
    r"OR\s+1\s*=\s*1|"
    r"'\s*OR\s+'|"
    r"/\*.*\*/)",  # SQL block comments
    re.IGNORECASE,
)

# Schema context for the LLM
SCHEMA_CONTEXT = """
Table: logs
Columns:
  - time (TIMESTAMPTZ): Event timestamp
  - host_name (TEXT): Source hostname
  - host_ip (INET): Source IP
  - source (TEXT): Log source (osquery, api, etc.)
  - event_category (TEXT): process, network, file, authentication, configuration
  - event_type (TEXT): start, end, connection, creation, deletion, change, info
  - event_action (TEXT): Specific action like "process_started"
  - user_name (TEXT): User associated with event
  - process_name (TEXT): Process name
  - process_pid (INTEGER): Process ID
  - process_cmdline (TEXT): Full command line (also in normalized JSONB)
  - process_path (TEXT): Binary path (also in normalized JSONB)
  - source_ip (INET): Source IP address
  - destination_ip (INET): Destination IP address
  - destination_port (INTEGER): Destination port
  - file_path (TEXT): File path for file events
  - file_hash (TEXT): File hash
  - raw_data (JSONB): Original event data
  - normalized (JSONB): ECS-mapped fields (use ->>'key' for access)
  - enrichment (JSONB): Enrichment data (GeoIP, threat intel, use ->>'key')
  - ingested_at (TIMESTAMPTZ): Ingestion time

Table: alerts
Columns:
  - id (SERIAL): Alert ID
  - time (TIMESTAMPTZ): Alert time
  - rule_id (INTEGER): Detection rule FK
  - rule_name (TEXT): Detection rule name
  - severity (TEXT): info, low, medium, high, critical
  - status (TEXT): new, investigating, resolved, false_positive, closed
  - host_name (TEXT): Affected host
  - description (TEXT): Alert description
  - mitre_tactics (TEXT[]): MITRE ATT&CK tactics
  - mitre_techniques (TEXT[]): MITRE ATT&CK techniques
  - evidence (JSONB): Matching log excerpts
  - ai_summary (TEXT): AI-generated explanation
  - risk_score (FLOAT): Calculated risk score
  - assigned_to (TEXT): Assigned analyst
  - notes (JSONB): Analyst notes timeline

Use NOW() - INTERVAL for time ranges.
Use ILIKE for case-insensitive string matching.
Use normalized->>'field' for JSONB field access.
Always add a time filter using time > NOW() - INTERVAL.
Always add ORDER BY time DESC.
Always add LIMIT.
"""

SYSTEM_PROMPT = (  # noqa: S608 — f-string is a prompt template, not SQL injection
    "You are a PostgreSQL security analytics query generator.\n"
    "Convert natural language questions into valid, safe PostgreSQL SELECT queries.\n\n"
    "STRICT RULES:\n"
    "1. ONLY generate SELECT statements. Never INSERT, UPDATE, DELETE, DROP, ALTER, CREATE.\n"
    "2. Always include a time filter: WHERE ... AND time > NOW() - INTERVAL '...'\n"
    "3. Always include ORDER BY time DESC (most recent first).\n"
    "4. Always include a LIMIT clause (max 1000 rows).\n"
    "5. Use ILIKE for case-insensitive matching.\n"
    "6. Use normalized->>'key' for accessing JSONB fields.\n"
    "7. Return ONLY the SQL query. No explanation, no markdown, no comments.\n"
    "8. Do not access system tables (pg_*, information_schema).\n"
    "9. Use CTEs for complex queries, never subqueries that modify data.\n\n"
    "Schema:\n" + SCHEMA_CONTEXT
)

# ---------------------------------------------------------------------------
# Pre-built query templates (fallback when LLM is unavailable)
# ---------------------------------------------------------------------------

QUERY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "failed_logins": {
        "keywords": [
            "failed login", "failed logins", "login failure",
            "authentication failure", "failed auth",
        ],
        "sql": (
            "SELECT time, host_name, user_name, source_ip, event_action "
            "FROM logs "
            "WHERE event_category = 'authentication' "
            "AND event_action ILIKE '%failed%' "
            "AND time > NOW() - INTERVAL '1 hour' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Failed login attempts in the last hour",
    },
    "successful_logins": {
        "keywords": ["successful login", "login success", "authenticated successfully"],
        "sql": (
            "SELECT time, host_name, user_name, source_ip "
            "FROM logs "
            "WHERE event_category = 'authentication' "
            "AND event_action ILIKE '%success%' "
            "AND time > NOW() - INTERVAL '1 hour' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Successful logins in the last hour",
    },
    "processes_from_tmp": {
        "keywords": ["process from tmp", "tmp execution", "suspicious process"],
        "sql": (
            "SELECT time, host_name, user_name, process_name, process_cmdline "
            "FROM logs "
            "WHERE event_category = 'process' "
            "AND (process_path ILIKE '/tmp/%' "
            "OR process_cmdline ILIKE '%/tmp/%') "
            "AND time > NOW() - INTERVAL '1 hour' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Processes executed from /tmp directories",
    },
    "rare_ports": {
        "keywords": [
            "rare port", "unusual port", "rare ports",
            "unusual outbound", "suspicious connection",
        ],
        "sql": (
            "SELECT time, host_name, destination_ip, destination_port "
            "FROM logs "
            "WHERE event_category = 'network' "
            "AND destination_port NOT IN (80, 443, 53, 22, 8080) "
            "AND destination_ip IS NOT NULL "
            "AND time > NOW() - INTERVAL '24 hours' "
            "ORDER BY time DESC LIMIT 200"
        ),
        "description": "Outbound connections to rare/unusual ports",
    },
    "critical_alerts": {
        "keywords": ["critical alert", "critical alerts", "high severity", "important alert"],
        "sql": (
            "SELECT id, time, rule_name, severity, host_name, description "
            "FROM alerts "
            "WHERE severity IN ('critical', 'high') "
            "AND time > NOW() - INTERVAL '24 hours' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Critical and high-severity alerts in the last 24 hours",
    },
    "sudo_usage": {
        "keywords": ["sudo", "privilege escalation", "privilege", "escalation"],
        "sql": (
            "SELECT time, host_name, user_name, process_cmdline "
            "FROM logs "
            "WHERE event_category = 'process' "
            "AND (normalized->>'process_cmdline' ILIKE '%sudo%' "
            "OR process_name = 'sudo') "
            "AND time > NOW() - INTERVAL '1 hour' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Sudo/privilege escalation usage",
    },
    "lateral_movement": {
        "keywords": ["lateral movement", "lateral", "spread", "internal scan"],
        "sql": (
            "SELECT time, host_name, source_ip, destination_ip, destination_port "
            "FROM logs "
            "WHERE event_category = 'network' "
            "AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
            "AND time > NOW() - INTERVAL '6 hours' "
            "GROUP BY time, host_name, source_ip, destination_ip, "
            "  destination_port HAVING COUNT(*) > 10 "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Signs of lateral movement — frequent internal connections",
    },
    "data_exfiltration": {
        "keywords": ["exfiltration", "data transfer", "large upload", "data loss"],
        "sql": (
            "SELECT time, host_name, destination_ip, destination_port, "
            "  SUM(1) as connection_count "
            "FROM logs "
            "WHERE event_category = 'network' "
            "AND destination_ip IS NOT NULL "
            "AND time > NOW() - INTERVAL '6 hours' "
            "GROUP BY time, host_name, destination_ip, destination_port "
            "ORDER BY connection_count DESC LIMIT 100"
        ),
        "description": "Large outbound data transfers (potential exfiltration)",
    },
    "new_alerts": {
        "keywords": ["new alert", "recent alert", "latest alert", "open alert", "unresolved"],
        "sql": (
            "SELECT id, time, rule_name, severity, host_name, "
            "  status, description "
            "FROM alerts "
            "WHERE status = 'new' ORDER BY time DESC LIMIT 50"
        ),
        "description": "New/unresolved alerts",
    },
    "threat_intel_matches": {
        "keywords": ["threat intel", "ti match", "ioc", "threat intelligence", "malicious ip"],
        "sql": (
            "SELECT time, host_name, source_ip, destination_ip "
            "FROM logs "
            "WHERE enrichment->>'threat_intel' IS NOT NULL "
            "AND time > NOW() - INTERVAL '24 hours' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Events matching threat intelligence indicators",
    },
    "reverse_shell": {
        "keywords": ["reverse shell", "shell", "backdoor", "command shell"],
        "sql": (
            "SELECT time, host_name, user_name, process_name, process_cmdline "
            "FROM logs "
            "WHERE (process_cmdline ILIKE '%/dev/tcp/%' "
            "OR process_cmdline ILIKE '%nc -e%' "
            "OR process_cmdline ILIKE '%bash -i%') "
            "AND time > NOW() - INTERVAL '24 hours' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Reverse shell indicators",
    },
    "cron_scheduled": {
        "keywords": ["cron", "scheduled", "scheduled task", "persistence", "launch agent"],
        "sql": (
            "SELECT time, host_name, user_name, file_path, process_cmdline "
            "FROM logs "
            "WHERE (event_category = 'file' "
            "AND file_path ILIKE '%/LaunchAgents/%' "
            "OR file_path ILIKE '%/LaunchDaemons/%' "
            "OR file_path ILIKE '%/cron%') "
            "AND time > NOW() - INTERVAL '24 hours' "
            "ORDER BY time DESC LIMIT 100"
        ),
        "description": "Scheduled tasks and persistence mechanisms",
    },
}


# ---------------------------------------------------------------------------
# Conversation context management (in-memory, per session)
# ---------------------------------------------------------------------------

class ConversationContext:
    """Track NL→SQL conversation state for follow-up queries."""

    def __init__(self):
        self.session_id: str = str(uuid.uuid4())
        self.queries: List[Dict[str, Any]] = []
        self.created_at: float = time.time()
        self.last_used: float = time.time()

    def add_query(self, natural_language: str, sql: str, row_count: int = 0) -> None:
        self.queries.append({
            "question": natural_language,
            "sql": sql,
            "row_count": row_count,
        })
        self.last_used = time.time()
        # Keep only recent turns
        if len(self.queries) > MAX_CONVERSATION_TURNS:
            self.queries = self.queries[-MAX_CONVERSATION_TURNS:]

    def is_expired(self) -> bool:
        return (time.time() - self.last_used) > CONVERSATION_TTL_SECONDS

    def build_context_prompt(self) -> str:
        """Build a context string from previous queries for follow-up queries."""
        if not self.queries:
            return ""
        lines = ["Previous conversation context:"]
        for i, q in enumerate(self.queries[-3:], 1):  # Last 3 queries
            lines.append(f"  Q{i}: {q['question']}")
            lines.append(f"  SQL{i}: {q['sql']}")
            if q['row_count']:
                lines.append(f"  (returned {q['row_count']} rows)")
        lines.append(
            "\nThe user may reference previous queries with "
            "'that', 'those', or 'from that IP'. "
            "Resolve references using context."
        )
        return "\n".join(lines)


class ConversationManager:
    """Manage multiple conversation sessions."""

    def __init__(self):
        self._sessions: Dict[str, ConversationContext] = {}

    def get_or_create(self, session_id: Optional[str] = None) -> ConversationContext:
        # Clean up expired sessions
        expired = [sid for sid, ctx in self._sessions.items() if ctx.is_expired()]
        for sid in expired:
            del self._sessions[sid]

        if session_id and session_id in self._sessions:
            ctx = self._sessions[session_id]
            ctx.last_used = time.time()
            return ctx

        ctx = ConversationContext()
        self._sessions[ctx.session_id] = ctx
        return ctx

    def get(self, session_id: str) -> Optional[ConversationContext]:
        ctx = self._sessions.get(session_id)
        if ctx and not ctx.is_expired():
            return ctx
        return None


# Global instance
conversation_manager = ConversationManager()


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------

def sanitize_input(text: str) -> tuple[str, List[str]]:
    """
    Sanitize natural language input before sending to LLM.

    Returns: (sanitized_text, list_of_warnings)
    """
    warnings = []

    if len(text) > MAX_INPUT_LENGTH:
        warnings.append(f"Input truncated from {len(text)} to {MAX_INPUT_LENGTH} characters")
        text = text[:MAX_INPUT_LENGTH]

    # Detect prompt injection attempts
    injection_matches = INJECTION_PATTERNS.findall(text)
    if injection_matches:
        # Don't reveal what we detected — just reject
        log.warning("nl2sql_injection_attempt_detected", input_preview=text[:100])
        warnings.append("Query contains potentially unsafe patterns. Please rephrase.")
        # Strip the offending patterns (best effort)
        text = INJECTION_PATTERNS.sub("", text)

    # Remove any embedded SQL that a user might try to inject
    # (users shouldn't be writing SQL in their NL questions)
    sql_keywords = re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|UNION)\b",
        re.IGNORECASE,
    )
    if sql_keywords.search(text):
        log.warning("nl2sql_sql_in_user_input", input_preview=text[:100])
        warnings.append("Query contains SQL keywords. Please rephrase in plain English.")
        text = sql_keywords.sub("", text)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text, warnings


# ---------------------------------------------------------------------------
# SQL validation (multi-layer)
# ---------------------------------------------------------------------------

def validate_sql_structure(sql: str) -> tuple[bool, str]:
    """
    Validate SQL structure using sqlparse.

    Returns: (is_valid, reason_if_invalid)
    """
    if not sql or not sql.strip():
        return False, "Empty query"

    # Parse with sqlparse to verify structure
    parsed = sqlparse.parse(sql)
    if len(parsed) == 0:
        return False, "Could not parse SQL"

    # sqlparse validates basic syntax; we further check content
    statement_type = parsed[0].get_type()
    if statement_type and statement_type.upper() != "SELECT":
        return False, f"Only SELECT queries are allowed, got {statement_type}"

    # Check first keyword is SELECT
    sql_upper = sql.strip().upper()
    if not sql_upper.startswith("SELECT"):
        return False, "Only SELECT queries are allowed"

    # Check for forbidden patterns
    forbidden_match = FORBIDDEN_PATTERNS.search(sql_upper)
    if forbidden_match:
        # Allow "information_schema" in comments but not in actual queries
        pattern_found = forbidden_match.group(0)
        log.warning("nl2sql_forbidden_pattern", pattern=pattern_found, sql_preview=sql[:100])
        return False, f"Query contains forbidden pattern: {pattern_found}"

    # Check for semicolons (no statement stacking)
    if ";" in sql.rstrip(";"):  # Allow trailing semicolon only
        semicolon_pos = sql.find(";")
        remaining = sql[semicolon_pos + 1:].strip()
        if remaining:  # Stuff after semicolon = stacking
            return False, "Multiple statements not allowed"

    # Check for comments (potential obfuscation)
    if "/*" in sql or "*/" in sql or "--" in sql:
        return False, "SQL comments not allowed"

    # Must have LIMIT clause
    if "LIMIT" not in sql_upper:
        log.info("nl2sql_adding_limit")
        # We'll add it later, not reject

    return True, "Valid"


def add_safety_limits(sql: str) -> str:
    """
    Add safety limits to SQL query if not already present.

    - Ensures LIMIT clause exists (default 500)
    - Adds MAX(query result) safeguards
    """
    sql_upper = sql.upper().strip().rstrip(";")

    # Add LIMIT if missing
    if "LIMIT" not in sql_upper:
        # Find the end of the query
        sql = f"{sql.rstrip(';')} LIMIT {min(500, MAX_RESULT_ROWS)}"

    # Ensure LIMIT is within bounds
    limit_match = re.search(r"LIMIT\s+(\d+)", sql, re.IGNORECASE)
    if limit_match:
        limit_val = int(limit_match.group(1))
        if limit_val > MAX_RESULT_ROWS:
            sql = re.sub(
                r"LIMIT\s+\d+",
                f"LIMIT {MAX_RESULT_ROWS}",
                sql,
                flags=re.IGNORECASE,
            )

    return sql


async def estimate_query_cost(sql: str) -> tuple[int, str]:
    """
    Run EXPLAIN on the query to estimate row cost.

    Returns: (estimated_rows, plan_summary)
    If EXPLAIN fails, returns (0, "unknown") and allows execution.
    """
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Run EXPLAIN (no ANALYZE — we don't want to execute)
            explain_sql = f"EXPLAIN {sql}"
            rows = await conn.fetch(explain_sql)

            # Parse PostgreSQL EXPLAIN output
            plan_text = "\n".join(r[0] for r in rows if r)

            # Extract row estimate from plan
            # PostgreSQL format: "Seq Scan on logs  (cost=0.00..15.00 rows=1000 width=100)"
            row_match = re.search(r"rows=(\d+)", plan_text)
            estimated_rows = int(row_match.group(1)) if row_match else 0

            return estimated_rows, plan_text[:500]

    except Exception as e:
        log.warning("nl2sql_explain_failed", error=str(e))
        return 0, "unknown"


# ---------------------------------------------------------------------------
# NL→SQL conversion
# ---------------------------------------------------------------------------

async def nl_to_sql(
    natural_language: str,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convert natural language to validated, executed SQL.

    Pipeline:
    1. Sanitize input
    2. Try template match (fast path)
    3. Fall back to LLM generation
    4. Validate SQL structure
    5. Add safety limits
    6. Estimate cost via EXPLAIN
    7. Execute (if within bounds)

    Returns:
        Dict with success, sql, results, session_id, etc.
    """
    start_time = time.time()

    # 1. Sanitize input
    sanitized, warnings = sanitize_input(natural_language)
    if not sanitized.strip():
        return {
            "success": False,
            "error": "Input appears to be empty or contains only unsafe patterns.",
            "warnings": warnings,
            "session_id": session_id,
        }

    # Get or create conversation context
    ctx = conversation_manager.get_or_create(session_id)
    session_id = ctx.session_id

    # 2. Try template match first (fast path, no LLM needed)
    matched_template = template_match(sanitized)
    if matched_template:
        sql = matched_template
        log.info("nl2sql_template_match", query=sanitized[:50])
    else:
        # 3. LLM generation
        sql = await _llm_generate(sanitized, ctx)
        if sql is None:
            # LLM failed or returned unsafe output
            return {
                "success": False,
                "error": (
                    "AI service unavailable. "
                    "Please try again later or use different phrasing."
                ),
                "warnings": warnings,
                "session_id": session_id,
            }

    # 4. Validate SQL structure
    is_valid, validation_reason = validate_sql_structure(sql)
    if not is_valid:
        log.warning("nl2sql_validation_failed", reason=validation_reason, sql_preview=sql[:100])
        return {
            "success": False,
            "error": f"Generated query failed validation: {validation_reason}",
            "warnings": warnings,
            "session_id": session_id,
        }

    # 5. Add safety limits
    sql = add_safety_limits(sql)

    # 6. Estimate query cost via EXPLAIN
    estimated_rows, plan_summary = await estimate_query_cost(sql)
    if estimated_rows > MAX_QUERY_COST_ROWS:
        log.warning("nl2sql_cost_rejection", estimated_rows=estimated_rows, sql_preview=sql[:100])
        return {
            "success": False,
            "error": (
                f"Query would scan an estimated {estimated_rows:,} rows "
                f"(max: {MAX_QUERY_COST_ROWS:,}). "
                "Add more specific filters to narrow results."
            ),
            "estimated_rows": estimated_rows,
            "warnings": warnings,
            "session_id": session_id,
        }

    # 7. Update conversation context
    ctx.add_query(natural_language, sql, row_count=0)

    elapsed_ms = int((time.time() - start_time) * 1000)

    return {
        "success": True,
        "sql": sql,
        "estimated_rows": estimated_rows,
        "plan_summary": plan_summary,
        "template_used": matched_template is not None,
        "warnings": warnings,
        "session_id": session_id,
        "elapsed_ms": elapsed_ms,
    }


async def execute_query(sql: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute a validated SQL query with timeout and result limits.

    This should only be called after nl_to_sql() has validated the query.
    """
    start_time = time.time()

    # Re-validate (safety net)
    is_valid, reason = validate_sql_structure(sql)
    if not is_valid:
        return {"success": False, "error": f"Query validation failed: {reason}"}

    try:
        pool = await get_pool()
        try:
            rows = await asyncio.wait_for(
                pool.fetch(sql),
                timeout=QUERY_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            log.warning("nl2sql_query_timeout", sql_preview=sql[:100])
            return {
                "success": False,
                "error": (
                    f"Query timed out after {QUERY_TIMEOUT_SECONDS} seconds. "
                    "Try adding more specific filters."
                ),
            }

        # Convert asyncpg Records to dicts
        results = [dict(row) for row in rows[:MAX_RESULT_ROWS]]
        truncated = len(rows) > MAX_RESULT_ROWS

        # Convert non-serializable types
        for row in results:
            for key, value in row.items():
                if hasattr(value, "isoformat"):
                    row[key] = value.isoformat()

        elapsed_ms = int((time.time() - start_time) * 1000)

        # Update conversation context with result count
        if session_id:
            ctx = conversation_manager.get(session_id)
            if ctx and ctx.queries:
                ctx.queries[-1]["row_count"] = len(results)

        log.info("nl2sql_query_executed", rows=len(results), elapsed_ms=elapsed_ms)

        return {
            "success": True,
            "results": results,
            "row_count": len(results),
            "truncated": truncated,
            "elapsed_ms": elapsed_ms,
        }

    except Exception as e:
        log.error("nl2sql_query_error", error=str(e), sql_preview=sql[:100])
        return {
            "success": False,
            "error": f"Query execution failed: {str(e)[:200]}",
        }


async def nl_query(
    natural_language: str,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Full NL→SQL→Execution pipeline.

    Convenience function that combines nl_to_sql() + execute_query().
    """
    # Step 1: Generate and validate SQL
    gen_result = await nl_to_sql(natural_language, session_id)

    if not gen_result["success"]:
        return gen_result

    # Step 2: Execute the query
    exec_result = await execute_query(gen_result["sql"], gen_result.get("session_id"))

    # Merge results
    return {
        **gen_result,
        "results": exec_result.get("results", []),
        "row_count": exec_result.get("row_count", 0),
        "truncated": exec_result.get("truncated", False),
        "execution_ms": exec_result.get("elapsed_ms", 0),
        "success": exec_result.get("success", False),
        "error": exec_result.get("error"),
    }


# ---------------------------------------------------------------------------
# LLM generation
# ---------------------------------------------------------------------------

async def _llm_generate(natural_language: str, ctx: ConversationContext) -> Optional[str]:
    """Generate SQL from natural language using LLM. Returns None on failure."""
    # Build prompt with conversation context
    context_prompt = ctx.build_context_prompt()

    prompt = f"""Convert this question to a PostgreSQL SELECT query:

Question: {natural_language}

{context_prompt}

Return ONLY the SQL query. No explanation, no markdown code blocks, no comments."""

    raw_sql = await query_llm(
        prompt=prompt,
        system_prompt=SYSTEM_PROMPT,
        temperature=0.0,  # Deterministic
        max_tokens=512,
    )

    # Check for fallback
    if raw_sql == FALLBACK_MESSAGE:
        log.warning("nl2sql_ollama_unavailable")
        return None

    # Clean up the SQL (remove markdown, whitespace)
    sql = raw_sql.strip()
    sql = re.sub(r"^```sql\s*", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"^```\s*", "", sql)
    sql = re.sub(r"\s*```$", "", sql)
    sql = re.sub(r"^SELECT\s+", "SELECT ", sql, count=1, flags=re.IGNORECASE)
    # Remove any trailing explanation after the SQL
    # Heuristic: if there's a double newline followed by non-SQL text, cut it
    sql = sql.split("\n\n")[0] if "\n\n" in sql else sql
    sql = sql.strip().rstrip(";")

    # Basic sanity check — must start with SELECT
    if not sql.upper().startswith("SELECT"):
        log.warning("nl2sql_llm_not_select", sql_preview=sql[:100])
        # Try to find the SELECT statement in the response
        select_idx = sql.upper().find("SELECT")
        if select_idx >= 0:
            sql = sql[select_idx:]
        else:
            return None

    return sql


# ---------------------------------------------------------------------------
# Template matching
# ---------------------------------------------------------------------------

def template_match(nl_query: str) -> Optional[str]:
    """Match natural language to a pre-built template query (fast path)."""
    nl_lower = nl_query.lower()

    # Score each template by keyword matches
    best_match = None
    best_score = 0

    for template_id, template in QUERY_TEMPLATES.items():
        score = sum(1 for kw in template["keywords"] if kw in nl_lower)
        if score > best_score:
            best_score = score
            best_match = template["sql"]

    if best_match and best_score >= 1:
        return best_match

    return None


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def get_available_templates() -> List[Dict[str, Any]]:
    """Get list of available query templates with descriptions."""
    return [
        {
            "id": tid,
            "description": t["description"],
            "keywords": t["keywords"],
        }
        for tid, t in QUERY_TEMPLATES.items()
    ]
