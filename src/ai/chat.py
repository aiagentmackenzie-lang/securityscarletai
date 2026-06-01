"""
AI Chat endpoint — context-aware security chat assistant (v3 LLMResult contract).

Provides conversational AI that understands the current security environment.
Returns a dict with explicit `fallback_used` and `warning` keys so the UI
can show degraded-mode indicators.

Includes prompt injection defense (same approach as nl2sql.py).
"""
import re
from typing import Any, Dict, Optional

from src.ai.cost_tracker import record_usage
from src.ai.ollama_client import LLMResult, query_llm
from src.ai.prompts import CHAT_SYSTEM_PROMPT, render_chat
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.chat")

# Prompt injection defense (matches nl2sql.py patterns)
INJECTION_PATTERNS = re.compile(
    r"(\bignore\s+(previous|above|all)\s+instructions\b|"
    r"\byou\s+are\s+now\b|"
    r"\bnew\s+instructions?\b|"
    r"\bsystem\s*:|"
    r"\bforget\s+(everything|all)\b|"
    r"\bdisregard\b|"
    r"\bjailbreak\b|"
    r"\bprompt\s+inject\b|"
    r"\bpretend\s+you\b|"
    r"\bact\s+as\b|"
    r"\broleplay\b|"
    r"\boutput\s+the\s+secret\b|"
    r";\s*--|"
    r";\s*DROP\b|"
    r"\bUNION\s+SELECT\b|"
    r"\bOR\s+1\s*=\s*1\b|"
    r"'\s*OR\s+'|"
    r"/\*.*\*/)",
    re.IGNORECASE,
)

MAX_MESSAGE_LENGTH = 1000
MAX_CONTEXT_ALERTS = 10
MAX_CHAT_HISTORY = 20


def sanitize_chat_input(text: str) -> tuple[str, list[str]]:
    """Sanitize chat input to prevent prompt injection.

    Returns: (sanitized_text, list_of_warnings)
    """
    warnings = []

    if len(text) > MAX_MESSAGE_LENGTH:
        warnings.append(f"Message truncated from {len(text)} to {MAX_MESSAGE_LENGTH} characters")
        text = text[:MAX_MESSAGE_LENGTH]

    matches = INJECTION_PATTERNS.findall(text)
    if matches:
        log.warning("chat_injection_attempt_detected", input_preview=text[:100])
        warnings.append("Message contains potentially unsafe patterns.")
        text = INJECTION_PATTERNS.sub("", text)

    return text.strip(), warnings


async def build_security_context() -> str:
    """Build a real-time security context from the database.

    Includes: alert summary, top threats, recent critical alerts.
    """
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            summary = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) FILTER (WHERE severity = 'low') as low,
                    COUNT(*) FILTER (WHERE status = 'new') as new_count,
                    COUNT(*) as total
                FROM alerts
                WHERE time > NOW() - INTERVAL '7 days'
                """
            )

            recent_alerts = await conn.fetch(
                """
                SELECT id, rule_name, severity, host_name, time, status
                FROM alerts
                WHERE severity IN ('critical', 'high')
                  AND time > NOW() - INTERVAL '7 days'
                ORDER BY time DESC
                LIMIT $1
                """,
                MAX_CONTEXT_ALERTS,
            )

            top_hosts = await conn.fetch(
                """
                SELECT host_name, COUNT(*) as alert_count
                FROM alerts
                WHERE time > NOW() - INTERVAL '7 days'
                GROUP BY host_name
                ORDER BY alert_count DESC
                LIMIT 5
                """
            )

            unresolved = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE status IN ('new', 'investigating')
                """
            )

    except Exception as e:
        log.warning("chat_context_build_failed", error=str(e))
        return "Security context unavailable (database connection issue)."

    lines = ["Current Security Environment (last 7 days):"]

    if summary and summary['total'] > 0:
        lines.append(
            f"- Alerts (7d): {summary['total']} total "
            f"({summary['critical']} critical, {summary['high']} high, "
            f"{summary['medium']} medium, {summary['low']} low)"
        )
        lines.append(f"- New/Investigating: {unresolved or 0}")
    else:
        lines.append("- No alerts in last 7 days")

    if top_hosts:
        host_list = ", ".join(
            f"{h['host_name']} ({h['alert_count']})" for h in top_hosts[:5]
        )
        lines.append(f"- Top hosts by alerts: {host_list}")

    if recent_alerts:
        lines.append("- Recent critical/high alerts:")
        for alert in recent_alerts[:5]:
            alert_time = (
                alert["time"].isoformat()[:19]
                if hasattr(alert["time"], "isoformat")
                else str(alert["time"])[:19]
            )
            lines.append(
                f"  * [{alert['severity'].upper()}] {alert['rule_name']} "
                f"on {alert['host_name']} ({alert_time})"
            )

    return "\n".join(lines)


async def chat(
    message: str,
    session_context: Optional[str] = None,
    user: Optional[str] = None,
) -> Dict[str, Any]:
    """Process a chat message and return an AI response.

    Returns a dict that always includes:
      - response       (str)   — the text to show
      - source         (str)   — "ollama" | "template_library"
      - fallback_used  (bool)
      - warning        (str|None)
      - context_used   (bool)
      - warnings       (list)  — prompt-injection warnings
      - tokens_in/out  (int)
      - latency_ms     (int)
      - prompt_version (str)
      - cost_recorded  (bool)
    """
    # 1. Sanitize input
    sanitized, warnings = sanitize_chat_input(message)

    if not sanitized.strip():
        return {
            "response": "I didn't catch that. Could you rephrase your question?",
            "context_used": False,
            "warnings": warnings,
            "source": "template_library",
            "fallback_used": True,
            "warning": None,
            "tokens_in": 0,
            "tokens_out": 0,
            "latency_ms": 0,
            "prompt_version": None,
            "cost_recorded": False,
        }

    # 2. Build security context
    context = await build_security_context()

    # 3. Render prompt via Jinja2 (versioned)
    prompt, prompt_version, _ = render_chat(
        context=context,
        sanitized_message=sanitized,
    )

    log.info("chat_request", message=sanitized[:50])

    # 4. Build a fallback response (used if Ollama is down)
    fallback_text = generate_fallback_response(sanitized, context)

    # 5. Query LLM
    result: LLMResult = await query_llm(
        prompt=prompt,
        system_prompt=CHAT_SYSTEM_PROMPT,
        temperature=0.2,
        max_tokens=800,
        prompt_version=prompt_version,
        fallback_text=fallback_text,
    )

    # 6. Cost tracking
    cost_recorded = await record_usage(
        user=user,
        endpoint="ai.chat",
        model=result.model_used or "template_library",
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        latency_ms=result.latency_ms,
        prompt_version=result.prompt_version,
        source=result.source,
        fallback_used=result.fallback_used,
        warning=result.warning,
    )

    if result.source == "template_library":
        warnings = warnings + ["AI service unavailable; using template response."]

    return {
        "response": result.text,
        "context_used": True,
        "warnings": warnings,
        "source": result.source,
        "fallback_used": result.fallback_used,
        "warning": result.warning,
        "tokens_in": result.tokens_in,
        "tokens_out": result.tokens_out,
        "latency_ms": result.latency_ms,
        "prompt_version": result.prompt_version,
        "cost_recorded": cost_recorded,
    }


def generate_fallback_response(message: str, context: str) -> str:
    """Generate a rule-based fallback response when Ollama is down."""
    message_lower = message.lower()

    if any(kw in message_lower for kw in ["priorit", "first", "important", "urgent"]):
        if "critical" in context.lower():
            return (
                "Focus on critical severity alerts first. "
                "Review the critical alerts listed in the context above, "
                "starting with any involving unknown IPs or lateral movement indicators. "
                "After addressing criticals, move to high-severity alerts on key assets."
            )
        return (
            "No critical alerts in the last 24 hours. "
            "Review high-severity alerts next, focusing on hosts with "
            "the most alert activity."
        )

    if any(kw in message_lower for kw in ["lateral", "movement", "spread", "pivot"]):
        return (
            "To investigate lateral movement: "
            "1. Check for authentication from unusual sources\n"
            "2. Look for RDP/SSH between internal hosts\n"
            "3. Review network connections to rare ports\n"
            "4. Run the lateral movement hunt template"
        )

    if any(kw in message_lower for kw in ["explain", "what happened", "why", "detail"]):
        return (
            "I can't provide detailed explanations right now (AI service unavailable). "
            "Try using the alert explanation feature on individual alerts, "
            "or run the hunt templates to investigate further."
        )

    if any(kw in message_lower for kw in ["posture", "summary", "overview", "status"]):
        return (
            "Security posture summary is based on current alert data. "
            "Check the dashboard for real-time metrics. "
            "Focus on unresolved critical and high-severity alerts."
        )

    return (
        "I'm unable to process your request right now (AI service unavailable). "
        "Please try again later, or use the hunting templates and query features "
        "to investigate directly."
    )
