"""
AI-powered alert analysis using Ollama.

Analyzes alert evidence and generates:
- Natural language summary of the threat
- Risk score (0-100) based on context
- Recommended response actions
- False positive likelihood assessment

Uses shared ollama_client for consistent timeout/error handling/fallback
instead of a separate raw httpx client.
"""
import json
from typing import Any, Optional, cast

from src.ai.ollama_client import query_llm
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("detection.ai")

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst AI. "
    "Analyze security alerts and provide structured assessments. "
    "Always respond with valid JSON (no markdown, no extra text)."
)


def build_prompt(rule_name: str, severity: str, host_name: str, evidence: dict) -> str:
    """Build the analysis prompt for Ollama."""
    # Truncate evidence to avoid token overflow
    evidence_str = json.dumps(evidence, default=str, indent=2)[:2000]

    return (
        f"Analyze this security alert and provide a structured assessment.\n\n"
        f"ALERT DETAILS:\n"
        f"- Rule: {rule_name}\n"
        f"- Severity: {severity}\n"
        f"- Host: {host_name}\n"
        f"- Evidence: {evidence_str}\n\n"
        f"Respond in this EXACT JSON format (no other text):\n"
        f'{{\n'
        f'  "summary": "One sentence describing what happened",\n'
        f'  "risk_score": 75,\n'
        f'  "verdict": "threat|suspicious|benign|false_positive",\n'
        f'  "response": ["Step 1", "Step 2", "Step 3"],\n'
        f'  "reasoning": "Why this verdict was chosen"\n'
        f'}}\n\n'
        f"Risk score: 0-25=benign, "
        f"26-50=suspicious, "
        f"51-75=threat, "
        f"76-100=critical threat."
    )


def _parse_json_response(raw_response: str) -> Optional[dict]:
    """Parse structured JSON from LLM response, handling markdown wrapping."""
    if not raw_response or not raw_response.strip():
        return None

    json_str = raw_response.strip()
    if "```json" in json_str:
        json_str = json_str.split("```json")[1].split("```")[0]
    elif "```" in json_str:
        json_str = json_str.split("```")[1].split("```")[0]

    try:
        return cast(dict[str, Any] | None, json.loads(json_str.strip()))
    except json.JSONDecodeError:
        return None


async def analyze_alert(
    alert_id: int,
    rule_name: str,
    severity: str,
    host_name: str,
    evidence: dict,
) -> Optional[dict]:
    """
    Send alert to Ollama for AI analysis via shared ollama_client.

    Returns parsed analysis dict or None on failure.
    Uses consistent timeout from settings (OLLAMA_TIMEOUT) and
    returns None (not FALLBACK_MESSAGE) so callers can skip enrichment.
    """
    prompt = build_prompt(rule_name, severity, host_name, evidence)

    try:
        raw_response = await query_llm(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT,
            temperature=0.3,
            max_tokens=500,
        )
    except Exception:
        log.warning("ai_analyzer_query_failed", alert_id=alert_id)
        return None

    # Fallback means Ollama is down — return None so enrichment is skipped.
    # query_llm returns an LLMResult; detect fallback via the structured
    # `fallback_used` flag or the canonical fallback text.
    from src.ai.ollama_client import FALLBACK_MESSAGE
    if raw_response.fallback_used or raw_response.text == FALLBACK_MESSAGE:
        log.warning("ai_analyzer_ollama_unavailable", alert_id=alert_id)
        return None

    # Parse structured JSON from response
    analysis = _parse_json_response(raw_response.text)
    if analysis is None:
        log.warning("ai_parse_failed", alert_id=alert_id, raw=raw_response.text[:200])
        return None

    log.info(
        "ai_analysis_complete",
        alert_id=alert_id,
        verdict=analysis.get("verdict"),
        risk_score=analysis.get("risk_score"),
    )
    return analysis


async def enrich_alert(alert_id: int, analysis: dict) -> None:
    """Write AI analysis back to the alert in the database."""
    if not analysis:
        return

    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE alerts
            SET ai_summary = $1,
                risk_score = $2,
                updated_at = NOW()
            WHERE id = $3
            """,
            analysis.get("summary", ""),
            analysis.get("risk_score", 50),
            alert_id,
        )

        log.info("alert_enriched", alert_id=alert_id, summary=analysis.get("summary", "")[:80])
