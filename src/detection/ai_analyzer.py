"""
AI-powered alert analysis using Ollama.

Analyzes alert evidence and generates:
- Natural language summary of the threat
- Risk score (0-100) based on context
- Recommended response actions
- False positive likelihood assessment
"""
import json
import httpx
from typing import Optional

from src.config.logging import get_logger
from src.config.settings import settings
from src.db.connection import get_pool

log = get_logger("detection.ai")

OLLAMA_URL = "http://localhost:11434"
MODEL = "mistral:7b"  # Fast local model for real-time analysis


def build_prompt(rule_name: str, severity: str, host_name: str, evidence: dict) -> str:
    """Build the analysis prompt for Ollama."""
    # Truncate evidence to avoid token overflow
    evidence_str = json.dumps(evidence, default=str, indent=2)[:2000]

    return f"""You are a cybersecurity analyst AI. Analyze this security alert and provide a structured assessment.

ALERT DETAILS:
- Rule: {rule_name}
- Severity: {severity}
- Host: {host_name}
- Evidence: {evidence_str}

Respond in this EXACT JSON format (no other text):
{{
  "summary": "One sentence describing what happened",
  "risk_score": 75,
  "verdict": "threat|suspicious|benign|false_positive",
  "response": ["Step 1", "Step 2", "Step 3"],
  "reasoning": "Why this verdict was chosen"
}}

Risk score: 0-25=benign, 26-50=suspicious, 51-75=threat, 76-100=critical threat."""


async def analyze_alert(
    alert_id: int,
    rule_name: str,
    severity: str,
    host_name: str,
    evidence: dict,
) -> Optional[dict]:
    """
    Send alert to Ollama for AI analysis.
    Returns parsed analysis dict or None on failure.
    """
    prompt = build_prompt(rule_name, severity, host_name, evidence)

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 500},
                },
            )

            if resp.status_code != 200:
                log.warning("ollama_error", status=resp.status_code, alert_id=alert_id)
                return None

            raw_response = resp.json().get("response", "").strip()

            # Parse JSON from response (handle markdown code blocks)
            json_str = raw_response
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0]
            elif "```" in json_str:
                json_str = json_str.split("```")[1].split("```")[0]

            analysis = json.loads(json_str)

            log.info(
                "ai_analysis_complete",
                alert_id=alert_id,
                verdict=analysis.get("verdict"),
                risk_score=analysis.get("risk_score"),
            )

            return analysis

    except json.JSONDecodeError as e:
        log.warning("ai_parse_failed", alert_id=alert_id, error=str(e), raw=raw_response[:200])
        return None
    except httpx.ConnectError:
        log.warning("ollama_unavailable", alert_id=alert_id)
        return None
    except Exception as e:
        log.warning("ai_analysis_failed", alert_id=alert_id, error=str(e), error_type=type(e).__name__)
        return None


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