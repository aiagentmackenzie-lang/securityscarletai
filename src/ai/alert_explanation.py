"""
AI-powered alert explanation generator.

Generates human-readable explanations of security alerts using LLM.
Helps analysts understand why an alert fired and what to investigate.
"""
import json
from typing import Optional, Dict, Any

from src.ai.ollama_client import query_llm
from src.config.logging import get_logger

log = get_logger("ai.alert_explanation")


SYSTEM_PROMPT = """You are a cybersecurity analyst explaining security alerts to SOC analysts.
Your explanations should be:
- Clear and concise (2-4 sentences)
- Actionable (what to investigate next)
- Technical but accessible
- Include risk assessment

Format your response as:
1. **What happened**: Brief description of the detected activity
2. **Why it matters**: Risk/context assessment  
3. **Next steps**: Specific investigation recommendations"""


async def explain_alert(
    rule_name: str,
    rule_description: str,
    severity: str,
    host_name: str,
    mitre_techniques: list[str],
    evidence: Optional[Dict[str, Any]] = None,
    related_logs_count: int = 0,
) -> str:
    """
    Generate an AI explanation for a security alert.
    
    Args:
        rule_name: Name of the detection rule that fired
        rule_description: Description from the rule
        severity: Alert severity (critical, high, medium, low)
        host_name: Affected host
        mitre_techniques: List of MITRE technique IDs
        evidence: Alert evidence data
        related_logs_count: Number of related log entries
    
    Returns:
        Human-readable explanation string
    """
    # Build context
    context = f"""Alert Details:
- Rule: {rule_name}
- Description: {rule_description}
- Severity: {severity.upper()}
- Affected Host: {host_name}
- MITRE ATT&CK: {', '.join(mitre_techniques) if mitre_techniques else 'N/A'}
- Related Events: {related_logs_count}
"""
    
    if evidence:
        context += f"\nEvidence:\n{json.dumps(evidence, indent=2, default=str)[:500]}"
    
    prompt = f"""Analyze this security alert and provide an explanation:

{context}

Generate a clear explanation covering what happened, why it matters, and what to investigate."""
    
    log.info("generating_alert_explanation", rule=rule_name, host=host_name)
    
    explanation = await query_llm(
        prompt=prompt,
        system_prompt=SYSTEM_PROMPT,
        temperature=0.2,
        max_tokens=512,
    )
    
    return explanation


async def summarize_multiple_alerts(alerts: list[dict]) -> str:
    """
    Summarize multiple related alerts into a single narrative.
    
    Useful for correlating alerts from the same attack campaign.
    """
    if not alerts:
        return "No alerts to summarize."
    
    # Build summary of alerts
    alert_summaries = []
    for alert in alerts[:5]:  # Limit to first 5
        summary = f"- [{alert.get('severity', 'unknown').upper()}] {alert.get('rule_name', 'Unknown')} on {alert.get('host_name', 'unknown')} at {alert.get('time', 'unknown')[:19]}"
        alert_summaries.append(summary)
    
    context = "Related Alerts:\n" + "\n".join(alert_summaries)
    
    if len(alerts) > 5:
        context += f"\n... and {len(alerts) - 5} more alerts"
    
    prompt = f"""Analyze these related security alerts and identify patterns:

{context}

Provide:
1. Pattern/campaign summary (what's the attack chain?)
2. Affected scope (which hosts/users?)
3. Recommended response priority
4. Suggested containment actions"""
    
    log.info("summarizing_alert_cluster", count=len(alerts))
    
    summary = await query_llm(
        prompt=prompt,
        system_prompt=SYSTEM_PROMPT,
        temperature=0.2,
        max_tokens=600,
    )
    
    return summary


async def suggest_investigation_steps(
    alert_type: str,
    host_name: str,
    user_name: Optional[str] = None,
) -> list[str]:
    """
    Suggest specific investigation steps for an alert type.
    
    Returns list of actionable investigation tasks.
    """
    context = f"""Alert Type: {alert_type}
Affected Host: {host_name}
"""
    if user_name:
        context += f"User: {user_name}\n"
    
    prompt = f"""Suggest 5-7 specific investigation steps for this security alert:

{context}

Format as a numbered list of actionable tasks an analyst should perform.
Include:
- What logs to check
- What artifacts to examine
- What questions to answer
- What tools might help"""
    
    log.info("suggesting_investigation", type=alert_type, host=host_name)
    
    response = await query_llm(
        prompt=prompt,
        system_prompt="You are a SOC analyst. Provide practical, actionable investigation steps.",
        temperature=0.3,
        max_tokens=400,
    )
    
    # Parse into list (simple split on newlines)
    steps = [s.strip() for s in response.split('\n') if s.strip() and s[0].isdigit()]
    
    return steps if steps else [response]


# Pre-defined explanations for common alert types (LLM fallback)
TEMPLATE_EXPLANATIONS = {
    "brute_force_ssh": """
**What happened**: Multiple failed SSH login attempts were detected from the same source IP, followed by a successful login.

**Why it matters**: This pattern indicates a brute force password attack that may have succeeded. The attacker now has valid credentials and may have gained unauthorized access.

**Next steps**:
1. Identify the successful login's username and source IP
2. Check for lateral movement from the compromised account
3. Review command history for the logged-in session
4. Consider rotating credentials if compromise is confirmed
5. Block the source IP if external
""",
    
    "suspicious_tmp_process": """
**What happened**: A process was executed from /tmp or /var/tmp, which is unusual for legitimate applications.

**Why it matters**: Malware commonly stages in temporary directories. This could indicate downloaded malware or a dropped payload.

**Next steps**:
1. Examine the process binary (file hash, signature)
2. Check process network connections
3. Review parent process to understand execution chain
4. Look for persistence mechanisms (cron, launch agents)
5. Scan for additional dropped files
""",
    
    "launch_agent_persistence": """
**What happened**: A new LaunchAgent or LaunchDaemon was created, configured to run automatically at login.

**Why it matters**: This is a common macOS persistence technique used by malware to survive reboots.

**Next steps**:
1. Review the plist file contents for suspicious commands
2. Identify what process created the file
3. Check if the program is legitimate or signed
4. Remove if malicious, document if authorized
""",
}


def get_template_explanation(alert_type: str) -> Optional[str]:
    """Get pre-defined explanation template (LLM fallback)."""
    return TEMPLATE_EXPLANATIONS.get(alert_type.lower().replace(" ", "_"))
