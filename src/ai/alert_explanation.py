"""
AI-powered alert explanation generator — v2 (Phase 3).

Generates human-readable explanations of security alerts using LLM.
Changes from Phase 0:
- Fallback when Ollama is down (template explanations)
- Async-friendly with configurable timeout
- Wired into alert creation flow
"""
import json
from typing import Any, Dict, List, Optional

from src.ai.ollama_client import FALLBACK_MESSAGE, query_llm
from src.config.logging import get_logger

log = get_logger("ai.alert_explanation")


SYSTEM_PROMPT = (
    "You are a cybersecurity analyst explaining security alerts to SOC analysts.\n"
    "Your explanations should be:\n"
    "- Clear and concise (2-4 sentences)\n"
    "- Actionable (what to investigate next)\n"
    "- Technical but accessible\n"
    "- Include risk assessment\n\n"
    "Format your response as:\n"
    "1. **What happened**: Brief description of the detected activity\n"
    "2. **Why it matters**: Risk/context assessment\n"
    "3. **Next steps**: Specific investigation recommendations"
)


async def explain_alert(
    rule_name: str,
    rule_description: str,
    severity: str,
    host_name: str,
    mitre_techniques: Optional[List[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    related_logs_count: int = 0,
) -> str:
    """
    Generate an AI explanation for a security alert.

    Falls back to template explanations when Ollama is unavailable.

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
    mitre_techniques = mitre_techniques or []

    # Build context
    context = (
        f"Alert Details:\n"
        f"- Rule: {rule_name}\n"
        f"- Description: {rule_description}\n"
        f"- Severity: {severity.upper()}\n"
        f"- Affected Host: {host_name}\n"
        f"- MITRE ATT&CK: {', '.join(mitre_techniques) if mitre_techniques else 'N/A'}\n"
        f"- Related Events: {related_logs_count}\n"
    )

    if evidence:
        evidence_str = json.dumps(evidence, indent=2, default=str)[:500]
        context += f"\nEvidence:\n{evidence_str}"

    prompt = (
        f"Analyze this security alert and provide an explanation:\n\n"
        f"{context}\n"
        f"Generate a clear explanation covering what happened, "
        f"why it matters, and what to investigate."
    )

    log.info("generating_alert_explanation", rule=rule_name, host=host_name)

    explanation = await query_llm(
        prompt=prompt,
        system_prompt=SYSTEM_PROMPT,
        temperature=0.2,
        max_tokens=512,
    )

    # Fallback to template if Ollama is down
    if explanation == FALLBACK_MESSAGE:
        log.info("alert_explanation_fallback_llm", rule=rule_name)
        template = get_template_explanation(rule_name)
        if template:
            return template
        # Generic fallback explanation
        return (
            f"**Alert: {rule_name}** (Severity: {severity.upper()})\n\n"
            f"This alert was triggered on host **{host_name}**.\n"
            f"Rule description: {rule_description}\n\n"
            f"**Next steps**: Review the alert evidence, check related logs, "
            f"and determine if this is a true positive or false positive."
        )

    return explanation


async def summarize_multiple_alerts(alerts: List[dict]) -> str:
    """
    Summarize multiple related alerts into a single narrative.

    Useful for correlating alerts from the same attack campaign.
    """
    if not alerts:
        return "No alerts to summarize."

    alert_summaries = []
    for alert in alerts[:5]:
        severity = alert.get("severity", "unknown").upper()
        rule = alert.get("rule_name", "Unknown")
        host = alert.get("host_name", "unknown")
        time_str = str(alert.get("time", "unknown"))[:19]
        alert_summaries.append(f"- [{severity}] {rule} on {host} at {time_str}")

    context = "Related Alerts:\n" + "\n".join(alert_summaries)
    if len(alerts) > 5:
        context += f"\n... and {len(alerts) - 5} more alerts"

    prompt = (
        f"Analyze these related security alerts and identify patterns:\n\n"
        f"{context}\n\n"
        f"Provide:\n"
        f"1. Pattern/campaign summary (what's the attack chain?)\n"
        f"2. Affected scope (which hosts/users?)\n"
        f"3. Recommended response priority\n"
        f"4. Suggested containment actions"
    )

    log.info("summarizing_alert_cluster", count=len(alerts))

    summary = await query_llm(
        prompt=prompt,
        system_prompt=SYSTEM_PROMPT,
        temperature=0.2,
        max_tokens=600,
    )

    if summary == FALLBACK_MESSAGE:
        return (
            f"Cluster of {len(alerts)} related alerts detected. "
            f"Severity breakdown: " +
            ", ".join(
                f"{s}: {sum(1 for a in alerts if a.get('severity') == s)}"
                for s in ["critical", "high", "medium", "low"]
            ) +
            ". Affected hosts: " +
            ", ".join(set(a.get("host_name", "?") for a in alerts[:5]))
        )

    return summary


async def suggest_investigation_steps(
    alert_type: str,
    host_name: str,
    user_name: Optional[str] = None,
) -> List[str]:
    """
    Suggest specific investigation steps for an alert type.

    Returns list of actionable investigation tasks.
    """
    context = f"Alert Type: {alert_type}\nAffected Host: {host_name}\n"
    if user_name:
        context += f"User: {user_name}\n"

    prompt = (
        f"Suggest 5-7 specific investigation steps for this security alert:\n\n"
        f"{context}\n"
        f"Format as a numbered list of actionable tasks an analyst should perform.\n"
        f"Include:\n"
        f"- What logs to check\n"
        f"- What artifacts to examine\n"
        f"- What questions to answer\n"
        f"- What tools might help"
    )

    log.info("suggesting_investigation", type=alert_type, host=host_name)

    response = await query_llm(
        prompt=prompt,
        system_prompt=(
            "You are a SOC analyst. "
            "Provide practical, actionable investigation steps."
        ),
        temperature=0.3,
        max_tokens=400,
    )

    if response == FALLBACK_MESSAGE:
        return _fallback_investigation_steps(alert_type, host_name)

    # Parse into list (simple split on newlines)
    steps = [
        s.strip() for s in response.split("\n")
        if s.strip() and s.strip()[0].isdigit()
    ]
    return steps if steps else [response]


def _fallback_investigation_steps(
    alert_type: str, host_name: str
) -> List[str]:
    """Provide fallback investigation steps when LLM is unavailable."""
    return [
        f"1. Review all recent alerts on {host_name}",
        f"2. Check authentication logs for {host_name}",
        f"3. Review process execution history on {host_name}",
        f"4. Check network connections from {host_name}",
        "5. Compare activity against known MITRE ATT&CK techniques",
        "6. Verify if host has threat intelligence matches",
    ]


# Pre-defined explanations for common alert types (LLM fallback)
TEMPLATE_EXPLANATIONS: Dict[str, str] = {
    "brute_force_ssh": (
        "**What happened**: Multiple failed SSH login attempts were detected from "
        "the same source IP, followed by a successful login.\n\n"
        "**Why it matters**: This pattern indicates a brute force password attack "
        "that may have succeeded. The attacker now has valid credentials.\n\n"
        "**Next steps**:\n"
        "1. Identify the successful login's username and source IP\n"
        "2. Check for lateral movement from the compromised account\n"
        "3. Review command history for the logged-in session\n"
        "4. Consider rotating credentials if compromise is confirmed\n"
        "5. Block the source IP if external"
    ),
    "suspicious_tmp_process": (
        "**What happened**: A process was executed from /tmp or /var/tmp, "
        "which is unusual for legitimate applications.\n\n"
        "**Why it matters**: Malware commonly stages in temporary directories. "
        "This could indicate downloaded malware or a dropped payload.\n\n"
        "**Next steps**:\n"
        "1. Examine the process binary (file hash, signature)\n"
        "2. Check process network connections\n"
        "3. Review parent process to understand execution chain\n"
        "4. Look for persistence mechanisms (cron, launch agents)\n"
        "5. Scan for additional dropped files"
    ),
    "launch_agent_persistence": (
        "**What happened**: A new LaunchAgent or LaunchDaemon was created, "
        "configured to run automatically at login.\n\n"
        "**Why it matters**: This is a common macOS persistence technique used "
        "by malware to survive reboots.\n\n"
        "**Next steps**:\n"
        "1. Review the plist file contents for suspicious commands\n"
        "2. Identify what process created the file\n"
        "3. Check if the program is legitimate or signed\n"
        "4. Remove if malicious, document if authorized"
    ),
    "reverse_shell": (
        "**What happened**: A process with command-line patterns consistent with "
        "reverse shell activity was detected.\n\n"
        "**Why it matters**: Reverse shells give attackers interactive access to "
        "the system, bypassing firewall restrictions.\n\n"
        "**Next steps**:\n"
        "1. Identify the process and its parent chain\n"
        "2. Check network connections from the process\n"
        "3. Determine the destination IP (C2 server?)\n"
        "4. Kill the process and block the C2 IP\n"
        "5. Investigate how the shell was established"
    ),
    "c2_beaconing": (
        "**What happened**: Network connections with regular timing patterns "
        "were detected, suggesting command-and-control beaconing.\n\n"
        "**Why it matters**: C2 beaconing indicates a compromised host "
        "communicating with an attacker's infrastructure.\n\n"
        "**Next steps**:\n"
        "1. Identify the destination IP and domain\n"
        "2. Check threat intelligence for the C2 endpoint\n"
        "3. Block the C2 IP/domain at the firewall\n"
        "4. Investigate the process making the connections\n"
        "5. Hunt for other hosts communicating with the same IP"
    ),
    "data_exfiltration_volume": (
        "**What happened**: Unusual data transfer volume was detected from "
        "a host to an external destination.\n\n"
        "**Why it matters**: This could indicate data exfiltration, "
        "an insider threat, or compromised credentials being used to steal data.\n\n"
        "**Next steps**:\n"
        "1. Identify the destination IP and port\n"
        "2. Check if the transfer was to a known cloud storage service\n"
        "3. Review the user account associated with the transfer\n"
        "4. Check for compression or encryption of transferred data\n"
        "5. Verify if this matches any known data loss prevention patterns"
    ),
}


def get_template_explanation(alert_type: str) -> Optional[str]:
    """Get pre-defined explanation template (LLM fallback)."""
    # Try exact match first
    key = alert_type.lower().replace(" ", "_").replace("-", "_")
    if key in TEMPLATE_EXPLANATIONS:
        return TEMPLATE_EXPLANATIONS[key]
    # Try partial match
    for template_key, template_val in TEMPLATE_EXPLANATIONS.items():
        if template_key in key or key in template_key:
            return template_val
    return None
