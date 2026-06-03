"""
AI-powered alert explanation — v3 (LLMResult contract).

Generates human-readable explanations of security alerts using the
local Ollama LLM. Returns a structured dict on every call so callers
can display `fallback_used` and `warning` to the end user.

Contract (returned dict keys):
  - explanation        (str)  — the text to show
  - source             (str)  — "ollama" | "template_library"
  - model              (str)  — model name or None
  - fallback_used      (bool) — True if served from template library
  - warning            (str|None) — user-facing warning when fallback fires
  - tokens_in          (int)
  - tokens_out         (int)
  - latency_ms         (int)
  - prompt_version     (str)  — which prompt template produced this output
  - cost_recorded      (bool) — True if written to ai_usage table
"""
import json
from typing import Any, Dict, List, Optional

from src.ai.cost_tracker import record_usage
from src.ai.ollama_client import LLMResult, query_llm
from src.ai.prompts import (
    ALERT_EXPLANATION_PROMPT_VERSION,
    ALERT_EXPLANATION_SYSTEM,
    render_alert_explanation,
    render_alert_summary,
    render_investigation_steps,
)
from src.config.logging import get_logger

log = get_logger("ai.alert_explanation")


# Backward-compat re-exports — these used to live in this module.
SYSTEM_PROMPT = ALERT_EXPLANATION_SYSTEM
PROMPT_VERSION = ALERT_EXPLANATION_PROMPT_VERSION
# FALLBACK_MESSAGE — also re-exported below for legacy callers
FALLBACK_MESSAGE = "[AI unavailable — Ollama is not responding. Feature degraded gracefully.]"


def _generic_fallback(
    rule_name: str,
    rule_description: str,
    severity: str,
    host_name: str,
) -> str:
    """Generic fallback explanation when no template matches."""
    return (
        f"**Alert: {rule_name}** (Severity: {severity.upper()})\n\n"
        f"This alert was triggered on host **{host_name}**.\n"
        f"Rule description: {rule_description}\n\n"
        f"**Next steps**: Review the alert evidence, check related logs, "
        f"and determine if this is a true positive or false positive."
    )


def _fallback_investigation_steps(alert_type: str, host_name: str) -> List[str]:
    """Provide fallback investigation steps when LLM is unavailable."""
    return [
        f"1. Review all recent alerts on {host_name}",
        f"2. Check authentication logs for {host_name}",
        f"3. Review process execution history on {host_name}",
        f"4. Check network connections from {host_name}",
        "5. Compare activity against known MITRE ATT&CK techniques",
        "6. Verify if host has threat intelligence matches",
    ]


async def _record(result: LLMResult, user: Optional[str], endpoint: str) -> bool:
    """Cost-tracking wrapper. Never raises."""
    return await record_usage(
        user=user,
        endpoint=endpoint,
        model=result.model_used or "template_library",
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        latency_ms=result.latency_ms,
        prompt_version=result.prompt_version,
        source=result.source,
        fallback_used=result.fallback_used,
        warning=result.warning,
    )


async def explain_alert(
    rule_name: str,
    rule_description: str,
    severity: str,
    host_name: str,
    mitre_techniques: Optional[List[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    related_logs_count: int = 0,
    user: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate an AI explanation for a security alert.

    Returns a dict that ALWAYS includes `fallback_used` and `warning`
    keys — callers can show these to the end user when Ollama is down.

    Never raises. Always returns a dict.
    """
    mitre_techniques = mitre_techniques or []

    # Build the fallback first so we can hand it to query_llm
    fallback_text = get_template_explanation(rule_name) or _generic_fallback(
        rule_name, rule_description, severity, host_name
    )

    # Build prompt via Jinja2 (versioned)
    evidence_str = ""
    if evidence:
        evidence_str = json.dumps(evidence, indent=2, default=str)[:500]
    prompt, prompt_version, _version_hash = render_alert_explanation(
        rule_name=rule_name,
        rule_description=rule_description,
        severity=severity,
        host_name=host_name,
        mitre_techniques=mitre_techniques,
        evidence_str=evidence_str,
        related_logs_count=related_logs_count,
    )

    log.info("generating_alert_explanation", rule=rule_name, host=host_name)

    result: LLMResult = await query_llm(
        prompt=prompt,
        system_prompt=ALERT_EXPLANATION_SYSTEM,
        temperature=0.2,
        max_tokens=512,
        prompt_version=prompt_version,
        fallback_text=fallback_text,
    )

    if result.source == "template_library":
        log.info("alert_explanation_fallback_llm", rule=rule_name)

    cost_recorded = await _record(result, user=user, endpoint="ai.explain")

    return {
        "explanation": result.text,
        "source": result.source,
        "model": result.model_used,
        "fallback_used": result.fallback_used,
        "warning": result.warning,
        "tokens_in": result.tokens_in,
        "tokens_out": result.tokens_out,
        "latency_ms": result.latency_ms,
        "prompt_version": result.prompt_version,
        "cost_recorded": cost_recorded,
    }


async def summarize_multiple_alerts(
    alerts: List[dict],
    user: Optional[str] = None,
) -> Dict[str, Any]:
    """Summarize multiple related alerts into a single narrative.

    Returns the same dict shape as `explain_alert`.
    """
    if not alerts:
        return {
            "explanation": "No alerts to summarize.",
            "source": "template_library",
            "model": None,
            "fallback_used": True,
            "warning": None,
            "tokens_in": 0,
            "tokens_out": 0,
            "latency_ms": 0,
            "prompt_version": None,
            "cost_recorded": False,
        }

    alert_summaries = []
    for alert in alerts[:5]:
        severity = alert.get("severity", "unknown").upper()
        rule = alert.get("rule_name", "Unknown")
        host = alert.get("host_name", "unknown")
        time_str = str(alert.get("time", "unknown"))[:19]
        alert_summaries.append(f"- [{severity}] {rule} on {host} at {time_str}")
    summaries_text = "\n".join(alert_summaries)
    truncated = max(0, len(alerts) - 5)

    prompt, prompt_version, _ = render_alert_summary(
        alert_summaries=summaries_text,
        truncated_count=truncated,
    )

    fallback_text = (
        f"Cluster of {len(alerts)} related alerts detected. "
        f"Severity breakdown: " +
        ", ".join(
            f"{s}: {sum(1 for a in alerts if a.get('severity') == s)}"
            for s in ["critical", "high", "medium", "low"]
        ) +
        ". Affected hosts: " +
        ", ".join(set(a.get("host_name", "?") for a in alerts[:5]))
    )

    log.info("summarizing_alert_cluster", count=len(alerts))

    result = await query_llm(
        prompt=prompt,
        system_prompt=ALERT_EXPLANATION_SYSTEM,
        temperature=0.2,
        max_tokens=600,
        prompt_version=prompt_version,
        fallback_text=fallback_text,
    )

    cost_recorded = await _record(result, user=user, endpoint="ai.summarize")

    return {
        "explanation": result.text,
        "source": result.source,
        "model": result.model_used,
        "fallback_used": result.fallback_used,
        "warning": result.warning,
        "tokens_in": result.tokens_in,
        "tokens_out": result.tokens_out,
        "latency_ms": result.latency_ms,
        "prompt_version": result.prompt_version,
        "cost_recorded": cost_recorded,
    }


async def suggest_investigation_steps(
    alert_type: str,
    host_name: str,
    user_name: Optional[str] = None,
    user: Optional[str] = None,
) -> Dict[str, Any]:
    """Suggest specific investigation steps for an alert type.

    Returns dict with `steps` (list) and the same metadata keys as
    `explain_alert`.
    """
    prompt, prompt_version, _ = render_investigation_steps(
        alert_type=alert_type,
        host_name=host_name,
        user_name=user_name,
    )

    fallback_steps = _fallback_investigation_steps(alert_type, host_name)
    fallback_text = "\n".join(fallback_steps)

    log.info("suggesting_investigation", type=alert_type, host=host_name)

    result = await query_llm(
        prompt=prompt,
        system_prompt=(
            "You are a SOC analyst. "
            "Provide practical, actionable investigation steps."
        ),
        temperature=0.3,
        max_tokens=400,
        prompt_version=prompt_version,
        fallback_text=fallback_text,
    )

    # Parse into list (simple split on newlines)
    if result.source == "ollama":
        steps = [
            s.strip() for s in result.text.split("\n")
            if s.strip() and s.strip()[0].isdigit()
        ]
        if not steps:
            steps = [result.text]
    else:
        steps = fallback_steps

    cost_recorded = await _record(result, user=user, endpoint="ai.investigate")

    return {
        "steps": steps,
        "source": result.source,
        "model": result.model_used,
        "fallback_used": result.fallback_used,
        "warning": result.warning,
        "tokens_in": result.tokens_in,
        "tokens_out": result.tokens_out,
        "latency_ms": result.latency_ms,
        "prompt_version": result.prompt_version,
        "cost_recorded": cost_recorded,
    }


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
    if not alert_type:
        return None
    key = alert_type.lower().replace(" ", "_").replace("-", "_")
    if key in TEMPLATE_EXPLANATIONS:
        return TEMPLATE_EXPLANATIONS[key]
    for template_key, template_val in TEMPLATE_EXPLANATIONS.items():
        if template_key in key or key in template_key:
            return template_val
    return None
