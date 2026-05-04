"""
Sequence-based detection patterns.

Defines event sequences (A → B within N minutes) that represent
attack chains. Used by the correlation engine for multi-event detection.

Each sequence defines:
- trigger_event: The initial event that starts the chain
- followup_event: The event that must follow within the time window
- time_window: Maximum allowed gap between trigger and followup
- confidence: Base confidence score when the full chain is detected
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class EventSequence:
    """Definition of a two-event attack sequence."""

    name: str
    title: str
    description: str
    severity: str
    trigger_category: str
    trigger_filter: dict  # Additional conditions for the trigger
    followup_category: str
    followup_filter: dict  # Additional conditions for the followup
    join_key: str  # Field to join on (e.g., "host_name", "source_ip")
    time_window_minutes: int
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    confidence_base: int = 70


# ───────────────────────────────────────────────────────────────
# Pre-defined attack sequences
# ───────────────────────────────────────────────────────────────

SEQUENCE_DEFINITIONS: list[EventSequence] = [
    EventSequence(
        name="brute_force_success",
        title="Brute Force → Successful Login",
        description="Multiple failed SSH logins followed by success from same source IP",
        severity="critical",
        trigger_category="authentication",
        trigger_filter={"event_action|contains": "failed"},
        followup_category="authentication",
        followup_filter={"event_action|contains": "success"},
        join_key="source_ip",
        time_window_minutes=5,
        mitre_tactics=["TA0006"],
        mitre_techniques=["T1110"],
        confidence_base=80,
    ),
    EventSequence(
        name="payload_callback",
        title="Dropped Payload → C2 Callback",
        description="Process launched from /tmp followed by outbound network connection",
        severity="critical",
        trigger_category="process",
        trigger_filter={"file_path|contains": "/tmp"},  # noqa: S108
        followup_category="network",
        followup_filter={"event_type": "connection"},
        join_key="host_name",
        time_window_minutes=10,
        mitre_tactics=["TA0002", "TA0011"],
        mitre_techniques=["T1059", "T1071"],
        confidence_base=75,
    ),
    EventSequence(
        name="persistence_activated",
        title="Persistence Created → Activated",
        description="LaunchAgent/LaunchDaemon creation followed by launchctl load",
        severity="high",
        trigger_category="file",
        trigger_filter={"file_path|contains": "LaunchAgents"},
        followup_category="process",
        followup_filter={"process_name": "launchctl", "process_cmdline|contains": "load"},
        join_key="host_name",
        time_window_minutes=30,
        mitre_tactics=["TA0003"],
        mitre_techniques=["T1547"],
        confidence_base=70,
    ),
    EventSequence(
        name="data_exfiltration",
        title="Large File Read → Large Network Transfer",
        description="Large data reads followed by significant outbound network transfers",
        severity="high",
        trigger_category="process",
        trigger_filter={"event_action|contains": "read"},
        followup_category="network",
        followup_filter={"event_type": "connection"},
        join_key="host_name",
        time_window_minutes=60,
        mitre_tactics=["TA0010"],
        mitre_techniques=["T1048"],
        confidence_base=65,
    ),
    EventSequence(
        name="privilege_escalation_chain",
        title="Privilege Escalation → Root Process",
        description="Sudo execution followed by root-level process spawning",
        severity="critical",
        trigger_category="authentication",
        trigger_filter={"process_name": "sudo"},
        followup_category="process",
        followup_filter={"user_name": "root"},
        join_key="host_name",
        time_window_minutes=10,
        mitre_tactics=["TA0004"],
        mitre_techniques=["T1548"],
        confidence_base=70,
    ),
    EventSequence(
        name="credential_theft_exfil",
        title="Credential Access → External Connection",
        description="Access to sensitive credential files followed by outbound connection",
        severity="critical",
        trigger_category="process",
        trigger_filter={"file_path|contains": ".ssh"},
        followup_category="network",
        followup_filter={"event_type": "connection"},
        join_key="host_name",
        time_window_minutes=15,
        mitre_tactics=["TA0006", "TA0010"],
        mitre_techniques=["T1555", "T1048"],
        confidence_base=80,
    ),
    EventSequence(
        name="defense_evasion_cleanup",
        title="Suspicious Activity → Log Deletion",
        description="High-severity process execution followed by log file deletion",
        severity="high",
        trigger_category="process",
        trigger_filter={"event_action|contains": "start"},
        followup_category="process",
        followup_filter={"process_name": "rm", "process_cmdline|contains": "/var/log"},
        join_key="host_name",
        time_window_minutes=30,
        mitre_tactics=["TA0005"],
        mitre_techniques=["T1070"],
        confidence_base=75,
    ),
]


def get_sequence(name: str) -> Optional[EventSequence]:
    """Get a sequence definition by name."""
    for seq in SEQUENCE_DEFINITIONS:
        if seq.name == name:
            return seq
    return None


def list_sequences() -> list[dict]:
    """List all available sequence definitions."""
    return [
        {
            "name": seq.name,
            "title": seq.title,
            "description": seq.description,
            "severity": seq.severity,
            "time_window_minutes": seq.time_window_minutes,
            "mitre_tactics": seq.mitre_tactics,
            "mitre_techniques": seq.mitre_techniques,
            "confidence_base": seq.confidence_base,
        }
        for seq in SEQUENCE_DEFINITIONS
    ]
