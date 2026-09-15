"""Deception-event ingest contract (Wave 1 W1.5 -- deception as a domain).

Deception alerts (HONEYTRAP -- Raphael's 7-service deception project --
and the deployment kit's canary playbook) POST into this SIEM as a
first-class log source with the same discipline as the auth source (V0.3)
and the AI-usage source (V0.4/5): ONE shape definition shared by
producers, generators, and tests; producers map INTO the closed
event_action vocabulary, never fake tokens.

    event_category = 'deception'
    event_action   = deception_service_probe | deception_canary_access |
                     deception_token_use
    source         = 'deception'

Doctrine (the near-zero-FP story): deception alerts are high-fidelity by
CONSTRUCTION -- nothing in production traffic should ever touch a
honeypot. The severity boost lives HERE (canary/token events default
CRITICAL, service probes HIGH). Propagation is the standard alert paths,
no special tier needed: W1.7 notification channels route by severity
(canary/token defaults are critical), and create_alert auto-creates a
case for CRITICAL deception alerts (canary/token kinds -- the
direct-escalation tier, src/detection/alerts.py). Probes alert + notify
without an auto-case (count-bursty, dedup-bounded).

Transport: producers write the NDJSON shipper line (HONEYTRAP's forwarder
tails it into the SIEM's deception events path; remote fleet hosts POST
via /ingest -- deploy/fleet/canary_playbook.sh) and the SIEM tails the
file with a normalized-format FileShipper (enable_deception_shipper).

Rule-title convention: deception-domain Sigma rule titles begin with
"Deception" (e.g. "Deception Canary File Accessed") -- the auto-case
doctrine keys on that prefix, case-insensitive
(src/detection/alerts.py; rules.name stores the title).

Field mapping (deliberate, documented):
    host_name    = the fleet host running the deception service (the
                   shipper's own host identity -- the same host binding as
                   the fleet shippers).
    user_name    = the actor the deception component observed touching it
                   (best-effort, may be None).
    raw_data     = {component, detail} -- chain of custody; NOT
                   Sigma-selectable (flat columns only).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from src.detection.alerts import SEVERITY_INDEX  # the alert severity vocabulary
from src.ingestion.schemas import NormalizedEvent

DECEPTION_SOURCE = "deception"
DECEPTION_CATEGORY = "deception"

# The closed kind -> (event_action, default_severity) mapping. Producers
# name a KIND; anything outside this table is rejected (fail-closed: an
# unknown kind must not silently become a guessed token). Severity defaults
# ARE the doctrine: canary/token events are CRITICAL (any access is
# malicious by definition), probes HIGH.
DECEPTION_KINDS: dict[str, tuple[str, str]] = {
    "service_probe": ("deception_service_probe", "high"),
    "canary_file_access": ("deception_canary_access", "critical"),
    "canary_token_use": ("deception_token_use", "critical"),
}

# The direct-escalation tiers (doctrine): these kinds are cases by
# construction -- the producer may raise their severity, never lower it.
CANARY_KINDS = ("canary_file_access", "canary_token_use")


def build_deception_event(
    kind: str,
    *,
    host_name: str,
    user_name: Optional[str] = None,
    component: Optional[str] = None,
    detail: Optional[dict] = None,
    severity: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> NormalizedEvent:
    """Build one normalized deception event.

    Args:
        kind: A key from DECEPTION_KINDS (fail-closed on anything else).
        host_name: The fleet host running the deception service (required --
            the deception signal is meaningless without the host it fired on).
        user_name: The observed actor (best-effort, may be None).
        component: The deception component (e.g. 'honeytrap-smb', 'canary').
        detail: Structured detail (chain of custody; NOT Sigma-selectable).
        severity: Optional override; a deception signal is never silently
            DOWNGRADED -- an override below the kind's doctrine default is
            refused.

    Raises:
        ValueError: unknown kind (fail-closed) or a downgrading override.
    """
    if kind not in DECEPTION_KINDS:
        raise ValueError(f"deception kind must be one of {sorted(DECEPTION_KINDS)}, got: {kind!r}")
    action, default_sev = DECEPTION_KINDS[kind]
    if severity is not None:
        given = str(severity).strip().lower()
        if given not in SEVERITY_INDEX:
            raise ValueError(f"deception severity must be a known value, got: {severity!r}")
        if SEVERITY_INDEX[given] < SEVERITY_INDEX[default_sev]:
            raise ValueError(
                f"deception severity override ({given!r}) may not downgrade "
                f"the doctrine default ({default_sev!r})"
            )
        effective_severity = given
    else:
        effective_severity = default_sev
    return NormalizedEvent(
        **{
            "@timestamp": timestamp or datetime.now(timezone.utc),
            "host_name": host_name,
            "event_category": DECEPTION_CATEGORY,
            "event_type": "info",
            "event_action": action,
            "source": DECEPTION_SOURCE,
            "user_name": user_name,
            "severity": effective_severity,
            "raw_data": {
                "shipper": DECEPTION_SOURCE,
                "component": component,
                "detail": detail,
            },
        }
    )


def event_to_shipper_line(event: NormalizedEvent) -> str:
    """Serialize a deception event as the NDJSON line the FileShipper
    (normalized format) consumes. One format for real shippers, generators,
    and tests."""
    return json.dumps(event.model_dump(by_alias=True, mode="json"))
