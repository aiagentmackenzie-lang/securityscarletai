"""Auth-event ingest contract (V0.3 -- the identity telemetry source).

Identity is the #1 visibility gap named by buyers (SANS 2026): osquery has
NO auth-failure table (utmpx `logged_in_users` is session state only), so
the brute-force detection chain was structurally dead on real telemetry.
The fix is a dedicated auth source that emits the ingest convention:

    event_category = 'authentication'
    event_action   = 'auth_failed' | 'auth_success'
    source         = 'auth_shipper'

ONE shape definition (`build_auth_event`) is shared by:
  - the macOS unified-log shipper (scripts/auth_log_shipper.py -- parses
    sshd Failed/Accepted/Invalid messages from `log show --style ndjson`)
  - the detection-matrix generators (synthetic true/false event pairs in
    the EXACT shipper format -- no rule can pass on a fake vocabulary)

The osquery parser deliberately does NOT produce 'auth_failed' (a utmpx
row can't fail); auth failures only ever come from this contract.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from src.ingestion.schemas import NormalizedEvent

AUTH_SOURCE_NAME = "auth_shipper"

#: The closed action vocabulary for auth events (subset of the ingest
#: convention -- see src/ingestion/schemas.py).
AUTH_ACTIONS = ("auth_failed", "auth_success")


def build_auth_event(
    timestamp: datetime,
    host_name: str,
    outcome: str,
    user_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    raw_message: Optional[str] = None,
) -> NormalizedEvent:
    """Build a normalized authentication event.

    Args:
        timestamp: Event time (UTC-aware).
        host_name: Host the auth event occurred on.
        outcome: 'failed' or 'success' -- the only two outcomes the
            brute-force chain keys on; anything else is rejected (fail-
            closed: an unknown outcome must not silently become success).
        user_name: The account involved (attempted user for failures).
        source_ip: The remote source of the auth attempt (utmpx/sshd
            messages carry it; local logins may be None).
        raw_message: The original log line (survives in raw_data -- chain
            of custody).
    """
    if outcome == "failed":
        event_action = "auth_failed"
    elif outcome == "success":
        event_action = "auth_success"
    else:
        raise ValueError(f"auth outcome must be 'failed' or 'success', got: {outcome!r}")

    return NormalizedEvent(
        **{
            "@timestamp": timestamp,
            "host_name": host_name,
            "event_category": "authentication",
            "event_type": "start",
            "event_action": event_action,
            "source": AUTH_SOURCE_NAME,
            "user_name": user_name,
            "source_ip": source_ip,
            "raw_data": {
                "shipper": AUTH_SOURCE_NAME,
                "message": raw_message,
            },
        }
    )


def event_to_shipper_line(event: NormalizedEvent) -> str:
    """Serialize an auth event as the NDJSON line the FileShipper (normalized
    format) consumes. Same shape the API /ingest contract accepts -- one
    format for real shippers, generators, and tests.
    """
    import json

    return json.dumps(event.model_dump(by_alias=True, mode="json"))
