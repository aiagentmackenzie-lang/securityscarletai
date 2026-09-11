"""
ECS (Elastic Common Schema) field mappings for SecurityScarletAI.
Reference: https://www.elastic.co/guide/en/ecs/current/index.html

Each osquery table maps to an ECS event.category + event.type combination.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from src.config.logging import get_logger

log = get_logger("ingestion.schemas")


class NormalizedEvent(BaseModel):
    """A single security event normalized to ECS fields."""

    model_config = ConfigDict(populate_by_name=True)

    timestamp: datetime = Field(alias="@timestamp")

    # Host context
    host_name: str
    host_ip: Optional[str] = None

    # Event classification (ECS)
    event_category: str  # process, network, file, authentication, configuration
    event_type: str  # start, end, connection, creation, deletion, change, info
    event_action: Optional[str] = None  # specific action, e.g., "process_started"
    source: str  # osquery table name or ingestion source

    # Actor
    user_name: Optional[str] = None

    # Process context (when applicable)
    process_name: Optional[str] = None
    process_cmdline: Optional[str] = None
    process_path: Optional[str] = None
    process_pid: Optional[int] = None

    # Network context (when applicable)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    # File context (when applicable)
    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    # Raw + enrichment
    raw_data: dict[str, Any]
    enrichment: dict[str, Any] = Field(default_factory=dict)

    # Severity for alerting
    severity: Optional[str] = None  # info, low, medium, high, critical

    @field_validator("host_ip", "source_ip", "destination_ip", mode="before")
    @classmethod
    def _empty_ip_to_none(cls, v: Any) -> Any:
        """Empty string is not an IP: INET columns reject it (asyncpg raises
        `'' does not appear to be an IPv4 or IPv6 interface`), which fails the
        whole executemany batch and strands good events in dead-letter
        (observed live 2026-09-07). Ship NULL instead. Applies to every
        construction path: osquery parse, API ingest, dead-letter replay."""
        if v == "":
            return None
        return v


# Mapping: osquery table name to ECS category + type.
# disk_encryption is scheduled in config/osquery.conf but intentionally NOT
# mapped here: it is a compliance/audit table with no clean ECS event
# equivalent, so its lines are dropped by parse_osquery_line as unmapped_table
# (debug-level) rather than forced into a wrong category (P2-37).
# browser_plugins was REMOVED from the schedule entirely (2026-09-04): the
# table is empty/deprecated on modern macOS (verified live against osquery
# 5.23.1) and only added scheduler noise.
OSQUERY_ECS_MAP: dict[str, dict[str, str]] = {
    "processes": {"event_category": "process", "event_type": "start"},
    "process_events": {"event_category": "process", "event_type": "start"},
    "listening_ports": {"event_category": "network", "event_type": "connection"},
    "open_sockets": {"event_category": "network", "event_type": "connection"},
    "logged_in_users": {"event_category": "authentication", "event_type": "start"},
    "file_events": {"event_category": "file", "event_type": "change"},
    "shell_history": {"event_category": "process", "event_type": "info"},
    "crontab": {"event_category": "configuration", "event_type": "info"},
    "startup_items": {"event_category": "configuration", "event_type": "info"},
    "launchd_entries": {"event_category": "configuration", "event_type": "info"},
    "user_ssh_keys": {"event_category": "configuration", "event_type": "info"},
    "sip_config": {"event_category": "configuration", "event_type": "info"},
}


# ───────────────────────────────────────────────────────────────
# The event_action vocabulary (P1.2b — the closed token set)
#
# History: the parser used to emit f"{table}_{action}" (e.g.
# "logged_in_users_added"). No detector, Sigma rule, or coverage check could
# ever match those values — the 2026-09-07 live-fire proved 7 of 8
# correlation chains structurally unable to fire on real ingestion shapes.
#
# The vocabulary is now a CLOSED set of lowercase ECS-aligned tokens, mapped
# by the parser from (table, osquery action, FIM action column). Every other
# producer maps into it at ingest:
#   - auth shipper      → auth_failed / auth_success  (never faked by the
#                         osquery parser: utmpx logged_in_users has session
#                         state only, no failed-login semantics)
#   - NeuralGuard etc.  → verdict_block and friends via POST /ingest
#
# Fail-closed: anything not derivable maps to None — a fake token is worse
# than no token. The original osquery action always survives in raw_data
# (chain of custody); detectors key on exact tokens only.
# ───────────────────────────────────────────────────────────────

# Tokens produced by the osquery parser (table-derived).
EVENT_ACTION_PROCESS_START = "process_start"
EVENT_ACTION_PROCESS_END = "process_end"
EVENT_ACTION_NETWORK_CONNECTION = "network_connection"
EVENT_ACTION_NETWORK_DISCONNECT = "network_disconnect"
EVENT_ACTION_NETWORK_LISTEN = "network_listen"
EVENT_ACTION_AUTH_SUCCESS = "auth_success"  # session opened (utmpx = success semantics)
EVENT_ACTION_SESSION_CLOSED = "session_closed"
EVENT_ACTION_FILE_CREATED = "file_created"
EVENT_ACTION_FILE_MODIFIED = "file_modified"
EVENT_ACTION_FILE_DELETED = "file_deleted"
EVENT_ACTION_FILE_OPENED = "file_opened"
EVENT_ACTION_FILE_EVENT = "file_event"  # FIM action not in the mapping
EVENT_ACTION_CONFIG_OBSERVED = "config_observed"
EVENT_ACTION_COMMAND_OBSERVED = "command_observed"

# Tokens produced by external ingesters via POST /ingest (the ingest
# convention). Not produced by the parser; listed here as the contract.
EVENT_ACTION_AUTH_FAILED = "auth_failed"  # auth shipper / any real auth source
EVENT_ACTION_VERDICT_BLOCK = "verdict_block"  # NeuralGuard AI-firewall verdicts


def derive_event_action(table_name: str, action: str, columns: dict) -> Optional[str]:
    """Map (table, osquery differential action, columns) → vocabulary token.

    Differential semantics: osquery snapshot mode emits 'added'/'removed'
    rows only for state CHANGES since the previous run — a processes 'added'
    row means the process launched since the last interval (that is the
    documented detection mode of this deployment's osquery.conf), a
    logged_in_users 'added' row means a session opened. Snapshot 'snapshot'
    action (full state dump) is NOT derivable → None.
    """
    # osquery action: differential rows are 'added'/'removed'; full dumps are
    # 'snapshot' (and 'items' in some builds). Only differentials carry the
    # start/end semantics the vocabulary encodes.
    if action == "removed":
        return {
            "processes": EVENT_ACTION_PROCESS_END,
            "process_events": EVENT_ACTION_PROCESS_END,
            "open_sockets": EVENT_ACTION_NETWORK_DISCONNECT,
            "listening_ports": EVENT_ACTION_NETWORK_DISCONNECT,
            "logged_in_users": EVENT_ACTION_SESSION_CLOSED,
        }.get(table_name)
    if action == "added":
        if table_name in ("processes", "process_events"):
            return EVENT_ACTION_PROCESS_START
        if table_name == "listening_ports":
            return EVENT_ACTION_NETWORK_LISTEN
        if table_name == "open_sockets":
            return EVENT_ACTION_NETWORK_CONNECTION
        if table_name == "logged_in_users":
            return EVENT_ACTION_AUTH_SUCCESS
        if table_name == "file_events":
            return _file_action_token(columns.get("action", ""))
        if table_name == "shell_history":
            return EVENT_ACTION_COMMAND_OBSERVED
        if table_name in (
            "crontab",
            "startup_items",
            "launchd_entries",
            "user_ssh_keys",
            "sip_config",
        ):
            return EVENT_ACTION_CONFIG_OBSERVED
    return None


def _file_action_token(fim_action: str) -> str:
    """Map an osquery FIM action (file_events.columns.action) to a token.

    Real FIM action values across osquery builds: CREATED, UPDATED,
    WRITTEN, DELETED, OPENED, ATTR, ATTRIBUTES_MODIFIED (case varies).
    Substring matching is deliberate — FIM action vocabularies differ per
    build/backend; the closed token set stays stable.
    """
    a = (fim_action or "").lower()
    if "creat" in a:
        return EVENT_ACTION_FILE_CREATED
    if "delet" in a or "unlink" in a:
        return EVENT_ACTION_FILE_DELETED
    if "open" in a or "read" in a:
        return EVENT_ACTION_FILE_OPENED
    if a:  # updated/written/modified/attr/… → change semantics
        return EVENT_ACTION_FILE_MODIFIED
    return EVENT_ACTION_FILE_EVENT


def parse_normalized_line(raw_line: str) -> Optional[NormalizedEvent]:
    """Parse one NDJSON NormalizedEvent line (the normalized shipper format).

    Used by FileShipper(format="normalized") for the auth shipper's output.
    The contract mirrors the API /ingest schema strictness: host_name,
    event_category, event_type and source are REQUIRED (a line missing any
    is skipped — fail-closed, never guessed); @timestamp defaults to now.
    Never raises — a stuck parser kills the pipeline.
    """
    try:
        data = json.loads(raw_line)
    except json.JSONDecodeError as e:
        log.warning("normalized_parse_failed", error=str(e), line_preview=raw_line[:200])
        return None
    if not isinstance(data, dict):
        log.warning("normalized_parse_not_object", line_preview=raw_line[:200])
        return None

    required = ("host_name", "event_category", "event_type", "source")
    missing = [k for k in required if not data.get(k)]
    if missing:
        log.warning("normalized_parse_missing_fields", fields=missing)
        return None

    try:
        return NormalizedEvent(
            **{
                "@timestamp": data.get("@timestamp") or datetime.now(timezone.utc),
                "host_name": data["host_name"],
                "event_category": data["event_category"],
                "event_type": data["event_type"],
                "event_action": data.get("event_action"),
                "source": data["source"],
                "user_name": data.get("user_name"),
                "process_name": data.get("process_name"),
                "process_pid": data.get("process_pid"),
                "process_cmdline": data.get("process_cmdline"),
                "process_path": data.get("process_path"),
                "source_ip": data.get("source_ip"),
                "destination_ip": data.get("destination_ip"),
                "destination_port": data.get("destination_port"),
                "file_path": data.get("file_path"),
                "file_hash": data.get("file_hash"),
                "severity": data.get("severity"),
                "enrichment": data.get("enrichment") or {},
                "raw_data": (
                    data.get("raw_data")
                    if isinstance(data.get("raw_data"), dict)
                    else {"line": data}
                ),
            }
        )
    except ValidationError as e:
        log.warning("normalized_parse_invalid", error=str(e))
        return None
