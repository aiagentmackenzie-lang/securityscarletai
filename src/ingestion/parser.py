"""
Parses raw osquery result log lines into NormalizedEvent objects.

osquery result log format (one JSON object per line):
{
  "name": "processes",
  "hostIdentifier": "MacBook-Pro.local",
  "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
  "unixTime": 1774267200,
  "epoch": 0,
  "counter": 0,
  "numerics": false,
  "columns": { "pid": "123", "name": "python3", ... },
  "action": "added"
}
"""

import json
import socket
from datetime import datetime, timezone
from typing import Optional

from src.config.logging import get_logger
from src.ingestion.schemas import OSQUERY_ECS_MAP, NormalizedEvent, derive_event_action

log = get_logger("ingestion.parser")

# Tables whose differential 'removed' rows carry real exit semantics.
# (file_events excluded -- see event_type note in parse_osquery_line.)
_EXIT_TABLES = frozenset(
    {"processes", "process_events", "logged_in_users", "open_sockets", "listening_ports"}
)


def parse_osquery_line(raw_line: str) -> Optional[NormalizedEvent]:
    """Parse a single line from osquery's result log.

    Returns None if the line is malformed or from an unmapped table.
    Never raises -- log errors and move on. A stuck parser kills the pipeline.
    """
    try:
        data = json.loads(raw_line)
    except json.JSONDecodeError as e:
        log.warning("json_parse_failed", error=str(e), line_preview=raw_line[:200])
        return None

    table_name = data.get("name", "")
    ecs_mapping = OSQUERY_ECS_MAP.get(table_name)

    if not ecs_mapping:
        log.debug("unmapped_table", table=table_name)
        return None

    columns = data.get("columns", {})
    osquery_action = data.get("action", "info")

    # Parse timestamp -- osquery provides both calendarTime and unixTime
    try:
        ts = datetime.fromtimestamp(int(data.get("unixTime", 0)), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        ts = datetime.now(tz=timezone.utc)

    # event_action: closed vocabulary token (see derive_event_action).
    # Fail-closed -- non-differential shapes (snapshot dumps, unknown actions)
    # carry NO token rather than a fake one; the raw action survives in
    # raw_data for the chain of custody.
    event_action = derive_event_action(table_name, osquery_action, columns)

    event_type = ecs_mapping["event_type"]
    if osquery_action == "removed" and table_name in _EXIT_TABLES:
        # Differential 'removed' rows are state EXITS, not observations:
        # process died, session closed, socket/listener gone. The ECS map
        # entry carries the default ('start'/'connection') for the added
        # rows; exits flip to 'end'. file_events is deliberately NOT in
        # _EXIT_TABLES: a FIM differential 'removed' row means the event
        # aged out of osquery's differential cache -- NOT a file exit.
        event_type = "end"
    elif table_name == "es_process_events":
        # EndpointSecurity exit rows arrive as 'added' events whose columns
        # carry event_type=exit (derived above into event_action).
        if (columns.get("event_type") or "").lower() == "exit":
            event_type = "end"
        elif osquery_action not in ("added", "removed"):
            event_type = "info"
    elif osquery_action not in ("added", "removed"):
        # Snapshot dumps / unknown shapes are plain observations -- neutral
        # ECS event_type, no fabricated start/end semantics.
        event_type = "info"

    return NormalizedEvent(
        **{
            "@timestamp": ts,
            "host_name": data.get("hostIdentifier", socket.gethostname()),
            "event_category": ecs_mapping["event_category"],
            "event_type": event_type,
            "event_action": event_action,
            "source": f"osquery:{table_name}",
            "user_name": columns.get("user") or columns.get("username") or columns.get("uid"),
            "process_name": columns.get("name"),
            "process_pid": _safe_int(columns.get("pid")),
            "process_cmdline": columns.get("cmdline"),
            "process_path": columns.get("path"),
            "source_ip": _safe_ip(columns.get("local_address") or columns.get("address")),
            "destination_ip": _safe_ip(columns.get("remote_address")),
            "destination_port": _safe_int(columns.get("remote_port") or columns.get("port")),
            "file_path": (columns.get("path") or columns.get("target_path"))
            if ecs_mapping["event_category"] == "file"
            else None,
            "file_hash": columns.get("sha256") or columns.get("md5"),
            "raw_data": data,
        }
    )


def _safe_ip(val: Optional[str]) -> Optional[str]:
    """Normalize an osquery address string for the logs INET columns.

    The database rejects empty strings for INET parameters
    (``'' does not appear to be an IPv4 or IPv6 interface``) -- an
    empty-address row (e.g. listening_ports on a socket with no local
    address) must ship as NULL, not ''. Without this, one empty-address
    event fails its whole executemany batch and strands up to 99 good
    events in the dead-letter queue (observed live 2026-09-07).
    """
    if val is None or val == "":
        return None
    return val


def _safe_int(val: Optional[str]) -> Optional[int]:
    """Convert string to int safely. osquery returns all values as strings."""
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
