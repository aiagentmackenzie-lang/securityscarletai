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
import re
import socket
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath
from typing import Optional

from src.config.logging import get_logger
from src.ingestion.schemas import OSQUERY_ECS_MAP, NormalizedEvent, derive_event_action

log = get_logger("ingestion.parser")

# Tables whose differential 'removed' rows carry real exit semantics.
# (file_events excluded -- see event_type note in parse_osquery_line.)
_EXIT_TABLES = frozenset(
    {"processes", "process_events", "logged_in_users", "open_sockets", "listening_ports"}
)

# windows_events `data` payload extraction bounds (V0.6a). The payload
# serialization varies by provider (JSON-ish for some, XML text for the
# Security channel), so extraction is best-effort over BOTH shapes and
# fail-closed: nothing found -> NULL, the raw payload ALWAYS survives in
# raw_data (chain of custody). 16 KB cap bounds pathological payloads.
_WE_DATA_SCAN_LIMIT = 16 * 1024
_WE_USER_KEYS = ("targetusername", "subjectusername")
_WE_IP_KEYS = ("ipaddress", "sourceip")


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
    elif table_name == "process_etw_events":
        # Windows ETW stop rows arrive as 'added' events whose columns
        # carry type=ProcessStop (derived above into event_action).
        if (columns.get("type") or "").strip().lower() == "processstop":
            event_type = "end"
        elif osquery_action not in ("added", "removed"):
            event_type = "info"
    elif osquery_action not in ("added", "removed"):
        # Snapshot dumps / unknown shapes are plain observations -- neutral
        # ECS event_type, no fabricated start/end semantics.
        event_type = "info"

    # ── Table-specific enrichment (fail-closed; raw always preserved) ──
    user_name = columns.get("user") or columns.get("username") or columns.get("uid")
    source_ip = _safe_ip(columns.get("local_address") or columns.get("address"))
    process_name = columns.get("name")

    if table_name == "windows_events":
        # The auth context (user, source IP) lives INSIDE the `data`
        # payload, not in columns -- extract best-effort (V0.6a, D2).
        we_user, we_ip = _windows_event_context(columns.get("data"))
        if we_user and not user_name:
            user_name = we_user
        if we_ip and not source_ip:
            source_ip = _safe_ip(we_ip)
    elif table_name in ("process_etw_events", "es_process_events") and not process_name:
        # ETW rows carry NO `name` column -- the executable basename IS the
        # process name shape the process rules expect. Same shape applies
        # to es_process_events (schedule selects path/cmdline/username, no
        # name column): without this fallback EVERY ES exec row had
        # process_name NULL -- process-name-keyed rules and the coverage
        # process-name probe could never fire on the macOS ES path
        # (found by code read 2026-09-14, V0.6b).
        process_name = _basename_any_platform(columns.get("path"))

    return NormalizedEvent(
        **{
            "@timestamp": ts,
            "host_name": data.get("hostIdentifier", socket.gethostname()),
            "event_category": ecs_mapping["event_category"],
            "event_type": event_type,
            "event_action": event_action,
            "source": f"osquery:{table_name}",
            "user_name": user_name,
            "process_name": process_name,
            "process_pid": _safe_int(columns.get("pid")),
            "process_cmdline": columns.get("cmdline") or columns.get("script_text"),
            # powershell_events carries the script location as `script_path`
            # (no `path` column) -- it IS the executing-file path shape.
            "process_path": columns.get("path") or columns.get("script_path"),
            "source_ip": source_ip,
            "destination_ip": _safe_ip(columns.get("remote_address")),
            "destination_port": _safe_int(columns.get("remote_port") or columns.get("port")),
            "file_path": (columns.get("path") or columns.get("target_path"))
            if ecs_mapping["event_category"] == "file"
            else None,
            "file_hash": columns.get("sha256") or columns.get("md5"),
            "raw_data": data,
        }
    )


def _windows_event_context(data_raw: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Best-effort (TargetUserName, IpAddress) extraction from a windows_events
    `data` payload (V0.6a spec D2).

    The serialization varies by provider: JSON-ish objects for some, XML
    text for the Security channel (<Data Name='TargetUserName'>x</Data>).
    Strategy: bounded JSON parse with a recursive key hunt first, then
    bounded regex over the raw text. NOTHING found -> (None, None) -- a
    failed extraction never fabricates identity context; the raw payload
    survives in raw_data for chain of custody.
    """
    if not data_raw:
        return None, None
    scan = data_raw[:_WE_DATA_SCAN_LIMIT]

    # Shape 1: JSON payload -- recursive, case-insensitive key hunt.
    try:
        payload = json.loads(scan)
    except (json.JSONDecodeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        user = _json_hunt(payload, _WE_USER_KEYS)
        ip = _json_hunt(payload, _WE_IP_KEYS)
        if user or ip:
            return _clean_context(user), _clean_context(ip)

    # Shape 2: XML/text fallback -- two bounded regexes per field, one for
    # the XML attribute form, one for the JSON key form.
    user = _regex_first(
        scan, r"(?:TargetUserName|SubjectUserName)['\"]?\s*>\s*([^<\s<]{1,64})"
    ) or _regex_first(scan, r"(?:TargetUserName|SubjectUserName)\"?'?\s*[:=]\s*\"([^\"]{1,64})\"")
    ip = _regex_first(
        scan, r"(?:IpAddress|IpAddressString|SourceIp)['\"]?\s*>\s*([^<\s<]{1,45})"
    ) or _regex_first(
        scan, r"(?:IpAddress|IpAddressString|SourceIp)\"?'?\s*[:=]\s*\"([^\"]{1,45})\""
    )
    return _clean_context(user), _clean_context(ip)


def _json_hunt(node: object, keys: tuple[str, ...], depth: int = 0) -> Optional[str]:
    """Depth-bounded recursive search for the first matching key's value."""
    if depth > 6:
        return None
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in keys and isinstance(v, str):
                return v
        for v in node.values():
            found = _json_hunt(v, keys, depth + 1)
            if found:
                return found
    elif isinstance(node, list):
        for v in node:
            found = _json_hunt(v, keys, depth + 1)
            if found:
                return found
    return None


def _regex_first(text: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, text)
    return m.group(1) if m else None


def _clean_context(val: Optional[str]) -> Optional[str]:
    """Normalize an extracted context value; sentinels ('-', '-') -> None."""
    if not val:
        return None
    v = val.strip()
    if not v or v in {"-", "::1"} or v.startswith("127."):
        return None
    return v[:64]


def _basename_any_platform(path: Optional[str]) -> Optional[str]:
    """Basename of a POSIX or Windows path -- ETW rows have no `name` column,
    and the fleet is cross-platform, so both separators are handled."""
    if not path:
        return None
    return (PureWindowsPath(path).name or PurePosixPath(path).name or None) or None


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
