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

from src.ingestion.schemas import NormalizedEvent, OSQUERY_ECS_MAP
from src.config.logging import get_logger

log = get_logger("ingestion.parser")


def parse_osquery_line(raw_line: str) -> Optional[NormalizedEvent]:
    """Parse a single line from osquery's result log.
    
    Returns None if the line is malformed or from an unmapped table.
    Never raises — log errors and move on. A stuck parser kills the pipeline.
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
    
    # Parse timestamp — osquery provides both calendarTime and unixTime
    try:
        ts = datetime.fromtimestamp(int(data.get("unixTime", 0)), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        ts = datetime.now(tz=timezone.utc)

    return NormalizedEvent(
        **{
            "@timestamp": ts,
            "host_name": data.get("hostIdentifier", socket.gethostname()),
            "event_category": ecs_mapping["event_category"],
            "event_type": ecs_mapping["event_type"],
            "event_action": f"{table_name}_{data.get('action', 'info')}",
            "source": f"osquery:{table_name}",
            "user_name": columns.get("user") or columns.get("username") or columns.get("uid"),
            "process_name": columns.get("name"),
            "process_pid": _safe_int(columns.get("pid")),
            "process_cmdline": columns.get("cmdline"),
            "process_path": columns.get("path"),
            "source_ip": columns.get("local_address") or columns.get("address"),
            "destination_ip": columns.get("remote_address"),
            "destination_port": _safe_int(columns.get("remote_port") or columns.get("port")),
            "file_path": columns.get("path") if ecs_mapping["event_category"] == "file" else None,
            "file_hash": columns.get("sha256") or columns.get("md5"),
            "raw_data": data,
        }
    )


def _safe_int(val: Optional[str]) -> Optional[int]:
    """Convert string to int safely. osquery returns all values as strings."""
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
