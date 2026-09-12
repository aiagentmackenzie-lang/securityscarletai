import json

from src.ingestion.parser import parse_osquery_line

SAMPLE_PROCESS_LOG = json.dumps(
    {
        "name": "processes",
        "hostIdentifier": "test-mac.local",
        "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
        "unixTime": 1774267200,
        "columns": {
            "pid": "1234",
            "name": "python3",
            "path": "/opt/homebrew/bin/python3",
            "cmdline": "python3 -m pytest",
            "uid": "501",
        },
        "action": "added",
    }
)


def test_parse_process_event():
    event = parse_osquery_line(SAMPLE_PROCESS_LOG)
    assert event is not None
    assert event.host_name == "test-mac.local"
    assert event.event_category == "process"
    assert event.process_name == "python3"
    assert event.process_pid == 1234


# ------------------------------------------------------------------------
# es_process_events (macOS EndpointSecurity native process telemetry)
# ------------------------------------------------------------------------


def _es_line(event_type, **extra):
    columns = {
        "pid": "4242",
        "parent": "1",
        "path": "/bin/zsh",
        "cmdline": "/bin/zsh -c id",
        "cwd": "/tmp",
        "uid": "501",
        "username": "raphael",
        "signing_id": "com.apple.zsh",
        "platform_binary": "1",
        "event_type": event_type,
        "time": "1774267200",
    }
    columns.update(extra)
    return json.dumps(
        {
            "name": "es_process_events",
            "hostIdentifier": "test-mac.local",
            "calendarTime": "Mon Mar 21 12:00:00 2026 UTC",
            "unixTime": 1774267200,
            "columns": columns,
            "action": "added",
        }
    )


def test_es_process_exec_maps_to_process_start():
    event = parse_osquery_line(_es_line("exec"))
    assert event is not None
    assert event.event_category == "process"
    assert event.event_type == "start"
    assert event.event_action == "process_start"
    assert event.process_pid == 4242
    assert event.process_path == "/bin/zsh"
    assert event.process_cmdline == "/bin/zsh -c id"
    assert event.user_name == "raphael"
    # ES evidence columns are NOT mapped into the closed NormalizedEvent
    # fields -- they ride in raw_data (chain of custody), unpadded schema.
    assert event.raw_data["columns"]["signing_id"] == "com.apple.zsh"


def test_es_process_exit_maps_to_process_end():
    event = parse_osquery_line(_es_line("exit", exit_code="0"))
    assert event is not None
    assert event.event_type == "end"
    assert event.event_action == "process_end"


def test_es_process_fork_is_fail_closed_unmapped():
    # A fork row carries the PARENT's pid (child in child_pid) -- mapping it
    # to process_start would misattribute. Honest: no token, raw preserved.
    event = parse_osquery_line(_es_line("fork", child_pid="4243"))
    assert event is not None
    assert event.event_action is None
    assert event.raw_data["columns"]["event_type"] == "fork"
    assert event.raw_data["columns"]["child_pid"] == "4243"


def test_es_process_snapshot_is_neutral_info():
    event = parse_osquery_line(_es_line("exec").replace('"added"', '"snapshot"'))
    assert event is not None
    assert event.event_action is None
    assert event.event_type == "info"


def test_parse_invalid_json():
    event = parse_osquery_line("not json at all{{{")
    assert event is None


def test_parse_unknown_table():
    line = json.dumps({"name": "unknown_table_xyz", "columns": {}, "unixTime": 0})
    event = parse_osquery_line(line)
    assert event is None


# --- Regression: empty INET strings must normalize to None (2026-09-07 live finding) ---
# listening_ports/open_sockets rows with no local_address produce
# source_ip="" — the writer's INET parameter rejects "" and the whole
# 100-event batch dead-letters. One empty-address row must not poison
# its batch: both address fields must ship as NULL instead.

LISTENING_PORTS_EMPTY_ADDR = json.dumps(
    {
        "name": "listening_ports",
        "hostIdentifier": "test-mac.local",
        "unixTime": 1774267200,
        "columns": {
            "pid": "940",
            "name": "limactl",
            "port": "0",
            "local_address": "",
            "remote_address": "",
        },
        "action": "added",
    }
)


def test_listening_ports_empty_source_ip_is_none():
    event = parse_osquery_line(LISTENING_PORTS_EMPTY_ADDR)
    assert event is not None
    assert event.source_ip is None
    assert event.destination_ip is None


def test_open_sockets_empty_address_falls_through_to_none():
    # The `local_address or address` chain returned "" when BOTH were empty —
    # "" is falsy so the chain yields the last candidate, still "".
    line = json.dumps(
        {
            "name": "open_sockets",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": {"pid": "1", "local_address": "", "address": "", "remote_address": ""},
            "action": "added",
        }
    )
    event = parse_osquery_line(line)
    assert event is not None
    assert event.source_ip is None
    assert event.destination_ip is None


def test_valid_addresses_pass_through():
    line = json.dumps(
        {
            "name": "open_sockets",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": {
                "pid": "1",
                "local_address": "127.0.0.1",
                "remote_address": "192.168.1.10",
                "remote_port": "8443",
            },
            "action": "added",
        }
    )
    event = parse_osquery_line(line)
    assert event is not None
    assert event.source_ip == "127.0.0.1"
    assert event.destination_ip == "192.168.1.10"
    assert event.destination_port == 8443


def test_safe_ip_none_passthrough():
    from src.ingestion.parser import _safe_ip

    assert _safe_ip(None) is None
    assert _safe_ip("") is None
    assert _safe_ip("10.0.0.1") == "10.0.0.1"


# --- Schema-level choke point: every path (API, parser, replay) ships NULL for "" ---
def test_normalized_event_empty_ip_becomes_none():
    from src.ingestion.schemas import NormalizedEvent

    ev = NormalizedEvent(
        **{
            "@timestamp": "2026-09-07T12:00:00Z",
            "host_name": "h",
            "event_category": "network",
            "event_type": "connection",
            "source": "osquery:open_sockets",
            "raw_data": {},
            "source_ip": "",
            "destination_ip": "",
        }
    )
    assert ev.source_ip is None
    assert ev.destination_ip is None


def test_normalized_event_valid_ip_passthrough():
    from src.ingestion.schemas import NormalizedEvent

    ev = NormalizedEvent(
        **{
            "@timestamp": "2026-09-07T12:00:00Z",
            "host_name": "h",
            "event_category": "network",
            "event_type": "connection",
            "source": "osquery:open_sockets",
            "raw_data": {},
            "source_ip": "10.1.2.3",
            "destination_ip": None,
        }
    )
    assert ev.source_ip == "10.1.2.3"


# --- file_events target_path: real osquery FIM schema uses target_path, not path ---
def test_file_event_target_path_mapped():
    line = json.dumps(
        {
            "name": "file_events",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": {
                "target_path": "/Users/admin/Library/LaunchAgents/com.apple.update.plist",
                "action": "CREATED",
            },
            "action": "added",
        }
    )
    event = parse_osquery_line(line)
    assert event is not None
    assert event.event_category == "file"
    assert event.file_path == "/Users/admin/Library/LaunchAgents/com.apple.update.plist"
