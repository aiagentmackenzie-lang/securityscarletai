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
