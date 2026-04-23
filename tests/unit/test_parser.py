import json

from src.ingestion.parser import parse_osquery_line

SAMPLE_PROCESS_LOG = json.dumps({
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
    "action": "added"
})


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
