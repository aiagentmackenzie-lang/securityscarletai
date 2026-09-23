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


# --- W1-C regression: the "never raises" contract was false for SHAPE errors ---
# A valid-JSON line with a non-dict top level or a non-dict `columns` raised
# AttributeError, which the FileShipper loop turned into an infinite
# same-offset retry (the AUD-006 stall pattern, alive for shape errors).


def test_parse_top_level_list_returns_none():
    event = parse_osquery_line('["name", "columns"]')
    assert event is None


def test_parse_top_level_string_returns_none():
    event = parse_osquery_line('"just a string"')
    assert event is None


def test_parse_top_level_number_returns_none():
    event = parse_osquery_line("42")
    assert event is None


def test_parse_columns_as_string_returns_none():
    line = json.dumps(
        {
            "name": "processes",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": "not-a-dict",
            "action": "added",
        }
    )
    event = parse_osquery_line(line)
    assert event is None


def test_parse_columns_as_list_returns_none():
    line = json.dumps(
        {
            "name": "processes",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": [{"pid": "1"}],
            "action": "added",
        }
    )
    event = parse_osquery_line(line)
    assert event is None


def test_parse_columns_as_number_returns_none():
    line = json.dumps(
        {
            "name": "processes",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": 12345,
            "action": "added",
        }
    )
    event = parse_osquery_line(line)
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


# ─────────────────────────────────────────────────────────────────────────
# V0.6a -- Windows fleet tables (cross-platform fleet)
# Every mapping below was verified against osquery source 2026-09-14 before
# implementation (see docs/internal/V0.6A_SPEC.md §0).
# ─────────────────────────────────────────────────────────────────────────


def _win_line(table: str, columns: dict, action: str = "added") -> str:
    return json.dumps(
        {
            "name": table,
            "hostIdentifier": "win-fleet-01",
            "calendarTime": "Mon Sep 14 12:00:00 2026 UTC",
            "unixTime": 1774267200,
            "columns": columns,
            "action": action,
        }
    )


class TestWindowsEventsAuth:
    """windows_events eventid 4624/4625 -> the closed auth vocabulary (D1).

    This is what arms the brute-force chain on Windows telemetry with ZERO
    rule changes: the Sigma threshold + brute_force_to_success correlation
    key on event_category='authentication' + auth_failed/auth_success.
    """

    def test_4625_maps_to_auth_failed_with_xml_payload(self):
        # Security channel data payloads arrive as XML text -- the classic
        # failed-logon shape, user + IP inside Data elements.
        data = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<EventData>"
            "<Data Name='TargetUserName'>administrator</Data>"
            "<Data Name='IpAddress'>203.0.113.50</Data>"
            "<Data Name='WorkstationName'>ATTACKBOX</Data>"
            "</EventData></Event>"
        )
        event = parse_osquery_line(
            _win_line("windows_events", {"eventid": "4625", "data": data, "source": "Security"})
        )
        assert event is not None
        assert event.event_category == "authentication"
        assert event.event_action == "auth_failed"
        assert event.user_name == "administrator"
        assert event.source_ip == "203.0.113.50"
        assert event.raw_data["columns"]["data"] == data  # chain of custody

    def test_4624_maps_to_auth_success_with_json_payload(self):
        # Some providers serialize `data` as JSON -- the JSON hunt path.
        data = json.dumps(
            {"EventData": {"TargetUserName": "svc-backup", "IpAddress": "198.51.100.7"}}
        )
        event = parse_osquery_line(_win_line("windows_events", {"eventid": "4624", "data": data}))
        assert event is not None
        assert event.event_action == "auth_success"
        assert event.user_name == "svc-backup"
        assert event.source_ip == "198.51.100.7"

    def test_4720_maps_to_account_created(self):
        # V0.6b per-token decision (the widening the V0.6a comment promised):
        # 4720 = "A user account was created" -- arms the T1136 rule.
        event = parse_osquery_line(_win_line("windows_events", {"eventid": "4720", "data": "<x/>"}))
        assert event is not None
        assert event.event_category == "authentication"
        assert event.event_action == "account_created"

    def test_other_eventids_fail_closed_unmapped(self):
        # 4724 (password reset), 4672 (special logon), group-membership ids
        # etc. stay UNMAPPED: adding tokens is a reviewed per-token decision,
        # never a silent widening.
        for eid in ("4724", "4672", "4732", "4728"):
            event = parse_osquery_line(
                _win_line("windows_events", {"eventid": eid, "data": "<x/>"})
            )
            assert event is not None  # row still ingests
            assert event.event_category == "authentication"
            assert event.event_action is None  # no fabricated token
            assert event.raw_data["columns"]["eventid"] == eid

    def test_unparseable_payload_keeps_token_from_eventid(self):
        # eventid is the ground truth; a malformed `data` payload must not
        # lose the auth token -- only the enrichment (user/IP) degrades.
        event = parse_osquery_line(
            _win_line("windows_events", {"eventid": "4625", "data": "<<<not-json-not-xml<<<"})
        )
        assert event is not None
        assert event.event_action == "auth_failed"
        assert event.user_name is None
        assert event.source_ip is None

    def test_loopback_and_sentinel_ips_dropped(self):
        # Local/loopback logons carry no remote-attacker context: 4624 with
        # IpAddress '-' (local) or ::1 ships source_ip=None.
        for bogus in ("-", "::1", "127.0.0.1", ""):
            data = json.dumps({"EventData": {"TargetUserName": "raph", "IpAddress": bogus}})
            event = parse_osquery_line(
                _win_line("windows_events", {"eventid": "4624", "data": data})
            )
            assert event.source_ip is None, bogus
            assert event.user_name == "raph"  # identity context survives

    def test_non_integer_eventid_fail_closed(self):
        event = parse_osquery_line(
            _win_line("windows_events", {"eventid": "not-a-number", "data": "{}"})
        )
        assert event is not None
        assert event.event_action is None


class TestProcessEtwEvents:
    """process_etw_events: ProcessStart/ProcessStop -> process vocabulary.

    The table has NO `name` column (verified) -- process_name comes from
    basename(path), on both separators.
    """

    def test_process_start_maps_and_derives_name_from_windows_path(self):
        event = parse_osquery_line(
            _win_line(
                "process_etw_events",
                {
                    "type": "ProcessStart",
                    "pid": "4242",
                    "ppid": "800",
                    "path": "C:\\Windows\\System32\\cmd.exe",
                    "cmdline": "cmd.exe /c whoami",
                    "username": "raph",
                    "token_elevation_type": "Full",
                },
            )
        )
        assert event is not None
        assert event.event_category == "process"
        assert event.event_action == "process_start"
        assert event.event_type == "start"
        assert event.process_name == "cmd.exe"
        assert event.process_pid == 4242
        assert event.process_cmdline == "cmd.exe /c whoami"

    def test_process_stop_flips_event_type_to_end(self):
        event = parse_osquery_line(
            _win_line(
                "process_etw_events",
                {"type": "ProcessStop", "pid": "4242", "path": "C:\\x\\tool.exe", "exit_code": "0"},
            )
        )
        assert event is not None
        assert event.event_action == "process_end"
        assert event.event_type == "end"

    def test_unknown_etw_type_fail_closed(self):
        event = parse_osquery_line(
            _win_line("process_etw_events", {"type": "SomethingElse", "pid": "1"})
        )
        assert event is not None
        assert event.event_action is None

    def test_posix_style_path_basename_fallback(self):
        # Defensive cross-platform fallback (a Windows host running a POSIX-
        # style path tool) -- basename still derives.
        event = parse_osquery_line(
            _win_line("process_etw_events", {"type": "ProcessStart", "path": "/usr/bin/python3"})
        )
        assert event is not None
        assert event.process_name == "python3"


class TestPowerShellEvents:
    def test_script_text_maps_to_command_observed_and_cmdline(self):
        event = parse_osquery_line(
            _win_line(
                "powershell_events",
                {
                    "script_text": "Invoke-Mimikatz -DumpCreds",
                    "script_name": "obfuscated.ps1",
                    "script_path": "C:\\Users\\raph\\AppData\\Temp\\obfuscated.ps1",
                    "script_block_id": "{abcd-1234}",
                },
            )
        )
        assert event is not None
        assert event.event_category == "process"
        assert event.event_action == "command_observed"
        assert event.process_cmdline == "Invoke-Mimikatz -DumpCreds"
        assert event.process_path == "C:\\Users\\raph\\AppData\\Temp\\obfuscated.ps1"


class TestNtfsJournalEvents:
    def test_action_maps_through_file_token_vocabulary(self):
        cases = {
            "Created": "file_created",
            "Deleted": "file_deleted",
            "Overwritten": "file_modified",
            "": "file_event",
        }
        for action, expected in cases.items():
            event = parse_osquery_line(
                _win_line(
                    "ntfs_journal_events",
                    {
                        "action": action,
                        "path": "C:\\Windows\\Temp\\drop.exe",
                        "category": "tmp_staging",
                    },
                )
            )
            assert event is not None
            assert event.event_category == "file"
            assert event.event_action == expected, action
            assert event.file_path == "C:\\Windows\\Temp\\drop.exe"


class TestWindowsStateTables:
    """scheduled_tasks / services / registry -> config observations."""

    def test_scheduled_tasks_maps_to_config_observed(self):
        event = parse_osquery_line(
            _win_line(
                "scheduled_tasks",
                {
                    "name": "MicrosoftWindowsUpdate",
                    "action": "C:\\Users\\raph\\AppData\\update.exe",
                    "path": "\\Microsoft\\Windows\\UPDATE\\",
                    "enabled": "1",
                    "hidden": "1",
                    "state": "Ready",
                },
            )
        )
        assert event is not None
        assert event.event_category == "configuration"
        assert event.event_action == "config_observed"
        assert event.raw_data["columns"]["hidden"] == "1"

    def test_services_maps_to_config_observed(self):
        event = parse_osquery_line(
            _win_line(
                "services",
                {
                    "name": "ScarletAgent",
                    "display_name": "Scarlet Agent Service",
                    "status": "RUNNING",
                    "start_type": "AUTO_START",
                    "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                },
            )
        )
        assert event is not None
        assert event.event_category == "configuration"
        assert event.event_action == "config_observed"

    def test_registry_maps_to_config_observed(self):
        event = parse_osquery_line(
            _win_line(
                "registry",
                {
                    "key": "HKEY_USERS\\S-1-5-21-x\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "path": "HKEY_USERS\\S-1-5-21-x\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
                    "name": "OneDrive",
                    "type": "REG_SZ",
                    "data": "C:\\Users\\raph\\AppData\\OneDrive.exe",
                    "mtime": "1774267200",
                },
            )
        )
        assert event is not None
        assert event.event_category == "configuration"
        assert event.event_action == "config_observed"
        # registry `path` is NOT a file path -- file context must stay NULL.
        assert event.file_path is None
