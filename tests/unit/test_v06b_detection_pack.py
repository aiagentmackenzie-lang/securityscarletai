"""V0.6b 2026 behavioral detection pack -- unit gates.

Covers:
- windows_events 4720 -> account_created (the reviewed per-token widening)
- es_process_events process_name fallback (basename(path)) -- the bug the
  code read found: ES rows carry no `name` column and every ES exec row
  had process_name NULL
- the two new correlation chains (metadata + parameter binding)
- coverage wiring for the new chains
- matrix generator scenarios for the new chains (fixture-level true/false
  validation: the shapes the deferred live-fire will drive through the real
  pipe)
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from scripts.generate_osquery_events import _matrix_scenarios
from src.detection import correlation as corr
from src.detection.correlation import (
    AI_PROCESS_NAMES,
    CLICKFIX_INTERPRETERS,
    CORRELATION_RULES,
)
from src.detection.coverage import CORRELATION_REQUIREMENTS
from src.ingestion.parser import parse_osquery_line

# ------------------------------------------------------------------------
# windows_events eventid 4720 -> account_created
# ------------------------------------------------------------------------


def _windows_event(eventid, data=None, **extra):
    columns = {
        "eventid": str(eventid),
        "source": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "computer_name": "WIN-TEST",
        "data": data or "",
    }
    columns.update(extra)
    return json.dumps(
        {
            "name": "windows_events",
            "hostIdentifier": "win-test.fleet",
            "unixTime": 1774267200,
            "columns": columns,
            "action": "added",
        }
    )


class TestWindowsAccountCreatedToken:
    def test_eventid_4720_maps_to_account_created(self):
        event = parse_osquery_line(_windows_event(4720, "TargetUserName: backdoor"))
        assert event is not None
        assert event.event_category == "authentication"
        assert event.event_action == "account_created"

    def test_other_eventids_stay_unmapped_fail_closed(self):
        # 4724 (password reset) and 4672 (special logon) are NOT widened --
        # every token addition is a reviewed, tested decision (V0.6a rule).
        for eid in (4724, 4672, 4732, 4728):
            event = parse_osquery_line(_windows_event(eid))
            assert event is not None
            assert event.event_action is None, f"eventid {eid} must stay unmapped"

    def test_4624_4625_auth_tokens_unchanged(self):
        assert parse_osquery_line(_windows_event(4624)).event_action == "auth_success"
        assert parse_osquery_line(_windows_event(4625)).event_action == "auth_failed"


# ------------------------------------------------------------------------
# es_process_events process_name fallback (the bug fix)
# ------------------------------------------------------------------------


def _es_exec(path, cmdline, **extra):
    columns = {
        "pid": "4242",
        "parent": "1",
        "path": path,
        "cmdline": cmdline,
        "uid": "501",
        "username": "raphael",
        "event_type": "exec",
        "time": "1774267200",
    }
    columns.update(extra)
    return json.dumps(
        {
            "name": "es_process_events",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": columns,
            "action": "added",
        }
    )


class TestEsProcessNameFallback:
    def test_exec_row_carries_process_name_from_basename(self):
        # THE BUG: the schedule selects no `name` column and the parser had
        # no basename fallback for ES rows -> process_name was NULL on every
        # ES exec row (the majority of macOS process telemetry).
        event = parse_osquery_line(_es_exec("/bin/zsh", "/bin/zsh -c id"))
        assert event.event_action == "process_start"
        assert event.process_name == "zsh"

    def test_windows_path_separator_handled(self):
        event = parse_osquery_line(_es_exec(r"C:\Windows\System32\cmd.exe", r"cmd.exe /c whoami"))
        assert event.process_name == "cmd.exe"


# ------------------------------------------------------------------------
# New correlation chains: metadata + parameter binding
# ------------------------------------------------------------------------


def _mock_conn_fetch_rows(rows):
    """AsyncMock conn whose fetch returns (sql, *params) call info + rows.

    Callers pass a LIST of rows (matching asyncpg's list-of-records return);
    the tests below assert on call_args for the SQL/param contract.
    """
    mock_conn = AsyncMock()

    async def fetch(sql, *params):
        return rows

    mock_conn.fetch = AsyncMock(side_effect=fetch)
    return mock_conn


class TestClickfixDropperExecutionChain:
    def test_metadata_registered(self):
        meta = CORRELATION_RULES["clickfix_dropper_execution"]
        assert meta["severity"] == "high"
        assert "T1204.004" in meta["mitre_techniques"]

    @pytest.mark.asyncio
    async def test_query_binds_19_params_and_enriches_matches(self):
        mock_conn = _mock_conn_fetch_rows(
            [
                {
                    "host_name": "live-matrix-clickfix_dropper_execution",
                    "file_path": "/tmp/cf-payload.command",
                    "user_name": "demo",
                    "drop_time": datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc),
                    "process_name": "zsh",
                    "process_path": "/bin/zsh",
                    "process_cmdline": "/bin/zsh /tmp/cf-payload.command",
                    "exec_time": datetime(2026, 9, 14, 12, 1, 0, tzinfo=timezone.utc),
                }
            ]
        )
        results = await corr.detect_clickfix_dropper_execution(
            mock_conn, datetime(2026, 9, 14, 13, 0, 0, tzinfo=timezone.utc)
        )
        # The SQL binds exactly the params it references ($1..$19).
        sql = mock_conn.fetch.call_args.args[0]
        params = list(mock_conn.fetch.call_args.args[1:])
        referenced = {
            int(tok[: tok.index(non_digit)])
            for tok in sql.split("$")[1:]
            if (non_digit := next((c for c in tok if not c.isdigit()), None))
        } | {int(tok) for tok in sql.split("$")[1:] if tok.isdigit()}
        assert len(params) == 19
        assert referenced == set(range(1, 20))
        assert len(results) == 1
        match = results[0]
        assert match["correlation_rule"] == "clickfix_dropper_execution"
        assert match["correlation_id"]
        assert match["severity"] == "high"
        assert match["mitre_techniques"] == ["T1204.004", "T1059"]

    def test_interpreter_list_covers_both_platforms(self):
        # POSIX shells + macOS script hosts + Windows script hosts: the
        # chain is cross-platform by construction.
        for name in ("sh", "zsh", "osascript", "mshta", "powershell", "cmd"):
            assert name in CLICKFIX_INTERPRETERS


class TestAiProcessEgressChain:
    def test_metadata_registered(self):
        meta = CORRELATION_RULES["ai_process_egress"]
        assert meta["severity"] == "medium"
        assert meta["mitre_tactics"] == ["TA0010"]

    @pytest.mark.asyncio
    async def test_query_binds_8_params_and_enriches_matches(self):
        mock_conn = _mock_conn_fetch_rows(
            [
                {
                    "host_name": "live-matrix-ai_process_egress",
                    "ai_process": "claude",
                    "user_name": "demo",
                    "start_time": datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc),
                    "destination_ip": "203.0.113.10",
                    "destination_port": 443,
                    "conn_time": datetime(2026, 9, 14, 12, 0, 30, tzinfo=timezone.utc),
                }
            ]
        )
        results = await corr.detect_ai_process_egress(
            mock_conn, datetime(2026, 9, 14, 13, 0, 0, tzinfo=timezone.utc)
        )
        sql = mock_conn.fetch.call_args.args[0]
        params = list(mock_conn.fetch.call_args.args[1:])
        assert len(params) == 8
        # The AI process list is bound as the $2 array.
        assert list(params[1]) == list(AI_PROCESS_NAMES)
        assert len(results) == 1
        assert results[0]["correlation_rule"] == "ai_process_egress"

    def test_run_all_registers_all_ten_chains(self):
        assert "clickfix_dropper_execution" in corr.CORRELATION_RULES
        assert "ai_process_egress" in corr.CORRELATION_RULES
        assert len(corr.CORRELATION_RULES) == 10


# ------------------------------------------------------------------------
# Coverage wiring: the new chains must be ARMABLE (not "no requirement")
# ------------------------------------------------------------------------


class TestCoverageWiringForNewChains:
    def test_new_chains_have_requirements(self):
        for chain in ("clickfix_dropper_execution", "ai_process_egress"):
            assert chain in CORRELATION_REQUIREMENTS, (
                f"{chain} missing from CORRELATION_REQUIREMENTS -- the coverage "
                "map would report 'no coverage requirement defined' forever"
            )

    def test_ai_process_names_shared_with_chain(self):
        req = CORRELATION_REQUIREMENTS["ai_process_egress"]
        assert list(req["process_names"]) == list(AI_PROCESS_NAMES)


# ------------------------------------------------------------------------
# Matrix generator: the deferred live-fire scenarios (fixture validation)
# ------------------------------------------------------------------------


class TestMatrixScenariosForNewChains:
    def test_scenarios_exist_for_both_chains(self):
        scenarios = _matrix_scenarios("/tmp/auth-matrix-test.log")
        assert "clickfix_dropper_execution" in scenarios
        assert "ai_process_egress" in scenarios
        # 10 chains total in the matrix (8 original + 2 new).
        assert len(scenarios) == 10

    def _host_lines(self, scenarios, chain):
        target, lines = scenarios[chain]
        assert target == "OSQUERY"
        return lines

    def test_clickfix_scenario_shapes_parse_to_chain_vocabulary(self):
        scenarios = _matrix_scenarios("/tmp/auth-matrix-test.log")
        lines = self._host_lines(scenarios, "clickfix_dropper_execution")
        events = [parse_osquery_line(line) for line in lines]
        assert all(e is not None for e in events)
        file_ev = next(e for e in events if e.event_category == "file")
        assert file_ev.event_action == "file_created"
        assert file_ev.file_path.startswith("/tmp/")
        exec_ev = next(e for e in events if e.event_category == "process")
        assert exec_ev.event_action == "process_start"
        assert exec_ev.process_name in CLICKFIX_INTERPRETERS
        assert "/tmp/cf-payload.command" in (exec_ev.process_cmdline or "")

    def test_ai_egress_scenario_shapes_parse_to_chain_vocabulary(self):
        scenarios = _matrix_scenarios("/tmp/auth-matrix-test.log")
        lines = self._host_lines(scenarios, "ai_process_egress")
        events = [parse_osquery_line(line) for line in lines]
        assert all(e is not None for e in events)
        start_ev = next(e for e in events if e.event_category == "process")
        assert start_ev.event_action == "process_start"
        assert start_ev.process_name in AI_PROCESS_NAMES
        conn_ev = next(e for e in events if e.event_category == "network")
        assert conn_ev.event_action == "network_connection"
        assert conn_ev.destination_ip is not None
        assert conn_ev.destination_ip.startswith("203.0.113.")

    def test_new_scenarios_use_the_live_matrix_cleanup_prefix(self):
        # The live-fire cleanup SQL scopes on live-matrix-% -- a scenario
        # host outside that prefix would strand synthetic rows in the
        # standing volume (HITL cleanup is scoped, not global).
        scenarios = _matrix_scenarios("/tmp/auth-matrix-test.log")
        for chain in ("clickfix_dropper_execution", "ai_process_egress"):
            for line in self._host_lines(scenarios, chain):
                assert '"live-matrix-' in line, f"{chain} host must be live-matrix-*"
