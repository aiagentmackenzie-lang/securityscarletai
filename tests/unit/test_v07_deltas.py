"""V0.7 plan-delta fixes -- unit gates.

The Sep-14 delta ledger (docs/internal/MARKET_LANDSCAPE §9 vs what shipped):
  (a) NIST CSF control rows in config/compliance_mappings.yaml (the plan
      named the overlay; only the title carried the name) -- see
      test_compliance.py for the shipped-config assertion.
  (b) the UEBA-ready outliers view in the posture report -- buildable
      read-only from existing tables, so built (src/compliance/outliers.py).
  (c) the macOS users-differential half of rogue-account creation (V0.6b
      item 2): the parser derives account_created from users-differential
      'added' rows, the schedule carries the table, and a Sigma rule keyed
      on source osquery:users mirrors the Windows 4720 half.

Plus the bug found during the session: purple_loop.CHAIN_HOSTS still
listed 8 chains while the generator emits 10.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scripts.generate_osquery_events import (
    SIGMA_FIXTURE_HOST,
    _matrix_scenarios,
    _sigma_fixture_lines,
)
from scripts.purple_loop import build_feedback
from src.compliance.outliers import (
    MIN_AUTH_FAILURES_TOTAL,
    ROBUST_Z_THRESHOLD,
    _robust_outliers,
    compute_posture_outliers,
)
from src.detection.sigma import ALLOWED_COLUMNS, load_rules_from_directory, sigma_to_sql
from src.ingestion.parser import parse_osquery_line

AS_OF = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "sigma"


def _pool_mock(conn):
    mock_pool = MagicMock()
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire = MagicMock(return_value=acquirer)
    return mock_pool


# ------------------------------------------------------------------------
# (c) the macOS users-differential token (parser)
# ------------------------------------------------------------------------


def _users_row(username, uid="502", action="added", **extra):
    columns = {
        "uid": uid,
        "username": username,
        "directory": f"/Users/{username}",
        "shell": "/bin/zsh",
    }
    columns.update(extra)
    return json.dumps(
        {
            "name": "users",
            "hostIdentifier": "test-mac.local",
            "unixTime": 1774267200,
            "columns": columns,
            "action": action,
        }
    )


class TestUsersDifferentialToken:
    def test_added_row_maps_to_account_created(self):
        event = parse_osquery_line(_users_row("svc-backup"))
        assert event is not None
        assert event.event_category == "authentication"
        assert event.event_type == "start"
        assert event.event_action == "account_created"
        assert event.user_name == "svc-backup"

    def test_removed_row_is_fail_closed_no_token(self):
        # Deleted-account semantics: event_type flips to 'end' (state exit),
        # but NO token -- the closed vocabulary has no account_deleted token
        # and widening it is a reviewed decision, not a silent one.
        event = parse_osquery_line(_users_row("old-user", action="removed"))
        assert event is not None
        assert event.event_type == "end"
        assert event.event_action is None

    def test_snapshot_dump_is_unmapped(self):
        event = parse_osquery_line(_users_row("someone", action="snapshot"))
        assert event is not None
        assert event.event_action is None
        assert event.event_type == "info"

    def test_logged_in_users_tokens_unchanged(self):
        # The session table is NOT part of the account-creation shape: a
        # login session is auth_success (utmpx), not an account creation.
        line = json.dumps(
            {
                "name": "logged_in_users",
                "hostIdentifier": "test-mac.local",
                "unixTime": 1774267200,
                "columns": {"type": "user", "user": "demo", "host": "", "time": "0", "pid": "9"},
                "action": "added",
            }
        )
        assert parse_osquery_line(line).event_action == "auth_success"


# ------------------------------------------------------------------------
# (c) the Sigma rule + source-keyed separation
# ------------------------------------------------------------------------


class TestMacosAccountCreatedRule:
    def test_rule_is_loaded_by_the_engine(self):
        titles = {r.title for r in load_rules_from_directory(RULES_DIR)}
        assert "macOS Local Account Created (users differential)" in titles

    def test_rule_compiles_with_the_source_key(self):
        path = RULES_DIR / "authentication" / "macos_local_account_created.yml"
        sql, params = sigma_to_sql(path.read_text())
        assert "osquery:users" in [str(p) for p in params]
        assert "event_action" in sql and "source" in sql

    def test_windows_rule_is_keyed_to_its_source(self):
        path = RULES_DIR / "authentication" / "windows_local_account_created.yml"
        sql, params = sigma_to_sql(path.read_text())
        assert "osquery:windows_events" in [str(p) for p in params]
        # The separation: the Windows rule must NOT select the macOS source.
        assert "osquery:users" not in [str(p) for p in params]
        assert "event_action" in sql and "source" in sql

    def test_source_column_is_whitelisted(self):
        assert "source" in ALLOWED_COLUMNS


# ------------------------------------------------------------------------
# (c) the matrix sigma fixture (the deferred live-fire shapes)
# ------------------------------------------------------------------------


class TestSigmaFixtureScenario:
    def test_fixture_lines_parse_and_key_the_true_shape(self):
        events = [parse_osquery_line(line) for line in _sigma_fixture_lines()]
        assert all(e is not None for e in events)
        added = next(e for e in events if e.event_action == "account_created")
        assert added.host_name == SIGMA_FIXTURE_HOST
        assert added.event_category == "authentication"
        assert added.event_type == "start"
        assert added.user_name == "svc-backup"

    def test_false_shapes_carry_no_account_created_token(self):
        events = [parse_osquery_line(line) for line in _sigma_fixture_lines()]
        # The removed-account row: no token (event_type 'end').
        removed = [e for e in events if e.event_type == "end"]
        assert removed and all(e.event_action is None for e in removed)
        # The session row: auth_success, NOT account_created.
        session = next(e for e in events if e.source == "osquery:logged_in_users")
        assert session.event_action == "auth_success"

    def test_fixture_host_uses_the_cleanup_prefix(self):
        # The HITL cleanup SQL scopes on live-matrix-% -- a fixture host
        # outside that prefix would strand synthetic rows in prod.
        for line in _sigma_fixture_lines():
            assert f'"hostIdentifier": "{SIGMA_FIXTURE_HOST}"' in line
        assert SIGMA_FIXTURE_HOST.startswith("live-matrix-")

    def test_sigma_fixture_is_not_scored_as_a_chain(self):
        # The chains dict stays exactly the 10 correlation chains; the
        # fixture rides separately (scored through its alert, not chains).
        scenarios = _matrix_scenarios("/tmp/auth-matrix-test.log")
        assert len(scenarios) == 10
        assert SIGMA_FIXTURE_HOST not in {h for h, _ in scenarios.values()}
        assert SIGMA_FIXTURE_HOST not in scenarios


# ------------------------------------------------------------------------
# purple-loop chain-host completeness (the 8-vs-10 bug)
# ------------------------------------------------------------------------


class TestPurpleLoopChainHosts:
    def test_scored_hosts_match_the_generator(self):
        from scripts.purple_loop import CHAIN_HOSTS

        scenarios = _matrix_scenarios("/tmp/auth-matrix-test.log")
        emitted = {f"live-matrix-{chain}" for chain in scenarios}
        assert set(CHAIN_HOSTS) == emitted, (
            "purple loop scores hosts the generator never emits (or vice versa)"
        )


class TestRunUniqueMatrixHosts:
    """Re-runs inside the 15-minute dedup window must score honestly:
    each run stamps its own hosts (fresh dedup slots), validated live
    2026-09-14 when an immediate re-run scored 0/10 with every detection
    deduped by design."""

    def test_run_host_stamp(self):
        from scripts.generate_osquery_events import _run_host

        assert _run_host("clickfix_dropper_execution") == ("live-matrix-clickfix_dropper_execution")
        assert _run_host("clickfix_dropper_execution", "130100Z") == (
            "live-matrix-clickfix_dropper_execution-130100Z"
        )

    def test_stamped_scenarios_keep_the_registry_shape(self):
        scenarios = _matrix_scenarios("/tmp/x.log", run_stamp="130100")
        assert len(scenarios) == 10
        # Every stamped scenario lands on a UNIQUE host carrying the stamp.
        for chain in scenarios:
            target, lines = scenarios[chain]
            for line in lines:
                host = json.loads(line).get("hostIdentifier") or json.loads(line).get("host_name")
                assert host.endswith("-130100"), host

    def test_stamped_scoring_by_expected_host(self):
        from scripts.purple_loop import _merge_chain_hosts

        expected = {
            "live-matrix-payload_callback-130100": "payload_callback",
            "live-matrix-clickfix_dropper_execution-130100": "clickfix_dropper_execution",
        }
        chains = _merge_chain_hosts(
            expected,
            alert_hosts={"live-matrix-payload_callback-130100"},
            match_hosts={"live-matrix-clickfix_dropper_execution-130100"},
        )
        assert chains == {
            "payload_callback": True,
            "clickfix_dropper_execution": True,
        }
        # A stale (previous-run) host must NOT satisfy this run's slots.
        chains = _merge_chain_hosts(
            expected, alert_hosts={"live-matrix-payload_callback"}, match_hosts=set()
        )
        assert chains["payload_callback"] is False

    def test_feedback_keys_are_chain_names(self):
        feedback = build_feedback({"clickfix_dropper_execution": False})
        assert feedback and feedback[0]["correlation_rule"] == "clickfix_dropper_execution"


# ------------------------------------------------------------------------
# (b) the UEBA-ready outliers view
# ------------------------------------------------------------------------


class TestRobustOutliers:
    def test_flags_entities_beyond_the_robust_threshold(self):
        # [2,3,2,30]: mean+2*stddev could NEVER flag the noisy host (its own
        # outlier inflates the baseline; max z at n=4 is 1.5) -- the robust
        # median/MAD z does. This is the small-fleet property the method
        # was chosen for.
        outliers, baseline = _robust_outliers(
            [("calm-1", 2), ("calm-2", 3), ("calm-3", 2), ("noisy", 30)]
        )
        assert baseline is not None and baseline["entities"] == 4
        assert [o["entity"] for o in outliers] == ["noisy"]
        assert outliers[0]["robust_z"] >= ROBUST_Z_THRESHOLD

    def test_few_entities_is_honestly_not_computable(self):
        outliers, baseline = _robust_outliers([("only-host", 5)])
        assert outliers == [] and baseline is None
        outliers, baseline = _robust_outliers([("a", 1), ("b", 2)])
        assert outliers == [] and baseline is None

    def test_flat_spread_around_median_has_no_outliers(self):
        outliers, baseline = _robust_outliers([("h1", 4), ("h2", 4), ("h3", 4), ("h4", 4)])
        assert outliers == []
        assert baseline is not None and baseline["mad"] == 0

    def test_auth_floor_total(self):
        # 3 users, tiny failure counts: below MIN_AUTH_FAILURES_TOTAL the
        # view refuses to call anything an outlier (noise floor).
        counts = [("u1", 1), ("u2", 1), ("u3", 2)]
        assert sum(c for _, c in counts) < MIN_AUTH_FAILURES_TOTAL
        outliers, _ = _robust_outliers(counts, min_total=MIN_AUTH_FAILURES_TOTAL)
        assert outliers == []


class TestComputePostureOutliers:
    @pytest.mark.asyncio
    async def test_shape_and_outlier_flagging(self):
        conn = AsyncMock()

        async def fetch_side_effect(sql, *params):
            if "FROM alerts" in sql:
                return [
                    {"host_name": "calm-1", "alert_count": 2},
                    {"host_name": "calm-2", "alert_count": 3},
                    {"host_name": "calm-3", "alert_count": 2},
                    {"host_name": "noisy-host", "alert_count": 30},
                ]
            return [
                {"user_name": "admin", "fail_count": 40},
                {"user_name": "u2", "fail_count": 1},
                {"user_name": "u3", "fail_count": 2},
            ]

        conn.fetch = AsyncMock(side_effect=fetch_side_effect)
        with patch("src.compliance.outliers.get_pool", return_value=_pool_mock(conn)):
            result = await compute_posture_outliers(24, as_of=AS_OF)

        assert result["window_hours"] == 24
        assert "ueba_note" in result["methodology"]
        assert "baselines" in result["methodology"]["ueba_note"]
        host_view = result["host_alert_outliers"]
        assert [o["entity"] for o in host_view["outliers"]] == ["noisy-host"]
        assert host_view["baseline"]["entities"] == 4
        auth_view = result["auth_failure_user_outliers"]
        assert [o["entity"] for o in auth_view["outliers"]] == ["admin"]

    @pytest.mark.asyncio
    async def test_queries_the_window_not_the_future(self):
        # W4-A pin: $1 is the window's LOWER bound (as_of - window_hours),
        # not as_of itself. The old code passed as_of (≈ now) =>
        # `WHERE time > now()` => always empty in production; these tests
        # mocked conn.fetch wholesale, so the SQL params were never
        # exercised and the bug shipped. This pin reads the params.
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        with patch("src.compliance.outliers.get_pool", return_value=_pool_mock(conn)):
            await compute_posture_outliers(24, as_of=AS_OF)

        assert conn.fetch.await_count == 2  # alerts query + logs query
        expected_start = AS_OF - timedelta(hours=24)
        for call in conn.fetch.await_args_list:
            params = call.args[1:]  # bind params after the SQL text
            assert len(params) == 1
            assert params[0] == expected_start, (
                f"$1 must be window_start ({expected_start}), got {params[0]}"
            )

    @pytest.mark.asyncio
    async def test_empty_fleet_zero_shape(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        with patch("src.compliance.outliers.get_pool", return_value=_pool_mock(conn)):
            result = await compute_posture_outliers(24, as_of=AS_OF)
        # Zero-shape guarantee: every key present, honest not-computable notes.
        assert result["host_alert_outliers"]["outliers"] == []
        assert result["host_alert_outliers"]["baseline"] is None
        assert "not meaningful" in result["host_alert_outliers"]["note"]
        assert result["auth_failure_user_outliers"]["outliers"] == []
        assert result["window_hours"] == 24
