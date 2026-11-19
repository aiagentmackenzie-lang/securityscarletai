"""Wave D regressions: Sigma compiler + correlation detector correctness.

SS-020 persistence fires on `launchctl unload`
SS-021 `a and not b and not c` silently drops `c` (over-match)
SS-022 mixed-case selection names never match (rule compiles to FALSE)
SS-023 an unknown field raises out of compilation instead of failing safe
SS-024 "external IP" gates treat loopback / link-local / ULA as external
SS-019 the exfil detector aggregates over the 24 h lookback, not its window
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.detection.correlation import (
    CORRELATION_DETECTORS,
    LOCAL_NETWORKS,
    detect_data_exfiltration,
)
from src.detection.sigma import SigmaParser, sigma_to_sql


def _rule(detection: str, condition: str, timeframe: str = "5m") -> str:
    return f"""
title: Wave D probe
detection:
{detection}
    condition: {condition}
timeframe: {timeframe}
level: high
"""


# ───────────────────────────────────────────────────────────────
# SS-021 — fold every `and not` clause
# ───────────────────────────────────────────────────────────────


class TestAndNotFolding:
    def test_third_exclusion_is_not_dropped(self):
        """`a and not b and not c` compiled to `(a) AND NOT (b)` — c ignored,
        so the rule matched MORE than written (the fail-open direction)."""
        rule = _rule(
            "    selection:\n        process_name: evil\n"
            "    filter_b:\n        user_name: root\n"
            "    filter_c:\n        host_name: trusted\n",
            "selection and not filter_b and not filter_c",
        )
        sql, params = sigma_to_sql(rule)
        assert "trusted" in params, f"filter_c was dropped from the query: {params}"
        assert sql.count("NOT") >= 2

    def test_two_clause_form_still_works(self):
        rule = _rule(
            "    selection:\n        process_name: evil\n    filter_b:\n        user_name: root\n",
            "selection and not filter_b",
        )
        sql, params = sigma_to_sql(rule)
        assert "root" in params
        assert "NOT" in sql

    def test_missing_selection_in_a_folded_clause_fails_safe(self):
        rule = _rule(
            "    selection:\n        process_name: evil\n    filter_b:\n        user_name: root\n",
            "selection and not filter_b and not filter_typo",
        )
        sql, _params = sigma_to_sql(rule)
        assert "FALSE" in sql


# ───────────────────────────────────────────────────────────────
# SS-022 — mixed-case selection names
# ───────────────────────────────────────────────────────────────


class TestSelectionNameCase:
    def test_mixed_case_selection_matches(self):
        """The condition was lowercased before the exact dict lookup, so
        `condition: Selection` + `detection: {Selection: ...}` compiled to
        FALSE (a silently dead operator-authored rule)."""
        rule = _rule("    Selection:\n        process_name: evil\n", "Selection")
        sql, params = sigma_to_sql(rule)
        assert "FALSE" not in sql
        assert "evil" in params

    def test_mixed_case_in_a_compound_condition(self):
        rule = _rule(
            "    Selection:\n        process_name: evil\n    Filter:\n        user_name: root\n",
            "Selection and not Filter",
        )
        sql, params = sigma_to_sql(rule)
        assert "FALSE" not in sql
        assert "evil" in params and "root" in params

    def test_lowercase_still_works(self):
        rule = _rule("    selection:\n        process_name: evil\n", "selection")
        sql, params = sigma_to_sql(rule)
        assert "FALSE" not in sql


# ───────────────────────────────────────────────────────────────
# SS-023 — unknown field must fail safe, not raise
# ───────────────────────────────────────────────────────────────


class TestUnknownFieldFailsSafe:
    def test_unknown_field_compiles_to_false_with_a_warning(self):
        """`_map_field` raises ValueError; `_parse_selection` only caught
        UnsupportedSigmaValue, so the ValueError escaped compile_where ->
        run_rule's generic except: the rule never evaluated and the only trace
        was `rule_execution_failed` on every tick."""
        rule = _rule("    selection:\n        not_a_real_column: x\n", "selection")
        sql, _params = sigma_to_sql(rule)  # must not raise
        assert "FALSE" in sql

    def test_warning_is_recorded(self):
        yaml_rule = _rule("    selection:\n        not_a_real_column: x\n", "selection")
        parser = SigmaParser()
        rule = parser.parse(yaml_rule)
        where, _params, _agg = parser.compile_where(rule)
        assert "FALSE" in where
        assert any("not_a_real_column" in w for w in parser.warnings)


# ───────────────────────────────────────────────────────────────
# SS-024 — one shared "external IP" predicate
# ───────────────────────────────────────────────────────────────


class TestExternalIpPredicate:
    def test_local_networks_cover_the_non_external_ranges(self):
        expected = {
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "0.0.0.0/8",
            "::1/128",
            "fe80::/10",
            "fc00::/7",
        }
        assert expected.issubset(set(LOCAL_NETWORKS)), set(LOCAL_NETWORKS)

    def test_every_external_gate_uses_the_shared_list(self):
        """Loopback / link-local / ULA used to count as external, so a /tmp
        process connecting to a local service fired a CRITICAL callback alert."""
        for name, detector in CORRELATION_DETECTORS.items():
            if name not in {
                "payload_callback",
                "data_exfiltration",
                "credential_theft_exfil",
                "ai_process_egress",
            }:
                continue
            source = __import__("inspect").getsource(detector)
            assert "ANY($" in source and "::inet[]" in source, (
                f"{name} does not use the shared external-IP predicate"
            )
            # No bare three-RFC1918 gate left behind.
            assert "192.168.0.0/16" not in source, f"{name} still binds RFC1918 only"

    def test_loopback_is_not_external(self):
        import ipaddress

        nets = [ipaddress.ip_network(n) for n in LOCAL_NETWORKS]

        def is_external(ip: str) -> bool:
            addr = ipaddress.ip_address(ip)
            return not any(addr in n for n in nets if n.version == addr.version)

        assert not is_external("127.0.0.1")
        assert not is_external("::1")
        assert not is_external("169.254.10.10")
        assert not is_external("fe80::1234")
        assert not is_external("fd00::1")
        assert not is_external("10.2.3.4")
        assert not is_external("192.168.1.1")
        assert is_external("8.8.8.8")
        assert is_external("2606:4700::1111")


# ───────────────────────────────────────────────────────────────
# SS-019 — the exfil detector must aggregate over its OWN window
# ───────────────────────────────────────────────────────────────


class TestDataExfiltrationWindow:
    @pytest.mark.asyncio
    async def test_time_window_hours_is_bound_to_the_aggregation_interval(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        await detect_data_exfiltration(
            conn,
            datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc),
            time_window_hours=1,
            lookback_hours=24,
        )
        binds = conn.fetch.call_args.args[1:]
        # The interval multiplier must be the documented window (1h), not the
        # 24h scan bound — otherwise the chain fires on "50 connections in 24h".
        assert 1 in binds
        window_idx = conn.fetch.call_args.args[0].index("INTERVAL '1 hour' * $")
        del window_idx
        assert 24 not in binds[2:5], f"24h lookback leaked into the window binds: {binds}"

    @pytest.mark.asyncio
    async def test_custom_window_is_used(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        await detect_data_exfiltration(
            conn,
            datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc),
            time_window_hours=6,
        )
        assert 6 in conn.fetch.call_args.args[1:]


# ───────────────────────────────────────────────────────────────
# SS-020 — persistence must not fire on `launchctl unload`
# ───────────────────────────────────────────────────────────────


class TestPersistenceUnload:
    @pytest.mark.asyncio
    async def test_load_match_excludes_unload(self):
        from src.detection.correlation import detect_persistence_activated

        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        await detect_persistence_activated(
            conn, datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
        )
        sql = conn.fetch.call_args.args[0]
        binds = list(conn.fetch.call_args.args[1:])
        # The load pattern must be explicit and paired with a NOT ... unload
        # guard (or an argv match); a bare '%load%' matches `unload`.
        assert "unload" in sql.lower(), f"no unload exclusion in: {sql}"
        assert any(isinstance(b, str) and "unload" in b.lower() for b in binds) or (
            "not" in sql.lower() and "unload" in sql.lower()
        )
        assert "%load%" not in binds, "bare %load% still matches launchctl unload"


# ───────────────────────────────────────────────────────────────
# SS-025 — coalescing must not run the same sweep twice
# ───────────────────────────────────────────────────────────────


class TestCorrelationCoalescing:
    @pytest.mark.asyncio
    async def test_a_caller_queued_behind_a_finished_run_skips(self):
        """A caller that passed the outer flag check before the first run set
        it then waited on the inner lock; when it got the lock the flag was
        false again, so it ran a FULL duplicate sweep. The generation counter
        makes "a run completed while I was queued" observable."""
        from src.detection import correlation as corr

        real_lock = corr._correlation_inflight_lock

        class _CompletingLock:
            """Simulates a run that finishes while this caller waits on the lock."""

            async def __aenter__(self):
                await real_lock.__aenter__()
                corr._correlation_runs_completed += 1
                return None

            async def __aexit__(self, *exc):
                return await real_lock.__aexit__(*exc)

        run_all = AsyncMock()
        with (
            patch.object(corr, "run_all_correlations", run_all),
            patch.object(corr, "_correlation_inflight", False),
            patch.object(corr, "_correlation_runs_completed", 0, create=True),
            patch.object(corr, "_correlation_inflight_lock", _CompletingLock()),
        ):
            await corr.trigger_correlation_coalesced()

        run_all.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sequential_calls_each_run(self):
        """Coalescing is about concurrency, not a permanent rate limit."""
        from src.detection import correlation as corr

        run_all = AsyncMock()
        with (
            patch.object(corr, "run_all_correlations", run_all),
            patch.object(corr, "_correlation_inflight", False),
            patch.object(corr, "_correlation_runs_completed", 0, create=True),
        ):
            await corr.trigger_correlation_coalesced()
            await corr.trigger_correlation_coalesced()

        assert run_all.await_count == 2


# ───────────────────────────────────────────────────────────────
# SS-026 — alerts.evidence has one shape on the wire
# ───────────────────────────────────────────────────────────────


class TestEvidenceShapeIsNormalized:
    @pytest.mark.asyncio
    async def test_dict_evidence_is_stored_as_an_array(self):
        from src.detection.alerts import create_alert
        from tests.unit._fake_tx import with_tx

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        conn.fetchval = AsyncMock(return_value=11)
        conn.execute = AsyncMock(return_value="UPDATE 1")
        with_tx(conn)
        acquirer = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool = AsyncMock()
        pool.acquire = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(
            return_value=acquirer
        )

        with (
            patch("src.detection.alerts.get_pool", AsyncMock(return_value=pool)),
            patch("src.detection.alerts._is_suppressed", AsyncMock(return_value=False)),
            patch(
                "src.detection.alerts._check_severity_escalation",
                AsyncMock(return_value="high"),
            ),
            patch("src.detection.alerts._send_alert_notification", AsyncMock()),
        ):
            await create_alert(
                rule_id=None,
                rule_name="Correlation thing",
                severity="high",
                host_name="h1",
                description="d",
                evidence={"match": {"correlation_id": "abc"}},
            )

        insert_args = [
            c for c in conn.fetchval.call_args_list if "INSERT INTO alerts" in str(c.args[0])
        ]
        assert insert_args, "no alert insert"
        payload = insert_args[0].args[8]
        assert json.loads(payload) == [{"match": {"correlation_id": "abc"}}]

    @pytest.mark.asyncio
    async def test_list_evidence_is_preserved(self):
        from src.detection.alerts import create_alert
        from tests.unit._fake_tx import with_tx

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        conn.fetchval = AsyncMock(return_value=12)
        conn.execute = AsyncMock(return_value="UPDATE 1")
        with_tx(conn)
        acq = AsyncMock()
        acq.__aenter__ = AsyncMock(return_value=conn)
        acq.__aexit__ = AsyncMock(return_value=None)
        pool = AsyncMock()
        pool.acquire = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(
            return_value=acq
        )

        with (
            patch("src.detection.alerts.get_pool", AsyncMock(return_value=pool)),
            patch("src.detection.alerts._is_suppressed", AsyncMock(return_value=False)),
            patch(
                "src.detection.alerts._check_severity_escalation",
                AsyncMock(return_value="high"),
            ),
            patch("src.detection.alerts._send_alert_notification", AsyncMock()),
        ):
            await create_alert(
                rule_id=1,
                rule_name="Rule",
                severity="high",
                host_name="h1",
                description="d",
                evidence=[{"excerpt": "a"}, {"excerpt": "b"}],
            )

        payload = conn.fetchval.call_args_list[0].args[8]
        assert json.loads(payload) == [{"excerpt": "a"}, {"excerpt": "b"}]

    def test_schema_documents_the_array_contract(self):
        from pathlib import Path

        schema = Path("src/db/schema.sql").read_text()
        line = next(ln for ln in schema.splitlines() if "evidence       JSONB" in ln)
        assert "array" in line.lower()
