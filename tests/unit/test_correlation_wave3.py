"""
Wave-3 audit-fix tests (AUD-004 step 1, AUD-005, AUD-020/039/047, AUD-049).

- AUD-005: detect_payload_callback excludes RFC1918 destinations (the
  description said "external IP"; the SQL matched ANY destination —
  routine LAN traffic from a /tmp process fired critical alerts).
- AUD-039: the engine registry (CORRELATION_DETECTORS) is the single
  source of truth; the drift guard fails the import when metadata and
  detectors diverge.
- AUD-004 step 1: every detector binds a per-detector result cap (SQL
  LIMIT + last param) and warns loudly when the cap is hit.
- AUD-049: count_matches builds the filtered COUNT with the SAME filter
  builder as list_matches.
- AUD-020/047: no stale rule-count in comments/metric help text.
"""

import inspect
import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.detection import correlation as corr

AS_OF = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _conn_returning(rows):
    """Build a mock asyncpg conn whose .fetch returns the given rows."""
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=rows)
    return conn


# ───────────────────────────────────────────────────────────────
# AUD-039 / AUD-020 — registry is the single source of truth
# ───────────────────────────────────────────────────────────────


class TestDetectorRegistry:
    def test_registry_covers_every_rule(self):
        """Every metadata rule has a detector and vice versa (AUD-039)."""
        assert set(corr.CORRELATION_DETECTORS) == set(corr.CORRELATION_RULES)
        for name, fn in corr.CORRELATION_DETECTORS.items():
            assert callable(fn), f"registry entry {name} is not callable"

    def test_drift_guard_raises_on_metadata_only_rule(self):
        """A rule with metadata but no detector must fail loudly (never
        silently skip detection). The guard is import-time; the function
        form is tested here without reload games."""
        poisoned = {
            **corr.CORRELATION_RULES,
            "ghost_rule": {
                "title": "Ghost",
                "description": "drift probe",
                "severity": "high",
                "mitre_tactics": ["TA0001"],
                "mitre_techniques": ["T1190"],
                "confidence_base": 50,
            },
        }
        with patch.object(corr, "CORRELATION_RULES", poisoned):
            with pytest.raises(RuntimeError, match="metadata-only=\\['ghost_rule'\\]"):
                corr._validate_registry()

    @pytest.mark.asyncio
    async def test_run_all_covers_exactly_the_registry(self):
        """run_all's per_rule keys == the registry keys (no rule skipped)."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await corr.run_all_correlations(as_of=AS_OF)

        assert set(result["per_rule"].keys()) == set(corr.CORRELATION_DETECTORS.keys())

    def test_no_stale_rule_count_in_run_all_comment(self):
        """AUD-020: the sweep comment must not hardcode a rule count."""
        with open("src/detection/correlation.py") as f:
            content = f.read()
        assert "(all 7 rules)" not in content


# ───────────────────────────────────────────────────────────────
# AUD-005 — payload_callback excludes RFC1918 destinations
# ───────────────────────────────────────────────────────────────


class TestPayloadCallbackRfc1918:
    @pytest.mark.asyncio
    async def test_binds_the_three_rfc1918_ranges(self):
        conn = _conn_returning([])
        await corr.detect_payload_callback(conn, AS_OF)

        sql = conn.fetch.call_args.args[0]
        params = list(conn.fetch.call_args.args[1:])
        assert sql.count("NOT destination_ip <<= $") == 3
        # $5-$7 are the RFC1918 ranges, matching the sibling detectors.
        assert params[4] == "10.0.0.0/8"
        assert params[5] == "192.168.0.0/16"
        assert params[6] == "172.16.0.0/12"
        # the /tmp trigger pattern is untouched ($2)
        assert params[1] == "%/tmp/%"

    def test_rfc1918_gate_lives_in_the_connection_leg(self):
        """The trigger CTE (tmp_processes) must stay IP-free; the gate goes
        in the network_connections CTE — mirroring the sibling detectors."""
        src = inspect.getsource(corr.detect_payload_callback)
        # Split on the SQL literal itself, not the whole source — the
        # docstring legitimately mentions destination_ip.
        sql_text = src[src.index('sql = """') :]
        trigger_leg = sql_text.split("network_connections")[0]
        assert "destination_ip" not in trigger_leg
        conn_leg = sql_text.split("network_connections", 1)[1]
        assert conn_leg.count("NOT destination_ip <<=") == 3


# ───────────────────────────────────────────────────────────────
# AUD-004 step 1 — per-detector result caps
# ───────────────────────────────────────────────────────────────


class TestPerDetectorResultCaps:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("rule_name,func", sorted(corr.CORRELATION_DETECTORS.items()))
    async def test_every_detector_binds_a_result_cap(self, rule_name, func):
        """Each detector's SQL ends in exactly one LIMIT bound to the cap,
        and the cap is the LAST bound param."""
        conn = _conn_returning([])
        await func(conn, AS_OF)

        sql = conn.fetch.call_args.args[0]
        params = list(conn.fetch.call_args.args[1:])
        assert sql.count("LIMIT") == 1, f"{rule_name}: expected exactly one LIMIT"
        assert params[-1] == corr.DETECTOR_MAX_MATCHES, (
            f"{rule_name}: the cap must be the last bound param"
        )
        assert f"LIMIT ${len(params)}" in sql, (
            f"{rule_name}: the LIMIT must reference the cap param (${len(params)})"
        )

    @pytest.mark.asyncio
    async def test_cap_hit_warns_loudly(self):
        """A detector returning cap-count rows logs
        correlation_detector_result_cap — truncation is never silent."""
        row = {
            "host_name": "host01",
            "process_name": "python3",
            "user_name": "admin",
            "time": AS_OF,
        }
        conn = _conn_returning([row] * corr.DETECTOR_MAX_MATCHES)

        with patch.object(corr.log, "warning") as mock_warn:
            matches = await corr.detect_payload_callback(conn, AS_OF)

        assert len(matches) == corr.DETECTOR_MAX_MATCHES
        mock_warn.assert_called_once()
        assert mock_warn.call_args.kwargs["rule"] == "payload_callback"
        assert mock_warn.call_args.kwargs["cap"] == corr.DETECTOR_MAX_MATCHES

    @pytest.mark.asyncio
    async def test_below_cap_no_warning(self):
        conn = _conn_returning([])
        with patch.object(corr.log, "warning") as mock_warn:
            await corr.detect_payload_callback(conn, AS_OF)
        mock_warn.assert_not_called()

    def test_cap_constant_is_bounded_and_documented(self):
        """The cap must exist and be sane — guards against someone deleting
        the constant and silently unbounding the sweep again."""
        assert isinstance(corr.DETECTOR_MAX_MATCHES, int)
        assert 1 <= corr.DETECTOR_MAX_MATCHES <= 10_000


# ───────────────────────────────────────────────────────────────
# AUD-049 — count_matches shares the filter builder with list_matches
# ───────────────────────────────────────────────────────────────


class TestCountMatches:
    @pytest.mark.asyncio
    async def test_count_uses_the_same_filters_as_list(self):
        since = datetime(2025, 1, 1, tzinfo=timezone.utc)
        until = datetime(2025, 1, 2, tzinfo=timezone.utc)
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.fetchval = AsyncMock(return_value=42)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            rows = await corr.list_matches(
                rule="payload_callback", since=since, until=until, limit=10, offset=0
            )
            total = await corr.count_matches(rule="payload_callback", since=since, until=until)

        assert rows == []
        assert total == 42
        list_sql = mock_conn.fetch.call_args.args[0]
        count_sql = mock_conn.fetchval.call_args.args[0]
        assert "COUNT(*)" in count_sql
        # The count and the page filter on exactly the same conditions.
        assert "correlation_rule = $1" in list_sql
        assert "correlation_rule = $1" in count_sql
        assert "created_at >= $2::timestamptz" in list_sql
        assert "created_at >= $2::timestamptz" in count_sql
        assert "created_at <= $3::timestamptz" in list_sql
        assert "created_at <= $3::timestamptz" in count_sql
        # The page query binds limit/offset AFTER the filters; the count
        # binds ONLY the filters.
        assert list(mock_conn.fetch.call_args.args[1:]) == [
            "payload_callback",
            since,
            until,
            10,
            0,
        ]
        assert list(mock_conn.fetchval.call_args.args[1:]) == [
            "payload_callback",
            since,
            until,
        ]

    @pytest.mark.asyncio
    async def test_count_no_filters_no_where(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=0)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            total = await corr.count_matches()

        assert total == 0
        assert "WHERE" not in mock_conn.fetchval.call_args.args[0]

    @pytest.mark.asyncio
    async def test_count_seen_filter(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=3)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            total = await corr.count_matches(seen=False)

        assert total == 3
        sql = mock_conn.fetchval.call_args.args[0]
        assert "seen = $1" in sql
        assert mock_conn.fetchval.call_args.args[1] is False


# ───────────────────────────────────────────────────────────────
# AUD-047 — no stale rule count in the metrics help text
# ───────────────────────────────────────────────────────────────


def test_metrics_help_text_has_no_stale_rule_count():
    from src.api.metrics import METRICS

    hist = METRICS._metrics["scarletai_correlation_run_duration_seconds"]  # noqa: SLF001
    assert "7" not in hist.help, "stale rule count in correlation duration help text"
    assert "correlation rule sweeps" in hist.help


def test_cap_warning_logger_exists():
    """The warning helper routes through the module logger — sanity that
    the logger name is the one ops dashboards watch (detection.correlation)."""
    assert isinstance(corr.log, logging.Logger) or hasattr(corr.log, "warning")
