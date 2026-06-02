"""
Tests for src/detection/correlation.py (Agent A, Epic 2).

Covers the new contract:
- run_all_correlations(as_of, persist) returns the new shape
- as_of defaults to current UTC time
- persist=True writes to correlation_matches
- persist=False does NOT write
- correlation_id (uuid) is populated on every match
- severity, title, mitre_tactics, mitre_techniques are enriched onto matches
- No NOW() appears in any query string (grep check)
- persist_match works with explicit as_of
- list_matches supports filter combinations
- mark_match_seen updates the seen flag
"""

import re
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.detection import correlation as corr


class TestRunAllCorrelationsContract:
    """The new Epic 2 contract: as_of + persist + new return shape."""

    @pytest.mark.asyncio
    async def test_returns_new_shape(self):
        """Result must have keys: matches, total_matches, persisted, as_of, per_rule."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])  # all rules return no matches
        mock_conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await corr.run_all_correlations(
                as_of=datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
            )

        assert "matches" in result
        assert "total_matches" in result
        assert "persisted" in result
        assert "as_of" in result
        assert "per_rule" in result
        assert result["total_matches"] == 0
        assert result["persisted"] == 0

    @pytest.mark.asyncio
    async def test_as_of_defaults_to_now(self):
        """When as_of is None, default to current UTC time."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            before = datetime.now(timezone.utc)
            result = await corr.run_all_correlations()
            after = datetime.now(timezone.utc)

        as_of = datetime.fromisoformat(result["as_of"])
        assert before <= as_of <= after

    @pytest.mark.asyncio
    async def test_explicit_as_of_echoed_back(self):
        """The as_of passed in is the one echoed in the response."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            target = datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
            result = await corr.run_all_correlations(as_of=target)

        assert result["as_of"] == target.isoformat()

    @pytest.mark.asyncio
    async def test_persist_true_writes_to_correlation_matches(self):
        """When persist=True, each match writes to correlation_matches."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        # brute_force returns one match; rest return empty
        call_count = {"n": 0}

        async def fake_fetch(sql, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [{
                    "host_name": "server-01",
                    "source_ip": "10.0.0.5",
                    "user_name": "admin",
                    "success_time": datetime(2026, 5, 31, 21, 55, tzinfo=timezone.utc),
                    "failed_count": 5,
                }]
            return []

        mock_conn.fetch = AsyncMock(side_effect=fake_fetch)
        mock_conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await corr.run_all_correlations(
                as_of=datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc),
                persist=True,
            )

        assert result["total_matches"] == 1
        assert result["persisted"] == 1
        # Verify execute was called for the insert
        assert mock_conn.execute.called
        # The insert SQL should mention correlation_matches
        insert_call = mock_conn.execute.call_args
        assert "INSERT INTO correlation_matches" in insert_call.args[0]
        assert "brute_force_success" in insert_call.args[1:]

    @pytest.mark.asyncio
    async def test_persist_false_does_not_insert(self):
        """When persist=False, no execute() insert calls happen."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await corr.run_all_correlations(persist=False)

        assert result["persisted"] == 0
        # execute is called in the `async with pool.acquire() as conn:` block
        # but we only care that no INSERT happened.
        for call in mock_conn.execute.call_args_list:
            assert "INSERT INTO correlation_matches" not in call.args[0]


class TestNoNowInQueryStrings:
    """The brief requires NOW() count = 0 in src/detection/correlation.py."""

    def test_no_now_in_query_strings(self):
        """NOW() should not appear anywhere in the file (except docstrings)."""
        with open("src/detection/correlation.py") as f:
            content = f.read()
        # Strip docstrings and comments
        in_docstring = False
        cleaned_lines = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            if stripped.startswith("#"):
                continue
            cleaned_lines.append(line)
        cleaned = "\n".join(cleaned_lines)
        # NOW() should not appear in actual code
        assert "NOW()" not in cleaned, (
            f"NOW() found in code. Brief requires 0 NOW() in query strings. "
            f"Lines with NOW(): {[l for l in cleaned.split(chr(10)) if 'NOW(' in l]}"
        )


class TestCorrelationIdEnrichment:
    """Every match must have a unique correlation_id (uuid) plus severity, title, mitre."""

    @pytest.mark.asyncio
    async def test_match_has_correlation_id(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        call_count = {"n": 0}

        async def fake_fetch(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [{
                    "host_name": "h1", "source_ip": "10.0.0.1", "user_name": "u",
                    "success_time": datetime(2026, 5, 31, tzinfo=timezone.utc),
                    "failed_count": 3,
                }]
            return []

        mock_conn.fetch = AsyncMock(side_effect=fake_fetch)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await corr.run_all_correlations(
                as_of=datetime(2026, 5, 31, tzinfo=timezone.utc),
            )

        assert len(result["matches"]) == 1
        m = result["matches"][0]
        assert "correlation_id" in m
        # Should be a valid UUID4 hex
        assert re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", m["correlation_id"])
        assert m["severity"] == "critical"
        assert m["title"] == "Brute Force → Successful Login"
        assert "TA0006" in m["mitre_tactics"]
        assert "T1110" in m["mitre_techniques"]

    @pytest.mark.asyncio
    async def test_correlation_ids_are_unique(self):
        """Two matches should have different correlation_ids."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        call_count = {"n": 0}

        async def fake_fetch(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [
                    {"host_name": "h1", "source_ip": "1.1.1.1", "user_name": "u",
                     "success_time": datetime(2026, 5, 31, tzinfo=timezone.utc),
                     "failed_count": 3},
                    {"host_name": "h2", "source_ip": "2.2.2.2", "user_name": "u2",
                     "success_time": datetime(2026, 5, 31, tzinfo=timezone.utc),
                     "failed_count": 4},
                ]
            return []

        mock_conn.fetch = AsyncMock(side_effect=fake_fetch)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            result = await corr.run_all_correlations(
                as_of=datetime(2026, 5, 31, tzinfo=timezone.utc),
            )

        ids = [m["correlation_id"] for m in result["matches"]]
        assert len(ids) == 2
        assert ids[0] != ids[1]


class TestAsOfBound:
    """Verify that as_of is bound to $1::timestamptz in each rule's SQL."""

    @pytest.mark.asyncio
    async def test_brute_force_binds_as_of(self):
        """The as_of param must be the first $1 bound param."""
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        await corr.detect_brute_force_then_success(
            mock_conn, datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
        )

        call = mock_conn.fetch.call_args
        # First param is the as_of datetime
        assert isinstance(call.args[1], datetime)
        # SQL string must reference $1::timestamptz
        assert "$1::timestamptz" in call.args[0]

    @pytest.mark.asyncio
    async def test_data_exfiltration_binds_as_of(self):
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        await corr.detect_data_exfiltration(
            mock_conn, datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc)
        )

        call = mock_conn.fetch.call_args
        assert isinstance(call.args[1], datetime)
        assert "$1::timestamptz" in call.args[0]


class TestPersistMatch:
    @pytest.mark.asyncio
    async def test_persists_with_explicit_as_of(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=42)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        match = {
            "correlation_rule": "brute_force_success",
            "severity": "critical",
            "correlation_id": "test-uuid",
            "host_name": "h1",
        }

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            new_id = await corr.persist_match(
                match,
                trigger_event_id=10,
                as_of=datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc),
            )

        assert new_id == 42
        # Verify the as_of was passed as $5::timestamptz
        call = mock_conn.fetchval.call_args
        assert "$5::timestamptz" in call.args[0]
        assert call.args[1] == "brute_force_success"
        assert call.args[2] == "critical"
        assert call.args[4] == 10  # trigger_event_id

    @pytest.mark.asyncio
    async def test_returns_none_on_error(self):
        with patch("src.detection.correlation.get_pool", new_callable=AsyncMock) as mock_get_pool:
            mock_get_pool.side_effect = Exception("DB down")
            new_id = await corr.persist_match(
                {"correlation_rule": "x", "severity": "low"},
            )
        assert new_id is None


class TestListMatches:
    @pytest.mark.asyncio
    async def test_no_filters(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            rows = await corr.list_matches(limit=10)

        assert rows == []
        call = mock_conn.fetch.call_args
        # No WHERE clause expected
        assert "WHERE" not in call.args[0]

    @pytest.mark.asyncio
    async def test_with_severity_filter(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            await corr.list_matches(severity="high", limit=50)

        call = mock_conn.fetch.call_args
        assert "severity = $1" in call.args[0]
        assert call.args[1] == "high"

    @pytest.mark.asyncio
    async def test_with_rule_and_seen_filters(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            await corr.list_matches(rule="payload_callback", seen=False, limit=10)

        call = mock_conn.fetch.call_args
        assert "correlation_rule = $1" in call.args[0]
        assert "seen = $2" in call.args[0]
        assert call.args[1] == "payload_callback"
        assert call.args[2] is False


class TestMarkMatchSeen:
    @pytest.mark.asyncio
    async def test_marks_seen(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 1")
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            ok = await corr.mark_match_seen(99)

        assert ok is True
        call = mock_conn.execute.call_args
        assert "UPDATE correlation_matches" in call.args[0]
        assert "SET seen = TRUE" in call.args[0]
        assert call.args[1] == 99

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 0")
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            ok = await corr.mark_match_seen(9999)

        assert ok is False

    @pytest.mark.asyncio
    async def test_returns_false_on_db_error(self):
        with patch("src.detection.correlation.get_pool", new_callable=AsyncMock) as mock_get_pool:
            mock_get_pool.side_effect = Exception("DB")
            ok = await corr.mark_match_seen(1)
        assert ok is False


class TestSerializeMatchData:
    def test_serializes_datetime(self):
        m = {"time": datetime(2026, 5, 31, 22, 0, 0, tzinfo=timezone.utc), "host": "h"}
        out = corr._serialize_match_data(m)
        assert "2026-05-31" in out

    def test_serializes_decimal(self):
        from decimal import Decimal
        m = {"bytes": Decimal("100.5")}
        out = corr._serialize_match_data(m)
        assert "100.5" in out
