"""
Tests for src/api/correlation.py (Agent A, Epic 2).

Function-level tests with mocked DB and auth (mirroring test_api_endpoints.py
pattern, since FastAPI's require_role() closures are hard to override via
dependency_overrides).

Covers:
- POST /api/v1/correlation/run with as_of and persist
- POST /api/v1/correlation/run/{rule} with as_of query param
- GET /api/v1/correlation/matches with filters
- POST /api/v1/correlation/matches/{id}/seen
- _parse_as_of helper
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from src.api.correlation import _parse_as_of


class TestParseAsOf:
    def test_none_returns_current_utc(self):
        before = datetime.now(timezone.utc)
        result = _parse_as_of(None)
        after = datetime.now(timezone.utc)
        assert before <= result <= after
        assert result.tzinfo is not None

    def test_iso_with_z(self):
        result = _parse_as_of("2026-05-31T22:00:00Z")
        assert result.year == 2026
        assert result.month == 5
        assert result.day == 31
        assert result.hour == 22
        assert result.tzinfo is not None

    def test_iso_with_offset(self):
        result = _parse_as_of("2026-05-31T22:00:00+00:00")
        assert result.hour == 22

    def test_invalid_raises_http_400(self):
        with pytest.raises(HTTPException) as exc_info:
            _parse_as_of("not a date")
        assert exc_info.value.status_code == 400


class TestCorrelationRunEndpoint:
    @pytest.mark.asyncio
    async def test_run_with_as_of_and_persist_passes_through(self):
        """Verify the endpoint forwards as_of and persist to run_all_correlations."""
        from src.api import correlation as api_corr
        from src.api.correlation import CorrelationRunRequest, run_correlations_post

        user = {"sub": "test", "role": "analyst"}
        request = CorrelationRunRequest(as_of="2026-05-31T22:00:00Z", persist=True)

        with patch.object(api_corr, "run_all_correlations", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {
                "matches": [],
                "total_matches": 0,
                "persisted": 0,
                "as_of": "2026-05-31T22:00:00+00:00",
                "per_rule": {},
            }
            response = await run_correlations_post(request=request, user=user)

        assert response.total_matches == 0
        assert response.persisted == 0
        # Verify the as_of and persist were passed
        call = mock_run.call_args
        assert call.kwargs["persist"] is True
        assert isinstance(call.kwargs["as_of"], datetime)

    @pytest.mark.asyncio
    async def test_run_defaults_to_now(self):
        """Empty request body should still work (defaults applied)."""
        from src.api import correlation as api_corr
        from src.api.correlation import CorrelationRunRequest, run_correlations_post

        user = {"sub": "test", "role": "analyst"}
        request = CorrelationRunRequest()

        with patch.object(api_corr, "run_all_correlations", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {
                "matches": [],
                "total_matches": 0,
                "persisted": 0,
                "as_of": "2026-06-01T00:00:00+00:00",
                "per_rule": {},
            }
            response = await run_correlations_post(request=request, user=user)

        assert response.as_of == "2026-06-01T00:00:00+00:00"
        # Should default to now() — verify it's recent
        call = mock_run.call_args
        as_of = call.kwargs["as_of"]
        delta = abs((datetime.now(timezone.utc) - as_of).total_seconds())
        assert delta < 5  # within 5 seconds

    @pytest.mark.asyncio
    async def test_run_invalid_as_of_raises_400(self):
        from src.api.correlation import CorrelationRunRequest, run_correlations_post

        user = {"sub": "test", "role": "analyst"}
        request = CorrelationRunRequest(as_of="garbage")

        with pytest.raises(HTTPException) as exc_info:
            await run_correlations_post(request=request, user=user)
        assert exc_info.value.status_code == 400


class TestSingleRuleEndpoint:
    @pytest.mark.asyncio
    async def test_run_single_rule(self):
        from src.api import correlation as api_corr
        from src.api.correlation import run_single_correlation

        user = {"sub": "test", "role": "analyst"}

        with patch.object(api_corr, "get_pool", new_callable=AsyncMock) as mock_pool:
            mock_conn = AsyncMock()
            mock_conn.fetch = AsyncMock(return_value=[])
            acquirer = MagicMock()
            acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
            acquirer.__aexit__ = AsyncMock(return_value=None)
            mock_pool.return_value.acquire = MagicMock(return_value=acquirer)

            response = await run_single_correlation(
                rule_name="brute_force_success",
                as_of="2026-05-31T22:00:00Z",
                user=user,
            )

        assert response["rule_name"] == "brute_force_success"
        assert "matches" in response
        assert response["match_count"] == 0

    @pytest.mark.asyncio
    async def test_run_unknown_rule_returns_404(self):
        from src.api.correlation import run_single_correlation

        user = {"sub": "test", "role": "analyst"}
        with pytest.raises(HTTPException) as exc_info:
            await run_single_correlation(rule_name="nonexistent", user=user)
        assert exc_info.value.status_code == 404


class TestListMatchesEndpoint:
    @pytest.mark.asyncio
    async def test_no_filters(self):
        from src.api import correlation as api_corr
        from src.api.correlation import get_correlation_matches

        user = {"sub": "test", "role": "viewer"}
        with patch.object(api_corr, "list_matches", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = [
                {"id": 1, "correlation_rule": "x", "severity": "high",
                 "created_at": datetime(2026, 5, 31, tzinfo=timezone.utc)},
            ]
            response = await get_correlation_matches(user=user)

        assert response.total == 1
        assert response.limit == 100
        assert response.offset == 0
        # datetime should be serialized to ISO string
        assert "2026-05-31" in response.matches[0]["created_at"]

    @pytest.mark.asyncio
    async def test_with_filters(self):
        from src.api import correlation as api_corr
        from src.api.correlation import get_correlation_matches

        user = {"sub": "test", "role": "viewer"}
        with patch.object(api_corr, "list_matches", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = []
            await get_correlation_matches(
                rule="brute_force_success",
                severity="high",
                seen=False,
                limit=50,
                user=user,
            )

        call = mock_list.call_args
        assert call.kwargs["rule"] == "brute_force_success"
        assert call.kwargs["severity"] == "high"
        assert call.kwargs["seen"] is False
        assert call.kwargs["limit"] == 50

    @pytest.mark.asyncio
    async def test_with_date_filters(self):
        from src.api import correlation as api_corr
        from src.api.correlation import get_correlation_matches

        user = {"sub": "test", "role": "viewer"}
        with patch.object(api_corr, "list_matches", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = []
            await get_correlation_matches(
                since="2026-05-01T00:00:00Z",
                until="2026-06-01T00:00:00Z",
                user=user,
            )

        call = mock_list.call_args
        assert call.kwargs["since"] is not None
        assert call.kwargs["until"] is not None

    @pytest.mark.asyncio
    async def test_serializes_jsonb_match_data(self):
        """If match_data comes back as a string (asyncpg quirk), it should be parsed."""
        from src.api import correlation as api_corr
        from src.api.correlation import get_correlation_matches

        user = {"sub": "test", "role": "viewer"}
        with patch.object(api_corr, "list_matches", new_callable=AsyncMock) as mock_list:
            mock_list.return_value = [
                {"id": 1, "match_data": '{"foo": "bar"}'},
            ]
            response = await get_correlation_matches(user=user)

        # The string JSON should be parsed
        assert response.matches[0]["match_data"] == {"foo": "bar"}

class TestMarkSeenEndpoint:
    @pytest.mark.asyncio
    async def test_mark_seen_success(self):
        from src.api import correlation as api_corr
        from src.api.correlation import mark_seen

        user = {"sub": "test", "role": "analyst"}
        with patch.object(api_corr, "mark_match_seen", new_callable=AsyncMock) as mock_seen:
            mock_seen.return_value = True
            response = await mark_seen(match_id=42, user=user)

        assert response == {"id": 42, "seen": True}

    @pytest.mark.asyncio
    async def test_mark_seen_not_found_returns_404(self):
        from src.api import correlation as api_corr
        from src.api.correlation import mark_seen

        user = {"sub": "test", "role": "analyst"}
        with patch.object(api_corr, "mark_match_seen", new_callable=AsyncMock) as mock_seen:
            mock_seen.return_value = False
            with pytest.raises(HTTPException) as exc_info:
                await mark_seen(match_id=99999, user=user)
        assert exc_info.value.status_code == 404


class TestPersistMatchEndpoint:
    @pytest.mark.asyncio
    async def test_persist_match_success(self):
        from src.api import correlation as api_corr
        from src.api.correlation import persist_single_match

        user = {"sub": "test", "role": "admin"}
        with patch.object(api_corr, "persist_match", new_callable=AsyncMock) as mock_p:
            mock_p.return_value = 99
            response = await persist_single_match(
                match_id=10,
                match={"correlation_rule": "x", "severity": "high", "correlation_id": "abc"},
                user=user,
            )

        assert response["id"] == 99
        assert response["correlation_id"] == "abc"

    @pytest.mark.asyncio
    async def test_persist_match_failure_returns_500(self):
        from src.api import correlation as api_corr
        from src.api.correlation import persist_single_match

        user = {"sub": "test", "role": "admin"}
        with patch.object(api_corr, "persist_match", new_callable=AsyncMock) as mock_p:
            mock_p.return_value = None
            with pytest.raises(HTTPException) as exc_info:
                await persist_single_match(match_id=10, match={}, user=user)
        assert exc_info.value.status_code == 500


class TestRulesEndpoints:
    @pytest.mark.asyncio
    async def test_list_rules(self):
        from src.api.correlation import list_rules

        user = {"sub": "test", "role": "viewer"}
        result = await list_rules(user=user)
        assert isinstance(result, list)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_get_rule_not_found(self):
        from src.api.correlation import get_rule

        user = {"sub": "test", "role": "viewer"}
        with pytest.raises(HTTPException) as exc_info:
            await get_rule(rule_name="nonexistent", user=user)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_rule_found(self):
        from src.api.correlation import get_rule

        user = {"sub": "test", "role": "viewer"}
        result = await get_rule(rule_name="brute_force_success", user=user)
        assert result["severity"] == "critical"
        assert "T1110" in result["mitre_techniques"]

    @pytest.mark.asyncio
    async def test_list_sequences(self):
        from src.api.correlation import list_sequence_rules

        user = {"sub": "test", "role": "viewer"}
        result = await list_sequence_rules(user=user)
        assert isinstance(result, list)
