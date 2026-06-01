"""
Tests for src/ai/cost_tracker.py (Agent A, Epic 1).

Covers:
- record_usage inserts into ai_usage table
- record_usage never raises on DB error (returns False)
- get_usage_summary returns sensible default on error
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.ai.cost_tracker import get_usage_summary, record_usage


class TestRecordUsage:
    @pytest.mark.asyncio
    async def test_inserts_into_ai_usage(self):
        """Successful insert returns True and passes correct params."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.cost_tracker.get_pool", return_value=mock_pool):
            ok = await record_usage(
                user="analyst1",
                endpoint="ai.explain",
                model="mistral:7b",
                tokens_in=100,
                tokens_out=50,
                latency_ms=200,
                prompt_version="v1.0.0",
                source="ollama",
                fallback_used=False,
                warning=None,
            )

        assert ok is True
        # Verify the insert was called with right endpoint
        call_args = mock_conn.execute.call_args
        assert call_args is not None
        assert "ai_usage" in call_args.args[0]
        assert "ai.explain" in call_args.args[1:]
        assert "mistral:7b" in call_args.args[1:]

    @pytest.mark.asyncio
    async def test_returns_false_on_db_error(self):
        """If the DB is down, record_usage returns False but does not raise."""
        with patch("src.ai.cost_tracker.get_pool", side_effect=Exception("DB down")):
            ok = await record_usage(
                user="u", endpoint="e", model="m",
                tokens_in=1, tokens_out=1, latency_ms=1,
            )
        assert ok is False

    @pytest.mark.asyncio
    async def test_handles_fallback_flag(self):
        """Fallback uses are recorded with the template_library model name."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.cost_tracker.get_pool", return_value=mock_pool):
            ok = await record_usage(
                user="u", endpoint="ai.explain", model="template_library",
                tokens_in=0, tokens_out=0, latency_ms=0,
                fallback_used=True, warning="Ollama down",
            )

        assert ok is True
        args = mock_conn.execute.call_args.args
        assert "template_library" in args


class TestGetUsageSummary:
    @pytest.mark.asyncio
    async def test_returns_empty_dict_on_error(self):
        with patch("src.ai.cost_tracker.get_pool", side_effect=Exception("nope")):
            summary = await get_usage_summary()
        assert summary["call_count"] == 0
        assert summary["total_tokens_in"] == 0
        assert summary["total_tokens_out"] == 0
        assert "error" in summary

    @pytest.mark.asyncio
    async def test_returns_normalized_summary(self):
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={
            "call_count": 5,
            "total_tokens_in": 100,
            "total_tokens_out": 50,
            "avg_latency_ms": 200,
            "fallback_count": 1,
        })
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.cost_tracker.get_pool", return_value=mock_pool):
            summary = await get_usage_summary(user="alice", since_hours=24)

        assert summary["call_count"] == 5
        assert summary["total_tokens_in"] == 100
        assert summary["avg_latency_ms"] == 200

    @pytest.mark.asyncio
    async def test_handles_none_row(self):
        """If fetchrow returns None (e.g. empty table), return zeros."""
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.cost_tracker.get_pool", return_value=mock_pool):
            summary = await get_usage_summary()

        assert summary["call_count"] == 0
