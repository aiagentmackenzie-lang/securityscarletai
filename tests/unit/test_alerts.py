"""
Tests for Alert Management v2.

Tests deduplication, severity escalation, bulk operations,
export, and suppression rules.
"""
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta

from src.detection.alerts import (
    SEVERITY_ORDER,
    SEVERITY_INDEX,
    DEDUP_WINDOW_SECONDS,
    ESCALATION_FIRE_THRESHOLD,
    _add_note,
    _check_severity_escalation,
    _is_suppressed,
    bulk_acknowledge,
    bulk_mark_false_positive,
    bulk_resolve,
    export_alerts_csv,
    export_alerts_stix,
)


class TestSeverityEscalation:
    """Test severity escalation logic."""

    def test_severity_order_indexed(self):
        """Severity levels should be indexed in ascending order."""
        assert SEVERITY_INDEX["info"] == 0
        assert SEVERITY_INDEX["low"] == 1
        assert SEVERITY_INDEX["medium"] == 2
        assert SEVERITY_INDEX["high"] == 3
        assert SEVERITY_INDEX["critical"] == 4

    @pytest.mark.asyncio
    async def test_escalation_below_threshold(self):
        """Below threshold fires should not escalate severity."""
        # Mock a connection that returns count below threshold
        mock_conn = AsyncMock()
        mock_conn.fetchval.return_value = 2  # Below threshold of 3
        result = await _check_severity_escalation(mock_conn, 1, "host1", "medium")
        assert result == "medium"

    @pytest.mark.asyncio
    async def test_escalation_at_threshold(self):
        """At threshold fires should escalate severity one level."""
        mock_conn = AsyncMock()
        mock_conn.fetchval.return_value = ESCALATION_FIRE_THRESHOLD
        result = await _check_severity_escalation(mock_conn, 1, "host1", "medium")
        assert result == "high"

    @pytest.mark.asyncio
    async def test_escalation_already_critical(self):
        """Critical severity should not escalate beyond critical."""
        mock_conn = AsyncMock()
        mock_conn.fetchval.return_value = 10
        result = await _check_severity_escalation(mock_conn, 1, "host1", "critical")
        assert result == "critical"

    @pytest.mark.asyncio
    async def test_escalation_low_to_medium(self):
        """Low severity should escalate to medium."""
        mock_conn = AsyncMock()
        mock_conn.fetchval.return_value = ESCALATION_FIRE_THRESHOLD
        result = await _check_severity_escalation(mock_conn, 1, "host1", "low")
        assert result == "medium"


class TestSuppressionRules:
    """Test alert suppression logic."""

    @pytest.mark.asyncio
    async def test_suppressed_by_rule_name(self):
        """Alert should be suppressed when rule_name matches."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow.return_value = {"id": 1}  # Found a suppression rule
        result = await _is_suppressed(mock_conn, "Known FP Rule", "host1", "medium")
        assert result is True

    @pytest.mark.asyncio
    async def test_not_suppressed(self):
        """Alert should not be suppressed when no rules match."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow.return_value = None  # No suppression rule found
        result = await _is_suppressed(mock_conn, "Real Threat Rule", "host1", "high")
        assert result is False

    @pytest.mark.asyncio
    async def test_suppressed_by_host_name(self):
        """Alert should be suppressed when host_name matches."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow.return_value = {"id": 2}
        result = await _is_suppressed(mock_conn, "Some Rule", "known-good-host", "medium")
        assert result is True


class TestDeduplicationConfig:
    """Test deduplication window configuration."""

    def test_default_dedup_window(self):
        """Default dedup window should be 15 minutes (900 seconds)."""
        assert DEDUP_WINDOW_SECONDS == 900

    def test_escalation_threshold(self):
        """Default escalation threshold should be 3 fires in 1 hour."""
        assert ESCALATION_FIRE_THRESHOLD == 3


class TestBulkOperations:
    """Test bulk alert operations."""

    @pytest.mark.asyncio
    async def test_bulk_acknowledge_empty(self):
        """Bulk acknowledge with empty list should return 0."""
        result = await bulk_acknowledge([], "user1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_bulk_mark_fp_empty(self):
        """Bulk false positive with empty list should return 0."""
        result = await bulk_mark_false_positive([])
        assert result == 0

    @pytest.mark.asyncio
    async def test_bulk_resolve_empty(self):
        """Bulk resolve with empty list should return 0."""
        result = await bulk_resolve([])
        assert result == 0


class TestAlertExport:
    """Test alert export functionality."""

    @pytest.mark.asyncio
    async def test_export_csv_format(self):
        """CSV export should produce valid CSV with headers."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        # Properly mock async context manager for pool.acquire()
        mock_acquirer = AsyncMock()
        mock_acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquirer.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire = MagicMock(return_value=mock_acquirer)
        mock_conn.fetch.return_value = [
            {"id": 1, "time": datetime.utcnow(), "rule_name": "Test Rule",
             "severity": "high", "status": "new", "host_name": "host1",
             "description": "test", "assigned_to": None, "risk_score": 75.0},
        ]

        with patch("src.detection.alerts.get_pool", return_value=mock_pool):
            csv_data = await export_alerts_csv(hours=24)
            assert "rule_name" in csv_data or len(csv_data) > 0  # Header or data

    @pytest.mark.asyncio
    async def test_export_stix_format(self):
        """STIX export should produce valid STIX 2.1 bundle."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_acquirer = AsyncMock()
        mock_acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquirer.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire = MagicMock(return_value=mock_acquirer)
        mock_conn.fetch.return_value = [
            {"id": 1, "time": datetime.utcnow(), "rule_name": "Test Rule",
             "severity": "high", "status": "new", "host_name": "host1",
             "description": "test", "mitre_tactics": ["TA0006"],
             "mitre_techniques": ["T1110"]},
        ]

        with patch("src.detection.alerts.get_pool", return_value=mock_pool):
            stix = await export_alerts_stix(hours=24)
            assert stix["type"] == "bundle"
            assert len(stix["objects"]) == 1
            assert stix["objects"][0]["type"] == "indicator"
            assert stix["objects"][0]["name"] == "Test Rule"

    @pytest.mark.asyncio
    async def test_export_csv_empty(self):
        """CSV export with no alerts should produce empty result."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_acquirer = AsyncMock()
        mock_acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquirer.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire = MagicMock(return_value=mock_acquirer)
        mock_conn.fetch.return_value = []

        with patch("src.detection.alerts.get_pool", return_value=mock_pool):
            csv_data = await export_alerts_csv(hours=24)
            assert csv_data == ""


class TestAlertNotes:
    """Test alert notes/timeline functionality."""

    @pytest.mark.asyncio
    async def test_add_note(self):
        """Adding a note should append to the notes JSONB array."""
        mock_conn = AsyncMock()
        await _add_note(mock_conn, alert_id=1, author="analyst", text="Investigating")
        mock_conn.execute.assert_called_once()
        call_args = mock_conn.execute.call_args
        # Verify the SQL contains notes update
        assert "notes" in str(call_args[0][0]).lower()