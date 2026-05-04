"""
Comprehensive tests for src/detection/alerts.py.

Covers:
- create_alert (dedup, escalation, suppression)
- _check_severity_escalation
- _is_suppressed
- update_alert_status
- bulk_acknowledge, bulk_mark_false_positive, bulk_assign, bulk_resolve
- add_alert_note
- get_alert_stats
- create_suppression_rule, list_suppression_rules
- export_alerts_csv, export_alerts_stix
- SEVERITY_ORDER, SEVERITY_INDEX constants
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.detection.alerts import (
    DEDUP_WINDOW_SECONDS,
    ESCALATION_WINDOW_HOURS,
    ESCALATION_FIRE_THRESHOLD,
    SEVERITY_ORDER,
    SEVERITY_INDEX,
    create_alert,
    _check_severity_escalation,
    _is_suppressed,
    update_alert_status,
    bulk_acknowledge,
    bulk_mark_false_positive,
    bulk_assign,
    bulk_resolve,
    add_alert_note,
    get_alert_stats,
    create_suppression_rule,
    list_suppression_rules,
    export_alerts_csv,
    export_alerts_stix,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestConstants:
    def test_dedup_window(self):
        assert DEDUP_WINDOW_SECONDS == 900  # 15 min

    def test_escalation_window(self):
        assert ESCALATION_WINDOW_HOURS == 1

    def test_escalation_threshold(self):
        assert ESCALATION_FIRE_THRESHOLD == 3

    def test_severity_order(self):
        assert SEVERITY_ORDER == ["info", "low", "medium", "high", "critical"]

    def test_severity_index(self):
        assert SEVERITY_INDEX["info"] == 0
        assert SEVERITY_INDEX["low"] == 1
        assert SEVERITY_INDEX["medium"] == 2
        assert SEVERITY_INDEX["high"] == 3
        assert SEVERITY_INDEX["critical"] == 4


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _check_severity_escalation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCheckSeverityEscalation:
    @pytest.mark.asyncio
    async def test_no_escalation_below_threshold(self):
        """Should not escalate when recent count is below threshold."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=2)  # Below threshold of 3

        result = await _check_severity_escalation(mock_conn, rule_id=1, host_name="ws-01", current_severity="medium")
        assert result == "medium"

    @pytest.mark.asyncio
    async def test_escalation_at_threshold(self):
        """Should escalate severity by one level when at threshold."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=3)  # At threshold

        result = await _check_severity_escalation(mock_conn, rule_id=1, host_name="ws-01", current_severity="medium")
        assert result == "high"

    @pytest.mark.asyncio
    async def test_escalation_from_high_to_critical(self):
        """Should escalate high to critical."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=5)  # Well above threshold

        result = await _check_severity_escalation(mock_conn, rule_id=1, host_name="ws-01", current_severity="high")
        assert result == "critical"

    @pytest.mark.asyncio
    async def test_escalation_capped_at_critical(self):
        """Should not escalate beyond critical."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=10)

        result = await _check_severity_escalation(mock_conn, rule_id=1, host_name="ws-01", current_severity="critical")
        assert result == "critical"

    @pytest.mark.asyncio
    async def test_escalation_from_low_to_medium(self):
        """Should escalate low to medium."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=3)

        result = await _check_severity_escalation(mock_conn, rule_id=1, host_name="ws-01", current_severity="low")
        assert result == "medium"

    @pytest.mark.asyncio
    async def test_escalation_from_info_to_low(self):
        """Should escalate info to low."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=4)

        result = await _check_severity_escalation(mock_conn, rule_id=1, host_name="ws-01", current_severity="info")
        assert result == "low"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _is_suppressed
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestIsSuppressed:
    @pytest.mark.asyncio
    async def test_not_suppressed(self):
        """Should return False when no matching suppression rule."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        result = await _is_suppressed(mock_conn, "test_rule", "server-01", "high")
        assert result is False

    @pytest.mark.asyncio
    async def test_suppressed_by_rule_name(self):
        """Should return True when matching suppression rule exists."""
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": 1})

        result = await _is_suppressed(mock_conn, "noisy_rule", "server-01", "low")
        assert result is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# create_alert
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCreateAlert:
    @pytest.mark.asyncio
    async def test_create_alert_dedup(self):
        """Should return existing alert ID when duplicate detected."""
        mock_conn = AsyncMock()
        # First query: find existing duplicate
        mock_conn.fetchrow = AsyncMock(return_value={"id": 42})

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await create_alert(
                rule_id=1,
                rule_name="Test Rule",
                severity="high",
                host_name="server-01",
                description="Test description",
            )

        assert result == 42  # Existing alert ID

    @pytest.mark.asyncio
    async def test_create_alert_suppressed(self):
        """Should return 0 when alert is suppressed."""
        mock_conn = AsyncMock()

        async def mock_fetchrow(sql, *args):
            # No duplicate, but is suppressed
            if "FROM alerts" in sql:
                return None  # No duplicate
            return None  # No suppression match initially

        # No duplicate
        call_count = [0]
        async def side_effect_fetchrow(sql, *args):
            call_count[0] += 1
            if call_count[0] == 1:
                return None  # No duplicate
            return {"id": 1}  # Suppression rule match

        mock_conn.fetchrow = side_effect_fetchrow
        mock_conn.fetchval = AsyncMock(return_value=0)  # Below escalation threshold

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await create_alert(
                rule_id=1,
                rule_name="noisy_rule",
                severity="low",
                host_name="server-01",
                description="Suppress me",
            )

        assert result == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# update_alert_status
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestUpdateAlertStatus:
    @pytest.mark.asyncio
    async def test_update_status(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            await update_alert_status(
                alert_id=1,
                status="investigating",
                assigned_to="analyst1",
                resolution_note=None,
                updated_by="admin",
            )

        # Should have called execute for the UPDATE
        assert mock_conn.execute.call_count >= 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Bulk operations
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestBulkAcknowledge:
    @pytest.mark.asyncio
    async def test_bulk_acknowledge(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 3")

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await bulk_acknowledge([1, 2, 3], "analyst1")
            assert result == 3

    @pytest.mark.asyncio
    async def test_bulk_acknowledge_empty(self):
        result = await bulk_acknowledge([], "analyst1")
        assert result == 0


class TestBulkMarkFalsePositive:
    @pytest.mark.asyncio
    async def test_bulk_false_positive(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 2")

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await bulk_mark_false_positive([4, 5])
            assert result == 2

    @pytest.mark.asyncio
    async def test_bulk_false_positive_empty(self):
        result = await bulk_mark_false_positive([])
        assert result == 0


class TestBulkAssign:
    @pytest.mark.asyncio
    async def test_bulk_assign(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 5")

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await bulk_assign([1, 2, 3, 4, 5], "analyst2")
            assert result == 5


class TestBulkResolve:
    @pytest.mark.asyncio
    async def test_bulk_resolve(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="UPDATE 4")

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await bulk_resolve([1, 2, 3, 4], "Resolved by bulk operation")
            assert result == 4


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# add_alert_note
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAddAlertNote:
    @pytest.mark.asyncio
    async def test_add_note(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            await add_alert_note(alert_id=1, author="analyst1", text="Investigating this alert")

        mock_conn.execute.assert_called_once()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# get_alert_stats
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestGetAlertStats:
    @pytest.mark.asyncio
    async def test_get_stats(self):
        mock_stats = {
            "new_count": 15,
            "investigating_count": 5,
            "resolved_count": 200,
            "false_positive_count": 30,
            "critical_count": 2,
            "high_count": 8,
            "medium_count": 20,
            "low_count": 50,
            "total_count": 295,
        }

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=mock_stats)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await get_alert_stats(hours=24)

        assert result["total_count"] == 295
        assert result["new_count"] == 15


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Suppression rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSuppressionRules:
    @pytest.mark.asyncio
    async def test_create_suppression_rule(self):
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()  # CREATE TABLE
        mock_conn.fetchval = AsyncMock(return_value=1)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await create_suppression_rule(
                rule_name="noisy_rule",
                host_name="server-01",
                reason="Known false positive",
                created_by="admin",
            )

        assert result == 1

    @pytest.mark.asyncio
    async def test_list_suppression_rules(self):
        mock_rules = [
            {"id": 1, "rule_name": "noisy_rule", "host_name": None, "reason": "FP", "enabled": True},
            {"id": 2, "rule_name": None, "host_name": "server-01", "reason": "Testing", "enabled": True},
        ]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=mock_rules)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await list_suppression_rules()

        assert len(result) == 2
        assert result[0]["rule_name"] == "noisy_rule"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Export
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestExportAlerts:
    @pytest.mark.asyncio
    async def test_export_csv(self):
        mock_rows = [
            {"id": 1, "time": "2024-01-01", "rule_name": "Test", "severity": "high",
             "status": "new", "host_name": "ws-01", "description": "Desc",
             "assigned_to": None, "risk_score": 75.0},
        ]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=mock_rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await export_alerts_csv(hours=24)

        assert "id" in result  # CSV header
        assert "Test" in result

    @pytest.mark.asyncio
    async def test_export_csv_with_status_filter(self):
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await export_alerts_csv(hours=24, status_filter="resolved")

        # Empty CSV but still valid
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_export_stix(self):
        mock_rows = [
            {
                "id": 1,
                "time": datetime(2024, 1, 1, 12, 0, 0),
                "rule_name": "Brute Force",
                "severity": "high",
                "status": "new",
                "host_name": "ws-01",
                "description": "Multiple failed logins",
                "mitre_tactics": ["initial_access"],
                "mitre_techniques": ["T1110"],
            },
        ]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=mock_rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await export_alerts_stix(hours=24)

        assert result["type"] == "bundle"
        assert len(result["objects"]) == 1
        assert result["objects"][0]["pattern"] == "[host_name = 'ws-01']"
        assert result["objects"][0]["confidence"] == 80  # High severity = 80

    @pytest.mark.asyncio
    async def test_export_stix_low_severity(self):
        """Low severity should get 50 confidence."""
        mock_rows = [
            {
                "id": 2,
                "time": datetime(2024, 1, 1, 12, 0, 0),
                "rule_name": "Low Alert",
                "severity": "low",
                "status": "new",
                "host_name": "ws-02",
                "description": "Minor issue",
                "mitre_tactics": [],
                "mitre_techniques": [],
            },
        ]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=mock_rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.detection.alerts.get_pool", AsyncMock(return_value=mock_pool)):
            result = await export_alerts_stix(hours=24)

        assert result["objects"][0]["confidence"] == 50  # Low severity