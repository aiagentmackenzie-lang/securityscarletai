"""
Tests for the detection scheduler.

Covers:
- run_rule() with valid rule, disabled rule, nonexistent rule
- schedule_rules() — scheduling enabled rules
- stop_scheduler()
- reload_rules()
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from datetime import timedelta

from src.detection.scheduler import run_rule, schedule_rules, stop_scheduler


class TestRunRule:
    """Test run_rule execution."""

    @pytest.mark.asyncio
    async def test_run_disabled_rule(self):
        """Should skip disabled rules."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)  # No enabled rule found

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            result = await run_rule(rule_id=99)
            # Should return None (no matches) without errors

    @pytest.mark.asyncio
    async def test_run_enabled_rule_no_matches(self):
        """Should handle a rule that finds no matches."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        rule_row = {
            "id": 1,
            "name": "Test Rule",
            "sigma_yaml": "title: Test\ndetection:\n  condition: selection",
            "severity": "medium",
            "description": "A test rule",
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110"],
        }
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.fetch = AsyncMock(return_value=[])  # No matches
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.sigma_to_sql", return_value=("SELECT 1", [])):
                await run_rule(rule_id=1)
                # last_run should be updated even with no matches
                assert mock_conn.execute.called

    @pytest.mark.asyncio
    async def test_run_rule_with_matches(self):
        """Should create alerts for matched rows."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        rule_row = {
            "id": 1,
            "name": "SSH Brute Force",
            "sigma_yaml": "title: Test",
            "severity": "high",
            "description": "Test rule",
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110"],
        }
        matched_rows = [
            {"host_name": "server01", "source_ip": "10.0.0.5"},
            {"host_name": "server02", "source_ip": "10.0.0.6"},
        ]

        # First call for rule, second call for matches, third for stats
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.fetch = AsyncMock(return_value=matched_rows)
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.sigma_to_sql", return_value=("SELECT * FROM logs WHERE host_name = $1", ["server01"])):
                with patch("src.detection.scheduler.create_alert", new_callable=AsyncMock) as mock_create:
                    mock_create.return_value = 1  # Return alert ID
                    with patch("src.detection.ai_analyzer.analyze_alert", new_callable=AsyncMock) as mock_analyze:
                        mock_analyze.return_value = {"summary": "test", "risk_score": 50, "verdict": "suspicious"}
                        with patch("src.detection.ai_analyzer.enrich_alert", new_callable=AsyncMock):
                            await run_rule(rule_id=1)
                            # Should have called create_alert for each match
                            assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_run_rule_sigma_parse_error(self):
        """Should handle Sigma parse errors gracefully."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        rule_row = {
            "id": 1,
            "name": "Bad Sigma",
            "sigma_yaml": "invalid: yaml: content",
            "severity": "low",
            "description": "",
            "mitre_tactics": [],
            "mitre_techniques": [],
        }
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.sigma_to_sql", side_effect=Exception("Invalid Sigma rule")):
                # Should not raise, just log error
                await run_rule(rule_id=1)


class TestScheduleRules:
    """Test schedule_rules function."""

    @pytest.mark.asyncio
    async def test_schedule_rules_adds_jobs(self):
        """Should schedule all enabled rules."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"id": 1, "run_interval": timedelta(seconds=60)},
            {"id": 2, "run_interval": timedelta(seconds=300)},
        ])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        mock_scheduler = MagicMock()
        mock_scheduler.add_job = MagicMock()

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.scheduler", mock_scheduler):
                result = await schedule_rules()
                assert mock_scheduler.add_job.call_count == 2

    @pytest.mark.asyncio
    async def test_schedule_empty_rules(self):
        """Should handle no enabled rules."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        mock_scheduler = MagicMock()

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.scheduler", mock_scheduler):
                await schedule_rules()
                mock_scheduler.add_job.assert_not_called()


class TestStopScheduler:
    """Test stop_scheduler function."""

    @pytest.mark.asyncio
    async def test_stop_scheduler(self):
        """Should call scheduler.shutdown()."""
        mock_scheduler = MagicMock()
        with patch("src.detection.scheduler.scheduler", mock_scheduler):
            await stop_scheduler()
            mock_scheduler.shutdown.assert_called_once()


class TestReloadRules:
    """Test reload rules functionality."""

    @pytest.mark.asyncio
    async def test_reload_rules(self):
        """Should remove all jobs and reschedule."""
        mock_scheduler = MagicMock()
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[
            {"id": 1, "run_interval": timedelta(seconds=60)},
        ])

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.scheduler", mock_scheduler):
                from src.detection.scheduler import reload_rules
                await reload_rules()
                mock_scheduler.remove_all_jobs.assert_called_once()