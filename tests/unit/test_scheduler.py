"""
Tests for the detection scheduler.

Covers:
- run_rule() with valid rule, disabled rule, nonexistent rule
- schedule_rules() — scheduling enabled rules
- stop_scheduler()
- reload_rules()
"""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import src.detection.scheduler as scheduler_mod
from src.detection.scheduler import run_rule, schedule_rules, stop_scheduler


@pytest.fixture(autouse=True)
def _clear_compile_cache():
    """AUD-002: the compile cache is process-global — clear it per test so
    no cached entry bypasses a test's sigma_to_sql patch."""
    scheduler_mod._compile_cache.clear()
    yield
    scheduler_mod._compile_cache.clear()


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
            with patch(
                "src.detection.scheduler.sigma_to_sql",
                return_value=("SELECT * FROM logs WHERE host_name = $1", ["server01"]),
            ):
                with patch(
                    "src.detection.scheduler.create_alert", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = 1  # Return alert ID
                    with patch(
                        "src.detection.ai_analyzer.analyze_alert", new_callable=AsyncMock
                    ) as mock_analyze:
                        mock_analyze.return_value = {
                            "summary": "test",
                            "risk_score": 50,
                            "verdict": "suspicious",
                        }
                        with patch(
                            "src.detection.ai_analyzer.enrich_alert", new_callable=AsyncMock
                        ):
                            await run_rule(rule_id=1)
                            # Should have called create_alert for each match
                            assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_deduped_alert_never_enriches(self):
        """W1-A: create_alert returns -1 for dedup/suppressed — truthy! The
        old `if alert_id:` scheduled a full LLM enrichment for a nonexistent
        alert, burning one of the two semaphore slots per deduped match and
        starving real alerts. No enrichment may be scheduled for id=-1."""
        import asyncio

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        rule_row = {
            "id": 1,
            "name": "Noisy Rule",
            "sigma_yaml": "title: Test",
            "severity": "high",
            "description": "Test rule",
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110"],
        }
        matched_rows = [{"host_name": "server01", "source_ip": "10.0.0.5"}]
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.fetch = AsyncMock(return_value=matched_rows)
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.sigma_to_sql", return_value=("SELECT 1", [])):
                with patch(
                    "src.detection.scheduler.create_alert", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = -1  # dedup/suppressed
                    with patch(
                        "src.detection.ai_analyzer.analyze_alert", new_callable=AsyncMock
                    ) as mock_analyze:
                        with patch(
                            "src.detection.ai_analyzer.enrich_alert", new_callable=AsyncMock
                        ) as mock_enrich:
                            await run_rule(rule_id=1)
                            # Give any (wrongly) scheduled fire-and-forget
                            # task a chance to run before the assert.
                            await asyncio.sleep(0.05)

        assert mock_create.call_count == 1
        mock_analyze.assert_not_awaited()
        mock_enrich.assert_not_awaited()
        assert scheduler_mod._enrich_tasks == set()

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
            with patch(
                "src.detection.scheduler.sigma_to_sql", side_effect=Exception("Invalid Sigma rule")
            ):
                # Should not raise, just log error
                await run_rule(rule_id=1)

    @pytest.mark.asyncio
    async def test_threshold_gates_alerting(self):
        """AUD-007: rules.threshold is 'minimum matches to trigger' — with
        threshold=5 and 2 matching rows, NO alert is created; the match
        stats still record the raw detection matches (the query matched;
        alerting is what is gated)."""
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
            "lookback": timedelta(seconds=300),
            "threshold": 5,
        }
        matched_rows = [
            {"host_name": "server01"},
            {"host_name": "server02"},
        ]
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.fetch = AsyncMock(return_value=matched_rows)
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch(
                "src.detection.scheduler.sigma_to_sql",
                return_value=("SELECT 1", []),
            ) as mock_compile:
                with patch(
                    "src.detection.scheduler.create_alert", new_callable=AsyncMock
                ) as mock_create:
                    await run_rule(rule_id=1)

        mock_create.assert_not_called()
        # stats: the 2 raw matches still count (match_count += 2, last_match set)
        stats_sql = mock_conn.execute.call_args_list[-1].args[0]
        assert "match_count = match_count + $1" in stats_sql
        assert mock_conn.execute.call_args_list[-1].args[1] == 2

    @pytest.mark.asyncio
    async def test_threshold_met_alerts_fire(self):
        """AUD-007: matches >= threshold behave exactly as before."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        rule_row = {
            "id": 1,
            "name": "SSH Brute Force",
            "sigma_yaml": "title: Test",
            "severity": "high",
            "description": "Test rule",
            "mitre_tactics": [],
            "mitre_techniques": [],
            "threshold": 1,
        }
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.fetch = AsyncMock(return_value=[{"host_name": "server01"}])
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch(
                "src.detection.scheduler.sigma_to_sql",
                return_value=("SELECT 1", []),
            ):
                with patch(
                    "src.detection.scheduler.create_alert", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = 1
                    with (
                        patch("src.detection.ai_analyzer.analyze_alert", new_callable=AsyncMock),
                        patch("src.detection.ai_analyzer.enrich_alert", new_callable=AsyncMock),
                    ):
                        await run_rule(rule_id=1)
        assert mock_create.call_count == 1

    @pytest.mark.asyncio
    async def test_lookback_override_passed_to_compiler(self):
        """AUD-007: the rules row's lookback (seconds) rides into the compile
        as lookback_seconds_override — the operator knob governs."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        rule_row = {
            "id": 1,
            "name": "Windowed Rule",
            "sigma_yaml": "title: Test",
            "severity": "medium",
            "description": "",
            "mitre_tactics": [],
            "mitre_techniques": [],
            "lookback": timedelta(seconds=300),
            "threshold": 1,
        }
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch(
                "src.detection.scheduler.sigma_to_sql", return_value=("SELECT 1", [])
            ) as mock_compile:
                await run_rule(rule_id=1)
        mock_compile.assert_called_once_with("title: Test", lookback_seconds_override=300)

    @pytest.mark.asyncio
    async def test_compile_cache_hit_and_yaml_invalidation(self):
        """AUD-002: the second run with the SAME yaml/lookback uses the cache
        (sigma_to_sql called once); a YAML change recompiles."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        rule_row = {
            "id": 1,
            "name": "Cached Rule",
            "sigma_yaml": "title: Test",
            "severity": "medium",
            "description": "",
            "mitre_tactics": [],
            "mitre_techniques": [],
        }
        mock_conn.fetchrow = AsyncMock(return_value=rule_row)
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.execute = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch(
                "src.detection.scheduler.sigma_to_sql", return_value=("SELECT 1", [])
            ) as mock_compile:
                await run_rule(rule_id=1)
                await run_rule(rule_id=1)
                assert mock_compile.call_count == 1  # cache hit on run 2

                # YAML change -> new content key -> recompile
                rule_row["sigma_yaml"] = "title: Test v2"
                await run_rule(rule_id=1)
                assert mock_compile.call_count == 2

                # lookback change -> new key -> recompile
                rule_row["lookback"] = timedelta(seconds=600)
                await run_rule(rule_id=1)
                assert mock_compile.call_count == 3
                mock_compile.assert_called_with("title: Test v2", lookback_seconds_override=600)


class TestScheduleRules:
    """Test schedule_rules function."""

    @pytest.mark.asyncio
    async def test_schedule_rules_adds_jobs(self):
        """Should schedule all enabled rules."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                {"id": 1, "run_interval": timedelta(seconds=60)},
                {"id": 2, "run_interval": timedelta(seconds=300)},
            ]
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        mock_scheduler = MagicMock()
        mock_scheduler.add_job = MagicMock()

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.scheduler", mock_scheduler):
                result = await schedule_rules()
                # 2 rule jobs + auto_train_check + correlation_sweep (P2-25 + F-10 sweep)
                assert mock_scheduler.add_job.call_count == 4
                # the auto_train_check job is registered with a stable id
                job_ids = [c.kwargs.get("id") for c in mock_scheduler.add_job.call_args_list]
                assert "auto_train_check" in job_ids

    @pytest.mark.asyncio
    async def test_correlation_sweep_job_registered(self):
        """The periodic correlation sweep (F-10 follow-up) must be scheduled:
        batch-triggered runs alone leave late-landing pairs uncorrelated once
        ingest goes quiet (found live 2026-09-12 via the purple-loop
        feedback artifact)."""
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
        job_ids = [c.kwargs.get("id") for c in mock_scheduler.add_job.call_args_list]
        assert "correlation_sweep" in job_ids
        # the sweep carries the settings-driven interval (default 60s)
        sweep_call = next(
            c
            for c in mock_scheduler.add_job.call_args_list
            if c.kwargs.get("id") == "correlation_sweep"
        )
        assert sweep_call.args[0].__name__ == "trigger_correlation_coalesced"

    @pytest.mark.asyncio
    async def test_null_run_interval_defaults_to_60s(self):
        """W1-H: an API-created rule with NULL run_interval raised
        AttributeError — one bad row bricked the lifespan boot. The row
        must default to 60s with a warning, not kill the process."""
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                {"id": 1, "run_interval": None},
            ]
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        mock_scheduler = MagicMock()

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.scheduler", mock_scheduler):
                # Must NOT raise (old code: AttributeError -> lifespan boot fails)
                await schedule_rules()

        rule_calls = [
            c for c in mock_scheduler.add_job.call_args_list if c.kwargs.get("id") == "rule_1"
        ]
        assert len(rule_calls) == 1
        assert rule_calls[0].kwargs["trigger"].interval == timedelta(seconds=60)

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
                # No rules, but the maintenance jobs still schedule (P2-25 + F-10 sweep)
                assert mock_scheduler.add_job.call_count == 2
                job_ids = [c.kwargs.get("id") for c in mock_scheduler.add_job.call_args_list]
                assert job_ids == ["auto_train_check", "correlation_sweep"]


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
        mock_conn.fetch = AsyncMock(
            return_value=[
                {"id": 1, "run_interval": timedelta(seconds=60)},
            ]
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.detection.scheduler.get_pool", return_value=mock_pool):
            with patch("src.detection.scheduler.scheduler", mock_scheduler):
                from src.detection.scheduler import reload_rules

                await reload_rules()
                mock_scheduler.remove_all_jobs.assert_called_once()


class TestJobDefaults:
    """W1-G: explicit job_defaults — APScheduler's defaults silently SKIP a
    job whose slot was missed by more than ~1s (busy loop, slow sweep). A
    60s grace + coalesce + max_instances=1 turns a transient misfire into a
    catch-up run instead of a silent detection hole."""

    def test_scheduler_carries_misfire_job_defaults(self):
        from src.detection.scheduler import scheduler

        assert scheduler._job_defaults["misfire_grace_time"] == 60
        assert scheduler._job_defaults["coalesce"] is True
        assert scheduler._job_defaults["max_instances"] == 1
