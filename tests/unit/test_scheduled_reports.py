"""W1.8 scheduled reports -- unit gates.

Covers the fail-closed schedule parsing (version gate, unknown reports,
bad intervals, channel validation), the report builders (shared with the
API endpoints -- posture never drifts), the compact report text, the
delivery through W1.7 channels (PagerDuty refused, unknown channel
refused, audited), and the scheduler wiring.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.response.scheduled_reports import (
    ReportSchedule,
    load_schedules_file,
    parse_schedules_document,
    report_text,
    run_scheduled_report,
)

AS_OF = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


def _schedule(name="daily-posture", report="posture", channels=("legacy-slack",)):
    return ReportSchedule(
        name=name,
        report=report,
        channels=channels,
        interval_hours=24,
        window_hours=24,
    )


class TestParseSchedulesDocument:
    def test_empty_and_malformed_documents_yield_no_schedules(self):
        assert parse_schedules_document(None) == []
        assert parse_schedules_document({}) == []
        assert parse_schedules_document({"scheduled_reports": {"schedules": []}}) == []

    def test_wrong_version_disables_everything(self):
        doc = {
            "scheduled_reports": {
                "version": 9,
                "schedules": [
                    {
                        "name": "x",
                        "report": "posture",
                        "enabled": True,
                        "interval_hours": 24,
                        "channels": ["c"],
                    }
                ],
            }
        }
        assert parse_schedules_document(doc) == []

    def test_unknown_report_bad_interval_and_disabled_dropped(self):
        doc = {
            "scheduled_reports": {
                "version": 1,
                "schedules": [
                    {
                        "name": "a",
                        "report": "stock_prices",
                        "enabled": True,
                        "interval_hours": 24,
                        "channels": ["c"],
                    },
                    {
                        "name": "b",
                        "report": "posture",
                        "enabled": True,
                        "interval_hours": 0,
                        "channels": ["c"],
                    },
                    {
                        "name": "c",
                        "report": "posture",
                        "enabled": False,
                        "interval_hours": 24,
                        "channels": ["c"],
                    },
                    {
                        "name": "d",
                        "report": "posture",
                        "enabled": True,
                        "interval_hours": 24,
                        "channels": [],
                    },
                    {
                        "name": "e",
                        "report": "coverage",
                        "enabled": True,
                        "interval_hours": 168,
                        "channels": ["slack-1", 5],
                    },
                    {
                        "name": "e",
                        "report": "posture",
                        "enabled": True,
                        "interval_hours": 24,
                        "channels": ["c"],
                    },
                ],
            }
        }
        schedules = parse_schedules_document(doc)
        assert [s.name for s in schedules] == ["e"]
        assert schedules[0].report == "coverage"
        assert schedules[0].channels == ("slack-1",)  # non-str entries filtered

    def test_bad_interval_type_dropped(self):
        doc = {
            "scheduled_reports": {
                "version": 1,
                "schedules": [
                    {
                        "name": "a",
                        "report": "posture",
                        "enabled": True,
                        "interval_hours": "daily",
                        "channels": ["c"],
                    }
                ],
            }
        }
        assert parse_schedules_document(doc) == []


class TestConfigFile:
    def test_shipped_config_parses_to_nothing_when_all_disabled(self):

        from src.response.scheduled_reports import SCHEDULE_CONFIG_PATH

        schedules = load_schedules_file(SCHEDULE_CONFIG_PATH)
        # The shipped file is DEFAULT-OFF: every schedule enabled: false.
        assert schedules == []


class TestReportText:
    def test_posture_text_compact_and_human(self):
        payload = {
            "window_hours": 24,
            "alerts": {
                "total": 10,
                "critical": 1,
                "high": 2,
                "new": 3,
                "resolved": 4,
                "false_positives": 1,
            },
            "mttr_seconds": 5400.0,
            "rule_scorecard_summary": {"retirement_candidates": 1},
        }
        text = report_text("posture", payload, AS_OF)
        assert "Alerts: 10" in text
        assert "MTTR: 1.5h" in text
        assert "retirement candidates: 1" in text

    def test_coverage_text(self):
        payload = {"summary": {"armed": 102, "total_rules": 123, "lookback_hours": 168}}
        text = report_text("coverage", payload, AS_OF)
        assert "Armed 102/123" in text

    def test_closed_cases_text_carries_count_only(self):
        payload = {"window_hours": 24, "closed_cases": [], "count": 0}
        text = report_text("closed_cases", payload, AS_OF)
        assert "0 case(s)" in text


class TestDelivery:
    @pytest.mark.asyncio
    async def test_run_delivers_through_named_channels_and_audits(self):
        from src.response.notification_channels import ChannelConfig

        channels = [
            ChannelConfig(
                name="legacy-slack",
                type="slack",
                severities=("critical",),
                config={"webhook_url_env": "U"},
            ),
            ChannelConfig(
                name="soc-webhook",
                type="webhook",
                severities=("critical",),
                config={"url": "https://soc.internal/x"},
            ),
        ]
        build = AsyncMock(
            return_value={
                "window_hours": 24,
                "alerts": {},
                "mttr_seconds": None,
                "rule_scorecard_summary": {},
                "outliers": {},
            }
        )
        with (
            patch("src.response.scheduled_reports.build_report", build),
            patch(
                "src.response.notification_channels.load_effective_channels",
                AsyncMock(return_value=channels),
            ),
            patch(
                "src.response.notification_channels._send_slack_channel",
                AsyncMock(return_value=(True, 1, "")),
            ),
            patch(
                "src.response.notification_channels._send_webhook_body",
                AsyncMock(return_value=(True, 1, "")),
            ) as webhook_send,
            patch("src.api.audit.log_audit_action", new=AsyncMock()) as audit,
        ):
            result = await run_scheduled_report(
                _schedule(channels=("legacy-slack", "soc-webhook")), as_of=AS_OF
            )
        assert result["delivered"] == ["legacy-slack", "soc-webhook"]
        assert result["failed"] == []
        # The webhook got the FULL payload (report + data), not just text.
        sent_body = webhook_send.await_args.args[1]
        assert sent_body["report"] == "posture"
        assert "data" in sent_body
        assert audit.await_count == 2

    @pytest.mark.asyncio
    async def test_unknown_and_incompatible_channels_refuse(self):
        from src.response.notification_channels import ChannelConfig

        channels = [
            ChannelConfig(
                name="duty-pager",
                type="pagerduty",
                severities=("critical",),
                config={"routing_key_env": "U2"},
            ),
        ]
        with (
            patch(
                "src.response.scheduled_reports.build_report",
                AsyncMock(return_value={"count": 0}),
            ),
            patch(
                "src.response.notification_channels.load_effective_channels",
                AsyncMock(return_value=channels),
            ),
            patch("src.api.audit.log_audit_action", new=AsyncMock()) as audit,
        ):
            result = await run_scheduled_report(
                _schedule(
                    name="x",
                    report="closed_cases",
                    channels=("duty-pager", "ghost-channel"),
                ),
                as_of=AS_OF,
            )
        assert result["delivered"] == []
        assert set(result["failed"]) == {"duty-pager", "ghost-channel"}
        details = [c.kwargs["new_values"].get("detail", "") for c in audit.await_args_list]
        assert any("not a report destination" in d for d in details)
        assert any("unknown channel" in d for d in details)

    @pytest.mark.asyncio
    async def test_build_failure_audited_and_never_raises(self):
        with (
            patch(
                "src.response.scheduled_reports.build_report",
                AsyncMock(side_effect=RuntimeError("db down")),
            ),
            patch("src.api.audit.log_audit_action", new=AsyncMock()) as audit,
        ):
            result = await run_scheduled_report(_schedule(), as_of=AS_OF)
        assert result["outcome"] == "failed"
        assert "db down" in result["detail"]
        assert audit.await_count == 1
        assert audit.await_args.kwargs["new_values"]["outcome"] == "failed"


class TestPostureSharedBuilder:
    @pytest.mark.asyncio
    async def test_posture_report_data_shape(self):
        """The shared builder returns the exact endpoint payload shape."""
        pool = MagicMock()
        conn = MagicMock()
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)
        conn.fetchrow = AsyncMock(
            return_value={
                "total": 5,
                "critical": 1,
                "high": 1,
                "new": 2,
                "investigating": 0,
                "resolved": 2,
                "false_positives": 0,
                "mttr_seconds": 3600.0,
            }
        )
        with (
            patch("src.response.scheduled_reports.get_pool", return_value=pool),
            patch(
                "src.detection.scorecard.compute_rule_scorecard",
                AsyncMock(return_value={"summary": {"retirement_candidates": 0}}),
            ),
            patch(
                "src.compliance.outliers.compute_posture_outliers",
                AsyncMock(return_value={"note": "not computable"}),
            ),
        ):
            from src.response.scheduled_reports import posture_report_data

            payload = await posture_report_data(24, as_of=AS_OF)
        assert payload["window_hours"] == 24
        assert payload["alerts"]["total"] == 5
        assert payload["mttr_seconds"] == 3600.0
        assert payload["rule_scorecard_summary"] == {"retirement_candidates": 0}

    @pytest.mark.asyncio
    async def test_endpoint_delegates_to_shared_builder(self):
        from src.api.compliance import posture_report

        expected = {
            "window_hours": 24,
            "alerts": {},
            "mttr_seconds": None,
            "rule_scorecard_summary": {},
            "outliers": {},
        }
        with patch(
            "src.response.scheduled_reports.posture_report_data",
            AsyncMock(return_value=expected),
        ) as mock_fn:
            result = await posture_report(window_hours=24, user={"sub": "analyst"})
        assert result == expected
        mock_fn.assert_awaited_once()
        assert mock_fn.await_args.args[0] == 24


class TestSchedulerWiring:
    @pytest.mark.asyncio
    async def test_enabled_schedules_become_jobs(self):
        """schedule_rules registers one interval job per enabled schedule."""
        schedules = [
            ReportSchedule(name="s1", report="posture", channels=("c",), interval_hours=24),
            ReportSchedule(name="s2", report="coverage", channels=("c",), interval_hours=168),
        ]
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)
        mock_scheduler = MagicMock()

        with (
            patch(
                "src.detection.scheduler.get_pool",
                new=AsyncMock(return_value=mock_pool),
            ),
            patch("src.services.shared_scheduler._scheduler", mock_scheduler),
            patch(
                "src.response.scheduled_reports.load_schedules_file",
                return_value=schedules,
            ),
        ):
            from src.detection.scheduler import schedule_rules

            await schedule_rules()
        job_ids = [c.kwargs.get("id") for c in mock_scheduler.add_job.call_args_list]
        assert "report_s1" in job_ids
        assert "report_s2" in job_ids
        # The job carries the schedule object and the interval trigger.
        s1_call = next(
            c for c in mock_scheduler.add_job.call_args_list if c.kwargs.get("id") == "report_s1"
        )
        assert s1_call.args[0].__name__ == "run_scheduled_report"
        assert s1_call.kwargs["args"][0].name == "s1"
