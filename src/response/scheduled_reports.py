"""Scheduled report delivery (Wave 1 W1.8) -- the recurring compliance
artifact a conversation actually uses.

Renders the V0.7 standing reports on a schedule and delivers them through
the W1.7 notification channels. Versioned, FAIL-CLOSED config (the
notification_channels pattern):

- an unknown file version disables EVERY schedule (never guessed)
- an unknown report name, invalid interval, or missing channels drop the
  schedule (logged loudly)
- PagerDuty is an ALERT-routing destination, not a report reader -- a
  schedule targeting a pagerduty channel refuses that delivery
- no config file = no scheduled reports (default-off)

Report types (standing reports; single source of truth with the API):
- coverage:     evidence-driven ATT&CK coverage (armed/dormant map)
- posture:      alert counts + MTTR + scorecard summary (+ outliers) --
                the SAME data the /compliance/reports/posture endpoint
                returns (shared builder, one implementation)
- retention:    the configured retention windows AS EVIDENCE
- closed_cases: digest of cases resolved/closed in the window (ids +
                pointers to the evidence-pack endpoint). The packs
                themselves stay on-demand: auto-broadcasting case
                evidence to notification channels would be a data-leak
                risk -- the digest points, it does not carry.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import yaml

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("response.scheduled_reports")

SCHEDULE_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "scheduled_reports.yaml"
)

# Closed report vocabulary; unknown names drop the schedule (fail-closed).
VALID_REPORTS = ("coverage", "posture", "retention", "closed_cases")

# Reports are informational; PagerDuty routes ALERTS. A report schedule
# pointing at a pagerduty channel is a misunderstanding -> dropped loudly.
REPORT_INCOMPATIBLE_TYPES = ("pagerduty",)


@dataclass(frozen=True)
class ReportSchedule:
    """One scheduled report, parsed + validated (or dropped upstream)."""

    name: str
    report: str
    channels: tuple[str, ...]
    interval_hours: int
    window_hours: int = 24
    lookback_hours: int = 168


def parse_schedules_document(document: Any) -> list[ReportSchedule]:
    """Pure: parse a scheduled_reports YAML document into schedules.

    Fail-closed: wrong version -> []; unknown report name, invalid
    interval, or missing channels drop the entry (logged loudly).
    """
    if not isinstance(document, dict):
        return []
    block = document.get("scheduled_reports")
    if not isinstance(block, dict):
        log.warning("scheduled_reports_block_missing")
        return []
    if block.get("version") != 1:
        log.error(
            "scheduled_reports_version_unsupported_disabling_all",
            version=str(block.get("version")),
        )
        return []
    schedules_raw = block.get("schedules")
    if not isinstance(schedules_raw, list):
        return []

    schedules: list[ReportSchedule] = []
    seen_names: set[str] = set()
    for raw in schedules_raw:
        if not isinstance(raw, dict):
            log.warning("scheduled_report_entry_invalid")
            continue
        name = raw.get("name")
        report = raw.get("report")
        if not isinstance(name, str) or not name.strip() or name in seen_names:
            log.warning("scheduled_report_name_invalid_or_duplicate", name=str(name))
            continue
        if report not in VALID_REPORTS:
            log.warning("scheduled_report_unknown_type_dropped", name=name, report=str(report))
            continue
        if raw.get("enabled") is not True:
            continue  # default-off
        channels = raw.get("channels")
        if not isinstance(channels, list) or not channels:
            log.warning("scheduled_report_no_channels_dropped", name=name)
            continue
        channel_names = tuple(str(c) for c in channels if isinstance(c, str))
        try:
            interval_hours = int(raw.get("interval_hours", 24))
            window_hours = int(raw.get("window_hours", 24))
            lookback_hours = int(raw.get("lookback_hours", 168))
        except (TypeError, ValueError):
            log.warning("scheduled_report_bad_interval_dropped", name=name)
            continue
        if interval_hours < 1:
            log.warning("scheduled_report_interval_too_small_dropped", name=name)
            continue
        seen_names.add(name)
        schedules.append(
            ReportSchedule(
                name=name,
                report=str(report),
                channels=channel_names,
                interval_hours=max(interval_hours, 1),
                window_hours=max(window_hours, 1),
                lookback_hours=max(lookback_hours, 1),
            )
        )
    return schedules


def load_schedules_file(path: str) -> list[ReportSchedule]:
    """Load + parse the schedules file. Missing/unreadable -> no reports."""
    try:
        with open(path) as f:
            document = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        log.error("scheduled_reports_load_failed", path=path, error=str(e))
        return []
    return parse_schedules_document(document)


# ─────────────────────────────────────────────────────────────
# Report builders (single source of truth with the API endpoints)
# ─────────────────────────────────────────────────────────────


async def posture_report_data(window_hours: int = 24, as_of: Optional[datetime] = None) -> dict:
    """The /compliance/reports/posture payload -- shared by the endpoint and
    the scheduled report so the two can never drift."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    pool = await get_pool()
    async with pool.acquire() as conn:
        posture = dict(
            await conn.fetchrow(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
                    COUNT(*) FILTER (WHERE severity = 'high') AS high,
                    COUNT(*) FILTER (WHERE status = 'new') AS new,
                    COUNT(*) FILTER (WHERE status = 'investigating') AS investigating,
                    COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) AS resolved,
                    COUNT(*) FILTER (WHERE status = 'false_positive') AS false_positives,
                    EXTRACT(EPOCH FROM AVG(
                        CASE WHEN resolved_at IS NOT NULL
                            THEN resolved_at - time END
                    )) AS mttr_seconds
                FROM alerts
                WHERE time > NOW() - INTERVAL '1 hour' * $1
                """,
                window_hours,
            )
        )
    mttr = posture.pop("mttr_seconds", None)
    from src.detection.scorecard import compute_rule_scorecard

    summary = (await compute_rule_scorecard(window_hours=window_hours, as_of=as_of))["summary"]
    from src.compliance.outliers import compute_posture_outliers

    outliers = await compute_posture_outliers(window_hours, as_of=as_of)
    return {
        "window_hours": window_hours,
        "alerts": posture,
        "mttr_seconds": float(mttr) if mttr is not None else None,
        "rule_scorecard_summary": summary,
        "outliers": outliers,
    }


async def coverage_report_data(lookback_hours: int = 168, as_of: Optional[datetime] = None) -> dict:
    """The /compliance/reports/coverage payload (the endpoint delegates to
    the same compute_coverage)."""
    from src.detection.coverage import compute_coverage

    return await compute_coverage(lookback_hours=lookback_hours, as_of=as_of)


async def retention_report_data(as_of: Optional[datetime] = None) -> dict:
    """The /compliance/retention-policy evidence payload (probe errors are
    carried as data -- the fail-closed evidence shape)."""
    from src.compliance.retention import retention_policy_evidence

    return await retention_policy_evidence(as_of=as_of)


async def closed_cases_digest(window_hours: int = 24, as_of: Optional[datetime] = None) -> dict:
    """Cases resolved/closed within the window: the digest only. The packs
    stay on-demand (auto-broadcasting case evidence would be a leak)."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    since = as_of - timedelta(hours=window_hours)
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, title, status, severity, resolution_note, resolved_at
            FROM cases
            WHERE status IN ('resolved', 'closed')
              AND resolved_at > $1::timestamptz
            ORDER BY resolved_at DESC
            LIMIT 50
            """,
            since,
        )
    cases = [
        {
            "id": r["id"],
            "title": r["title"],
            "status": r["status"],
            "severity": r["severity"],
            "resolved_at": r["resolved_at"].isoformat() if r["resolved_at"] else None,
            "resolution_note": (r["resolution_note"] or "")[:200],
        }
        for r in rows
    ]
    return {"window_hours": window_hours, "closed_cases": cases, "count": len(cases)}


async def build_report(report: str, schedule: ReportSchedule, as_of: datetime) -> dict:
    """Dispatch to the report builder (closed vocabulary upstream)."""
    if report == "posture":
        return await posture_report_data(schedule.window_hours, as_of)
    if report == "coverage":
        return await coverage_report_data(schedule.lookback_hours, as_of)
    if report == "retention":
        return await retention_report_data(as_of)
    return await closed_cases_digest(schedule.window_hours, as_of)


def report_text(report: str, payload: dict, as_of: datetime) -> str:
    """Compact human-readable summary (Slack/email); the full payload goes
    to webhook channels as signed JSON."""
    stamp = as_of.strftime("%Y-%m-%d %H:%M UTC")
    if report == "posture":
        alerts = payload.get("alerts", {})
        mttr = payload.get("mttr_seconds")
        mttr_note = f"{mttr / 3600:.1f}h" if isinstance(mttr, (int, float)) else "n/a"
        summary = payload.get("rule_scorecard_summary", {})
        return (
            f"*SecurityScarletAI posture report* ({stamp}, "
            f"window {payload.get('window_hours')}h)\n"
            f"Alerts: {alerts.get('total', 0)} (critical {alerts.get('critical', 0)}, "
            f"high {alerts.get('high', 0)}, new {alerts.get('new', 0)}, "
            f"resolved {alerts.get('resolved', 0)}, FP {alerts.get('false_positives', 0)})\n"
            f"MTTR: {mttr_note} | retirement candidates: "
            f"{summary.get('retirement_candidates', 0)}"
        )
    if report == "coverage":
        return (
            f"*SecurityScarletAI coverage report* ({stamp})\n"
            f"Armed {payload.get('summary', {}).get('armed', 0)}/"
            f"{payload.get('summary', {}).get('total_rules', 0)} rules "
            f"(lookback {payload.get('summary', {}).get('lookback_hours', '?')}h)"
        )
    if report == "retention":
        return (
            f"*SecurityScarletAI retention evidence* ({stamp}) -- configured "
            f"windows as evidence (0 = keep forever); full payload on "
            f"webhook/email channels"
        )
    return (
        f"*SecurityScarletAI closed cases digest* ({stamp}, "
        f"window {payload.get('window_hours')}h): {payload.get('count', 0)} case(s)"
    )


async def run_scheduled_report(
    schedule: ReportSchedule, as_of: Optional[datetime] = None
) -> dict[str, Any]:
    """Render + deliver one schedule through the W1.7 channels (audited).
    Never raises: report failures must not wedge the scheduler tick."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    try:
        payload = await build_report(schedule.report, schedule, as_of)
    except Exception as e:
        log.error("scheduled_report_build_failed", schedule=schedule.name, error=str(e))
        await _audit_report(schedule, "failed", channel="", detail=f"build error: {e}")
        return {"schedule": schedule.name, "outcome": "failed", "detail": str(e)}

    from src.response.notification_channels import (
        load_effective_channels,
        send_to_channel,
    )

    by_name = {c.name: c for c in await load_effective_channels()}
    text = report_text(schedule.report, payload, as_of)
    subject = f"[SecurityScarletAI] report: {schedule.report} ({schedule.name})"
    delivered: list[str] = []
    failed: list[str] = []
    for name in schedule.channels:
        channel = by_name.get(name)
        outcome, attempts, detail = "failed", 0, ""
        if channel is None:
            detail = "unknown channel (refused, fail-closed)"
        elif channel.type in REPORT_INCOMPATIBLE_TYPES:
            detail = f"channel type '{channel.type}' is not a report destination (refused)"
        else:
            try:
                ok, attempts, detail = await send_to_channel(
                    channel,
                    text=text,
                    subject=subject,
                    payload={"report": schedule.report, "schedule": schedule.name, "data": payload},
                )
                outcome = "delivered" if ok else "failed"
            except Exception as e:  # delivery must never wedge the scheduler
                detail = f"sender error: {e}"
        if outcome == "delivered":
            delivered.append(name)
        else:
            failed.append(name)
        await _audit_report(schedule, outcome, name, detail)

    log.info(
        "scheduled_report_ran",
        schedule=schedule.name,
        report=schedule.report,
        delivered=delivered,
        failed=failed,
    )
    return {
        "schedule": schedule.name,
        "report": schedule.report,
        "delivered": delivered,
        "failed": failed,
    }


async def _audit_report(
    schedule: ReportSchedule, outcome: str, channel: str, detail: str = ""
) -> None:
    """One audited report delivery per channel (never raises)."""
    try:
        from src.api.audit import log_audit_action

        await log_audit_action(
            actor="system",
            action="report.attempt",
            target_type="scheduled_report",
            target_id=None,
            new_values={
                "schedule": schedule.name,
                "report": schedule.report,
                "channel": channel,
                "outcome": outcome,
                **({"detail": detail} if detail else {}),
            },
        )
    except Exception as e:
        log.warning("scheduled_report_audit_failed", schedule=schedule.name, error=str(e))
