"""Rule backtesting (Wave 1 W1.1) -- "would this rule have fired, and at what cost?"

Closes the detection-engineering loop started by the V0.7b scorecard:
author -> BACKTEST -> arm -> measure -> retire. A backtest compiles any
draft or enabled Sigma rule through the PRODUCTION Sigma->SQL compiler
(src.detection.sigma) and replays it read-only against the stored logs
window. Returns: hit count, per-day distribution, top offending
field values, an estimated alert volume, and -- where prior dispositions
exist for the same rule -- a projected FP ratio.

Doctrine (least-agency, matches scorecard/coverage):
- READ-ONLY. Every query is a SELECT over a bounded, index-aware window
  (time > $1 AND time <= $2 -- idx_logs_time / BRIN shapes). No writes,
  no persistence, never auto-arms; results land in the run record (the
  API response), never in the rules table.
- HONESTY (the adopted sigmaforge gate): when the corpus cannot support a
  number, the report says "unmeasured" -- never a fake 0 and never a
  tautological 1.0. Unmeasured happens when (a) the rule failed safe to
  FALSE during compilation (it would match nothing, so 0 hits is a compile
  artifact, not a measurement) or (b) the window contains zero logs (a 0
  hit count would be indistinguishable from "no data").
- ESTIMATION is labeled as estimation. estimated_alerts replays
  create_alert's actual dedup semantics ((rule, host_name) inside a
  15-minute window, DEDUP_WINDOW_SECONDS). Suppression rules and severity
  escalation are NOT modeled (documented in the response note).
- Aggregation (count-by) rules: the runtime path creates aggregation
  alerts with host_name="unknown" (the aggregation query returns only
  (group, cnt)), so their dedup collapses to one alert per rule per
  dedup window regardless of group. The estimate mirrors that behavior.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.alerts import DEDUP_WINDOW_SECONDS
from src.detection.scorecard import _VERDICT_TOKENS
from src.detection.sigma import (
    FIELD_MAPPING,
    SigmaParser,
    _timeframe_to_seconds,
)

log = get_logger("detection.backtest")

# Per-query wall-clock bound: a heavy backtest query fails THIS backtest
# (fail-closed), never the API pool (scheduler RULE_QUERY_TIMEOUT pattern).
BACKTEST_QUERY_TIMEOUT_SECONDS = 30

# The compiler itself caps rule lookback at 30d (_timeframe_to_seconds); the
# backtest window is capped identically so a report never scans beyond it.
MAX_BACKTEST_WINDOW_HOURS = 24 * 30

# Top offending values: at most this many selected columns, this many values
# per column, and this many over-threshold buckets fetched for aggregation
# rules (chronological; the estimate is marked truncated if the cap bites).
MAX_TOP_VALUE_COLUMNS = 4
MAX_TOP_VALUES = 5
MAX_TRIGGER_BUCKETS = 500


def _clamp_window_hours(window_hours: int) -> int:
    """Clamp the window to [1, 30d] -- defense in depth on top of the API
    validation (the module is also callable directly)."""
    return max(1, min(window_hours, MAX_BACKTEST_WINDOW_HOURS))


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_selected_columns(detection: dict[str, Any]) -> list[str]:
    """The logs columns a rule's selections name (rule order, deduped,
    capped at MAX_TOP_VALUE_COLUMNS) -- the "top offending values" columns.

    Only columns the production compiler maps (FIELD_MAPPING) survive;
    unknown fields are the compiler's error to raise, not ours to guess.
    """
    columns: list[str] = []
    for key, selection in detection.items():
        if key in ("condition", "timeframe") or not isinstance(selection, dict):
            continue
        for sel_key in selection:
            field = sel_key.split("|")[0].strip()
            column = FIELD_MAPPING.get(field, field)
            if column not in FIELD_MAPPING.values():
                continue
            if column not in columns:
                columns.append(column)
        if len(columns) >= MAX_TOP_VALUE_COLUMNS:
            break
    return columns[:MAX_TOP_VALUE_COLUMNS]


def _replay_dedup(trigger_times: list[datetime], dedup_seconds: int) -> int:
    """Replay create_alert's dedup over trigger timestamps (ascending).

    An alert is created iff the trigger is NOT within dedup_seconds of the
    previous ALERT (the runtime semantic: the window keys on the alert's
    own time, not the last match). Exact given the trigger series; the
    bucketing of aggregation triggers is the only approximation and it is
    labeled per estimate_method.
    """
    alerts = 0
    last_alert: Optional[datetime] = None
    for t in trigger_times:
        if last_alert is None or (t - last_alert).total_seconds() > dedup_seconds:
            alerts += 1
            last_alert = t
    return alerts


async def _fetch(conn, sql: str, params: list[Any]):
    """One bounded read-only fetch: timeout fail-closed, never the API."""
    return await asyncio.wait_for(conn.fetch(sql, *params), timeout=BACKTEST_QUERY_TIMEOUT_SECONDS)


def _compile_rule(sigma_yaml: str):
    """Parse + compile with the PRODUCTION compiler.

    Returns (parser, rule, where, params, aggregation). Raises ValueError
    with a clean message on YAML/grammar failures (the API maps to 400);
    fail-safe compilations (selection -> FALSE) are collected in
    parser.warnings, not raised -- a 0-hit result under warnings is a
    compile artifact the report must surface, not hide.
    """
    parser = SigmaParser()
    try:
        rule = parser.parse(sigma_yaml)
    except Exception as exc:
        raise ValueError(f"Invalid Sigma rule: {exc}") from None
    try:
        where, params, agg = parser.compile_where(rule)
    except ValueError as exc:
        raise ValueError(f"Invalid Sigma rule: {exc}") from None
    return parser, rule, where, params, agg


async def run_backtest(
    sigma_yaml: str,
    window_hours: int = 168,
    rule_id: Optional[int] = None,
    rule_name: Optional[str] = None,
    as_of: Optional[datetime] = None,
) -> dict:
    """Backtest one Sigma rule against the stored logs window (read-only).

    Args:
        sigma_yaml: the rule YAML (a draft, or fetched from the rules table
            by the caller for an existing rule).
        window_hours: lookback window, clamped to [1, 720] (30 days).
        rule_id: when set, the rule exists -- the report gains a calibration
            block (actual alerts + dispositions for the SAME rule).
        rule_name: the rules.name for an existing rule (the alert identity).
        as_of: window end (injectable for tests); default now(UTC).

    Raises:
        ValueError: invalid YAML or a Sigma field/column the compiler rejects.
        RuleNotFound: rule_id given but no such row in the rules table.
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    window_hours = _clamp_window_hours(window_hours)
    window_start = as_of - timedelta(hours=window_hours)

    parser, rule, where, where_params, agg = _compile_rule(sigma_yaml)

    report: dict[str, Any] = {
        "note": (
            "Read-only backtest over the stored logs window. Never persists, "
            "never auto-arms. estimated_alerts replays the "
            f"{DEDUP_WINDOW_SECONDS}s alert-dedup window; suppression rules "
            "and severity escalation are NOT modeled."
        ),
        "rule": {
            "source": "existing" if rule_id is not None else "draft",
            "rule_id": rule_id,
            "rule_name": rule_name,
            "sigma_title": rule.title,
            "description": rule.description,
            "severity": rule.level,
            "mitre_tactics": rule.mitre_tactics,
            "mitre_techniques": rule.mitre_techniques,
        },
        "window": {
            "hours": window_hours,
            "start": _iso(window_start),
            "end": _iso(as_of),
        },
        "compilation": {
            "aggregation": agg is not None,
            "group_by": agg.group_by if agg else None,
            "threshold": agg.threshold if agg else None,
            "timeframe_seconds": _timeframe_to_seconds(rule.timeframe),
            "selected_fields": _extract_selected_columns(rule.detection),
            "warnings": list(parser.warnings),
        },
    }

    pool = await get_pool()
    async with pool.acquire() as conn:
        corpus = await _fetch(
            conn,
            "SELECT COUNT(*) AS n FROM logs "
            "WHERE time > $1::timestamptz AND time <= $2::timestamptz",
            [window_start, as_of],
        )
        logs_in_window = corpus[0]["n"]

        if agg is not None:
            results = await _backtest_aggregation(
                conn,
                where,
                where_params,
                agg,
                rule.timeframe,
                window_start,
                as_of,
                logs_in_window,
            )
        else:
            results = await _backtest_simple(
                conn, where, where_params, rule, window_start, as_of, logs_in_window
            )
        report["results"] = results

        # Honesty gates (sigmaforge pattern): unmeasured beats a fake number.
        unmeasured_reasons: list[str] = []
        if parser.warnings:
            unmeasured_reasons.append(
                "rule compiled fail-safe to FALSE (would match nothing): "
                "the 0-hit result is a compile artifact, not a measurement"
            )
        if logs_in_window == 0:
            unmeasured_reasons.append(
                "no logs in the window: a 0-hit count is indistinguishable from no data"
            )
        if unmeasured_reasons:
            results["measured"] = False
            report["unmeasured_reasons"] = unmeasured_reasons
            report["projected_fp_ratio"] = {
                "measured": False,
                "note": "unmeasured: " + "; ".join(unmeasured_reasons),
            }
        else:
            report["projected_fp_ratio"] = await _fp_projection(conn, rule_id, as_of)

    return report


async def _backtest_simple(
    conn,
    where: str,
    where_params: list[Any],
    rule,
    window_start: datetime,
    window_end: datetime,
    logs_in_window: int,
) -> dict[str, Any]:
    """Simple (non-aggregation) rule: hits, per-day distribution,
    dedup-replay alert estimate, top offending values."""
    # 1. Per-day distribution (its sum is the total hit count).
    p = list(where_params)
    start_idx, end_idx = len(p) + 1, len(p) + 2
    p.extend([window_start, window_end])
    per_day_rows = await _fetch(
        conn,
        f"SELECT date_trunc('day', time) AS day, COUNT(*) AS n FROM logs "  # noqa: S608
        f"WHERE ({where}) AND time > ${start_idx}::timestamptz "
        f"AND time <= ${end_idx}::timestamptz GROUP BY day ORDER BY day",
        p,
    )
    total_rows = sum(r["n"] for r in per_day_rows)

    # 2. Estimated alert volume: island replay of the runtime dedup.
    #    Islands = per-host match runs separated by > dedup window; each
    #    island contributes ceil(span/dedup) alerts (>=1).
    p = list(where_params)
    start_idx, end_idx = len(p) + 1, len(p) + 2
    dedup_idx = len(p) + 3
    p.extend([window_start, window_end, DEDUP_WINDOW_SECONDS])
    est_rows = await _fetch(
        conn,
        f"""
        WITH matched AS (
            SELECT time, host_name FROM logs
            WHERE ({where}) AND time > ${start_idx}::timestamptz
              AND time <= ${end_idx}::timestamptz
        ),
        gapped AS (
            SELECT host_name, time,
                   time - LAG(time) OVER (PARTITION BY host_name ORDER BY time) AS gap
            FROM matched
        ),
        islands AS (
            SELECT host_name, time,
                   SUM(CASE WHEN gap IS NULL OR gap > INTERVAL '1 second' * ${dedup_idx}
                            THEN 1 ELSE 0 END)
                     OVER (PARTITION BY host_name ORDER BY time) AS island
            FROM gapped
        ),
        bursts AS (
            SELECT host_name, island, COUNT(*) AS hits, MIN(time) AS t0, MAX(time) AS t1
            FROM islands GROUP BY host_name, island
        )
        SELECT COUNT(*) AS bursts,
               COUNT(DISTINCT host_name) AS hosts,
               COALESCE(SUM(GREATEST(
                   CEIL(EXTRACT(EPOCH FROM (t1 - t0)) / GREATEST(${dedup_idx}, 1)), 1
               )), 0)::bigint AS est_alerts
        FROM bursts
        """,  # noqa: S608
        p,
    )
    est = est_rows[0]

    # 3. Top offending values per selected column.
    top_values = await _top_values(conn, where, where_params, rule, window_start, window_end)

    return {
        "measured": logs_in_window > 0,
        "total_rows": total_rows,
        "per_day": [{"day": r["day"].strftime("%Y-%m-%d"), "rows": r["n"]} for r in per_day_rows],
        "estimated_alerts": int(est["est_alerts"]) if total_rows else 0,
        "estimate_method": (
            f"island replay of the {DEDUP_WINDOW_SECONDS}s (rule, host) dedup "
            "window: exact for dense match streams, an upper bound for sparse "
            "patterns; suppression and escalation not modeled"
        ),
        "hosts_affected": int(est["hosts"]) if total_rows else 0,
        "top_values": top_values,
    }


async def _top_values(
    conn,
    where: str,
    where_params: list[Any],
    rule,
    window_start: datetime,
    window_end: datetime,
) -> dict[str, list[dict]]:
    """Top-N values per selected column (bounded, read-only)."""
    top: dict[str, list[dict]] = {}
    for column in _extract_selected_columns(rule.detection):
        p = list(where_params)
        start_idx, end_idx = len(p) + 1, len(p) + 2
        limit_idx = len(p) + 3
        p.extend([window_start, window_end, MAX_TOP_VALUES])
        try:
            rows = await _fetch(
                conn,
                f"SELECT {column} AS value, COUNT(*) AS cnt FROM logs "  # noqa: S608
                f"WHERE ({where}) AND time > ${start_idx}::timestamptz "
                f"AND time <= ${end_idx}::timestamptz AND {column} IS NOT NULL "
                f"GROUP BY {column} ORDER BY cnt DESC LIMIT ${limit_idx}",
                p,
            )
        except Exception as exc:  # one grouped scan failing must not kill the run
            log.warning("backtest_top_values_failed", column=column, error=str(exc))
            continue
        top[column] = [{"value": str(r["value"]), "count": r["cnt"]} for r in rows]
    return top


async def _backtest_aggregation(
    conn,
    where: str,
    where_params: list[Any],
    agg,
    timeframe: Optional[str],
    window_start: datetime,
    window_end: datetime,
    logs_in_window: int,
) -> dict[str, Any]:
    """Aggregation (count-by) rule: base matches + bucketed over-threshold
    triggers + a dedup-replay estimate."""
    bucket_seconds = _timeframe_to_seconds(timeframe)

    # 1. Base selection matches in the window (the rows feeding COUNT()).
    p = list(where_params)
    start_idx, end_idx = len(p) + 1, len(p) + 2
    p.extend([window_start, window_end])
    base_rows = await _fetch(
        conn,
        f"SELECT COUNT(*) AS n FROM logs WHERE ({where}) "  # noqa: S608
        f"AND time > ${start_idx}::timestamptz AND time <= ${end_idx}::timestamptz",
        p,
    )
    total_rows = base_rows[0]["n"]

    # 2. Per-day distribution of the base matches.
    p = list(where_params)
    start_idx, end_idx = len(p) + 1, len(p) + 2
    p.extend([window_start, window_end])
    per_day_rows = await _fetch(
        conn,
        f"SELECT date_trunc('day', time) AS day, COUNT(*) AS n FROM logs "  # noqa: S608
        f"WHERE ({where}) AND time > ${start_idx}::timestamptz "
        f"AND time <= ${end_idx}::timestamptz GROUP BY day ORDER BY day",
        p,
    )

    # 3. Over-threshold (bucket, group) pairs: the triggers. Bucketed on the
    # rule's own timeframe (its count() window), chronological, capped.
    p = list(where_params)
    start_idx, end_idx = len(p) + 1, len(p) + 2
    bucket_idx = len(p) + 3
    threshold_idx = len(p) + 4
    limit_idx = len(p) + 5
    p.extend([window_start, window_end, bucket_seconds, agg.threshold, MAX_TRIGGER_BUCKETS])
    bucket_rows = await _fetch(
        conn,
        f"""
        SELECT to_timestamp(FLOOR(EXTRACT(EPOCH FROM time) / ${bucket_idx}) * ${bucket_idx})
                 AS bucket,
               {agg.group_by} AS grp, COUNT(*) AS cnt
        FROM logs
        WHERE ({where}) AND time > ${start_idx}::timestamptz
          AND time <= ${end_idx}::timestamptz
        GROUP BY bucket, {agg.group_by}
        HAVING COUNT(*) > ${threshold_idx}
        ORDER BY bucket ASC
        LIMIT ${limit_idx}
        """,  # noqa: S608
        p,
    )

    # 4. Estimated alerts: the runtime dedup (per rule; host_name collapses
    # to 'unknown' in the aggregation path) replayed over trigger buckets.
    bucket_times = [r["bucket"] for r in bucket_rows]
    estimated = _replay_dedup(bucket_times, DEDUP_WINDOW_SECONDS) if bucket_rows else 0

    # Top offending groups (from the fetched trigger set, capped).
    top_groups: list[dict] = []
    if bucket_rows:
        counts: dict[str, int] = {}
        for r in bucket_rows:
            key = str(r["grp"])
            counts[key] = max(counts.get(key, 0), r["cnt"])
        ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_TOP_VALUES]
        top_groups = [{"value": k, "count": v} for k, v in ordered]

    truncated = len(bucket_rows) == MAX_TRIGGER_BUCKETS

    return {
        "measured": logs_in_window > 0,
        "total_rows": total_rows,
        "per_day": [{"day": r["day"].strftime("%Y-%m-%d"), "rows": r["n"]} for r in per_day_rows],
        "estimated_alerts": estimated,
        "estimate_method": (
            f"over-threshold ({agg.group_by}, {bucket_seconds}s bucket) pairs "
            f"replayed through the {DEDUP_WINDOW_SECONDS}s dedup window (the "
            "runtime aggregation path collapses host_name to 'unknown', so "
            "the dedup key is the rule itself); suppression and escalation "
            "not modeled"
        ),
        "trigger_buckets": [
            {
                "bucket": r["bucket"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "group": str(r["grp"]),
                "count": r["cnt"],
            }
            for r in bucket_rows
        ],
        "trigger_buckets_truncated": truncated,
        "hosts_affected": 0,  # aggregation alerts carry no host at runtime
        "top_values": {agg.group_by: top_groups},
    }


async def _fp_projection(conn, rule_id: Optional[int], as_of: datetime) -> dict[str, Any]:
    """Projected FP ratio from prior dispositions for the SAME rule.

    The sigmaforge honesty gate: when no prior adjudicated alerts exist,
    report unmeasured -- never a fake 0 and never a tautological number.
    Drafts have no prior dispositions by definition.
    """
    if rule_id is None:
        return {
            "measured": False,
            "note": (
                "unmeasured: draft rule has no prior adjudicated alerts -- "
                "re-backtest after arming to calibrate"
            ),
        }
    # Same precedence as the scorecard (documented there):
    # alert_labels > alert status false_positive > case verdict.
    rows = await _fetch(
        conn,
        """
        SELECT COUNT(*) AS alerts_lifetime,
               COUNT(*) FILTER (WHERE time > $2::timestamptz
                                 AND time <= $3::timestamptz) AS alerts_window,
               COUNT(*) FILTER (WHERE d IS NOT NULL) AS dispositions,
               COUNT(*) FILTER (WHERE d = 'false_positive') AS false_positives
        FROM (
            SELECT a.time AS time,
                   COALESCE(
                       l.label,
                       CASE WHEN a.status = 'false_positive' THEN 'false_positive' END,
                       cv.v
                   ) AS d
            FROM alerts a
            LEFT JOIN alert_labels l ON l.alert_id = a.id
            LEFT JOIN LATERAL (
                SELECT ce.payload->>'verdict' AS v
                FROM case_events ce
                WHERE ce.event_type = 'verdict' AND ce.alert_id = a.id
                  AND ce.payload->>'verdict' = ANY($4::text[])
                ORDER BY ce.created_at DESC
                LIMIT 1
            ) cv ON TRUE
            WHERE a.rule_id = $1
        ) x
        """,  # noqa: S608
        [
            rule_id,
            as_of - timedelta(days=365),
            as_of,
            list(_VERDICT_TOKENS),
        ],
    )
    r = rows[0]
    dispositions = r["dispositions"] or 0
    fps = r["false_positives"] or 0
    if dispositions == 0:
        return {
            "measured": False,
            "note": (
                "unmeasured: no adjudicated (labeled/statused/verdicted) alerts for this rule yet"
            ),
        }
    return {
        "measured": True,
        "ratio": fps / dispositions,
        "dispositions": dispositions,
        "false_positives": fps,
        "actual_alerts_lifetime": r["alerts_lifetime"] or 0,
        "actual_alerts_window": r["alerts_window"] or 0,
        "basis": "lifetime dispositions for this rule (labels > status-fp > case verdict)",
    }
