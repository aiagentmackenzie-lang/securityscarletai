"""Rule lifecycle scorecard (V0.7b -- the detection-engineering loop).

The industry maturity bar (detection engineering as software): every rule
is OWNED, MEASURED (fire rate, true/false-positive rate, last-fired, age),
and RETIRABLE. The raw material already existed in the SIEM's own tables --
HITL dispositions (alert_labels, alert status, case verdicts) + the rules
table's match counters -- this module folds it into per-rule lifecycle
metrics and a RETIREMENT REPORT.

Doctrine (least-agency, matches V0.4/V0.4/5):
- READ-ONLY. No auto-tuning, no auto-suppression, no auto-retirement.
- The retirement report is ADVICE for the operator. Retiring a rule is a
  HITL decision (POST /rules/{id} enabled=false by the operator, audited).

Metric semantics (documented, not conflated):
- rules.match_count = MATCHER ROW HITS (the Sigma query matched N log rows
  across runs) -- NOT alerts. It answers "does the matcher see anything",
  not "how many alerts did the analyst see".
- alerts counts (lifetime + window) = ALERTS the analyst sees.
- Dispositions per alert use a DOCUMENTED precedence:
  alert_labels (the dedicated human ground-truth table, one per alert)
  > alert status 'false_positive' (the quick operational mark)
  > case verdict events (the governed adjudication, linked via
    case_events.alert_id).
- fp_ratio = false_positives / dispositions (None when no dispositions).
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("detection.scorecard")

# Retirement advice thresholds (advisory only).
RETIREMENT_MIN_AGE_DAYS = 30
RETIREMENT_MIN_DISPOSITIONS = 5

# Case-verdict tokens that count as a TRUE-POSITIVE disposition for the
# FP ratio (needs_review and benign are non-terminal for the ratio; benign
# counts toward DISPOSITIONS but not the FP ratio -- a benign case verdict
# is neither a confirmed true positive nor a false positive).
_VERDICT_TOKENS = ("true_positive", "false_positive", "benign", "needs_review")


async def _fetch_fires_and_dispositions(
    conn, as_of: datetime, window_start: datetime
) -> tuple[dict[int, dict], dict[str, dict]]:
    """One grouped query per alert kind (sigma rule_id / correlation name).

    Per-alert disposition = COALESCE(alert label, status false_positive,
    latest case verdict) -- the documented precedence. Both metrics come
    from the same grouped scan; no per-rule queries.
    """
    sql = """
    SELECT
        {key}                                   AS rule_key,
        COUNT(*)                                AS lifetime_fires,
        COUNT(*) FILTER (WHERE a.time > $1::timestamptz) AS window_fires,
        MAX(a.time)                             AS last_fired,
        COUNT(*) FILTER (WHERE d IS NOT NULL)   AS dispositions,
        COUNT(*) FILTER (WHERE d = 'true_positive')      AS true_positives,
        COUNT(*) FILTER (WHERE d = 'false_positive')     AS false_positives,
        COUNT(*) FILTER (WHERE d = 'benign')             AS benign,
        COUNT(*) FILTER (WHERE d = 'needs_review')       AS needs_review
    FROM (
        SELECT
            a.{key} AS {key},
            a.time AS time,
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
              AND ce.payload->>'verdict' = ANY($3::text[])
            ORDER BY ce.created_at DESC
            LIMIT 1
        ) cv ON TRUE
        WHERE {where}
    ) a
    GROUP BY rule_key
    """
    sigma_sql = sql.format(
        key="rule_id",
        where="a.rule_id IS NOT NULL",
    )
    corr_sql = sql.format(
        key="rule_name",
        where="a.rule_id IS NULL AND a.rule_name IS NOT NULL",
    )
    window_rows = await conn.fetch(sigma_sql, as_of, window_start, list(_VERDICT_TOKENS))
    corr_rows = await conn.fetch(corr_sql, as_of, window_start, list(_VERDICT_TOKENS))
    return _group_metrics(window_rows, by="rule_key"), _group_metrics(corr_rows, by="rule_key")


def _row_to_metrics(row) -> dict:
    d = dict(row)
    dispositions = d["dispositions"] or 0
    fp = d["false_positives"] or 0
    tp = d["true_positives"] or 0
    return {
        "lifetime_fires": d["lifetime_fires"] or 0,
        "window_fires": d["window_fires"] or 0,
        "last_fired": d["last_fired"].isoformat() if d["last_fired"] else None,
        "dispositions": dispositions,
        "true_positives": tp,
        "false_positives": fp,
        "benign": d["benign"] or 0,
        "needs_review": d["needs_review"] or 0,
        "fp_ratio": (fp / dispositions) if dispositions else None,
    }


def _zero_metrics() -> dict:
    """Stable zero-shape for rules with no alert history (API consumers get
    every metric key on every rule, never a missing key)."""
    return {
        "lifetime_fires": 0,
        "window_fires": 0,
        "last_fired": None,
        "dispositions": 0,
        "true_positives": 0,
        "false_positives": 0,
        "benign": 0,
        "needs_review": 0,
        "fp_ratio": None,
    }


def _group_metrics(rows, by: str) -> dict[Any, dict]:
    """Grouped metric rows keyed by their rule_key (rule_id or rule_name)."""
    return {row["rule_key"]: _row_to_metrics(row) for row in rows}


async def compute_rule_scorecard(window_hours: int = 720, as_of: Optional[datetime] = None) -> dict:
    """Per-rule lifecycle metrics + retirement advice (read-only).

    Returns {"summary": {...}, "rules": [...], "retirement_advice": [...]}.
    Covers BOTH rule kinds: Sigma rules (by id) and correlation chains
    (by rule_name on correlation-origin alerts).
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    window_start = as_of - timedelta(hours=window_hours)

    pool = await get_pool()
    async with pool.acquire() as conn:
        # Sigma rules -- the registry (runtime truth, reconciled from disk).
        rule_rows = await conn.fetch(
            """
            SELECT id, name, severity, mitre_techniques, enabled,
                   match_count, last_match, last_run, created_at
            FROM rules
            ORDER BY id
            """
        )
        sigma_metrics, corr_metrics = await _fetch_fires_and_dispositions(conn, as_of, window_start)

    output_rules: list[dict] = []
    for row in rule_rows:
        m = sigma_metrics.get(row["id"]) or _zero_metrics()
        age_days = max((as_of - row["created_at"]).days, 0) if row["created_at"] else None
        entry = {
            "kind": "sigma",
            "id": row["id"],
            "name": row["name"],
            "severity": row["severity"],
            "enabled": row["enabled"],
            "mitre_techniques": row["mitre_techniques"] or [],
            "age_days": age_days,
            # rules.match_count = MATCHER ROW HITS across runs (documented
            # distinction: a rule can match rows the scheduler already
            # deduped away before an alert was created).
            "matcher_hits_lifetime": row["match_count"] or 0,
            "last_match": row["last_match"].isoformat() if row["last_match"] else None,
            "last_run": row["last_run"].isoformat() if row["last_run"] else None,
            **m,
        }
        entry["retirement_candidates"] = _retirement_reasons(entry, window_start)
        output_rules.append(entry)

    for rule_name, m in corr_metrics.items():
        entry = {
            "kind": "correlation",
            "id": None,
            "name": rule_name,
            "enabled": True,  # chains are code-defined, always on
            **m,
        }
        entry["retirement_candidates"] = _retirement_reasons(entry, window_start)
        output_rules.append(entry)

    # Ordering: kind, then window fires desc, then name -- stable for the
    # snapshot regression test and the dashboard table.
    output_rules.sort(key=lambda r: (r["kind"], -(r["window_fires"] or 0), r["name"]))

    dispositions_total = sum(r["dispositions"] or 0 for r in output_rules)
    fp_total = sum(r["false_positives"] or 0 for r in output_rules)
    advice = [r for r in output_rules if r["retirement_candidates"]]
    return {
        "summary": {
            "total_rules": len(output_rules),
            "sigma_rules": sum(1 for r in output_rules if r["kind"] == "sigma"),
            "correlation_chains": sum(1 for r in output_rules if r["kind"] == "correlation"),
            "dispositions_total": dispositions_total,
            "false_positives_total": fp_total,
            "retirement_candidates": len(advice),
            "window_hours": window_hours,
            "as_of": as_of.isoformat(),
            "note": (
                "rules.match_count is MATCHER ROW HITS, not alerts; "
                "dispositions use precedence alert_labels > alert status "
                "false_positive > case verdict; retirement advice is "
                "advisory only (HITL), never automatic"
            ),
        },
        "rules": output_rules,
        "retirement_advice": [
            {
                "name": r["name"],
                "kind": r["kind"],
                "reasons": r["retirement_candidates"],
            }
            for r in advice
        ],
    }


def _retirement_reasons(entry: dict, window_start: datetime) -> list[dict]:
    """Why a rule is a retirement candidate -- ADVICE ONLY, never auto-deleted."""
    reasons: list[dict] = []
    age = entry.get("age_days")
    lifetime = entry["lifetime_fires"] or 0
    matcher = entry.get("matcher_hits_lifetime") or 0
    dispositions = entry["dispositions"] or 0
    fp = entry["false_positives"] or 0

    if (
        entry["kind"] == "sigma"
        and age is not None
        and age >= RETIREMENT_MIN_AGE_DAYS
        and lifetime == 0
        and matcher == 0
    ):
        reasons.append(
            {
                "reason": "never_fired",
                "detail": (
                    f"no alerts and no matcher hits in its {age}-day lifetime "
                    "-- the selection may be dead (wrong vocabulary/shape)"
                ),
            }
        )

    last_fired = entry.get("last_fired")
    if lifetime > 0 and last_fired is not None:
        fired_at = datetime.fromisoformat(last_fired)
        if fired_at < window_start:
            reasons.append(
                {
                    "reason": "stale",
                    "detail": (
                        f"has not fired since {last_fired} -- outside the "
                        "scorecard window; verify the telemetry source still exists"
                    ),
                }
            )

    if dispositions >= RETIREMENT_MIN_DISPOSITIONS and fp == dispositions:
        reasons.append(
            {
                "reason": "all_false_positive",
                "detail": (
                    f"every disposition ({dispositions}) was a false positive "
                    "-- tighten the selection or retire"
                ),
            }
        )

    return reasons
