"""UEBA-ready posture outliers (V0.7 delta fix -- the plan's V0.7 item 1).

HONEST SCOPE: per-window statistical outliers computed READ-ONLY from
existing tables (alerts, logs). This is the "UEBA-ready" half the plan
asked for: it is buildable today because it needs NO UEBA state -- the
statistics are self-contained inside the reporting window (robust
median/MAD z-scores over per-entity counts, minimum entity floor, empty +
explained when variance or population is too small to mean anything).

Why robust (median/MAD), not mean + 2*stddev: on a small fleet (2-5 hosts
-- this deployment) a single noisy host inflates BOTH the mean and the
stddev of its own baseline; with n entities the maximum achievable z-score
against mean/stddev is (n-1)/sqrt(n) -- below 2.0 for every n < 9, so the
classic rule can mathematically NEVER fire on a small fleet. The Iglewicz
& Hoberg robust z (0.6745*(x-median)/MAD, threshold 3.5) stays meaningful
at n=3. Documented, not hidden.

What this is NOT: behavioral baselines. Anything requiring state that
persists between runs (per-user process-frequency norms, host routines) is
UEBA (V0.8+ backlog, customer-gated) and stays out of scope here. A V0.8
UEBA engine supersedes this view's statistics with baselines; the view's
shape (per-entity outliers with the method stated) is the part that
survives.

Fail-closed honesty: the report NEVER pretends. Too few hosts -> empty
list + baseline None; a distribution flat around its median -> empty list
+ the flat spread stated. A flat fleet has no outliers -- saying so is
the feature.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from statistics import median
from typing import Any

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("compliance.outliers")

# Statistical gates: below MIN_ENTITIES an outlier verdict is noise (with
# 1-2 entities every entity is trivially "unusual"); a distribution flat
# around its median (MAD = 0) has no computable outliers.
MIN_ENTITIES = 3
# Iglewicz & Hoberg robust z-score threshold (the standard 3.5 -- the
# classic mean/stddev rule cannot fire at all on small fleets, see the
# module docstring).
ROBUST_Z_THRESHOLD = 3.5
# Auth-failure outliers additionally need a floor: 1-2 failures in a window
# is noise on any fleet, not an anomaly worth surfacing.
MIN_AUTH_FAILURES_TOTAL = 5


def _median_value(values: Sequence[float]) -> float:
    """Median of a non-empty numeric list (int or float entries)."""
    return float(median(values))


def _robust_outliers(
    counts: list[tuple[str, int]],
    *,
    min_total: int = 0,
) -> tuple[list[dict], dict | None]:
    """Pure: flag entities with a robust z above ROBUST_Z_THRESHOLD.

    Robust z (Iglewicz & Hoberg): 0.6745 * (x - median) / MAD. Unlike
    mean/stddev this stays meaningful on small populations (n = 3+), which
    this deployment is. Returns (outliers, baseline). baseline is None when
    the population is too small -- the honest "not computable" signal; a
    MAD of 0 (flat spread around the median) yields outliers=[] with the
    baseline stating the flat spread. Never fabricated numbers.
    """
    if len(counts) < MIN_ENTITIES:
        return [], None
    values = [c for _, c in counts]
    total = sum(values)
    if total < min_total:
        return [], None
    med = _median_value(values)
    mad = _median_value([abs(v - med) for v in values])
    baseline = {
        "entities": len(counts),
        "total": total,
        "median": round(med, 3),
        "mad": round(mad, 3),
        "method": (
            "robust z (Iglewicz & Hoberg: 0.6745*(x-median)/MAD) > "
            f"{ROBUST_Z_THRESHOLD:g} within the reporting window"
        ),
    }
    if mad == 0:
        return [], baseline  # flat spread around the median: state it
    outliers = [
        {
            "entity": name,
            "count": count,
            "robust_z": round(0.6745 * (count - med) / mad, 2),
        }
        for name, count in sorted(counts, key=lambda kv: kv[1], reverse=True)
        if abs(0.6745 * (count - med) / mad) > ROBUST_Z_THRESHOLD
    ]
    return outliers, baseline


def _entity_outlier_view(outliers: list[dict], baseline: dict | None) -> dict:
    """Stable per-view shape: outliers always a list; baseline carries the
    honest not-computable reason when the statistics had nothing to say."""
    if baseline is None:
        return {
            "outliers": outliers,
            "baseline": None,
            "note": (
                f"fewer than {MIN_ENTITIES} entities with activity in the "
                "window -- outlier statistics not meaningful"
            ),
        }
    return {"outliers": outliers, "baseline": baseline}


async def compute_posture_outliers(window_hours: int, as_of: datetime | None = None) -> dict:
    """Per-window outliers, read-only: host alert-volume + user auth-failure.

    Both statistics run on tables that already exist (alerts, logs); no
    new tables, no baseline state, no writes. The zero-shape guarantee:
    every key is always present, even on an empty fleet.
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    pool = await get_pool()
    async with pool.acquire() as conn:
        host_rows = await conn.fetch(
            """
            SELECT host_name, COUNT(*) AS alert_count
            FROM alerts
            WHERE time > $1::timestamptz
            GROUP BY host_name
            """,
            as_of,
        )
        auth_rows = await conn.fetch(
            """
            SELECT user_name, COUNT(*) AS fail_count
            FROM logs
            WHERE event_category = 'authentication'
              AND event_action = 'auth_failed'
              AND user_name IS NOT NULL
              AND time > $1::timestamptz
            GROUP BY user_name
            """,
            as_of,
        )

    host_counts = [(r["host_name"], int(r["alert_count"])) for r in host_rows]
    user_counts = [(r["user_name"], int(r["fail_count"])) for r in auth_rows]

    host_outliers, host_baseline = _robust_outliers(host_counts)
    auth_outliers, auth_baseline = _robust_outliers(user_counts, min_total=MIN_AUTH_FAILURES_TOTAL)

    result: dict[str, Any] = {
        "window_hours": window_hours,
        "methodology": {
            "name": "per-window statistical outliers (UEBA-ready)",
            "description": (
                "Naive self-contained statistics over the reporting window: "
                "per-host alert volume and per-user auth-failure volume "
                "flagged by robust median/MAD z-scores of the window's own "
                "population. READ-ONLY from alerts/logs; no persisted "
                "baselines."
            ),
            "ueba_note": (
                "Behavioral baselines that persist across windows are UEBA "
                "(V0.8+ backlog, customer-gated); they supersede these "
                "per-window statistics, not this view's shape."
            ),
        },
        "host_alert_outliers": _entity_outlier_view(host_outliers, host_baseline),
        "auth_failure_user_outliers": _entity_outlier_view(auth_outliers, auth_baseline),
    }
    log.debug(
        "posture_outliers_computed",
        window_hours=window_hours,
        host_outliers=len(host_outliers),
        auth_outliers=len(auth_outliers),
    )
    return result
