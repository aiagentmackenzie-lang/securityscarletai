"""
Generate synthetic labeled alert training data for the triage model.

Produces a stratified CSV of synthetic alerts with feature columns matching
AlertTriageModel.FEATURES plus a `label` column (`true_positive` /
`false_positive`).

Why a separate generator:
- `scripts/generate_attack_data.py` emits raw osquery event dicts for
  ingestion/detection rule testing. Different purpose, different shape.
- The triage model trains on engineered alert features, not raw events.
- The brief (Epic 3) requires a 1000-row stratified synthetic dataset that
  is reproducible (fixed seed) and CI-runnable without a real database.

Usage:
    python -m scripts.generate_training_data --output data/training/alerts_v3.csv
    python -m scripts.generate_training_data --n 500 --seed 7 --output /tmp/x.csv
"""
from __future__ import annotations

import argparse
import csv
import math
import random
import sys
from pathlib import Path

# Feature column order MUST match AlertTriageModel.FEATURES in src/ai/alert_triage.py.
FEATURE_COLUMNS = [
    "severity_score",          # 0-1 based on severity
    "hour_of_day",             # Normalized hour (0-1)
    "rule_hit_count",          # How often this rule fires
    "host_alert_count",        # Host's historical alert count
    "asset_risk_score",        # Host risk score
    "mitre_count",             # Number of MITRE techniques
    "time_since_last_hours",   # Hours since last similar alert
    "has_threat_intel",        # Boolean: TI match
    "command_entropy",         # Shannon entropy of recent process names
    "session_duration_hours",  # Duration of user session
    "login_hour_deviation",    # Deviation from normal login hour
]

LABEL_COLUMN = "label"
ALERT_ID_COLUMN = "alert_id"

LABEL_TP = "true_positive"
LABEL_FP = "false_positive"

# Plausible ranges — kept inside [0, 1] for the three normalized features the
# model itself uses; other features stored in their raw normalized form to
# match what extract_features() would compute on a real alert.
SEVERITY_BANDS = ("critical", "high", "medium", "low", "info")
SEVERITY_SCORE_MAP = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.0,
}


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _tp_profile(rng: random.Random) -> dict:
    """Profile for true-positive alerts: high signal across most features."""
    severity = rng.choices(
        population=list(SEVERITY_BANDS),
        weights=[0.20, 0.35, 0.25, 0.15, 0.05],
        k=1,
    )[0]
    return {
        # Higher severity score
        "severity_score": SEVERITY_SCORE_MAP[severity],
        # Off-hours more likely (but not always)
        "hour_of_day": rng.choice([rng.uniform(0.0, 0.2), rng.uniform(0.7, 0.95)]),
        # Rarely-firing rule (specific)
        "rule_hit_count": _clamp(rng.betavariate(2, 8)),
        # Host has fewer prior alerts (not a noisy asset)
        "host_alert_count": _clamp(rng.betavariate(2, 6)),
        # High-value host
        "asset_risk_score": _clamp(rng.betavariate(8, 3)),
        # More MITRE techniques
        "mitre_count": _clamp(rng.uniform(0.4, 1.0)),
        # Recently-seen
        "time_since_last_hours": _clamp(rng.betavariate(2, 5)),
        # Threat intel present most of the time
        "has_threat_intel": 1.0 if rng.random() < 0.75 else 0.0,
        # Diverse (possibly malicious) command set
        "command_entropy": _clamp(rng.betavariate(5, 2)),
        # Anomalous session length
        "session_duration_hours": _clamp(rng.uniform(0.1, 1.0)),
        # Off-pattern login time
        "login_hour_deviation": _clamp(rng.betavariate(5, 2)),
    }


def _fp_profile(rng: random.Random) -> dict:
    """Profile for false-positives: low signal, noisy or routine."""
    severity = rng.choices(
        population=list(SEVERITY_BANDS),
        weights=[0.02, 0.08, 0.30, 0.45, 0.15],
        k=1,
    )[0]
    return {
        "severity_score": SEVERITY_SCORE_MAP[severity],
        # Business hours
        "hour_of_day": _clamp(rng.gauss(0.45, 0.08)),
        # Noisy rule (fires constantly)
        "rule_hit_count": _clamp(rng.betavariate(8, 2)),
        # Noisy host
        "host_alert_count": _clamp(rng.betavariate(7, 2)),
        # Low-value host
        "asset_risk_score": _clamp(rng.betavariate(2, 5)),
        # Few MITRE techniques
        "mitre_count": _clamp(rng.betavariate(2, 6)),
        # Either very recent (auto-fire) or ancient (stale rule)
        "time_since_last_hours": rng.choice([
            _clamp(rng.betavariate(8, 2)),    # very recent
            _clamp(rng.uniform(0.7, 1.0)),   # old
        ]),
        # No threat intel
        "has_threat_intel": 1.0 if rng.random() < 0.05 else 0.0,
        # Boring, repetitive command set
        "command_entropy": _clamp(rng.betavariate(2, 5)),
        # Standard session length
        "session_duration_hours": _clamp(rng.betavariate(3, 3)),
        # Normal login time
        "login_hour_deviation": _clamp(rng.betavariate(2, 5)),
    }


def _generate_rows(n: int, seed: int) -> list[dict]:
    """Generate n stratified rows, half TP / half FP, deterministic by seed."""
    if n < 2:
        raise ValueError(f"n must be >= 2, got {n}")
    if n % 2 != 0:
        # Round up to even, then truncate — keeps stratification simple.
        n_pairs = n // 2 + 1
    else:
        n_pairs = n // 2

    rng = random.Random(seed)  # noqa: S311 — reproducible test data, not crypto
    rows: list[dict] = []
    for _i in range(n_pairs):
        for label, profile_fn in ((LABEL_TP, _tp_profile), (LABEL_FP, _fp_profile)):
            if len(rows) >= n:
                break
            row = profile_fn(rng)
            row[ALERT_ID_COLUMN] = len(rows) + 1
            row[LABEL_COLUMN] = label
            rows.append(row)
    return rows


def _validate_rows(rows: list[dict], expected_n: int) -> None:
    """Sanity-check the generated data. Raises ValueError on any defect."""
    if len(rows) != expected_n:
        raise ValueError(f"expected {expected_n} rows, got {len(rows)}")

    label_counts: dict[str, int] = {LABEL_TP: 0, LABEL_FP: 0}
    required_cols = set(FEATURE_COLUMNS + [LABEL_COLUMN, ALERT_ID_COLUMN])

    for i, row in enumerate(rows):
        missing = required_cols - set(row.keys())
        if missing:
            raise ValueError(f"row {i} missing columns: {sorted(missing)}")
        extra = set(row.keys()) - required_cols
        if extra:
            raise ValueError(f"row {i} has unexpected columns: {sorted(extra)}")

        for col in FEATURE_COLUMNS:
            v = row[col]
            if not isinstance(v, (int, float)):
                raise ValueError(f"row {i} col {col} not numeric: {v!r}")
            if math.isnan(v) or math.isinf(v):
                raise ValueError(f"row {i} col {col} not finite: {v}")
            if not (0.0 <= v <= 1.0):
                raise ValueError(f"row {i} col {col} out of [0,1]: {v}")

        if row[LABEL_COLUMN] not in label_counts:
            raise ValueError(f"row {i} has invalid label: {row[LABEL_COLUMN]!r}")
        label_counts[row[LABEL_COLUMN]] += 1

    # Stratification: 50/50 ±2 percentage points.
    expected = expected_n / 2
    for label, count in label_counts.items():
        drift = abs(count - expected) / expected
        if drift > 0.02:
            raise ValueError(
                f"label {label} drifted from 50/50: got {count}/{expected_n} "
                f"({drift:.1%} off)"
            )

    # IDs must be unique and dense.
    ids = [row[ALERT_ID_COLUMN] for row in rows]
    if sorted(ids) != list(range(1, expected_n + 1)):
        raise ValueError("alert_id is not a dense 1..N sequence")


def write_csv(rows: list[dict], output_path: Path) -> None:
    """Write rows to CSV in canonical column order."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [ALERT_ID_COLUMN] + FEATURE_COLUMNS + [LABEL_COLUMN]
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate stratified synthetic alert training data for triage model.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/training/alerts_v3.csv"),
        help="Output CSV path (default: data/training/alerts_v3.csv)",
    )
    parser.add_argument(
        "--n",
        type=int,
        default=1000,
        help="Total number of rows (default: 1000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip post-generation validation (not recommended).",
    )
    args = parser.parse_args(argv)

    if args.n < 2:
        print(f"error: --n must be >= 2, got {args.n}", file=sys.stderr)
        return 2

    rows = _generate_rows(args.n, args.seed)

    if not args.no_validate:
        _validate_rows(rows, args.n)

    write_csv(rows, args.output)

    tp = sum(1 for r in rows if r[LABEL_COLUMN] == LABEL_TP)
    fp = sum(1 for r in rows if r[LABEL_COLUMN] == LABEL_FP)
    print(
        f"wrote {len(rows)} rows to {args.output} "
        f"(tp={tp}, fp={fp}, seed={args.seed})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
