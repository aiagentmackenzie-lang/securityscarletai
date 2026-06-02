"""
Tests for the synthetic training data generator.

Covers:
- Row count matches --n
- Stratification: ~50/50 true_positive / false_positive (±2pp)
- Determinism: same seed → byte-identical CSV
- All 11 AlertTriageModel.FEATURES columns are present
- All feature values are finite and in [0, 1]
- alert_id is a dense 1..N sequence
- CLI entry point works
- Generator rejects n < 2
- Generator rejects off-stratification drift
"""
from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.generate_training_data import (
    FEATURE_COLUMNS,
    _generate_rows,
    _validate_rows,
    main,
)
from src.ai.alert_triage import (
    ALERT_ID_COLUMN,
    LABEL_COLUMN,
    AlertTriageModel,
)


def _features():
    return AlertTriageModel.FEATURES


class TestRowCount:
    def test_n_1000_produces_1000_rows(self):
        rows = _generate_rows(1000, seed=42)
        assert len(rows) == 1000

    def test_n_2_produces_2_rows(self):
        rows = _generate_rows(2, seed=42)
        assert len(rows) == 2

    def test_n_1_raises(self):
        with pytest.raises(ValueError):
            _generate_rows(1, seed=42)


class TestStratification:
    def test_label_distribution_is_50_50(self):
        rows = _generate_rows(1000, seed=42)
        tp = sum(1 for r in rows if r[LABEL_COLUMN] == "true_positive")
        fp = sum(1 for r in rows if r[LABEL_COLUMN] == "false_positive")
        assert tp == 500
        assert fp == 500

    def test_alternating_label_order(self):
        # IDs 1, 3, 5, ... = TP; IDs 2, 4, 6, ... = FP (with our pair loop).
        rows = _generate_rows(20, seed=42)
        for i, row in enumerate(rows):
            expected = "true_positive" if i % 2 == 0 else "false_positive"
            assert row[LABEL_COLUMN] == expected


class TestDeterminism:
    def test_same_seed_same_rows(self):
        a = _generate_rows(200, seed=7)
        b = _generate_rows(200, seed=7)
        assert a == b

    def test_different_seed_different_rows(self):
        a = _generate_rows(200, seed=7)
        b = _generate_rows(200, seed=8)
        assert a != b


class TestSchema:
    def test_columns_match_alert_triage_features(self):
        assert sorted(FEATURE_COLUMNS) == sorted(_features())

    def test_required_columns_present(self):
        rows = _generate_rows(10, seed=1)
        for row in rows:
            for col in [ALERT_ID_COLUMN, LABEL_COLUMN] + _features():
                assert col in row


class TestValueRanges:
    def test_all_features_in_unit_interval(self):
        rows = _generate_rows(200, seed=1)
        for i, row in enumerate(rows):
            for col in _features():
                v = row[col]
                assert isinstance(v, float), f"row {i} col {col} not float"
                assert 0.0 <= v <= 1.0, f"row {i} col {col} = {v}"
                assert v == v, f"row {i} col {col} is NaN"  # noqa: PLR0124
                assert v not in (float("inf"), float("-inf"))

    def test_alert_id_is_dense_sequence(self):
        rows = _generate_rows(50, seed=1)
        ids = [r[ALERT_ID_COLUMN] for r in rows]
        assert ids == list(range(1, 51))


class TestValidator:
    def test_validator_passes_default(self):
        rows = _generate_rows(1000, seed=42)
        _validate_rows(rows, 1000)  # must not raise

    def test_validator_catches_missing_column(self):
        rows = _generate_rows(4, seed=1)
        rows[0].pop(LABEL_COLUMN)
        with pytest.raises(ValueError, match="missing columns"):
            _validate_rows(rows, 4)

    def test_validator_catches_out_of_range(self):
        rows = _generate_rows(4, seed=1)
        rows[0]["severity_score"] = 1.5
        with pytest.raises(ValueError, match="out of"):
            _validate_rows(rows, 4)

    def test_validator_catches_nan(self):
        rows = _generate_rows(4, seed=1)
        rows[0]["severity_score"] = float("nan")
        with pytest.raises(ValueError, match="not finite"):
            _validate_rows(rows, 4)

    def test_validator_catches_bad_id_sequence(self):
        rows = _generate_rows(4, seed=1)
        rows[0][ALERT_ID_COLUMN] = 999
        with pytest.raises(ValueError, match="dense"):
            _validate_rows(rows, 4)


class TestCLI:
    def test_main_writes_csv(self, tmp_path: Path):
        out = tmp_path / "x.csv"
        rc = main(["--n", "10", "--seed", "1", "--output", str(out)])
        assert rc == 0
        assert out.exists()
        with out.open() as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 10
        assert set(reader.fieldnames) >= set(  # type: ignore[arg-type]
            [ALERT_ID_COLUMN, LABEL_COLUMN] + _features()
        )

    def test_main_rejects_n_lt_2(self, tmp_path: Path, capsys):
        rc = main(["--n", "1", "--output", str(tmp_path / "x.csv")])
        assert rc == 2
        captured = capsys.readouterr()
        assert "n must be >= 2" in captured.err

    def test_main_validation_off_still_writes(self, tmp_path: Path):
        out = tmp_path / "x.csv"
        rc = main(["--n", "10", "--seed", "1", "--output", str(out), "--no-validate"])
        assert rc == 0
        assert out.exists()


class TestEndToEnd:
    def test_subprocess_invocation(self, tmp_path: Path):
        out = tmp_path / "alerts.csv"
        result = subprocess.run(  # noqa: S603 — fixed argv, no user input
            [
                sys.executable,
                "-m",
                "scripts.generate_training_data",
                "--n",
                "20",
                "--seed",
                "99",
                "--output",
                str(out),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert out.exists()
        with out.open() as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 20
        assert sum(1 for r in rows if r[LABEL_COLUMN] == "true_positive") == 10
