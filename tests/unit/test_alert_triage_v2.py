"""
Tests for the V2 (Epic 3) calibrated triage retrain pipeline.

Covers:
- train_v2() on a well-separated synthetic CSV → accepted, persisted
- train_v2() on noisy data → below threshold, not persisted, no model swap
- train_v2() with missing CSV → ok=False, reason=csv_not_found
- train_v2() with empty/invalid CSV → ok=False, reason=csv_invalid
- _load_training_data() returns correct shapes and class distribution
- _db_reachable() returns False when no DB is listening
- latest_provenance() returns None when DB is unavailable
- New model_type string is the calibrated wrapper description
- fold_accuracies is a list of 5 floats
- Persisted model_path is non-None only on accept
"""
from __future__ import annotations

import math
import random
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

from src.ai.alert_triage import (
    ALERT_ID_COLUMN,
    LABEL_COLUMN,
    MIN_CV_ACCURACY,
    AlertTriageModel,
    _db_reachable,
    _load_training_data,
)

# ──────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────


@pytest.fixture
def good_csv(tmp_path: Path) -> Path:
    """A small, well-separated 100-row CSV (50 TP / 50 FP) with a clear signal."""
    from scripts.generate_training_data import _generate_rows, write_csv

    rows = _generate_rows(n=100, seed=42)
    out = tmp_path / "good.csv"
    write_csv(rows, out)
    return out


@pytest.fixture
def noisy_csv(tmp_path: Path) -> Path:
    """A 200-row CSV with random feature values — classification should fail."""
    rng = random.Random(0)  # noqa: S311 — noisy test data, not crypto
    rows = []
    for i in range(200):
        rows.append(
            {
                ALERT_ID_COLUMN: i + 1,
                "severity_score": rng.random(),
                "hour_of_day": rng.random(),
                "rule_hit_count": rng.random(),
                "host_alert_count": rng.random(),
                "asset_risk_score": rng.random(),
                "mitre_count": rng.random(),
                "time_since_last_hours": rng.random(),
                "has_threat_intel": rng.random(),
                "command_entropy": rng.random(),
                "session_duration_hours": rng.random(),
                "login_hour_deviation": rng.random(),
                LABEL_COLUMN: "true_positive" if i < 100 else "false_positive",
            }
        )
    out = tmp_path / "noisy.csv"
    import csv as _csv

    with out.open("w", newline="") as f:
        writer = _csv.DictWriter(
            f,
            fieldnames=[ALERT_ID_COLUMN]
            + AlertTriageModel.FEATURES
            + [LABEL_COLUMN],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return out


@pytest.fixture
def empty_csv(tmp_path: Path) -> Path:
    out = tmp_path / "empty.csv"
    out.write_text(
        "alert_id," + ",".join(AlertTriageModel.FEATURES) + ",label\n"
    )
    return out


# ──────────────────────────────────────────────────────────
# CSV loader
# ──────────────────────────────────────────────────────────


class TestLoadTrainingData:
    def test_shapes(self, good_csv: Path):
        X, y, meta = _load_training_data(good_csv)
        assert X.shape == (100, 11)
        assert y.shape == (100,)
        assert len(meta) == 100

    def test_class_balance(self, good_csv: Path):
        X, y, _ = _load_training_data(good_csv)
        unique, counts = np.unique(y, return_counts=True)
        assert dict(zip(unique.tolist(), counts.tolist(), strict=False)) == {0: 50, 1: 50}

    def test_features_in_correct_order(self, good_csv: Path):
        X, _, _ = _load_training_data(good_csv)
        # First feature is severity_score; in our TP profile it's typically > 0.2
        # and varies. We just verify the column is finite and in [0,1].
        col = X[:, 0]
        assert np.all((col >= 0.0) & (col <= 1.0))
        assert np.all(np.isfinite(col))

    def test_meta_contains_alert_id_and_label(self, good_csv: Path):
        _, _, meta = _load_training_data(good_csv)
        for entry in meta:
            assert ALERT_ID_COLUMN in entry
            assert LABEL_COLUMN in entry
            assert isinstance(entry[ALERT_ID_COLUMN], int)

    def test_empty_csv_raises(self, empty_csv: Path):
        with pytest.raises(ValueError, match="empty"):
            _load_training_data(empty_csv)

    def test_missing_columns_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.csv"
        bad.write_text("foo,bar\n1,2\n")
        with pytest.raises(ValueError, match="missing required columns"):
            _load_training_data(bad)


# ──────────────────────────────────────────────────────────
# DB reachability probe
# ──────────────────────────────────────────────────────────


class TestDbReachable:
    def test_returns_bool(self):
        result = _db_reachable()
        assert isinstance(result, bool)

    def test_does_not_raise_on_bad_host(self):
        # Should always return False, never raise.
        assert _db_reachable(host="this-host-does-not-exist.invalid", port=1) is False


# ──────────────────────────────────────────────────────────
# train_v2 — happy path
# ──────────────────────────────────────────────────────────


class TestTrainV2Accepted:
    @pytest.mark.asyncio
    async def test_well_separated_data_accepted(self, good_csv: Path, tmp_path: Path):
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=good_csv)

        assert result["ok"] is True
        assert result["accepted"] is True
        assert result["calibrated"] is True
        assert result["n_samples"] == 100
        assert result["cv_accuracy"] >= MIN_CV_ACCURACY
        assert result["persisted_path"] is not None
        assert result["provenance_row_id"] is None  # no DB in test env
        assert "CalibratedClassifierCV" in (result["model_type"] or "")

    @pytest.mark.asyncio
    async def test_five_fold_cv_returns_five_accuracies(
        self, good_csv: Path, tmp_path: Path
    ):
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=good_csv)

        folds = result["fold_accuracies"]
        assert len(folds) == 5
        for a in folds:
            assert 0.0 <= a <= 1.0
            assert math.isfinite(a)

    @pytest.mark.asyncio
    async def test_run_id_returned(self, good_csv: Path, tmp_path: Path):
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=good_csv)
        assert result["run_id"].startswith("v2-")
        assert len(result["run_id"]) > 5

    @pytest.mark.asyncio
    async def test_explicit_run_id_honored(self, good_csv: Path, tmp_path: Path):
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=good_csv, run_id="v2-fixed-xyz")
        assert result["run_id"] == "v2-fixed-xyz"


# ──────────────────────────────────────────────────────────
# train_v2 — rejection path
# ──────────────────────────────────────────────────────────


class TestTrainV2Rejected:
    @pytest.mark.asyncio
    async def test_noisy_data_below_threshold(self, noisy_csv: Path, tmp_path: Path):
        m = AlertTriageModel(load=False)
        original_model = m.model
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=noisy_csv, min_cv_accuracy=0.70)

        assert result["ok"] is True
        assert result["accepted"] is False
        assert result["calibrated"] is False
        assert result["cv_accuracy"] < 0.70
        assert result["persisted_path"] is None
        assert result["model_type"] is None
        assert "below_threshold" in result["reason"]
        # The model's own state should NOT have been replaced with garbage.
        assert m.model is original_model or m.model is None

    @pytest.mark.asyncio
    async def test_missing_csv_returns_clean_error(self, tmp_path: Path):
        m = AlertTriageModel(load=False)
        result = await m.train_v2(csv_path=tmp_path / "nope.csv")
        assert result["ok"] is False
        assert "csv_not_found" in result["reason"]
        assert result["accepted"] is False

    @pytest.mark.asyncio
    async def test_empty_csv_returns_clean_error(self, empty_csv: Path):
        m = AlertTriageModel(load=False)
        result = await m.train_v2(csv_path=empty_csv)
        assert result["ok"] is False
        assert "csv_invalid" in result["reason"]
        assert result["accepted"] is False

    @pytest.mark.asyncio
    async def test_custom_threshold(self, noisy_csv: Path, tmp_path: Path):
        # Lowering the floor to 0.3 should accept the noisy data.
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=noisy_csv, min_cv_accuracy=0.30)
        assert result["accepted"] is True
        assert result["cv_accuracy"] >= 0.30


# ──────────────────────────────────────────────────────────
# latest_provenance
# ──────────────────────────────────────────────────────────


class TestLatestProvenance:
    @pytest.mark.asyncio
    async def test_returns_none_when_no_db(self):
        m = AlertTriageModel(load=False)
        # _db_reachable should be False in this CI env, so we get None fast.
        with patch("src.ai.alert_triage._db_reachable", return_value=False):
            result = await m.latest_provenance()
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_db_pool_fails(self):
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage._db_reachable", return_value=True):
            with patch(
                "src.ai.alert_triage.get_pool",
                side_effect=RuntimeError("nope"),
            ):
                result = await m.latest_provenance()
        assert result is None
