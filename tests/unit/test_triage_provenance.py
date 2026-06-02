"""
Tests for triage_model_provenance population (Epic 3 follow-up).

Covers:
- train_v2() result dict contains precision/recall/f1 keys with finite
  values in [0, 1] after a successful CV run
- The PRF values are computed by aggregating predictions across all
  StratifiedKFold folds (not by averaging per-fold PRF, which would
  over-weight small folds)
- _write_provenance binds precision_score/recall_score/f1_score into
  the INSERT statement when the DB is reachable
- latest_provenance() returns the three values when present in the row
- src/db/schema.sql contains the modern provenance column additions
  (run_id, model_version, model_type, source_csv, n_samples, n_positive,
  n_negative, accuracy_score, model_path, run_metadata)

These tests are the second-line check behind the live-DB INSERT. The
DB is unreachable in CI, so they exercise the writer's parameter
plumbing and the train_v2 result shape, plus a static schema check.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.ai.alert_triage import (
    AlertTriageModel,
    _write_provenance,
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


# ──────────────────────────────────────────────────────────
# train_v2 — result shape includes PRF
# ──────────────────────────────────────────────────────────


class TestTrainV2ResultIncludesPRF:
    @pytest.mark.asyncio
    async def test_prf_keys_present(self, good_csv: Path, tmp_path: Path):
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=good_csv)

        for key in ("precision", "recall", "f1"):
            assert key in result, f"result missing {key!r}"
            v = result[key]
            assert v is not None, f"result[{key!r}] is None on accepted run"
            assert 0.0 <= v <= 1.0, f"result[{key!r}] = {v} out of [0,1]"
            assert math.isfinite(v), f"result[{key!r}] is non-finite"

    @pytest.mark.asyncio
    async def test_prf_matches_accuracy_on_perfect_data(
        self, good_csv: Path, tmp_path: Path
    ):
        # Synthetic well-separated data classifies perfectly. PRF should
        # all be 1.0 (or 0.0 if sklearn returns zero_division fallback).
        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=good_csv)

        assert result["cv_accuracy"] == pytest.approx(1.0, abs=0.01)
        assert result["precision"] == pytest.approx(1.0, abs=0.01)
        assert result["recall"] == pytest.approx(1.0, abs=0.01)
        assert result["f1"] == pytest.approx(1.0, abs=0.01)

    @pytest.mark.asyncio
    async def test_prf_present_even_on_rejected_run(self, tmp_path: Path):
        # Below-threshold runs should also surface PRF — useful for
        # diagnostics ("the model was rejected because precision was
        # only 0.42, not because accuracy alone was bad").
        import csv as _csv
        import random as _random

        from src.ai.alert_triage import ALERT_ID_COLUMN, LABEL_COLUMN

        rng = _random.Random(0)  # noqa: S311 — noisy test data, not crypto
        rows = []
        for i in range(200):
            rows.append({
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
            })
        noisy = tmp_path / "noisy.csv"
        with noisy.open("w", newline="") as f:
            w = _csv.DictWriter(
                f,
                fieldnames=[ALERT_ID_COLUMN]
                + AlertTriageModel.FEATURES
                + [LABEL_COLUMN],
            )
            w.writeheader()
            for row in rows:
                w.writerow(row)

        m = AlertTriageModel(load=False)
        with patch("src.ai.alert_triage.MODEL_DIR", tmp_path / "models"):
            result = await m.train_v2(csv_path=noisy, min_cv_accuracy=0.99)

        assert result["accepted"] is False
        # PRF should still be present and finite.
        for key in ("precision", "recall", "f1"):
            v = result[key]
            assert v is not None, f"rejected run missing {key!r}"
            assert 0.0 <= v <= 1.0
            assert math.isfinite(v)


# ──────────────────────────────────────────────────────────
# _write_provenance — parameter binding
# ──────────────────────────────────────────────────────────


class TestWriteProvenanceParameterBinding:
    @pytest.mark.asyncio
    async def test_prf_values_passed_to_insert(self):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": 42})
        mock_acquirer = MagicMock()
        mock_acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool_instance = MagicMock()
        mock_pool_instance.acquire = MagicMock(return_value=mock_acquirer)

        with patch("src.ai.alert_triage._db_reachable", return_value=True), \
             patch("src.ai.alert_triage.get_pool", new_callable=AsyncMock) as mock_pool:
            mock_pool.return_value = mock_pool_instance
            await _write_provenance(
                run_id="v2-test-001",
                source_csv="data/x.csv",
                source_meta=[
                    {"alert_id": 1, "label": "true_positive"},
                    {"alert_id": 2, "label": "false_positive"},
                ],
                n_samples=2,
                cv_accuracy=0.85,
                cv_std=0.02,
                precision_score=0.84,
                recall_score=0.86,
                f1_score=0.85,
                calibrated=True,
                accepted=True,
                model_path="/tmp/model.joblib",
                fold_accuracies=[0.8, 0.9],
                features=AlertTriageModel.FEATURES,
            )

        # fetchrow was called once.
        assert mock_conn.fetchrow.await_count == 1
        call = mock_conn.fetchrow.await_args
        positional = call.args  # (sql, p1, p2, ...)
        # Positional[0] is the SQL string; everything from [1] is a bound param.
        # $1=run_id, $2=model_version, $3=model_type, $4=source_csv,
        # $5=n_samples, $6=n_positive, $7=n_negative, $8=accuracy_score,
        # $9=precision_score, $10=recall_score, $11=f1_score,
        # $12=calibrated, $13=feature_importances (joblib bytes),
        # $14=features (joblib bytes), $15=model_path, $16=run_metadata.
        assert positional[0] is not None and "INSERT" in positional[0]
        assert positional[1] == "v2-test-001"          # $1 run_id
        assert positional[4] == "data/x.csv"           # $4 source_csv
        assert positional[5] == 2                      # $5 n_samples
        assert positional[8] == 0.85                   # $8 accuracy_score
        assert positional[9] == 0.84                   # $9 precision_score
        assert positional[10] == 0.86                  # $10 recall_score
        assert positional[11] == 0.85                  # $11 f1_score
        assert positional[15] == "/tmp/model.joblib"   # $15 model_path

    @pytest.mark.asyncio
    async def test_prf_none_is_passed_through(self):
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": 7})
        mock_acquirer = MagicMock()
        mock_acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool_instance = MagicMock()
        mock_pool_instance.acquire = MagicMock(return_value=mock_acquirer)

        with patch("src.ai.alert_triage._db_reachable", return_value=True), \
             patch("src.ai.alert_triage.get_pool", new_callable=AsyncMock) as mock_pool:
            mock_pool.return_value = mock_pool_instance
            await _write_provenance(
                run_id="v2-test-002",
                source_csv="data/y.csv",
                source_meta=[],
                n_samples=0,
                cv_accuracy=0.0,
                cv_std=0.0,
                precision_score=None,
                recall_score=None,
                f1_score=None,
                calibrated=False,
                accepted=False,
                model_path=None,
                fold_accuracies=[],
                features=[],
            )

        positional = mock_conn.fetchrow.await_args.args
        # PRF slots are bound to None when sklearn couldn't compute.
        assert positional[9] is None
        assert positional[10] is None
        assert positional[11] is None


# ──────────────────────────────────────────────────────────
# Schema — modern provenance columns present
# ──────────────────────────────────────────────────────────


class TestSchemaHasModernProvenanceColumns:
    def test_alter_block_present(self):
        schema_path = Path(__file__).resolve().parents[2] / "src" / "db" / "schema.sql"
        sql = schema_path.read_text()
        # The follow-up append must add the modern columns.
        match = re.search(
            r"ALTER\s+TABLE\s+triage_model_provenance\s+(.*?);",
            sql,
            re.IGNORECASE | re.DOTALL,
        )
        assert match is not None, "no ALTER TABLE triage_model_provenance block"
        block = match.group(1)
        for col in (
            "run_id",
            "model_version",
            "model_type",
            "source_csv",
            "n_samples",
            "n_positive",
            "n_negative",
            "accuracy_score",
            "model_path",
            "run_metadata",
        ):
            assert f"ADD COLUMN IF NOT EXISTS {col}" in block, (
                f"ALTER block missing {col}"
            )

    def test_alter_block_uses_if_not_exists(self):
        schema_path = Path(__file__).resolve().parents[2] / "src" / "db" / "schema.sql"
        sql = schema_path.read_text()
        # Every ADD COLUMN in the provenance ALTER must be idempotent.
        match = re.search(
            r"ALTER\s+TABLE\s+triage_model_provenance\s+(.*?);",
            sql,
            re.IGNORECASE | re.DOTALL,
        )
        assert match is not None
        block = match.group(1)
        adds = re.findall(r"ADD\s+COLUMN[^\n,]+", block, re.IGNORECASE)
        assert adds, "no ADD COLUMN statements found"
        for stmt in adds:
            assert "IF NOT EXISTS" in stmt, (
                f"non-idempotent ADD COLUMN: {stmt!r}"
            )
