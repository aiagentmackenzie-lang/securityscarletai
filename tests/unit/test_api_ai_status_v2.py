"""
Tests for the V2 (Epic 3) provenance block in GET /api/v1/ai/status.

The endpoint is expected to add a `provenance` key to the existing
`StatusResponse.triage` dict, sourced from the latest
triage_model_provenance row. When the DB is unreachable, `provenance`
must be None — the endpoint must still return 200 with all existing
keys intact (backward compatibility).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestGetStatusIncludesProvenance:
    @pytest.mark.asyncio
    async def test_provenance_none_when_db_unreachable(self):
        # AUD-043: the status path uses the SHARED singleton with
        # train_if_missing=False — the fresh-model-per-poll shape (joblib
        # load + SHA-256 on every dashboard poll) is gone, so the tests
        # patch the accessor, not the constructor.
        model_instance = MagicMock()
        model_instance.get_status.return_value = {
            "is_trained": False,
            "training_samples": 0,
            "model_type": "RandomForestClassifier",
        }
        model_instance.latest_provenance = AsyncMock(return_value=None)

        with (
            patch("src.api.ai.get_triage_model", new_callable=AsyncMock) as mock_get_model,
            patch("src.api.ai.get_ueba") as mock_ueba,
            patch(
                "src.api.health._cached_ollama_check",
                new_callable=AsyncMock,
                return_value=(False, None, "unreachable"),
            ),
        ):
            mock_get_model.return_value = model_instance
            ueba_instance = MagicMock()
            ueba_instance.get_status.return_value = {"is_trained": False}
            mock_ueba.return_value = ueba_instance

            # Lazy import so test module is importable without FastAPI deps loaded.
            from src.api.ai import get_status

            response = await get_status(_user={"sub": "tester", "role": "viewer"})

        # The singletons were accessed READ-ONLY (no training side effect).
        mock_get_model.assert_awaited_once_with(train_if_missing=False)
        mock_ueba.assert_awaited_once_with(train_if_missing=False)
        # Existing keys preserved.
        assert response.triage["is_trained"] is False
        assert response.triage["model_type"] == "RandomForestClassifier"
        # New key present and None.
        assert "provenance" in response.triage
        assert response.triage["provenance"] is None

    @pytest.mark.asyncio
    async def test_provenance_populated_when_available(self):
        sample_provenance = {
            "id": 7,
            "run_id": "v2-test-1234",
            "source_csv": "data/training/alerts_v3.csv",
            "n_samples": 1000,
            "accuracy": 0.92,
            "precision": None,
            "recall": None,
            "f1": None,
            "calibrated": True,
            "trained_at": "2026-06-01T00:00:00+00:00",
        }
        model_instance = MagicMock()
        model_instance.get_status.return_value = {"is_trained": True, "model_type": "X"}
        model_instance.latest_provenance = AsyncMock(return_value=sample_provenance)

        with (
            patch("src.api.ai.get_triage_model", new_callable=AsyncMock) as mock_get_model,
            patch("src.api.ai.get_ueba") as mock_ueba,
            patch(
                "src.api.health._cached_ollama_check",
                new_callable=AsyncMock,
                return_value=(False, None, "unreachable"),
            ),
        ):
            mock_get_model.return_value = model_instance
            # Use a plain MagicMock for the awaited return value so .get_status()
            # stays synchronous (matching the real UEBA API).
            ueba_instance = MagicMock()
            ueba_instance.get_status.return_value = {"is_trained": False}
            mock_ueba.return_value = ueba_instance

            from src.api.ai import get_status

            response = await get_status(_user={"sub": "tester", "role": "viewer"})

        assert response.triage["provenance"] == sample_provenance
        # Existing keys still present.
        assert response.triage["is_trained"] is True

    @pytest.mark.asyncio
    async def test_provenance_lookup_exception_yields_none(self):
        # If latest_provenance() raises, the endpoint must swallow it
        # and still return a valid 200 with provenance=None.
        model_instance = MagicMock()
        model_instance.get_status.return_value = {"is_trained": False}
        model_instance.latest_provenance = AsyncMock(side_effect=RuntimeError("db down"))

        with (
            patch("src.api.ai.get_triage_model", new_callable=AsyncMock) as mock_get_model,
            patch("src.api.ai.get_ueba") as mock_ueba,
            patch(
                "src.api.health._cached_ollama_check",
                new_callable=AsyncMock,
                return_value=(False, None, "unreachable"),
            ),
        ):
            mock_get_model.return_value = model_instance
            ueba_instance = MagicMock()
            ueba_instance.get_status.return_value = {"is_trained": False}
            mock_ueba.return_value = ueba_instance

            from src.api.ai import get_status

            response = await get_status(_user={"sub": "tester", "role": "viewer"})

        assert response.triage["provenance"] is None


def _acquirer(conn):
    """House-pattern async context manager wrapper for pool.acquire()."""
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    return acquirer


class TestReadEndpointsNeverTrain:
    """W2-B: AUD-043/044 hardened /ai/status and /ai/train but MISSED the
    triage/ueba read paths — their default train_if_missing=True ran the
    full training INLINE in an analyst's first click. The read paths must
    access the singletons READ-ONLY and surface the honest 'not trained'
    payloads instead."""

    @pytest.mark.asyncio
    async def test_triage_endpoint_never_trains(self):
        # Alert exists (the 404 path is covered elsewhere) — only the model
        # accessor contract matters here.
        mock_conn = MagicMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": 1, "rule_name": "r", "severity": "high"})
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(return_value=_acquirer(mock_conn))

        model_instance = MagicMock()
        model_instance.predict = AsyncMock(
            return_value={
                "prediction": "unknown",
                "confidence": 0.0,
                "priority_score": 50.0,
                "reason": "Model not trained",
            }
        )

        with patch("src.api.ai.get_pool", return_value=mock_pool):
            with patch("src.api.ai.get_triage_model", new_callable=AsyncMock) as mock_get_model:
                mock_get_model.return_value = model_instance
                from src.api.ai import triage_alert

                response = await triage_alert(alert_id=1, _user={"sub": "a", "role": "analyst"})

        mock_get_model.assert_awaited_once_with(train_if_missing=False)
        assert response.prediction == "unknown"
        assert response.reason == "Model not trained"

    @pytest.mark.asyncio
    async def test_ueba_endpoint_never_trains(self):
        ueba_instance = MagicMock()
        ueba_instance.score_user = AsyncMock(
            return_value={"anomaly_score": None, "is_anomaly": False, "error": "Model not trained"}
        )

        with patch("src.api.ai.get_ueba", new_callable=AsyncMock) as mock_get_ueba:
            mock_get_ueba.return_value = ueba_instance
            from src.api.ai import get_ueba_score

            response = await get_ueba_score(
                user_name="j.doe", _user={"sub": "a", "role": "analyst"}
            )

        mock_get_ueba.assert_awaited_once_with(train_if_missing=False)
        assert response.anomaly_score is None
        assert response.error == "Model not trained"
