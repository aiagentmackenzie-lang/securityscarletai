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
        # Stub out everything the endpoint calls so we only exercise
        # the new provenance-attachment branch.
        with patch("src.api.ai.AlertTriageModel") as MockModel, patch(
            "src.api.ai.get_ueba"
        ) as mock_ueba, patch(
            "src.ai.ollama_client.is_ollama_available",
            new_callable=AsyncMock,
            return_value=False,
        ):
            instance = MockModel.return_value
            instance.get_status.return_value = {
                "is_trained": False,
                "training_samples": 0,
                "model_type": "RandomForestClassifier",
            }
            instance.latest_provenance = AsyncMock(return_value=None)
            ueba_instance = MagicMock()
            ueba_instance.get_status.return_value = {"is_trained": False}
            mock_ueba.return_value = ueba_instance

            # Lazy import so test module is importable without FastAPI deps loaded.
            from src.api.ai import get_status

            response = await get_status(_user={"sub": "tester", "role": "viewer"})

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
        with patch("src.api.ai.AlertTriageModel") as MockModel, patch(
            "src.api.ai.get_ueba"
        ) as mock_ueba, patch(
            "src.ai.ollama_client.is_ollama_available", new_callable=AsyncMock, return_value=False
        ):
            instance = MockModel.return_value
            instance.get_status.return_value = {"is_trained": True, "model_type": "X"}
            instance.latest_provenance = AsyncMock(return_value=sample_provenance)
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
        with patch("src.api.ai.AlertTriageModel") as MockModel, patch(
            "src.api.ai.get_ueba"
        ) as mock_ueba, patch(
            "src.ai.ollama_client.is_ollama_available", new_callable=AsyncMock, return_value=False
        ):
            instance = MockModel.return_value
            instance.get_status.return_value = {"is_trained": False}
            instance.latest_provenance = AsyncMock(
                side_effect=RuntimeError("db down")
            )
            ueba_instance = MagicMock()
            ueba_instance.get_status.return_value = {"is_trained": False}
            mock_ueba.return_value = ueba_instance

            from src.api.ai import get_status

            response = await get_status(_user={"sub": "tester", "role": "viewer"})

        assert response.triage["provenance"] is None
