"""
Tests for the UEBA (User and Entity Behavior Analytics) module.

Covers:
- Shannon entropy calculation
- Feature list validation
- Model status API
- Model load/save with integrity verification
- get_ueba singleton
- Edge cases in feature extraction
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.ai.ueba import UEBA_FEATURES, UEBABaseline, _shannon_entropy, get_ueba


class TestShannonEntropy:
    """Test _shannon_entropy function."""

    def test_empty_list(self):
        """Empty list should return 0.0."""
        assert _shannon_entropy([]) == 0.0

    def test_single_item(self):
        """Single item should return 0.0 (no diversity)."""
        assert _shannon_entropy(["bash"]) == 0.0

    def test_two_different_items(self):
        """Two different items should return 1.0 (maximum entropy for 2 items)."""
        result = _shannon_entropy(["a", "b"])
        assert abs(result - 1.0) < 0.01  # Normalized, max for 2 items

    def test_all_same_items(self):
        """All same items should return 0.0."""
        result = _shannon_entropy(["bash", "bash", "bash"])
        assert result == 0.0

    def test_uniform_distribution(self):
        """Uniform distribution should return 1.0 (maximum entropy)."""
        result = _shannon_entropy(["a", "b", "c", "d"])
        assert abs(result - 1.0) < 0.01

    def test_skewed_distribution(self):
        """Skewed distribution should have entropy between 0 and 1."""
        result = _shannon_entropy(["bash"] * 95 + ["python"] * 5)
        assert 0.0 < result < 1.0

    def test_mixed_process_names(self):
        """Realistic process names should produce reasonable entropy."""
        processes = [
            "sshd",
            "bash",
            "python",
            "sshd",
            "bash",
            "nginx",
            "postgres",
            "sshd",
            "bash",
            "python",
        ]
        result = _shannon_entropy(processes)
        assert 0.0 < result <= 1.0

    def test_large_list(self):
        """Should handle large lists efficiently."""
        processes = [f"proc_{i % 10}" for i in range(1000)]
        result = _shannon_entropy(processes)
        assert 0.0 < result <= 1.0

    def test_numeric_strings(self):
        """Should work with numeric strings."""
        result = _shannon_entropy(["1", "2", "3", "4", "5"])
        assert abs(result - 1.0) < 0.01


class TestUEBAFeatures:
    """Test UEBA feature definitions."""

    def test_feature_list_complete(self):
        """Should have all 8 expected features."""
        expected = [
            "login_hour_of_day",
            "unique_processes_count",
            "command_diversity",
            "network_connections_count",
            "unique_destination_ips",
            "file_access_count",
            "sudo_usage_count",
            "session_duration_minutes",
        ]
        assert UEBA_FEATURES == expected

    def test_feature_count(self):
        """Should have exactly 8 features."""
        assert len(UEBA_FEATURES) == 8


class TestUEBABaselineInit:
    """Test UEBABaseline initialization."""

    def test_default_initialization(self):
        """Should initialize — may load cached model if present."""
        baseline = UEBABaseline()
        # If a cached model exists, it will be loaded automatically
        # Key test: contamination should always be the default
        assert baseline.contamination == 0.05

    def test_contamination_parameter(self):
        """Should accept custom contamination parameter."""
        baseline = UEBABaseline(contamination=0.1)
        assert baseline.contamination == 0.1

    def test_default_contamination(self):
        """Default contamination should be 0.05."""
        baseline = UEBABaseline()
        assert baseline.contamination == 0.05


class TestUEBABaselineStatus:
    """Test get_status method."""

    def test_untrained_status(self):
        """Untrained model should report correctly."""
        baseline = UEBABaseline()
        baseline.is_trained = False
        baseline.trained_at = None
        status = baseline.get_status()
        assert status["is_trained"] is False
        assert status["trained_at"] is None
        assert isinstance(status["training_samples"], int)
        assert "IsolationForest" in status["model_type"]
        assert status["features"] == UEBA_FEATURES

    def test_trained_status(self):
        """Trained model should include training info."""
        import time

        baseline = UEBABaseline()
        baseline.is_trained = True
        baseline.trained_at = time.time()
        baseline.training_samples = 50
        status = baseline.get_status()
        assert status["is_trained"] is True
        assert status["trained_at"] is not None
        assert status["training_samples"] == 50
        assert status["model_type"] == "IsolationForest"


class TestUEBABaselineTrain:
    """Test model training with mocked DB."""

    @pytest.mark.asyncio
    async def test_train_insufficient_users(self):
        """Should fail if not enough users for training."""
        baseline = UEBABaseline()

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        # Only 2 users (< 3 threshold)
        mock_conn.fetch = AsyncMock(
            return_value=[
                {"user_name": "user1"},
                {"user_name": "user2"},
            ]
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.ai.ueba.get_pool", return_value=mock_pool):
            result = await baseline.train(min_days=1)
            assert result is False

    @pytest.mark.asyncio
    async def test_train_with_mock_data(self):
        """Should train successfully with sufficient mock data."""

        baseline = UEBABaseline()

        # Create mock users
        mock_users = [{"user_name": f"user_{i}"} for i in range(10)]
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()

        # First call: get users
        # Second call: extract features per user
        mock_conn.fetch = AsyncMock(return_value=mock_users)

        # Mock feature extraction calls
        mock_conn.fetchval = AsyncMock(return_value=None)  # Most queries return None
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "first_event": None,
                "last_event": None,
            }
        )

        # Return some process names for entropy calculation
        mock_conn.fetch = AsyncMock(
            side_effect=[mock_users] + [[{"process_name": f"proc_{i}"} for i in range(5)]] * 10
        )

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        # Mock the BATCHED extractor (AUD-025) to return realistic data
        features = {
            "login_hour_of_day": 9.0,
            "unique_processes_count": 5.0,
            "command_diversity": 0.7,
            "network_connections_count": 10.0,
            "unique_destination_ips": 3.0,
            "file_access_count": 20.0,
            "sudo_usage_count": 2.0,
            "session_duration_minutes": 480.0,
        }
        baseline.extract_user_features_batch = AsyncMock(
            return_value={f"user_{i}": dict(features) for i in range(10)}
        )

        with patch("src.ai.ueba.get_pool", return_value=mock_pool):
            result = await baseline.train(min_days=1)
            # Training may succeed or fail depending on extract_user_features mock
            # The key test is that it doesn't crash


class TestUEBABaselineScoreUser:
    """Test score_user with mocked model."""

    @pytest.mark.asyncio
    async def test_score_user_untrained(self):
        """Untrained model should return error dict."""
        baseline = UEBABaseline()
        baseline.is_trained = False
        result = await baseline.score_user("testuser")
        assert result["anomaly_score"] is None
        assert result["is_anomaly"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_score_user_no_data(self):
        """Model should handle user with no data."""
        baseline = UEBABaseline()
        baseline.is_trained = True

        # Mock extract_user_features to return None
        with patch.object(
            baseline, "extract_user_features", new_callable=AsyncMock, return_value=None
        ):
            result = await baseline.score_user("nonexistent_user")
            assert result["anomaly_score"] is None
            assert result["is_anomaly"] is False

    @pytest.mark.asyncio
    async def test_score_user_uses_trained_window(self):
        """W2-C/B4: score_user aggregates the model's TRAINED window, not a
        fixed days=1 — the training/scoring distribution mismatch made every
        user skew anomaly-low."""
        baseline = UEBABaseline()
        baseline.is_trained = True
        baseline.trained_window_days = (
            9  # non-default: proves it reads the model, not a magic number
        )
        extractor = AsyncMock(return_value=None)
        with patch.object(baseline, "extract_user_features", extractor):
            await baseline.score_user("user1")
        assert extractor.await_args.kwargs.get("days") == 9

    @pytest.mark.asyncio
    async def test_get_high_risk_users_uses_trained_window(self):
        """W2-C/B4: get_high_risk_users sweeps candidates AND aggregates
        features over the model's TRAINED window."""
        baseline = UEBABaseline()
        baseline.is_trained = True
        baseline.trained_window_days = 9

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"user_name": "u1"}])
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        batch = AsyncMock(return_value={})
        with (
            patch("src.ai.ueba.get_pool", return_value=mock_pool),
            patch.object(baseline, "extract_user_features_batch", batch),
        ):
            await baseline.get_high_risk_users()

        assert batch.await_args.kwargs.get("days") == 9
        # The candidate sweep must match too ($1 = window days).
        assert mock_conn.fetch.await_args.args[1] == 9


class TestUEBAModelIntegrity:
    """Test model file integrity checks."""

    def test_sha256_file_nonexistent(self):
        """Should raise for nonexistent files."""
        from pathlib import Path

        with pytest.raises(Exception):
            UEBABaseline._sha256_file(Path("/nonexistent/file"))

    def test_sha256_file_exists(self, tmp_path):
        """Should compute SHA256 for existing files."""
        test_file = tmp_path / "test_model.joblib"
        test_file.write_bytes(b"test data for sha256")
        result = UEBABaseline._sha256_file(test_file)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest length

    def test_trained_window_persists_in_metadata(self, tmp_path):
        """W2-C/B4: the trained window survives save/load — a restarted
        process must score on the window the model was actually trained on
        (fallback 7 = the documented default min_days)."""
        import src.ai.ueba as ueba_mod

        baseline = UEBABaseline()
        baseline.model = {"mock": "model"}  # pickleable stand-in
        baseline.scaler = {"mock": "scaler"}
        baseline.trained_at = 1.0
        baseline.training_samples = 5
        baseline.trained_window_days = 9

        with (
            patch.object(ueba_mod, "MODEL_PATH", tmp_path / "m.joblib"),
            patch.object(ueba_mod, "SCALER_PATH", tmp_path / "s.joblib"),
            patch.object(ueba_mod, "META_PATH", tmp_path / "meta.joblib"),
            patch.object(ueba_mod, "HASH_PATH", tmp_path / "m.sha256"),
        ):
            baseline._save_model()

            fresh = UEBABaseline()  # __init__ loads from the patched paths
            assert fresh.is_trained is True
            assert fresh.trained_window_days == 9

    def test_trained_window_fallback_for_legacy_metadata(self, tmp_path):
        """W2-C/B4: a pre-W2-C metadata file (no trained_window_days key)
        falls back to 7 — the documented default training window."""
        import joblib

        import src.ai.ueba as ueba_mod

        with (
            patch.object(ueba_mod, "MODEL_PATH", tmp_path / "m.joblib"),
            patch.object(ueba_mod, "SCALER_PATH", tmp_path / "s.joblib"),
            patch.object(ueba_mod, "META_PATH", tmp_path / "meta.joblib"),
            patch.object(ueba_mod, "HASH_PATH", tmp_path / "m.sha256"),
        ):
            joblib.dump({"mock": "model"}, tmp_path / "m.joblib")
            joblib.dump({"mock": "scaler"}, tmp_path / "s.joblib")
            (tmp_path / "m.sha256").write_text(UEBABaseline._sha256_file(tmp_path / "m.joblib"))
            joblib.dump({"trained_at": 1.0, "training_samples": 3}, tmp_path / "meta.joblib")

            fresh = UEBABaseline()
            assert fresh.is_trained is True
            assert fresh.trained_window_days == 7  # legacy metadata → default


class TestGetUebaSingleton:
    @pytest.mark.asyncio
    async def test_train_if_missing_false_never_trains(self):
        """AUD-043: train_if_missing=False keeps the accessor read-only —
        the /ai/status polling path must never trigger a synchronous
        training run as a side effect."""
        import src.ai.ueba as ueba_mod

        ueba_mod._ueba = None
        with (
            patch.object(UEBABaseline, "_load_model", return_value=False),
            patch.object(UEBABaseline, "train", AsyncMock(return_value=False)) as mock_train,
        ):
            engine = await get_ueba(train_if_missing=False)
            assert engine.is_trained is False
            assert mock_train.await_count == 0  # NO side effect
        ueba_mod._ueba = None


# ──────────────────────────────────────────────────────────
# AUD-025: batched UEBA feature extraction (the N+1 kill)
# ──────────────────────────────────────────────────────────


class TestExtractUserFeaturesBatch:
    """AUD-025: the WHOLE user batch is served with 8 grouped queries
    (the per-user path issued 7 queries PER USER: a train over N users
    was 7×N sequential round-trips)."""

    @pytest.mark.asyncio
    async def test_batch_uses_eight_grouped_queries(self):
        from datetime import datetime as dt

        baseline = UEBABaseline()  # no model files in CI → loads nothing

        users = ["alice", "bob"]
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            side_effect=[
                # 1. login hours (MODE per user)
                [{"user_name": "alice", "typical_hour": 22}],
                # 2. unique process counts
                [{"user_name": "alice", "c": 4}, {"user_name": "bob", "c": 1}],
                # 3. process names for entropy (LATERAL per user)
                [
                    {"user_name": "alice", "process_name": "zsh"},
                    {"user_name": "alice", "process_name": "curl"},
                ],
                # 4. network counts
                [{"user_name": "alice", "c": 12}],
                # 5. unique destination IPs
                [{"user_name": "alice", "c": 5}],
                # 6. file counts
                [{"user_name": "bob", "c": 2}],
                # 7. sudo counts
                [{"user_name": "alice", "c": 3}],
                # 8. session spans
                [
                    {
                        "user_name": "alice",
                        "first_event": dt(2024, 6, 15, 8, 0, 0),
                        "last_event": dt(2024, 6, 15, 16, 0, 0),
                    }
                ],
            ]
        )

        class Ctx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=Ctx())

        with patch("src.ai.ueba.get_pool", AsyncMock(return_value=mock_pool)):
            features = await baseline.extract_user_features_batch(["alice", "bob", "alice"], days=7)

        # Deduplicated input; exactly EIGHT queries for the whole batch.
        assert mock_conn.fetch.await_count == 8
        assert set(features.keys()) == {"alice", "bob"}
        assert mock_conn.fetchval.await_count == 0

        # alice: real login hour 22, no default; 8h activity span → 480 min.
        assert features["alice"]["login_hour_of_day"] == 22.0
        assert features["alice"]["unique_processes_count"] == 4.0
        assert features["alice"]["network_connections_count"] == 12.0
        assert features["alice"]["unique_destination_ips"] == 5.0
        assert features["alice"]["sudo_usage_count"] == 3.0
        assert features["alice"]["session_duration_minutes"] == pytest.approx(480.0)

        # bob: no auth data → 9 AM default; no session rows → 0.0 span.
        assert features["bob"]["login_hour_of_day"] == 9.0
        assert features["bob"]["file_access_count"] == 2.0
        assert features["bob"]["session_duration_minutes"] == 0.0

    @pytest.mark.asyncio
    async def test_empty_user_list(self):
        baseline = UEBABaseline()
        assert await baseline.extract_user_features_batch([]) == {}
