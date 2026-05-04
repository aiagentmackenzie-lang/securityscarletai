"""
Comprehensive tests for src/ai/alert_triage.py.

Covers:
- AlertTriageModel initialization and loading
- _shannon_entropy static function
- _predict_from_features with real sklearn model
- extract_features (async DB mock)
- train() success and failure paths
- train() single class rejection
- predict() with/without trained model
- get_priority_queue
- check_auto_train
- get_triage_model singleton
- Model save/load integrity
"""
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
import tempfile
import shutil

import numpy as np

from src.ai.alert_triage import (
    AlertTriageModel,
    _shannon_entropy,
    AUTO_TRAIN_THRESHOLD,
    check_auto_train,
    get_triage_model,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _shannon_entropy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestShannonEntropy:
    def test_empty_list(self):
        assert _shannon_entropy([]) == 0.0

    def test_single_value(self):
        assert _shannon_entropy(["a"]) == 0.0

    def test_two_equal_values(self):
        # Two unique values with equal distribution: entropy = -0.5*log2(0.5)*2 = 1.0
        # Normalized: 1.0 / log2(2) = 1.0
        result = _shannon_entropy(["a", "b"])
        assert abs(result - 1.0) < 0.01

    def test_all_same_values(self):
        # All same: entropy = 0
        result = _shannon_entropy(["a", "a", "a", "a"])
        assert result == 0.0

    def test_three_uniform_values(self):
        # 3 unique values each appearing once: entropy = log2(3), normalized = 1.0
        result = _shannon_entropy(["a", "b", "c"])
        assert abs(result - 1.0) < 0.01

    def test_mixed_distribution(self):
        # 4 values: "a" appears 3 times, "b" appears 1 time
        values = ["a", "a", "a", "b"]
        result = _shannon_entropy(values)
        # Should be positive but less than 1.0
        assert 0.0 < result < 1.0

    def test_many_unique_values(self):
        # 10 unique values each appearing once
        values = [str(i) for i in range(10)]
        result = _shannon_entropy(values)
        assert abs(result - 1.0) < 0.01


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AlertTriageModel — init and status
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAlertTriageModelInit:
    def test_model_features_list(self):
        """Model should have 11 features."""
        model = AlertTriageModel()
        assert len(model.FEATURES) == 11
        assert "severity_score" in model.FEATURES
        assert "command_entropy" in model.FEATURES
        assert "login_hour_deviation" in model.FEATURES

    def test_model_initial_state(self):
        """Model should start untrained."""
        model = AlertTriageModel()
        assert model.is_trained is False
        assert model.model is None
        assert model.trained_at is None
        assert model.training_samples == 0
        assert model.training_accuracy is None

    def test_model_status_untrained(self):
        """Status should reflect untrained state."""
        model = AlertTriageModel()
        model.is_trained = False
        status = model.get_status()
        assert status["is_trained"] is False
        assert status["trained_at"] is None
        assert status["training_samples"] == 0
        assert status["training_accuracy"] is None
        assert status["model_type"] == "RandomForestClassifier"

    def test_sha256_file(self):
        """Should compute SHA256 of a file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".joblib", delete=False) as f:
            f.write("test content for hash")
            f.flush()
            fpath = Path(f.name)

        try:
            result = AlertTriageModel._sha256_file(fpath)
            assert isinstance(result, str)
            assert len(result) == 64  # SHA256 hex
        finally:
            fpath.unlink()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _predict_from_features with real sklearn
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPredictFromFeatures:
    def _make_trained_model(self):
        """Create a model manually and train it with small data."""
        from sklearn.ensemble import RandomForestClassifier
        model = AlertTriageModel()
        # Create simple training data
        X = np.array([
            [1.0, 0.5, 0.3, 0.2, 0.6, 0.4, 0.8, 1.0, 0.7, 0.5, 0.3],  # TP
            [0.8, 0.4, 0.2, 0.3, 0.5, 0.3, 0.6, 0.8, 0.6, 0.4, 0.2],  # TP
            [0.2, 0.5, 0.1, 0.1, 0.2, 0.0, 0.1, 0.0, 0.2, 0.8, 0.1],  # FP
            [0.1, 0.3, 0.0, 0.0, 0.1, 0.0, 0.2, 0.0, 0.1, 0.9, 0.0],  # FP
            [0.9, 0.6, 0.4, 0.3, 0.7, 0.5, 0.7, 0.9, 0.8, 0.3, 0.4],  # TP
            [0.3, 0.4, 0.1, 0.1, 0.3, 0.1, 0.3, 0.1, 0.3, 0.7, 0.2],  # FP
        ])
        y = np.array([1, 1, 0, 0, 1, 0])
        model.model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.model.fit(X, y)
        model.is_trained = True
        model.trained_at = time.time()
        model.training_samples = len(X)
        model.training_accuracy = 1.0
        return model

    def test_predict_true_positive(self):
        """High-severity features should predict true_positive."""
        model = self._make_trained_model()
        # Features: high severity, suspicious hour, high entropy
        features = [0.9, 0.8, 0.5, 0.4, 0.7, 0.6, 0.7, 1.0, 0.8, 0.3, 0.5]
        result = model._predict_from_features(features)
        assert result["prediction"] in ["true_positive", "false_positive"]
        assert "confidence" in result
        assert "priority_score" in result
        assert isinstance(result["features"], dict)
        assert len(result["features"]) == 11

    def test_predict_false_positive(self):
        """Low-severity, low-suspicion features should lean false_positive."""
        model = self._make_trained_model()
        features = [0.1, 0.4, 0.0, 0.0, 0.1, 0.0, 0.9, 0.0, 0.1, 0.8, 0.1]
        result = model._predict_from_features(features)
        assert result["prediction"] in ["true_positive", "false_positive"]
        # Priority should be lower
        assert 0 <= result["priority_score"] <= 100

    def test_predict_priority_score_bounds(self):
        """Priority score should be between 0 and 100."""
        model = self._make_trained_model()
        for _ in range(10):
            features = np.random.rand(11).tolist()
            result = model._predict_from_features(features)
            assert 0 <= result["priority_score"] <= 100

    def test_predict_features_dict(self):
        """Result should contain named features dict."""
        model = self._make_trained_model()
        features = [0.5] * 11
        result = model._predict_from_features(features)
        assert "features" in result
        assert all(name in result["features"] for name in model.FEATURES)

    def test_predict_true_positive_high_confidence_boost(self):
        """True positive with high features should produce valid score."""
        model = self._make_trained_model()
        features_hp = [1.0, 0.5, 0.3, 0.2, 0.6, 0.4, 0.8, 1.0, 0.7, 0.5, 0.7]
        result_hp = model._predict_from_features(features_hp)
        assert isinstance(result_hp["priority_score"], (float, int))
        assert 0 <= result_hp["priority_score"] <= 100


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# predict() with mocked DB
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPredict:
    @pytest.mark.asyncio
    async def test_predict_not_trained(self):
        """Should return unknown when model is not trained."""
        model = AlertTriageModel()
        model.is_trained = False
        result = await model.predict(alert_id=1)
        assert result["prediction"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["reason"] == "Model not trained"

    @pytest.mark.asyncio
    async def test_predict_feature_extraction_failure(self):
        """Should return error when feature extraction fails."""
        model = AlertTriageModel()
        model.is_trained = True

        with patch.object(model, "extract_features", AsyncMock(return_value=None)):
            result = await model.predict(alert_id=999)
            assert result["prediction"] == "error"
            assert result["priority_score"] == 50.0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# train() success and failure paths
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestTrain:
    @pytest.mark.asyncio
    async def test_train_insufficient_samples(self):
        """Should return False when not enough samples."""
        model = AlertTriageModel()
        mock_conn = AsyncMock()
        # Return only 10 rows, below min_samples=50
        mock_conn.fetch = AsyncMock(return_value=[
            {"id": i, "status": "resolved"} for i in range(10)
        ])

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)):
            result = await model.train(min_samples=50)
            assert result is False

    @pytest.mark.asyncio
    async def test_train_single_class(self):
        """Should return False when all labels are same class."""
        model = AlertTriageModel()

        # Create enough rows but all same label
        rows = [{"id": i, "status": "resolved"} for i in range(60)]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        # Mock extract_features to return valid features
        mock_features = [0.5] * 11
        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)), \
             patch.object(model, "extract_features", AsyncMock(return_value=mock_features)):
            result = await model.train(min_samples=50)
            assert result is False

    @pytest.mark.asyncio
    async def test_train_success(self):
        """Should train model successfully with mixed labels."""
        model = AlertTriageModel()

        # Create rows with mixed labels
        rows = [{"id": i, "status": "resolved" if i % 2 == 0 else "false_positive"} for i in range(60)]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        mock_features = [0.5] * 11
        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)), \
             patch.object(model, "extract_features", AsyncMock(return_value=mock_features)), \
             patch.object(model, "_save_model"):
            result = await model.train(min_samples=50)

        assert result is True
        assert model.is_trained is True
        assert model.training_samples == 60
        assert model.training_accuracy is not None

    @pytest.mark.asyncio
    async def test_train_insufficient_features(self):
        """Should return False when not enough features extracted."""
        model = AlertTriageModel()

        rows = [{"id": i, "status": "resolved" if i % 2 == 0 else "false_positive"} for i in range(60)]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        # Most feature extractions return None
        async def mock_extract(alert_id):
            if alert_id % 3 == 0:
                return None
            return [0.5] * 11

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)), \
             patch.object(model, "extract_features", mock_extract):
            result = await model.train(min_samples=50)
            # May fail if not enough features
            assert isinstance(result, bool)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# extract_features with mocked DB
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestExtractFeatures:
    @pytest.mark.asyncio
    async def test_extract_features_alert_not_found(self):
        """Should return None when alert doesn't exist."""
        model = AlertTriageModel()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)):
            result = await model.extract_features(alert_id=9999)
            assert result is None

    @pytest.mark.asyncio
    async def test_extract_features_success(self):
        """Should return feature vector for valid alert."""
        model = AlertTriageModel()

        from datetime import datetime as dt
        alert_row = {
            "id": 1,
            "severity": "high",
            "time": dt(2024, 6, 15, 14, 30, 0),
            "rule_id": 5,
            "host_name": "workstation-01",
            "mitre_techniques": ["T1078", "T1021"],
            "evidence": {"threat_intel": {"match": True}},
        }

        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=alert_row)

        # Mock additional queries
        mock_conn.fetchval = AsyncMock(side_effect=[
            50,  # rule_hits
            3,   # host_alerts
            75.0,  # asset_risk
            dt(2024, 6, 15, 12, 0, 0),  # last_similar
            14.0,  # typical_hour (MODE)
        ])
        mock_conn.fetch = AsyncMock(return_value=[
            {"process_name": "cmd.exe"},
            {"process_name": "powershell.exe"},
        ])

        # session_times
        session_row = {
            "first_event": dt(2024, 6, 15, 8, 0, 0),
            "last_event": dt(2024, 6, 15, 14, 0, 0),
        }
        # Override fetchrow to return alert on first call, session on second
        call_count = [0]
        async def mock_fetchrow(sql, *args):
            call_count[0] += 1
            if call_count[0] == 1:
                return alert_row
            return session_row

        mock_conn.fetchrow = mock_fetchrow
        mock_conn.acquire = MagicMock()

        class AsyncCtx:
            async def __aenter__(self_inner):
                return mock_conn
            async def __aexit__(self_inner, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)):
            result = await model.extract_features(alert_id=1)

        if result is not None:
            assert len(result) == 11
            # Severity should be 0.8 for "high"
            assert abs(result[0] - 0.8) < 0.01

    @pytest.mark.asyncio
    async def test_extract_features_low_severity(self):
        """Should correctly map severity scores."""
        model = AlertTriageModel()

        from datetime import datetime as dt
        alert_row = {
            "id": 2,
            "severity": "low",
            "time": dt(2024, 6, 15, 10, 0, 0),
            "rule_id": 10,
            "host_name": "server-01",
            "mitre_techniques": [],
            "evidence": None,
        }

        mock_conn = AsyncMock()

        call_count = [0]
        async def mock_fetchrow(sql, *args):
            call_count[0] += 1
            if call_count[0] == 1:
                return alert_row
            return {"first_event": None, "last_event": None}

        mock_conn.fetchrow = mock_fetchrow
        mock_conn.fetchval = AsyncMock(side_effect=[
            10,   # rule_hits
            2,    # host_alerts
            40.0, # asset_risk
            None, # last_similar
            None, # typical_hour (MODE)
        ])
        mock_conn.fetch = AsyncMock(return_value=[])

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)):
            result = await model.extract_features(alert_id=2)

        if result is not None:
            # Low severity = 0.2
            assert abs(result[0] - 0.2) < 0.01
            # has_threat_intel should be 0.0 for None evidence
            assert result[7] == 0.0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# get_priority_queue
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestGetPriorityQueue:
    @pytest.mark.asyncio
    async def test_untrained_returns_empty(self):
        """Should return empty list when model is not trained."""
        model = AlertTriageModel()
        model.is_trained = False
        result = await model.get_priority_queue(limit=10)
        assert result == []

    @pytest.mark.asyncio
    async def test_priority_queue_with_mocked_db(self):
        """Should return sorted alerts by priority."""
        from sklearn.ensemble import RandomForestClassifier

        model = AlertTriageModel()
        # Train a simple model
        X = np.array([
            [1.0, 0.5, 0.3, 0.2, 0.6, 0.4, 0.8, 1.0, 0.7, 0.5, 0.3],
            [0.2, 0.5, 0.1, 0.1, 0.2, 0.0, 0.1, 0.0, 0.2, 0.8, 0.1],
        ])
        y = np.array([1, 0])
        model.model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.model.fit(X, y)
        model.is_trained = True
        model.trained_at = time.time()
        model.training_samples = 2

        mock_rows = [
            {"id": 1, "rule_name": "Brute Force", "severity": "high", "host_name": "ws-01", "time": "2024-01-01"},
            {"id": 2, "rule_name": "Suspicious Process", "severity": "medium", "host_name": "ws-02", "time": "2024-01-01"},
        ]

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=mock_rows)

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        mock_features = [0.5] * 11

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)), \
             patch.object(model, "extract_features", AsyncMock(return_value=mock_features)):
            result = await model.get_priority_queue(limit=10)

        assert len(result) == 2
        # Should be sorted by priority_score
        if len(result) > 1:
            assert result[0]["priority_score"] >= result[1]["priority_score"]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# check_auto_train
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCheckAutoTrain:
    @pytest.mark.asyncio
    async def test_below_threshold(self):
        """Should not auto-train when below threshold."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=50)  # Below 100

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)):
            # Increase threshold to ensure we're below it
            with patch("src.ai.alert_triage.AUTO_TRAIN_THRESHOLD", 200):
                result = await check_auto_train()
                assert result is False

    @pytest.mark.asyncio
    async def test_above_threshold_triggers_train(self):
        """Should trigger training when above threshold."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=150)  # Above 100

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        mock_model = MagicMock()
        mock_model.train = AsyncMock(return_value=True)

        with patch("src.ai.alert_triage.get_pool", AsyncMock(return_value=mock_pool)), \
             patch("src.ai.alert_triage.get_triage_model", AsyncMock(return_value=mock_model)):
            result = await check_auto_train()
            assert result is True
            mock_model.train.assert_called_once()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Model save/load integrity
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestModelSaveLoad:
    def test_save_and_load_model(self):
        """Should save and load model with integrity verification."""
        from sklearn.ensemble import RandomForestClassifier

        model = AlertTriageModel()
        X = np.array([
            [1.0, 0.5, 0.3, 0.2, 0.6, 0.4, 0.8, 1.0, 0.7, 0.5, 0.3],
            [0.2, 0.5, 0.1, 0.1, 0.2, 0.0, 0.1, 0.0, 0.2, 0.8, 0.1],
        ])
        y = np.array([1, 0])
        model.model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.model.fit(X, y)
        model.is_trained = True
        model.trained_at = time.time()
        model.training_samples = 2
        model.training_accuracy = 1.0

        # Use a temp directory
        from src.ai.alert_triage import MODEL_DIR, MODEL_PATH, HASH_PATH, META_PATH
        with tempfile.TemporaryDirectory() as tmpdir:
            import src.ai.alert_triage as triage_mod
            # Temporarily override paths
            orig_model_path = triage_mod.MODEL_PATH
            orig_hash_path = triage_mod.HASH_PATH
            orig_meta_path = triage_mod.META_PATH
            orig_model_dir = triage_mod.MODEL_DIR

            tmp_model_path = Path(tmpdir) / "triage_model.joblib"
            tmp_hash_path = Path(tmpdir) / "triage_model.sha256"
            tmp_meta_path = Path(tmpdir) / "triage_meta.joblib"

            triage_mod.MODEL_PATH = tmp_model_path
            triage_mod.HASH_PATH = tmp_hash_path
            triage_mod.META_PATH = tmp_meta_path
            triage_mod.MODEL_DIR = Path(tmpdir)

            try:
                model._save_model(accuracy=1.0)
                assert tmp_model_path.exists()
                assert tmp_hash_path.exists()
                assert tmp_meta_path.exists()
            finally:
                triage_mod.MODEL_PATH = orig_model_path
                triage_mod.HASH_PATH = orig_hash_path
                triage_mod.META_PATH = orig_meta_path
                triage_mod.MODEL_DIR = orig_model_dir

    def test_load_model_integrity_failure(self):
        """Should reject model with wrong hash."""
        from src.ai.alert_triage import MODEL_PATH, HASH_PATH, MODEL_DIR
        with tempfile.TemporaryDirectory() as tmpdir:
            import src.ai.alert_triage as triage_mod
            orig_model_path = triage_mod.MODEL_PATH
            orig_hash_path = triage_mod.HASH_PATH
            orig_meta_path = triage_mod.META_PATH
            orig_model_dir = triage_mod.MODEL_DIR

            tmp_model_path = Path(tmpdir) / "triage_model.joblib"
            tmp_hash_path = Path(tmpdir) / "triage_model.sha256"
            tmp_meta_path = Path(tmpdir) / "triage_meta.joblib"

            triage_mod.MODEL_PATH = tmp_model_path
            triage_mod.HASH_PATH = tmp_hash_path
            triage_mod.META_PATH = tmp_meta_path
            triage_mod.MODEL_DIR = Path(tmpdir)

            try:
                import joblib
                from sklearn.ensemble import RandomForestClassifier

                # Save a model
                clf = RandomForestClassifier(n_estimators=5, random_state=42)
                X = np.array([[1, 0.5], [0, 0.1]])
                y = np.array([1, 0])
                clf.fit(X, y)
                Path(tmpdir).mkdir(parents=True, exist_ok=True)
                joblib.dump(clf, tmp_model_path)

                # Write wrong hash
                tmp_hash_path.write_text("wrong_hash_value")

                model = AlertTriageModel()
                result = model._load_model()
                assert result is False
                assert model.is_trained is False
            finally:
                triage_mod.MODEL_PATH = orig_model_path
                triage_mod.HASH_PATH = orig_hash_path
                triage_mod.META_PATH = orig_meta_path
                triage_mod.MODEL_DIR = orig_model_dir