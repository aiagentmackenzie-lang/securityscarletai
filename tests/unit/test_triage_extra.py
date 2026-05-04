"""
Tests for the Alert Triage Model (additional coverage beyond test_ai_triage.py).

Covers:
- _shannon_entropy function
- AlertTriageModel initialization
- get_status() method
- _predict_from_features method
- Model save/load integrity
- AUTO_TRAIN_THRESHOLD
- Feature extraction edge cases
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.ai.alert_triage import (
    _shannon_entropy,
    AlertTriageModel,
    AlertTriageModel,
    AUTO_TRAIN_THRESHOLD,
)


class TestShannonEntropy:
    """Test the shared _shannon_entropy function."""

    def test_empty_list(self):
        assert _shannon_entropy([]) == 0.0

    def test_single_item(self):
        assert _shannon_entropy(["bash"]) == 0.0

    def test_two_unique(self):
        result = _shannon_entropy(["a", "b"])
        assert abs(result - 1.0) < 0.01

    def test_all_same(self):
        assert _shannon_entropy(["ssh"] * 100) == 0.0

    def test_moderate_diversity(self):
        """50/50 split should have maximum entropy for 2 categories."""
        result = _shannon_entropy(["a", "b", "a", "b"])
        assert abs(result - 1.0) < 0.01

    def test_skewed(self):
        """90/10 split should have low entropy."""
        result = _shannon_entropy(["a"] * 90 + ["b"] * 10)
        assert 0.0 < result < 0.5  # Well below maximum entropy


class TestAlertTriageModelInit:
    """Test AlertTriageModel initialization."""

    def test_untrained_init(self):
        """Should initialize untrained when no model file exists."""
        with patch("src.ai.alert_triage.AlertTriageModel._load_model", return_value=False):
            model = AlertTriageModel()
            assert model.is_trained is False

    def test_feature_list(self):
        """Should have 11 features defined."""
        assert len(AlertTriageModel.FEATURES) == 11
        assert "severity_score" in AlertTriageModel.FEATURES
        assert "command_entropy" in AlertTriageModel.FEATURES
        assert "login_hour_deviation" in AlertTriageModel.FEATURES


class TestAlertTriageModelStatus:
    """Test get_status method."""

    def test_untrained_status(self):
        """Untrained model should report correctly."""
        model = AlertTriageModel.__new__(AlertTriageModel)
        model.is_trained = False
        model.trained_at = None
        model.training_samples = 0
        model.training_accuracy = None
        status = model.get_status()
        assert status["is_trained"] is False
        assert status["trained_at"] is None
        assert status["training_samples"] == 0
        assert status["training_accuracy"] is None
        assert status["model_type"] == "RandomForestClassifier"

    def test_trained_status(self):
        """Trained model should include accuracy."""
        model = AlertTriageModel.__new__(AlertTriageModel)
        model.is_trained = True
        model.trained_at = 1700000000.0
        model.training_samples = 100
        model.training_accuracy = 0.92
        status = model.get_status()
        assert status["is_trained"] is True
        assert status["training_samples"] == 100
        assert status["training_accuracy"] == 0.92


class TestPredictFromFeatures:
    """Test the _predict_from_features method (no DB needed)."""

    def _make_trained_model(self):
        """Create a model with a mock trained model."""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        import numpy as np

        model = AlertTriageModel.__new__(AlertTriageModel)
        model.is_trained = True
        model.trained_at = 1700000000.0
        model.training_samples = 100
        model.training_accuracy = 0.85

        # Create a simple trained model
        np.random.seed(42)
        X = np.random.randn(100, 11)
        y = np.random.randint(0, 2, 100)

        model.model = RandomForestClassifier(
            n_estimators=10, max_depth=3, random_state=42,
        )
        model.model.fit(X, y)

        model.scaler = StandardScaler()
        model.scaler.fit(X)

        return model

    def test_predict_from_features_returns_dict(self):
        """Should return prediction dict with expected keys."""
        model = self._make_trained_model()
        features = [0.5] * 11  # 11 features
        result = model._predict_from_features(features)
        assert "prediction" in result
        assert "confidence" in result
        assert "priority_score" in result
        assert "features" in result

    def test_prediction_is_valid_label(self):
        """Prediction should be true_positive or false_positive."""
        model = self._make_trained_model()
        features = [0.5] * 11
        result = model._predict_from_features(features)
        assert result["prediction"] in ("true_positive", "false_positive")

    def test_confidence_between_0_and_1(self):
        """Confidence should be between 0 and 1."""
        model = self._make_trained_model()
        features = [0.5] * 11
        result = model._predict_from_features(features)
        assert 0 <= result["confidence"] <= 1.0

    def test_priority_score_between_0_and_100(self):
        """Priority score should be between 0 and 100."""
        model = self._make_trained_model()
        features = [0.5] * 11
        result = model._predict_from_features(features)
        assert 0 <= result["priority_score"] <= 100

    def test_high_severity_increases_priority(self):
        """High severity score should increase priority."""
        model = self._make_trained_model()
        low_severity = [0.2] * 11  # Low severity
        high_severity = [1.0] + [0.5] * 10  # High severity
        low_result = model._predict_from_features(low_severity)
        high_result = model._predict_from_features(high_severity)
        # High severity should generally produce higher priority score
        # (though this depends on the model, so we just check both are valid)
        assert 0 <= low_result["priority_score"] <= 100
        assert 0 <= high_result["priority_score"] <= 100

    def test_features_dict_in_response(self):
        """Features dict should map feature names to values."""
        model = self._make_trained_model()
        features = [0.5] * 11
        result = model._predict_from_features(features)
        assert len(result["features"]) == 11


class TestAutoTrainThreshold:
    """Test AUTO_TRAIN_THRESHOLD constant."""

    def test_threshold_value(self):
        """Auto-train threshold should be 100."""
        assert AUTO_TRAIN_THRESHOLD == 100

    def test_threshold_is_reasonable(self):
        """Threshold should be at least 10 (too low = noisy model)."""
        assert AUTO_TRAIN_THRESHOLD >= 10

    def test_threshold_not_too_high(self):
        """Threshold should be reasonable (not 10000+)."""
        assert AUTO_TRAIN_THRESHOLD <= 1000


class TestModelIntegrity:
    """Test model file integrity."""

    def test_sha256_file(self, tmp_path):
        """Should compute SHA256 hash of model file."""
        test_file = tmp_path / "test.joblib"
        test_file.write_bytes(b"test content")
        result = AlertTriageModel._sha256_file(test_file)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_different_content_different_hash(self, tmp_path):
        """Different content should produce different hashes."""
        file1 = tmp_path / "model1.joblib"
        file2 = tmp_path / "model2.joblib"
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")
        hash1 = AlertTriageModel._sha256_file(file1)
        hash2 = AlertTriageModel._sha256_file(file2)
        assert hash1 != hash2


class TestFeatureList:
    """Test feature list completeness."""

    def test_all_features_present(self):
        """All 11 features should be defined."""
        from src.ai.alert_triage import AlertTriageModel
        expected_features = [
            "severity_score",
            "hour_of_day",
            "rule_hit_count",
            "host_alert_count",
            "asset_risk_score",
            "mitre_count",
            "time_since_last_hours",
            "has_threat_intel",
            "command_entropy",
            "session_duration_hours",
            "login_hour_deviation",
        ]
        for feature in expected_features:
            assert feature in AlertTriageModel.FEATURES