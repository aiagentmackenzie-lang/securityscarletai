"""
Alert Triage ML Model — v2 (Phase 3).

Classifies alerts as true positive or false positive,
and prioritizes alerts for analyst review.

Changes from Phase 0:
- joblib + SHA256 integrity (already done)
- Real feature engineering (Shannon entropy, session duration, login hour)
- Auto-training trigger when 100+ resolved alerts
- Model training + status API endpoints
- Fallback when Ollama is down
"""
import hashlib
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.triage")

# Model persistence — use project-local directory, gitignored
MODEL_DIR = Path(__file__).parent.parent.parent / "models"
MODEL_PATH = MODEL_DIR / "triage_model.joblib"
HASH_PATH = MODEL_DIR / "triage_model.sha256"
META_PATH = MODEL_DIR / "triage_meta.joblib"

# Auto-training threshold
AUTO_TRAIN_THRESHOLD = 100


def _shannon_entropy(values: List[str]) -> float:
    """
    Calculate Shannon entropy of a list of string values.

    Higher entropy = more diverse = more suspicious for process names.
    Range: 0 (all same) to log2(N) (uniform distribution).
    Normalized to 0-1 by dividing by max possible entropy.
    """
    if not values:
        return 0.0

    # Count frequency of each unique value
    freq: Dict[str, int] = {}
    for v in values:
        freq[v] = freq.get(v, 0) + 1

    total = len(values)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    # Normalize: max entropy is log2(N) where N = number of unique values
    max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0
    return entropy / max_entropy if max_entropy > 0 else 0.0


class AlertTriageModel:
    """ML model for alert triage and prioritization."""

    FEATURES = [
        "severity_score",           # 0-1 based on severity
        "hour_of_day",             # Normalized hour (0-1)
        "rule_hit_count",          # How often this rule fires
        "host_alert_count",        # Host's historical alert count
        "asset_risk_score",        # Host risk score
        "mitre_count",             # Number of MITRE techniques
        "time_since_last_hours",   # Hours since last similar alert
        "has_threat_intel",         # Boolean: TI match
        "command_entropy",         # Shannon entropy of recent process names
        "session_duration_hours",  # Duration of user session
        "login_hour_deviation",     # Deviation from normal login hour
    ]

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.is_trained = False
        self.trained_at: Optional[float] = None
        self.training_samples: int = 0
        self.training_accuracy: Optional[float] = None

        self._load_model()

    @staticmethod
    def _sha256_file(filepath: Path) -> str:
        """Calculate SHA256 hash of a file for integrity verification."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _load_model(self) -> bool:
        """Load trained model from disk with integrity verification."""
        try:
            if MODEL_PATH.exists() and HASH_PATH.exists():
                # Verify integrity before loading
                stored_hash = HASH_PATH.read_text().strip()
                current_hash = self._sha256_file(MODEL_PATH)
                if stored_hash != current_hash:
                    log.warning(
                        "triage_model_integrity_check_failed",
                        stored=stored_hash[:16],
                        current=current_hash[:16],
                    )
                    return False

                self.model = joblib.load(MODEL_PATH)
                self.is_trained = True

                # Load metadata if available
                if META_PATH.exists():
                    meta = joblib.load(META_PATH)
                    self.trained_at = meta.get("trained_at")
                    self.training_samples = meta.get("training_samples", 0)
                    self.training_accuracy = meta.get("accuracy")

                log.info("triage_model_loaded", samples=self.training_samples)
                return True
        except Exception as e:
            log.warning("triage_model_load_failed", error=str(e))
        return False

    def _save_model(self, accuracy: Optional[float] = None) -> None:
        """Save trained model to disk with integrity hash and metadata."""
        if self.model:
            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, MODEL_PATH)

            # Save metadata
            meta = {
                "trained_at": self.trained_at,
                "training_samples": self.training_samples,
                "accuracy": accuracy,
                "features": self.FEATURES,
            }
            joblib.dump(meta, META_PATH)

            # Save integrity hash
            model_hash = self._sha256_file(MODEL_PATH)
            HASH_PATH.write_text(model_hash)
            log.info("triage_model_saved", hash=model_hash[:16])

    async def extract_features(self, alert_id: int) -> Optional[List[float]]:
        """Extract feature vector from an alert with real feature engineering."""
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Get alert details
            alert = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id = $1",
                alert_id,
            )
            if not alert:
                return None

            # --- Basic features ---

            # Severity score
            severity_map = {
                "critical": 1.0, "high": 0.8, "medium": 0.5,
                "low": 0.2, "info": 0.0,
            }
            severity_score = severity_map.get(
                alert["severity"].lower() if alert["severity"] else "info", 0.0
            )

            # Hour of day (normalized 0-1)
            alert_time = alert["time"]
            if isinstance(alert_time, str):
                alert_time = datetime.fromisoformat(
                    alert_time.replace("Z", "+00:00")
                )
            hour_of_day = alert_time.hour if hasattr(alert_time, "hour") else 12

            # Rule hit count (how often this rule fires)
            rule_hits = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE rule_id = $1",
                alert["rule_id"],
            )
            rule_hit_normalized = min((rule_hits or 0) / 100, 1.0)

            # Host alert count (24h)
            host_alerts = await conn.fetchval(
                """
                SELECT COUNT(*) FROM alerts
                WHERE host_name = $1 AND time > NOW() - INTERVAL '24 hours'
                """,
                alert["host_name"],
            )
            host_alert_normalized = min((host_alerts or 0) / 20, 1.0)

            # Asset risk score
            asset_risk = await conn.fetchval(
                "SELECT COALESCE(risk_score, 50) FROM assets WHERE hostname = $1",
                alert["host_name"],
            ) or 50.0
            asset_risk_normalized = asset_risk / 100.0

            # MITRE technique count
            mitre_techniques = alert["mitre_techniques"] or []
            mitre_normalized = min(len(mitre_techniques) / 5, 1.0)

            # Time since last similar alert (in hours, normalized)
            last_similar = await conn.fetchval(
                """
                SELECT MAX(time) FROM alerts
                WHERE rule_id = $1 AND id != $2 AND time < $3
                """,
                alert["rule_id"],
                alert_id,
                alert["time"],
            )
            if last_similar:
                delta = alert_time - last_similar
                if hasattr(delta, "total_seconds"):
                    seconds = delta.total_seconds()
                    time_since_hours = max(seconds / 3600, 0)
                else:
                    time_since_hours = 1.0
            else:
                time_since_hours = 168.0  # 1 week = "never seen before"
            time_since_normalized = min(time_since_hours / 168, 1.0)

            # Threat intel match
            has_ti = 1.0 if alert.get("evidence") and "threat_intel" in str(
                alert["evidence"]
            ) else 0.0

            # --- Real UEBA features ---

            # 1. Command diversity (Shannon entropy of process names)
            process_names = await conn.fetch(
                """
                SELECT DISTINCT process_name FROM logs
                WHERE host_name = $1
                  AND event_category = 'process'
                  AND time > NOW() - INTERVAL '1 hour'
                LIMIT 50
                """,
                alert["host_name"],
            )
            command_entropy = _shannon_entropy(
                [r["process_name"] for r in process_names if r["process_name"]]
            )

            # 2. Session duration
            # Find first and last event for this host in the last 24h
            session_times = await conn.fetchrow(
                """
                SELECT MIN(time) as first_event, MAX(time) as last_event
                FROM logs
                WHERE host_name = $1
                  AND time > NOW() - INTERVAL '24 hours'
                """,
                alert["host_name"],
            )
            if session_times and session_times["first_event"] and session_times["last_event"]:
                first = session_times["first_event"]
                last = session_times["last_event"]
                if hasattr(first, "timestamp") and hasattr(last, "timestamp"):
                    session_hours = (last.timestamp() - first.timestamp()) / 3600
                else:
                    session_hours = 8.0  # Default 8h
            else:
                session_hours = 0.0
            session_duration_normalized = min(session_hours / 24, 1.0)

            # 3. Login hour deviation (deviation from typical 9-5)
            # Check actual login time distribution for this host
            typical_hour = await conn.fetchval(
                """
                SELECT MODE() WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM time))
                FROM logs
                WHERE host_name = $1
                  AND event_category = 'authentication'
                  AND time > NOW() - INTERVAL '30 days'
                """,
                alert["host_name"],
            )
            if typical_hour is not None:
                hour_deviation = abs(hour_of_day - float(typical_hour))
                if hour_deviation > 12:
                    hour_deviation = 24 - hour_deviation
                login_hour_deviation = hour_deviation / 12.0  # Normalize to 0-1
            else:
                # No login history — use deviation from 9 AM (typical work hour)
                hour_deviation = abs(hour_of_day - 9)
                if hour_deviation > 12:
                    hour_deviation = 24 - hour_deviation
                login_hour_deviation = hour_deviation / 12.0

            return [
                severity_score,
                hour_of_day / 24.0,
                rule_hit_normalized,
                host_alert_normalized,
                asset_risk_normalized,
                mitre_normalized,
                time_since_normalized,
                has_ti,
                command_entropy,
                session_duration_normalized,
                login_hour_deviation,
            ]

    async def train(self, min_samples: int = 50) -> bool:
        """
        Train triage model on historical alerts.

        Uses resolved alerts (true_positive vs false_positive) as labels.
        Auto-triggered when 100+ resolved alerts exist.
        """
        log.info("triage_training_started")

        pool = await get_pool()
        async with pool.acquire() as conn:
            # Get resolved alerts for training
            rows = await conn.fetch(
                """
                SELECT id, status
                FROM alerts
                WHERE status IN ('resolved', 'false_positive', 'closed')
                  AND time > NOW() - INTERVAL '30 days'
                LIMIT 1000
                """,
            )

            if len(rows) < min_samples:
                log.warning(
                    "triage_training_insufficient_samples", count=len(rows)
                )
                return False

        # Extract features for each alert
        X = []
        y = []

        for row in rows:
            features = await self.extract_features(row["id"])
            if features:
                X.append(features)
                # Label: true_positive (1) vs false_positive (0)
                label = 1 if row["status"] in ["resolved", "closed"] else 0
                y.append(label)

        if len(X) < min_samples:
            log.warning(
                "triage_training_insufficient_features", count=len(X)
            )
            return False

        # Train model
        X_array = np.array(X)
        y_array = np.array(y)

        # Check class balance
        unique, counts = np.unique(y_array, return_counts=True)
        if len(unique) < 2:
            log.warning("triage_training_single_class", classes=unique.tolist())
            return False

        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42,
            class_weight="balanced",
        )
        self.model.fit(X_array, y_array)

        # Calculate training accuracy
        predictions = self.model.predict(X_array)
        accuracy = float(np.mean(predictions == y_array))

        self.is_trained = True
        self.trained_at = time.time()
        self.training_samples = len(X)
        self.training_accuracy = accuracy

        self._save_model(accuracy=accuracy)

        log.info(
            "triage_training_complete",
            samples=len(X),
            accuracy=round(accuracy, 2),
        )
        return True

    async def predict(self, alert_id: int) -> Dict[str, Any]:
        """
        Predict triage outcome for an alert.

        Returns:
            Dict with prediction, confidence, and priority score
        """
        if not self.is_trained:
            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "priority_score": 50.0,
                "reason": "Model not trained",
            }

        features = await self.extract_features(alert_id)
        if not features:
            return {
                "prediction": "error",
                "confidence": 0.0,
                "priority_score": 50.0,
                "reason": "Feature extraction failed",
            }

        return self._predict_from_features(features)

    def _predict_from_features(self, features: List[float]) -> Dict[str, Any]:
        """Predict from a feature vector (internal use, no DB call)."""
        X = np.array([features])
        prediction = self.model.predict(X)[0]  # type: ignore[union-attr]
        probabilities = self.model.predict_proba(X)[0]  # type: ignore[union-attr]
        confidence = float(max(probabilities))

        # Calculate priority score (0-100)
        # Higher = more urgent to investigate
        severity_score = features[0]  # First feature is severity
        base_priority = severity_score * 50.0

        # Adjust based on prediction
        if prediction == 1:  # True positive
            base_priority += 30.0
        else:  # False positive
            base_priority -= 20.0

        # Adjust based on confidence
        if confidence > 0.8:
            base_priority += 10.0
        elif confidence < 0.6:
            base_priority -= 5.0

        # Adjust for UEBA features
        command_entropy = features[8]  # High entropy = more suspicious
        login_deviation = features[10]  # Non-standard hours = more suspicious

        base_priority += command_entropy * 10.0
        base_priority += login_deviation * 10.0

        priority_score = max(0, min(100, base_priority))

        # Feature names for interpretability
        feature_dict = dict(zip(self.FEATURES, features))

        return {
            "prediction": "true_positive" if prediction == 1 else "false_positive",
            "confidence": round(confidence, 2),
            "priority_score": round(priority_score, 2),
            "features": feature_dict,
        }

    async def get_priority_queue(self, limit: int = 50) -> List[Dict]:
        """
        Get alerts prioritized by ML model.

        Returns alerts sorted by priority score (highest first).
        """
        if not self.is_trained:
            return []

        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, rule_name, severity, host_name, time
                FROM alerts
                WHERE status = 'new'
                  AND time > NOW() - INTERVAL '24 hours'
                ORDER BY time DESC
                LIMIT $1
                """,
                limit,
            )

        scored_alerts = []
        for row in rows:
            prediction = await self.predict(row["id"])
            scored_alerts.append({
                **dict(row),
                **prediction,
            })

        scored_alerts.sort(key=lambda x: x["priority_score"], reverse=True)
        return scored_alerts

    def get_status(self) -> Dict[str, Any]:
        """Get model status for API endpoint."""
        return {
            "is_trained": self.is_trained,
            "trained_at": (
                datetime.fromtimestamp(
                    self.trained_at, tz=timezone.utc
                ).isoformat()
                if self.trained_at
                else None
            ),
            "training_samples": self.training_samples,
            "training_accuracy": (
                round(self.training_accuracy, 2)
                if self.training_accuracy is not None
                else None
            ),
            "features": self.FEATURES,
            "model_type": "RandomForestClassifier",
            "model_path": str(MODEL_PATH) if MODEL_PATH.exists() else None,
        }


async def check_auto_train() -> bool:
    """
    Check if auto-training should be triggered.

    Returns True if training was triggered.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        resolved_count = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status IN ('resolved', 'false_positive', 'closed')
            """
        )

    if (resolved_count or 0) >= AUTO_TRAIN_THRESHOLD:
        log.info(
            "auto_train_triggered",
            resolved_count=resolved_count,
            threshold=AUTO_TRAIN_THRESHOLD,
        )
        model = await get_triage_model()
        return await model.train()

    return False


# Global instance
_triage_model: Optional[AlertTriageModel] = None


async def get_triage_model() -> AlertTriageModel:
    """Get singleton triage model instance."""
    global _triage_model
    if _triage_model is None:
        _triage_model = AlertTriageModel()
        if not _triage_model.is_trained:
            await _triage_model.train()
    return _triage_model
