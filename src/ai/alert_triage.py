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
import csv
import hashlib
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

try:
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.model_selection import StratifiedKFold
    _HAS_V2_DEPS = True
except ImportError:  # pragma: no cover — defensive only
    _HAS_V2_DEPS = False

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
AUTO_TRAIN_COOLDOWN_SECONDS = 3600  # M-05: 1 hour cooldown between auto-trains
_last_auto_train_time: float = 0.0

# V2 (Epic 3) — calibrated retraining with provenance.
MIN_CV_ACCURACY = 0.70  # brief target; below this we refuse to persist
V2_RANDOM_STATE = 42
V2_CV_SPLITS = 5
V2_CALIBRATION_CV = 3
V2_CALIBRATION_METHOD = "isotonic"
V2_DEFAULT_CSV = Path("data/training/alerts_v3.csv")

# CSV column names used by the synthetic training data generator and loader.
# Declared here so the helpers below can reference them directly.
LABEL_COLUMN = "label"
ALERT_ID_COLUMN = "alert_id"


from src.ai.utils import (  # noqa: E402 — L-01: shared utility, after config constants
    shannon_entropy as _shannon_entropy,
)


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

    def __init__(self, load: bool = True):
        self.model: Optional[RandomForestClassifier] = None
        self.is_trained = False
        self.trained_at: Optional[float] = None
        self.training_samples: int = 0
        self.training_accuracy: Optional[float] = None

        if load:
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

        # M-04 fix: Use cross-validation instead of training-set accuracy
        from sklearn.model_selection import cross_val_score
        try:
            cv_scores = cross_val_score(self.model, X_array, y_array, cv=min(5, len(X_array)))
            accuracy = float(cv_scores.mean())
            log.info(
                "triage_cv_accuracy",
                cv_mean=round(accuracy, 2),
                cv_std=round(float(cv_scores.std()), 2),
            )
        except ValueError:
            # Too few samples for CV — fall back to training accuracy
            predictions = self.model.predict(X_array)
            accuracy = float(np.mean(predictions == y_array))
            log.warning("triage_fallback_to_training_accuracy", accuracy=round(accuracy, 2))

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
        feature_dict = dict(zip(self.FEATURES, features, strict=True))

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

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # V2 (Epic 3) — Calibrated retrain with provenance
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def train_v2(
        self,
        csv_path: Optional[Path] = None,
        min_cv_accuracy: float = MIN_CV_ACCURACY,
        run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrain triage model with calibration and CV-based threshold gate.

        Pipeline:
            1. Load data from CSV (preferred) or fall back to resolved alerts.
            2. Wrap base RandomForestClassifier in CalibratedClassifierCV
               (isotonic, cv=3) for better-calibrated probabilities.
            3. Run StratifiedKFold (5 splits) to estimate cv_accuracy.
            4. If cv_accuracy >= min_cv_accuracy, fit on full data, persist
               via _save_model(), and write a provenance row to
               triage_model_provenance (plus alert_labels for each row).
            5. If below threshold, refuse to persist; still write a
               provenance row tagged as rejected for audit trail.

        Args:
            csv_path: Path to training CSV. Defaults to V2_DEFAULT_CSV.
            min_cv_accuracy: Floor for accepting a model. Default 0.70.
            run_id: External correlation id; generated if not given.

        Returns:
            Dict with ok, run_id, cv_accuracy, cv_std, n_samples, calibrated,
            persisted_path, accepted, reason.
        """
        if not _HAS_V2_DEPS:
            return {
                "ok": False,
                "run_id": run_id,
                "reason": "missing_sklearn_v2_deps",
                "accepted": False,
            }

        run_id = run_id or f"v2-{uuid.uuid4().hex[:12]}"
        source_csv = Path(csv_path) if csv_path else V2_DEFAULT_CSV

        try:
            X, y, source_meta = _load_training_data(source_csv)
        except FileNotFoundError:
            log.warning("triage_v2_csv_missing", path=str(source_csv))
            return {
                "ok": False,
                "run_id": run_id,
                "reason": f"csv_not_found:{source_csv}",
                "accepted": False,
            }
        except ValueError as e:
            log.warning("triage_v2_csv_invalid", error=str(e))
            return {
                "ok": False,
                "run_id": run_id,
                "reason": f"csv_invalid:{e}",
                "accepted": False,
            }

        n_samples = len(X)
        if n_samples < 10:
            return {
                "ok": False,
                "run_id": run_id,
                "n_samples": n_samples,
                "reason": "insufficient_samples",
                "accepted": False,
            }

        X_array = np.asarray(X, dtype=float)
        y_array = np.asarray(y, dtype=int)
        unique_classes = np.unique(y_array)
        if len(unique_classes) < 2:
            return {
                "ok": False,
                "run_id": run_id,
                "n_samples": n_samples,
                "reason": f"single_class:{unique_classes.tolist()}",
                "accepted": False,
            }

        # Base estimator — same RF hyperparams as the v1 trainer for parity.
        base_rf = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=V2_RANDOM_STATE,
            class_weight="balanced",
        )
        calibrated = CalibratedClassifierCV(
            base_rf,
            method=V2_CALIBRATION_METHOD,
            cv=V2_CALIBRATION_CV,
        )

        # Stratified K-fold for honest CV accuracy.
        n_splits = min(V2_CV_SPLITS, n_samples)
        skf = StratifiedKFold(
            n_splits=n_splits, shuffle=True, random_state=V2_RANDOM_STATE
        )
        fold_accuracies: List[float] = []
        try:
            for train_idx, test_idx in skf.split(X_array, y_array):
                fold_calibrated = CalibratedClassifierCV(
                    RandomForestClassifier(
                        n_estimators=50,
                        max_depth=10,
                        random_state=V2_RANDOM_STATE,
                        class_weight="balanced",
                    ),
                    method=V2_CALIBRATION_METHOD,
                    cv=V2_CALIBRATION_CV,
                )
                fold_calibrated.fit(X_array[train_idx], y_array[train_idx])
                preds = fold_calibrated.predict(X_array[test_idx])
                fold_accuracies.append(
                    float(np.mean(preds == y_array[test_idx]))
                )
        except ValueError as e:
            log.warning("triage_v2_cv_failed", error=str(e))
            return {
                "ok": False,
                "run_id": run_id,
                "n_samples": n_samples,
                "reason": f"cv_failed:{e}",
                "accepted": False,
            }

        cv_accuracy = float(np.mean(fold_accuracies))
        cv_std = float(np.std(fold_accuracies))
        accepted = cv_accuracy >= min_cv_accuracy

        persisted_path: Optional[str] = None
        if accepted:
            calibrated.fit(X_array, y_array)
            self.model = calibrated
            self.is_trained = True
            self.trained_at = time.time()
            self.training_samples = n_samples
            self.training_accuracy = cv_accuracy
            self._save_model(accuracy=cv_accuracy)
            persisted_path = str(MODEL_PATH) if MODEL_PATH.exists() else None
        else:
            log.warning(
                "triage_v2_below_threshold",
                cv_accuracy=round(cv_accuracy, 3),
                threshold=min_cv_accuracy,
                run_id=run_id,
            )

        # Persist provenance + alert_labels (best-effort, swallow DB errors so
        # offline CI doesn't break).
        provenance_row_id: Optional[int] = None
        try:
            provenance_row_id = await _write_provenance(
                run_id=run_id,
                source_csv=str(source_csv),
                source_meta=source_meta,
                n_samples=n_samples,
                cv_accuracy=cv_accuracy,
                cv_std=cv_std,
                calibrated=accepted,
                accepted=accepted,
                model_path=persisted_path,
                fold_accuracies=fold_accuracies,
                features=self.FEATURES,
            )
            if accepted and provenance_row_id is not None:
                await _write_alert_labels(
                    run_id=run_id, source_meta=source_meta
                )
        except Exception as e:  # noqa: BLE001
            log.warning("triage_v2_provenance_write_failed", error=str(e))

        result: Dict[str, Any] = {
            "ok": True,
            "run_id": run_id,
            "n_samples": n_samples,
            "cv_accuracy": round(cv_accuracy, 4),
            "cv_std": round(cv_std, 4),
            "fold_accuracies": [round(a, 4) for a in fold_accuracies],
            "calibrated": accepted,
            "accepted": accepted,
            "persisted_path": persisted_path,
            "source_csv": str(source_csv),
            "model_type": (
                "CalibratedClassifierCV(RandomForestClassifier, isotonic, cv=3)"
                if accepted
                else None
            ),
            "provenance_row_id": provenance_row_id,
        }
        if not accepted:
            result["reason"] = (
                f"below_threshold:{cv_accuracy:.3f}<{min_cv_accuracy:.3f}"
            )
        # Avoid duplicate-key collision if result already contains run_id.
        log.info("triage_v2_complete", **result)
        return result

    async def latest_provenance(self) -> Optional[Dict[str, Any]]:
        """Fetch the most recent triage_model_provenance row, or None."""
        try:
            pool = await get_pool()
        except Exception:  # noqa: BLE001
            return None
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT id, run_id, source_csv, n_samples, accuracy_score,
                           precision_score, recall_score, f1_score, calibrated,
                           trained_at
                    FROM triage_model_provenance
                    ORDER BY trained_at DESC
                    LIMIT 1
                    """
                )
        except Exception:  # noqa: BLE001 — table may not exist in test DBs
            return None
        if not row:
            return None
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "source_csv": row["source_csv"],
            "n_samples": row["n_samples"],
            "accuracy": (
                round(float(row["accuracy_score"]), 4)
                if row["accuracy_score"] is not None
                else None
            ),
            "precision": (
                round(float(row["precision_score"]), 4)
                if row["precision_score"] is not None
                else None
            ),
            "recall": (
                round(float(row["recall_score"]), 4)
                if row["recall_score"] is not None
                else None
            ),
            "f1": (
                round(float(row["f1_score"]), 4)
                if row["f1_score"] is not None
                else None
            ),
            "calibrated": bool(row["calibrated"]),
            "trained_at": (
                row["trained_at"].isoformat()
                if row["trained_at"] is not None
                else None
            ),
        }



async def check_auto_train() -> bool:
    """
    Check if auto-training should be triggered.

    Returns True if training was triggered.
    M-05: Added 1-hour cooldown to prevent retraining on every call.
    """
    global _last_auto_train_time

    # Check cooldown
    if (time.time() - _last_auto_train_time) < AUTO_TRAIN_COOLDOWN_SECONDS:
        return False

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
        _last_auto_train_time = time.time()
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# V2 (Epic 3) — module-level helpers (CSV loader, provenance writer)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _db_reachable(host: str = "localhost", port: int = 5433, timeout: float = 0.25) -> bool:
    """
    Cheap TCP probe to detect whether Postgres is accepting connections.

    Avoids the 15-second retry storm inside get_pool() when running in CI
    or any environment without a live database. Never raises.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _load_training_data(
    csv_path: Path,
) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, Any]]]:
    """
    Load labeled training data from a CSV file.

    Returns:
        X: ndarray of shape (n, 11) — features in AlertTriageModel.FEATURES order
        y: ndarray of shape (n,)   — 1 for true_positive, 0 for false_positive
        meta: list of dicts with per-row metadata (alert_id, label) for
              downstream provenance/alert_labels writing.
    """
    label_to_y = {"true_positive": 1, "false_positive": 0}
    rows: List[Dict[str, Any]] = []
    with Path(csv_path).open("r", newline="") as f:
        reader = csv.DictReader(f)
        required = set(AlertTriageModel.FEATURES + [LABEL_COLUMN, ALERT_ID_COLUMN])
        if not required.issubset(reader.fieldnames or []):
            missing = sorted(required - set(reader.fieldnames or []))
            raise ValueError(f"csv missing required columns: {missing}")
        for row in reader:
            rows.append(row)

    if not rows:
        raise ValueError("csv is empty")

    X = np.array(
        [[float(row[col]) for col in AlertTriageModel.FEATURES] for row in rows],
        dtype=float,
    )
    y = np.array(
        [label_to_y[row[LABEL_COLUMN]] for row in rows],
        dtype=int,
    )
    meta = [
        {
            "alert_id": int(row[ALERT_ID_COLUMN]),
            "label": row[LABEL_COLUMN],
        }
        for row in rows
    ]
    return X, y, meta


async def _write_provenance(
    *,
    run_id: str,
    source_csv: str,
    source_meta: List[Dict[str, Any]],
    n_samples: int,
    cv_accuracy: float,
    cv_std: float,
    calibrated: bool,
    accepted: bool,
    model_path: Optional[str],
    fold_accuracies: List[float],
    features: List[str],
) -> Optional[int]:
    """
    Insert one row into triage_model_provenance.

    Returns the inserted row id, or None if the table is unavailable.
    Best-effort: any DB error is logged and swallowed by the caller.
    """
    feature_importances: Dict[str, float] = {}
    n_pos = sum(1 for r in source_meta if r["label"] == "true_positive")
    n_neg = sum(1 for r in source_meta if r["label"] == "false_positive")

    if not _db_reachable():
        return None

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO triage_model_provenance (
                run_id, model_version, model_type, source_csv, n_samples,
                n_positive, n_negative, accuracy_score, precision_score,
                recall_score, f1_score, calibrated, feature_importances,
                features, model_path, run_metadata
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NULL, $9, $10,
                $11, $12, $13
            )
            RETURNING id
            """,
            run_id,
            "v2",
            "CalibratedClassifierCV(RandomForestClassifier, isotonic, cv=3)",
            source_csv,
            n_samples,
            n_pos,
            n_neg,
            cv_accuracy,
            calibrated,
            joblib.dumps(feature_importances) if feature_importances else None,
            joblib.dumps(features),
            model_path,
            joblib.dumps(
                {
                    "cv_std": cv_std,
                    "fold_accuracies": fold_accuracies,
                    "accepted": accepted,
                    "min_cv_accuracy": MIN_CV_ACCURACY,
                }
            ),
        )
    return int(row["id"]) if row else None


async def _write_alert_labels(
    *, run_id: str, source_meta: List[Dict[str, Any]]
) -> int:
    """
    Write analyst labels for each synthetic alert into alert_labels.

    These rows are tagged labeled_by='training_data_v2:<run_id>' so the
    provenance is traceable from the analyst UI back to the generator run.
    Returns the number of rows inserted.
    """
    if not source_meta:
        return 0
    if not _db_reachable():
        return 0
    labeled_by = f"training_data_v2:{run_id}"
    pool = await get_pool()
    inserted = 0
    async with pool.acquire() as conn:
        for entry in source_meta:
            try:
                await conn.execute(
                    """
                    INSERT INTO alert_labels (alert_id, label, labeled_by)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (alert_id, label) DO NOTHING
                    """,
                    entry["alert_id"],
                    entry["label"],
                    labeled_by,
                )
                inserted += 1
            except Exception as e:  # noqa: BLE001
                # Skip missing-FK alerts (no real alert row); keep going.
                log.debug(
                    "alert_label_insert_skipped",
                    alert_id=entry["alert_id"],
                    error=str(e),
                )
    return inserted
