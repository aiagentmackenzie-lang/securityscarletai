"""
UEBA (User and Entity Behavior Analytics) baseline using Isolation Forest — v2 (Phase 3).

Learns "normal" user behavior and flags anomalies for insider threat detection.

Changes from Phase 0:
- Replaced placeholder features with real calculations:
  - command_diversity: Shannon entropy of process names
  - session_duration_minutes: derived from first/last event timestamps
  - login_hour_of_day: actual mode of login hour distribution
- joblib + SHA256 integrity (already from Phase 0)
- Model status API endpoint
"""
import hashlib
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.ueba")

# Model persistence — use project-local directory, gitignored
MODEL_DIR = Path(__file__).parent.parent.parent / "models"
MODEL_PATH = MODEL_DIR / "ueba_model.joblib"
SCALER_PATH = MODEL_DIR / "ueba_scaler.joblib"
HASH_PATH = MODEL_DIR / "ueba_model.sha256"
META_PATH = MODEL_DIR / "ueba_meta.joblib"


def _shannon_entropy(values: List[str]) -> float:
    """Calculate Shannon entropy of a list of strings. Normalized 0-1."""
    if not values:
        return 0.0
    freq: Dict[str, int] = {}
    for v in values:
        freq[v] = freq.get(v, 0) + 1
    total = len(values)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0
    return entropy / max_entropy if max_entropy > 0 else 0.0


# Features to extract per user per day (updated with real calculations)
UEBA_FEATURES = [
    "login_hour_of_day",           # Most common login hour (normalized)
    "unique_processes_count",       # How many distinct processes
    "command_diversity",            # Shannon entropy of process names (real)
    "network_connections_count",    # Outbound connections
    "unique_destination_ips",      # Distinct IPs connected to
    "file_access_count",           # File operations
    "sudo_usage_count",            # Privilege escalations
    "session_duration_minutes",   # Session length (real, not placeholder)
]


class UEBABaseline:
    """UEBA behavior baseline with Isolation Forest."""

    def __init__(self, contamination: float = 0.05):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.contamination = contamination
        self.is_trained = False
        self.trained_at: Optional[float] = None
        self.training_samples: int = 0

        # Try to load existing model
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
            if MODEL_PATH.exists() and SCALER_PATH.exists():
                # Verify integrity before loading
                if HASH_PATH.exists():
                    stored_hash = HASH_PATH.read_text().strip()
                    current_hash = self._sha256_file(MODEL_PATH)
                    if stored_hash != current_hash:
                        log.warning(
                            "ueba_model_integrity_check_failed",
                            stored=stored_hash[:16],
                            current=current_hash[:16],
                        )
                        return False

                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                self.is_trained = True

                # Load metadata
                if META_PATH.exists():
                    meta = joblib.load(META_PATH)
                    self.trained_at = meta.get("trained_at")
                    self.training_samples = meta.get("training_samples", 0)

                log.info("ueba_model_loaded", samples=self.training_samples)
                return True
        except Exception as e:
            log.warning("ueba_model_load_failed", error=str(e))
        return False

    def _save_model(self) -> None:
        """Save trained model to disk with integrity hash and metadata."""
        if self.model and self.scaler:
            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, MODEL_PATH)
            joblib.dump(self.scaler, SCALER_PATH)

            # Save metadata
            meta = {
                "trained_at": self.trained_at,
                "training_samples": self.training_samples,
                "contamination": self.contamination,
                "features": UEBA_FEATURES,
            }
            joblib.dump(meta, META_PATH)

            model_hash = self._sha256_file(MODEL_PATH)
            HASH_PATH.write_text(model_hash)
            log.info("ueba_model_saved", hash=model_hash[:16])

    async def extract_user_features(
        self,
        user_name: str,
        days: int = 7,
    ) -> Optional[Dict[str, float]]:
        """Extract behavior features for a single user (real calculations)."""
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Login hour — use MODE (most common hour) from actual data
            login_hour = await conn.fetchval(
                """
                SELECT MODE() WITHIN GROUP (
                    ORDER BY EXTRACT(HOUR FROM time)
                )
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'authentication'
                  AND time > NOW() - INTERVAL '1 day' * $2
                """,
                user_name,
                days,
            )
            # Default to 9 AM if no auth data
            login_hour = float(login_hour) if login_hour is not None else 9.0

            # Unique processes
            unique_processes = await conn.fetchval(
                """
                SELECT COUNT(DISTINCT process_name)
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'process'
                  AND time > NOW() - INTERVAL '1 day' * $2
                """,
                user_name,
                days,
            ) or 0

            # Command diversity — Shannon entropy of process names (REAL)
            process_rows = await conn.fetch(
                """
                SELECT process_name
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'process'
                  AND process_name IS NOT NULL
                  AND time > NOW() - INTERVAL '1 day' * $2
                LIMIT 1000
                """,
                user_name,
                days,
            )
            process_names = [r["process_name"] for r in process_rows]
            command_diversity = _shannon_entropy(process_names)

            # Network connections
            network_count = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'network'
                  AND time > NOW() - INTERVAL '1 day' * $2
                """,
                user_name,
                days,
            ) or 0

            # Unique destination IPs
            unique_ips = await conn.fetchval(
                """
                SELECT COUNT(DISTINCT destination_ip)
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'network'
                  AND destination_ip IS NOT NULL
                  AND time > NOW() - INTERVAL '1 day' * $2
                """,
                user_name,
                days,
            ) or 0

            # File operations
            file_count = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'file'
                  AND time > NOW() - INTERVAL '1 day' * $2
                """,
                user_name,
                days,
            ) or 0

            # Sudo usage
            sudo_count = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'process'
                  AND (
                    normalized->>'process_cmdline' ILIKE '%sudo%'
                    OR process_name = 'sudo'
                  )
                  AND time > NOW() - INTERVAL '1 day' * $2
                """,
                user_name,
                days,
            ) or 0

            # Session duration — derived from first/last event (REAL)
            session_times = await conn.fetchrow(
                """
                SELECT MIN(time) as first_event,
                       MAX(time) as last_event
                FROM logs
                WHERE user_name = $1
                  AND time > NOW() - INTERVAL '1 day' * $2
                """,
                user_name,
                days,
            )

            if (
                session_times
                and session_times["first_event"]
                and session_times["last_event"]
            ):
                first = session_times["first_event"]
                last = session_times["last_event"]
                if hasattr(first, "timestamp") and hasattr(last, "timestamp"):
                    session_minutes = (last.timestamp() - first.timestamp()) / 60
                else:
                    session_minutes = 480.0  # Default 8 hours
            else:
                session_minutes = 0.0

            return {
                "login_hour_of_day": float(login_hour),
                "unique_processes_count": float(unique_processes),
                "command_diversity": command_diversity,
                "network_connections_count": float(network_count),
                "unique_destination_ips": float(unique_ips),
                "file_access_count": float(file_count),
                "sudo_usage_count": float(sudo_count),
                "session_duration_minutes": float(session_minutes),
            }

    async def train(self, min_days: int = 7) -> bool:
        """
        Train UEBA model on historical data.

        Args:
            min_days: Minimum days of data required
        """
        log.info("ueba_training_started", min_days=min_days)

        # Get all users with sufficient data
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT user_name
                FROM logs
                WHERE user_name IS NOT NULL
                  AND time > NOW() - INTERVAL '1 day' * $1
                GROUP BY user_name
                HAVING COUNT(*) > 100
                """,
                min_days,
            )

            user_names = [r["user_name"] for r in rows]

        if len(user_names) < 3:
            log.warning("ueba_training_insufficient_data", users=len(user_names))
            return False

        # Extract features for each user
        feature_vectors = []
        for user in user_names:
            features = await self.extract_user_features(user, days=min_days)
            if features:
                feature_vectors.append([
                    features["login_hour_of_day"],
                    features["unique_processes_count"],
                    features["command_diversity"],
                    features["network_connections_count"],
                    features["unique_destination_ips"],
                    features["file_access_count"],
                    features["sudo_usage_count"],
                    features["session_duration_minutes"],
                ])

        if len(feature_vectors) < 3:
            log.warning(
                "ueba_training_insufficient_vectors", count=len(feature_vectors)
            )
            return False

        # Train model
        X = np.array(feature_vectors)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self.model.fit(X_scaled)

        self.is_trained = True
        self.trained_at = time.time()
        self.training_samples = len(feature_vectors)
        self._save_model()

        log.info("ueba_training_complete", users=len(feature_vectors))
        return True

    async def score_user(self, user_name: str) -> Dict[str, Any]:
        """
        Score a user's current behavior for anomalies.

        Returns:
            Dict with anomaly_score, is_anomaly, and feature_values
        """
        if not self.is_trained:
            return {
                "anomaly_score": None,
                "is_anomaly": False,
                "error": "Model not trained",
            }

        features = await self.extract_user_features(user_name, days=1)
        if not features:
            return {
                "anomaly_score": None,
                "is_anomaly": False,
                "error": "No data for user",
            }

        # Create feature vector
        X = np.array([[
            features["login_hour_of_day"],
            features["unique_processes_count"],
            features["command_diversity"],
            features["network_connections_count"],
            features["unique_destination_ips"],
            features["file_access_count"],
            features["sudo_usage_count"],
            features["session_duration_minutes"],
        ]])

        # Scale and predict
        X_scaled = self.scaler.transform(X)  # type: ignore[union-attr]

        # Anomaly score: -1 = anomaly, 1 = normal
        raw_score = self.model.decision_function(X_scaled)[0]  # type: ignore[union-attr]

        # Convert to 0-1 scale (1 = high anomaly)
        anomaly_score = 1 - (raw_score + 0.5)  # Normalize

        # Isolation Forest: -1 = anomaly, 1 = normal
        is_anomaly = self.model.predict(X_scaled)[0] == -1  # type: ignore[union-attr]

        return {
            "user_name": user_name,
            "anomaly_score": float(anomaly_score),
            "is_anomaly": bool(is_anomaly),
            "features": features,
        }

    async def get_high_risk_users(self, threshold: float = 0.8) -> List[Dict]:
        """Get users with high anomaly scores."""
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT user_name
                FROM logs
                WHERE user_name IS NOT NULL
                  AND time > NOW() - INTERVAL '1 day'
                """
            )
            user_names = [r["user_name"] for r in rows]

        high_risk = []
        for user in user_names:
            score = await self.score_user(user)
            if score["is_anomaly"] and score.get("anomaly_score", 0) >= threshold:
                high_risk.append(score)

        # Sort by anomaly score descending
        high_risk.sort(key=lambda x: x["anomaly_score"], reverse=True)
        return high_risk

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
            "contamination": self.contamination,
            "features": UEBA_FEATURES,
            "model_type": "IsolationForest",
            "model_path": str(MODEL_PATH) if MODEL_PATH.exists() else None,
        }


# Global instance
_ueba: Optional[UEBABaseline] = None


async def get_ueba() -> UEBABaseline:
    """Get singleton UEBA instance."""
    global _ueba
    if _ueba is None:
        _ueba = UEBABaseline()
        if not _ueba.is_trained:
            await _ueba.train()
    return _ueba
