"""
UEBA (User and Entity Behavior Analytics) baseline using Isolation Forest.

Learns "normal" user behavior and flags anomalies for insider threat detection.
"""
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.ueba")

# Model persistence
MODEL_PATH = Path.home() / ".scarletai_ueba_model.pkl"
SCALER_PATH = Path.home() / ".scarletai_ueba_scaler.pkl"

# Features to extract per user per day
UEBA_FEATURES = [
    "login_hour_of_day",           # What hour does this user normally log in?
    "unique_processes_count",       # How many distinct processes
    "command_diversity",            # Command entropy (0-1)
    "network_connections_count",    # Outbound connections
    "unique_destination_ips",       # Distinct IPs connected to
    "file_access_count",           # File operations
    "sudo_usage_count",            # Privilege escalations
    "session_duration_minutes",    # Session length
]


class UEBABaseline:
    """UEBA behavior baseline with Isolation Forest."""

    def __init__(self, contamination: float = 0.05):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.contamination = contamination
        self.is_trained = False

        # Try to load existing model
        self._load_model()

    def _load_model(self) -> bool:
        """Load trained model from disk."""
        try:
            if MODEL_PATH.exists() and SCALER_PATH.exists():
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, "rb") as f:
                    self.scaler = pickle.load(f)
                self.is_trained = True
                log.info("ueba_model_loaded")
                return True
        except Exception as e:
            log.warning("ueba_model_load_failed", error=str(e))
        return False

    def _save_model(self) -> None:
        """Save trained model to disk."""
        if self.model and self.scaler:
            with open(MODEL_PATH, "wb") as f:
                pickle.dump(self.model, f)
            with open(SCALER_PATH, "wb") as f:
                pickle.dump(self.scaler, f)
            log.info("ueba_model_saved")

    async def extract_user_features(
        self,
        user_name: str,
        days: int = 7,
    ) -> Optional[Dict[str, float]]:
        """Extract behavior features for a single user."""
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Login hour (most common)
            login_hour = await conn.fetchval(
                """
                SELECT MODE() WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM time))
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'authentication'
                  AND time > NOW() - INTERVAL '$2 days'
                """,
                user_name,
                days,
            ) or 9  # Default to 9 AM

            # Unique processes
            unique_processes = await conn.fetchval(
                """
                SELECT COUNT(DISTINCT process_name)
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'process'
                  AND time > NOW() - INTERVAL '$2 days'
                """,
                user_name,
                days,
            ) or 0

            # Network connections
            network_count = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE user_name = $1
                  AND event_category = 'network'
                  AND time > NOW() - INTERVAL '$2 days'
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
                  AND time > NOW() - INTERVAL '$2 days'
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
                  AND time > NOW() - INTERVAL '$2 days'
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
                  AND (process_cmdline ILIKE '%sudo%' OR process_name = 'sudo')
                  AND time > NOW() - INTERVAL '$2 days'
                """,
                user_name,
                days,
            ) or 0

            return {
                "login_hour_of_day": float(login_hour),
                "unique_processes_count": float(unique_processes),
                "command_diversity": 0.5,  # Placeholder - would calculate entropy
                "network_connections_count": float(network_count),
                "unique_destination_ips": float(unique_ips),
                "file_access_count": float(file_count),
                "sudo_usage_count": float(sudo_count),
                "session_duration_minutes": 480.0,  # Placeholder
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
                  AND time > NOW() - INTERVAL '$1 days'
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
            log.warning("ueba_training_insufficient_vectors", count=len(feature_vectors))
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
        X_scaled = self.scaler.transform(X)

        # Anomaly score: -1 = anomaly, 1 = normal
        raw_score = self.model.decision_function(X_scaled)[0]

        # Convert to 0-1 scale (1 = high anomaly)
        anomaly_score = 1 - (raw_score + 0.5)  # Normalize

        # Isolation Forest: -1 = anomaly, 1 = normal
        is_anomaly = self.model.predict(X_scaled)[0] == -1

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
            if score["is_anomaly"] and score["anomaly_score"] >= threshold:
                high_risk.append(score)

        # Sort by anomaly score descending
        high_risk.sort(key=lambda x: x["anomaly_score"], reverse=True)

        return high_risk


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
