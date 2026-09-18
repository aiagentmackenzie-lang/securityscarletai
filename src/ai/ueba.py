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

import asyncio
import hashlib
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


from src.ai.utils import (  # noqa: E402 — L-01: shared utility, after config constants
    shannon_entropy as _shannon_entropy,
)

# Features to extract per user per day (updated with real calculations)
UEBA_FEATURES = [
    "login_hour_of_day",  # Most common login hour (normalized)
    "unique_processes_count",  # How many distinct processes
    "command_diversity",  # Shannon entropy of process names (real)
    "network_connections_count",  # Outbound connections
    "unique_destination_ips",  # Distinct IPs connected to
    "file_access_count",  # File operations
    "sudo_usage_count",  # Privilege escalations
    "session_duration_minutes",  # Session length (real, not placeholder)
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
        """Extract behavior features for ONE user (7 queries).

        Kept for the single-user path (score_user); bulk consumers (train,
        get_high_risk_users) use extract_user_features_batch — AUD-025."""
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
            )

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
            )

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
            )

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
            )

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
            )

            # Session duration — derived from first/last event (REAL)
            # M-02: Note this is "activity span" not true session length.
            # True session boundaries require login/logout pairs which aren't
            # always available. Span is a reasonable proxy for UEBA anomaly detection.
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

            first_event = session_times["first_event"] if session_times else None
            last_event = session_times["last_event"] if session_times else None

        return self._user_features_from_rows(
            login_hour=login_hour,
            unique_processes=unique_processes,
            process_names=[r["process_name"] for r in process_rows],
            network_count=network_count,
            unique_ips=unique_ips,
            file_count=file_count,
            sudo_count=sudo_count,
            session_first=first_event,
            session_last=last_event,
        )

    @staticmethod
    def _user_features_from_rows(
        *,
        login_hour: Optional[float],
        unique_processes: Optional[int],
        process_names: List[Any],
        network_count: Optional[int],
        unique_ips: Optional[int],
        file_count: Optional[int],
        sudo_count: Optional[int],
        session_first: Optional[Any],
        session_last: Optional[Any],
    ) -> Dict[str, float]:
        """The per-user feature math from raw query rows (pure, DB-free).

        Single source for BOTH extract_user_features (7 queries per user)
        and extract_user_features_batch (8 queries per BATCH) — AUD-025.
        Math lifted verbatim from the original per-user implementation.
        """
        # Default to 9 AM if no auth data
        login_hour = float(login_hour) if login_hour is not None else 9.0
        command_diversity = _shannon_entropy(process_names)

        if session_first and session_last:
            if hasattr(session_first, "timestamp") and hasattr(session_last, "timestamp"):
                session_minutes = (session_last.timestamp() - session_first.timestamp()) / 60
            else:
                session_minutes = 480.0  # Default 8 hours
        else:
            session_minutes = 0.0

        return {
            "login_hour_of_day": float(login_hour),
            "unique_processes_count": float(unique_processes or 0),
            "command_diversity": command_diversity,
            "network_connections_count": float(network_count or 0),
            "unique_destination_ips": float(unique_ips or 0),
            "file_access_count": float(file_count or 0),
            "sudo_usage_count": float(sudo_count or 0),
            "session_duration_minutes": float(session_minutes),
        }

    async def extract_user_features_batch(
        self,
        user_names: List[str],
        days: int = 7,
    ) -> Dict[str, Dict[str, float]]:
        """Behavior features for a BATCH of users in 8 grouped queries.

        AUD-025: the per-user path costs 7 round-trips per user — a train()
        over N users issued 7×N sequential queries. This batches the same
        feature math over the whole batch (8 queries regardless of N). The
        math lives in _user_features_from_rows, shared with
        extract_user_features.
        """
        users = [u for u in dict.fromkeys(user_names) if u]
        if not users:
            return {}

        pool = await get_pool()
        async with pool.acquire() as conn:
            login_hour_rows = await conn.fetch(
                """
                SELECT user_name,
                       MODE() WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM time)) AS typical_hour
                FROM logs
                WHERE user_name = ANY($1::text[])
                  AND event_category = 'authentication'
                  AND time > NOW() - INTERVAL '1 day' * $2
                GROUP BY user_name
                """,
                users,
                days,
            )
            login_hour_by_user = {r["user_name"]: r["typical_hour"] for r in login_hour_rows}

            unique_process_rows = await conn.fetch(
                """
                SELECT user_name, COUNT(DISTINCT process_name) AS c
                FROM logs
                WHERE user_name = ANY($1::text[])
                  AND event_category = 'process'
                  AND time > NOW() - INTERVAL '1 day' * $2
                GROUP BY user_name
                """,
                users,
                days,
            )
            unique_processes_by_user = {r["user_name"]: r["c"] for r in unique_process_rows}

            process_rows = await conn.fetch(
                """
                SELECT u.user_name, p.process_name
                FROM (SELECT DISTINCT user_name FROM logs WHERE user_name = ANY($1::text[])) u
                CROSS JOIN LATERAL (
                    SELECT process_name
                    FROM logs
                    WHERE user_name = u.user_name
                      AND event_category = 'process'
                      AND process_name IS NOT NULL
                      AND time > NOW() - INTERVAL '1 day' * $2
                    LIMIT 1000
                ) p
                """,
                users,
                days,
            )
            process_names_by_user: Dict[str, List[Any]] = {}
            for r in process_rows:
                process_names_by_user.setdefault(r["user_name"], []).append(r["process_name"])

            network_rows = await conn.fetch(
                """
                SELECT user_name, COUNT(*) AS c
                FROM logs
                WHERE user_name = ANY($1::text[])
                  AND event_category = 'network'
                  AND time > NOW() - INTERVAL '1 day' * $2
                GROUP BY user_name
                """,
                users,
                days,
            )
            network_by_user = {r["user_name"]: r["c"] for r in network_rows}

            unique_ip_rows = await conn.fetch(
                """
                SELECT user_name, COUNT(DISTINCT destination_ip) AS c
                FROM logs
                WHERE user_name = ANY($1::text[])
                  AND event_category = 'network'
                  AND destination_ip IS NOT NULL
                  AND time > NOW() - INTERVAL '1 day' * $2
                GROUP BY user_name
                """,
                users,
                days,
            )
            unique_ips_by_user = {r["user_name"]: r["c"] for r in unique_ip_rows}

            file_rows = await conn.fetch(
                """
                SELECT user_name, COUNT(*) AS c
                FROM logs
                WHERE user_name = ANY($1::text[])
                  AND event_category = 'file'
                  AND time > NOW() - INTERVAL '1 day' * $2
                GROUP BY user_name
                """,
                users,
                days,
            )
            file_by_user = {r["user_name"]: r["c"] for r in file_rows}

            sudo_rows = await conn.fetch(
                """
                SELECT user_name, COUNT(*) AS c
                FROM logs
                WHERE user_name = ANY($1::text[])
                  AND event_category = 'process'
                  AND (
                    normalized->>'process_cmdline' ILIKE '%sudo%'
                    OR process_name = 'sudo'
                  )
                  AND time > NOW() - INTERVAL '1 day' * $2
                GROUP BY user_name
                """,
                users,
                days,
            )
            sudo_by_user = {r["user_name"]: r["c"] for r in sudo_rows}

            session_rows = await conn.fetch(
                """
                SELECT user_name, MIN(time) AS first_event, MAX(time) AS last_event
                FROM logs
                WHERE user_name = ANY($1::text[])
                  AND time > NOW() - INTERVAL '1 day' * $2
                GROUP BY user_name
                """,
                users,
                days,
            )
            session_by_user = {
                r["user_name"]: (r["first_event"], r["last_event"]) for r in session_rows
            }

        features: Dict[str, Dict[str, float]] = {}
        for user in users:
            first_event, last_event = session_by_user.get(user, (None, None))
            features[user] = self._user_features_from_rows(
                login_hour=login_hour_by_user.get(user),
                unique_processes=unique_processes_by_user.get(user),
                process_names=process_names_by_user.get(user, []),
                network_count=network_by_user.get(user),
                unique_ips=unique_ips_by_user.get(user),
                file_count=file_by_user.get(user),
                sudo_count=sudo_by_user.get(user),
                session_first=first_event,
                session_last=last_event,
            )
        return features

    @staticmethod
    def _feature_vector(features: Dict[str, float]) -> List[float]:
        """The 8-feature vector in UEBA_FEATURES order (single source)."""
        return [
            features["login_hour_of_day"],
            features["unique_processes_count"],
            features["command_diversity"],
            features["network_connections_count"],
            features["unique_destination_ips"],
            features["file_access_count"],
            features["sudo_usage_count"],
            features["session_duration_minutes"],
        ]

    def _score_vector(self, feature_vector: List[float]) -> tuple[float, bool]:
        """Scale + score one feature vector (is_trained assumed checked).

        Shared by score_user and get_high_risk_users — AUD-025."""
        X = np.array([feature_vector])
        X_scaled = self.scaler.transform(X)  # type: ignore[union-attr]
        raw_score = self.model.decision_function(X_scaled)[0]  # type: ignore[union-attr]
        # Convert to 0-1 scale (1 = high anomaly); Isolation Forest:
        # -1 = anomaly, 1 = normal.
        anomaly_score = max(0.0, min(1.0, 1 - (raw_score + 0.5)))  # M-01: clamp to [0, 1]
        is_anomaly = self.model.predict(X_scaled)[0] == -1  # type: ignore[union-attr]
        return float(anomaly_score), bool(is_anomaly)

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

        # M-03: We train on 1 aggregated feature vector per user.
        # With min 3 users, the model is a rough heuristic, not statistically robust.
        # For production: aggregate per-session features or use min_users=10+.
        # For this SIEM portfolio project, 3 users with per-user aggregates is acceptable.

        # AUD-025: one batched extraction (8 queries total) instead of the
        # per-user loop (7 queries per user).
        features_by_user = await self.extract_user_features_batch(user_names, days=min_days)
        feature_vectors = []
        for user in user_names:
            features = features_by_user.get(user)
            if features:
                feature_vectors.append(self._feature_vector(features))

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

        model = self.model  # narrowed: closure re-widens Optional attr

        def _fit_isolation_forest() -> None:
            """CPU-bound sklearn fit — off the event loop (P2.7)."""
            model.fit(X_scaled)

        await asyncio.to_thread(_fit_isolation_forest)

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

        # Scale and predict (the shared scoring path)
        anomaly_score, is_anomaly = self._score_vector(self._feature_vector(features))

        return {
            "user_name": user_name,
            "anomaly_score": float(anomaly_score),
            "is_anomaly": bool(is_anomaly),
            "features": features,
        }

    async def get_high_risk_users(self, threshold: float = 0.8) -> List[Dict]:
        """Get users with high anomaly scores.

        AUD-025: one batched feature extraction (8 queries total) instead of
        score_user per user (7 queries each)."""
        if not self.is_trained:
            return []
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

        features_by_user = await self.extract_user_features_batch(user_names, days=1)

        high_risk: List[Dict] = []
        for user, features in features_by_user.items():
            anomaly_score, is_anomaly = self._score_vector(self._feature_vector(features))
            if is_anomaly and anomaly_score >= threshold:
                high_risk.append(
                    {
                        "user_name": user,
                        "anomaly_score": anomaly_score,
                        "is_anomaly": is_anomaly,
                        "features": features,
                    }
                )

        # Sort by anomaly score descending
        high_risk.sort(key=lambda x: x["anomaly_score"], reverse=True)
        return high_risk

    def get_status(self) -> Dict[str, Any]:
        """Get model status for API endpoint."""
        return {
            "is_trained": self.is_trained,
            "trained_at": (
                datetime.fromtimestamp(self.trained_at, tz=timezone.utc).isoformat()
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


async def get_ueba(*, train_if_missing: bool = True) -> UEBABaseline:
    """Get singleton UEBA instance.

    train_if_missing=False keeps the accessor READ-ONLY: the /ai/status
    polling path must never trigger a synchronous training run as a side
    effect (AUD-043). Default behavior (True) is unchanged for callers
    that rely on lazy-train."""
    global _ueba
    if _ueba is None:
        _ueba = UEBABaseline()
        if train_if_missing and not _ueba.is_trained:
            await _ueba.train()
    return _ueba
