"""
Alert Triage ML Model.

Classifies alerts as true positive or false positive,
and prioritizes alerts for analyst review.
"""
import pickle
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.triage")

# Model persistence
MODEL_PATH = Path.home() / ".scarletai_triage_model.pkl"
ENCODER_PATH = Path.home() / ".scarletai_triage_encoder.pkl"


class AlertTriageModel:
    """ML model for alert triage and prioritization."""
    
    FEATURES = [
        "severity_score",      # 0-1 based on severity
        "hour_of_day",         # When alert fired
        "rule_hit_count",      # How often this rule fires
        "user_alert_count",    # User's historical alert count
        "asset_risk_score",    # Host risk score
        "mitre_count",         # Number of MITRE techniques
        "time_since_last",     # Time since last similar alert
        "has_threat_intel",    # Boolean: TI match
    ]
    
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.encoder: Optional[LabelEncoder] = None
        self.is_trained = False
        
        self._load_model()
    
    def _load_model(self) -> bool:
        """Load trained model from disk."""
        try:
            if MODEL_PATH.exists() and ENCODER_PATH.exists():
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(ENCODER_PATH, "rb") as f:
                    self.encoder = pickle.load(f)
                self.is_trained = True
                log.info("triage_model_loaded")
                return True
        except Exception as e:
            log.warning("triage_model_load_failed", error=str(e))
        return False
    
    def _save_model(self) -> None:
        """Save trained model to disk."""
        if self.model and self.encoder:
            with open(MODEL_PATH, "wb") as f:
                pickle.dump(self.model, f)
            with open(ENCODER_PATH, "wb") as f:
                pickle.dump(self.encoder, f)
            log.info("triage_model_saved")
    
    async def extract_features(self, alert_id: int) -> Optional[List[float]]:
        """Extract feature vector from an alert."""
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Get alert details
            alert = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id = $1",
                alert_id
            )
            
            if not alert:
                return None
            
            # Severity score
            severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.0}
            severity_score = severity_map.get(alert["severity"].lower(), 0.0)
            
            # Hour of day
            alert_time = alert["time"]
            if isinstance(alert_time, str):
                alert_time = datetime.fromisoformat(alert_time.replace("Z", "+00:00"))
            hour_of_day = alert_time.hour if hasattr(alert_time, "hour") else 12
            
            # Rule hit count (how often this rule fires)
            rule_hits = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE rule_id = $1",
                alert["rule_id"]
            )
            rule_hit_normalized = min(rule_hits / 100, 1.0)
            
            # Asset risk score
            asset_risk = await conn.fetchval(
                "SELECT COALESCE(risk_score, 50) FROM assets WHERE hostname = $1",
                alert["host_name"]
            ) or 50.0
            asset_risk_normalized = asset_risk / 100.0
            
            # MITRE technique count
            mitre_count = len(alert.get("mitre_techniques") or [])
            mitre_normalized = min(mitre_count / 5, 1.0)
            
            # Time since last similar alert
            last_similar = await conn.fetchval(
                """
                SELECT MAX(time) FROM alerts 
                WHERE rule_id = $1 AND id != $2 AND time < $3
                """,
                alert["rule_id"],
                alert_id,
                alert["time"]
            )
            
            if last_similar:
                time_since = 1.0  # Recent
            else:
                time_since = 0.0  # First occurrence
            
            # Threat intel match
            has_ti = 1.0 if alert.get("evidence") and "threat_intel" in str(alert["evidence"]) else 0.0
            
            # User alert count
            user_alerts = await conn.fetchval(
                """
                SELECT COUNT(*) FROM alerts 
                WHERE host_name = $1 AND time > NOW() - INTERVAL '24 hours'
                """,
                alert["host_name"]
            )
            user_alert_normalized = min(user_alerts / 20, 1.0)
            
            return [
                severity_score,
                hour_of_day / 24.0,
                rule_hit_normalized,
                user_alert_normalized,
                asset_risk_normalized,
                mitre_normalized,
                time_since,
                has_ti,
            ]
    
    async def train(self, min_samples: int = 100) -> bool:
        """
        Train triage model on historical alerts.
        
        Uses resolved alerts (true_positive vs false_positive) as labels.
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
                """
            )
            
            if len(rows) < min_samples:
                log.warning("triage_training_insufficient_samples", count=len(rows))
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
                log.warning("triage_training_insufficient_features", count=len(X))
                return False
            
            # Train model
            X_array = np.array(X)
            y_array = np.array(y)
            
            self.model = RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42,
            )
            self.model.fit(X_array, y_array)
            
            self.is_trained = True
            self._save_model()
            
            log.info("triage_training_complete", samples=len(X))
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
        
        # Predict
        X = np.array([features])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = max(probabilities)
        
        # Calculate priority score (0-100)
        # Higher = more urgent to investigate
        base_priority = 50.0
        
        # Adjust based on prediction
        if prediction == 1:  # True positive
            base_priority += 30.0
        else:  # False positive
            base_priority -= 20.0
        
        # Adjust based on confidence
        if confidence > 0.8:
            base_priority += 10.0
        
        # Cap at 0-100
        priority_score = max(0, min(100, base_priority))
        
        return {
            "prediction": "true_positive" if prediction == 1 else "false_positive",
            "confidence": round(float(confidence), 2),
            "priority_score": round(priority_score, 2),
            "features": features,
        }
    
    async def get_priority_queue(self, limit: int = 50) -> List[Dict]:
        """
        Get alerts prioritized by ML model.
        
        Returns alerts sorted by priority score (highest first).
        """
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Get recent unreviewed alerts
            rows = await conn.fetch(
                """
                SELECT id, rule_name, severity, host_name, time
                FROM alerts
                WHERE status = 'new'
                  AND time > NOW() - INTERVAL '24 hours'
                ORDER BY time DESC
                LIMIT $1
                """,
                limit
            )
        
        # Score each alert
        scored_alerts = []
        for row in rows:
            prediction = await self.predict(row["id"])
            scored_alerts.append({
                **dict(row),
                **prediction,
            })
        
        # Sort by priority score descending
        scored_alerts.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return scored_alerts


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
