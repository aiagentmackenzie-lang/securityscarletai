"""
Risk scoring engine.

Combines multiple signals into unified risk scores for:
- Assets (hosts/endpoints)
- Users
- Alerts
"""
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("ai.risk_scoring")


@dataclass
class RiskFactors:
    """Individual risk factor weights."""
    alert_severity: float = 0.0      # Critical=1.0, High=0.8, Medium=0.5, Low=0.2
    alert_count: float = 0.0         # Normalized count
    anomaly_score: float = 0.0     # UEBA anomaly (0-1)
    threat_intel_hits: float = 0.0 # Threat matches
    exposure_score: float = 0.0    # Internet-facing, etc.


class RiskScorer:
    """Calculate risk scores for entities."""
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
        "info": 0.0,
    }
    
    # Risk factor weights (sum to 1.0)
    FACTOR_WEIGHTS = {
        "alert_severity": 0.3,
        "alert_count": 0.2,
        "anomaly_score": 0.25,
        "threat_intel": 0.15,
        "exposure": 0.1,
    }
    
    @staticmethod
    def calculate_alert_risk(
        severity: str,
        asset_criticality: float = 0.5,
        threat_intel_match: bool = False,
        user_anomaly_score: float = 0.0,
    ) -> float:
        """
        Calculate risk score for an individual alert.
        
        Returns:
            Risk score 0-100
        """
        # Base score from severity
        base = RiskScorer.SEVERITY_WEIGHTS.get(severity.lower(), 0.0) * 50
        
        # Adjustments
        asset_adj = asset_criticality * 20  # Up to +20
        ti_adj = 15 if threat_intel_match else 0  # +15 if TI match
        anomaly_adj = user_anomaly_score * 15  # Up to +15
        
        total = base + asset_adj + ti_adj + anomaly_adj
        return min(total, 100)  # Cap at 100
    
    @staticmethod
    async def calculate_asset_risk(
        hostname: str,
        hours: int = 24,
    ) -> Dict[str, Any]:
        """
        Calculate risk score for an asset/host.
        
        Returns:
            Dict with score, factors, and top risks
        """
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Alert stats
            alert_stats = await conn.fetchrow(
                """
                SELECT 
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) as total
                FROM alerts
                WHERE host_name = $1
                  AND time > NOW() - INTERVAL '$2 hours'
                """,
                hostname,
                hours,
            )
            
            # Open high/critical alerts (ongoing risk)
            open_alerts = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE host_name = $1
                  AND severity IN ('critical', 'high')
                  AND status = 'new'
                """,
                hostname,
            )
            
            # Threat intel hits
            ti_hits = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE host_name = $1
                  AND enrichment @> '{"threat_intel": {"match": true}}'
                  AND time > NOW() - INTERVAL '$2 hours'
                """,
                hostname,
                hours,
            )
        
        # Calculate factors
        factors = RiskFactors()
        
        # Alert severity score
        critical = alert_stats["critical"] if alert_stats else 0
        high = alert_stats["high"] if alert_stats else 0
        medium = alert_stats["medium"] if alert_stats else 0
        total = alert_stats["total"] if alert_stats else 0
        
        factors.alert_severity = min(
            (critical * 1.0 + high * 0.5 + medium * 0.2) / 10,  # Normalize
            1.0
        )
        factors.alert_count = min(total / 50, 1.0)  # Normalize
        
        # Threat intel
        factors.threat_intel_hits = min(ti_hits / 5, 1.0) if ti_hits else 0.0
        
        # Calculate weighted risk
        risk_score = (
            factors.alert_severity * RiskScorer.FACTOR_WEIGHTS["alert_severity"] +
            factors.alert_count * RiskScorer.FACTOR_WEIGHTS["alert_count"] +
            factors.anomaly_score * RiskScorer.FACTOR_WEIGHTS["anomaly_score"] +
            factors.threat_intel_hits * RiskScorer.FACTOR_WEIGHTS["threat_intel"] +
            factors.exposure_score * RiskScorer.FACTOR_WEIGHTS["exposure"]
        ) * 100
        
        return {
            "hostname": hostname,
            "risk_score": round(risk_score, 2),
            "risk_level": RiskScorer._get_level(risk_score),
            "factors": {
                "alert_severity": round(factors.alert_severity, 2),
                "alert_count": round(factors.alert_count, 2),
                "threat_intel_hits": round(factors.threat_intel_hits, 2),
            },
            "open_high_critical_alerts": open_alerts or 0,
            "calculation_time": datetime.now().isoformat(),
        }
    
    @staticmethod
    async def calculate_user_risk(
        username: str,
        hours: int = 24,
    ) -> Dict[str, Any]:
        """
        Calculate risk score for a user.
        
        Returns:
            Dict with score and risk factors
        """
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Alerts involving user
            user_alerts = await conn.fetchrow(
                """
                SELECT 
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE a.status = 'new') as open_count
                FROM alerts a
                JOIN logs l ON l.user_name = $1
                WHERE l.time > NOW() - INTERVAL '$2 hours'
                """,
                username,
                hours,
            )
            
            # Privileged activity
            sudo_count = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE user_name = $1
                  AND (process_cmdline ILIKE '%sudo%' OR process_name = 'sudo')
                  AND time > NOW() - INTERVAL '$2 hours'
                """,
                username,
                hours,
            )
        
        # Calculate risk
        critical = user_alerts["critical"] if user_alerts else 0
        high = user_alerts["high"] if user_alerts else 0
        
        severity_score = min((critical * 1.0 + high * 0.5) / 5, 1.0)
        priv_score = min(sudo_count / 20, 1.0) if sudo_count else 0.0
        
        risk_score = (severity_score * 0.6 + priv_score * 0.4) * 100
        
        return {
            "username": username,
            "risk_score": round(risk_score, 2),
            "risk_level": RiskScorer._get_level(risk_score),
            "factors": {
                "alert_severity": round(severity_score, 2),
                "privilege_escalation": round(priv_score, 2),
            },
            "open_alerts": user_alerts["open_count"] if user_alerts else 0,
        }
    
    @staticmethod
    def _get_level(score: float) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "minimal"
    
    @staticmethod
    async def get_top_risk_assets(limit: int = 10) -> List[Dict]:
        """Get highest risk assets."""
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Get active hosts
            rows = await conn.fetch(
                """
                SELECT DISTINCT host_name
                FROM logs
                WHERE time > NOW() - INTERVAL '24 hours'
                LIMIT 50
                """
            )
            hosts = [r["host_name"] for r in rows]
        
        # Score each host
        scored = []
        for host in hosts:
            score = await RiskScorer.calculate_asset_risk(host)
            scored.append(score)
        
        # Sort by risk score
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return scored[:limit]
    
    @staticmethod
    async def get_top_risk_users(limit: int = 10) -> List[Dict]:
        """Get highest risk users."""
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT user_name
                FROM logs
                WHERE user_name IS NOT NULL
                  AND time > NOW() - INTERVAL '24 hours'
                LIMIT 50
                """
            )
            users = [r["user_name"] for r in rows]
        
        scored = []
        for user in users:
            score = await RiskScorer.calculate_user_risk(user)
            scored.append(score)
        
        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored[:limit]


async def update_asset_risk_scores() -> None:
    """
    Batch update risk scores for all assets.
    
    Called periodically to refresh risk assessments.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Get all assets
        rows = await conn.fetch("SELECT hostname FROM assets")
        
        for row in rows:
            hostname = row["hostname"]
            risk = await RiskScorer.calculate_asset_risk(hostname)
            
            # Update asset record
            await conn.execute(
                """
                UPDATE assets 
                SET risk_score = $1, updated_at = NOW()
                WHERE hostname = $2
                """,
                risk["risk_score"],
                hostname,
            )
    
    log.info("asset_risk_scores_updated", count=len(rows))
