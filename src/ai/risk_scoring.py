"""
Risk scoring engine.

Combines multiple signals into unified risk scores for:
- Assets (hosts/endpoints)
- Users
- Alerts
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

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
        threat_intel_match: bool = False,
        user_anomaly_score: float = 0.0,
    ) -> float:
        """
        Calculate risk score for an individual alert.

        The real factors: severity (base), threat-intel match, UEBA anomaly
        (user_anomaly_score). An "asset criticality" term was previously
        included but was vapor -- it took a fixed 0.5 default that no caller
        overrode, backed by an `assets` table that was never populated (now
        dropped from the schema). It is removed for honesty (P2-8).

        Returns:
            Risk score 0-100
        """
        # Base score from severity
        base = RiskScorer.SEVERITY_WEIGHTS.get(severity.lower(), 0.0) * 50

        # Adjustments
        ti_adj = 15 if threat_intel_match else 0  # +15 if TI match
        anomaly_adj = user_anomaly_score * 15  # Up to +15

        total = base + ti_adj + anomaly_adj
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
            # Alert stats — parameterized interval via multiplication (safe)
            alert_stats = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) as total
                FROM alerts
                WHERE host_name = $1
                  AND time > NOW() - INTERVAL '1 hour' * $2
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

            # Threat intel hits — parameterized interval
            ti_hits = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE host_name = $1
                  AND enrichment @> '{"threat_intel": {"match": true}}'
                  AND time > NOW() - INTERVAL '1 hour' * $2
                """,
                hostname,
                hours,
            )

            # P1-09: exposure score must run on the same (still-acquired)
            # connection. Previously this query ran AFTER the `async with` block
            # released the connection, raising a use-after-release that the
            # bare except swallowed -> exposure_score was always 0.0.
            try:
                exposed = await conn.fetchval(
                    """
                    SELECT COUNT(*)
                    FROM logs
                    WHERE host_name = $1
                      AND source_ip NOT << '10.0.0.0/8'::inet
                      AND source_ip NOT << '192.168.0.0/16'::inet
                      AND source_ip NOT << '172.16.0.0/12'::inet
                      AND time > NOW() - INTERVAL '1 hour' * $2
                      AND event_category = 'network'
                    """,
                    hostname,
                    hours,
                )
            except Exception as e:
                log.warning("asset_risk_exposure_query_failed", host=hostname, error=str(e))
                exposed = 0

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

        # UEBA anomaly score: UEBA is user-scoped (IsolationForest over
        # per-user features), not host-scoped, so the host risk path leaves
        # anomaly_score at its default 0.0. The previous block imported a
        # non-existent `UEBAEngine` class and called a non-existent
        # `get_user_anomaly_score` — dead code whose ImportError was silently
        # swallowed. User-level UEBA scoring belongs in calculate_user_risk
        # (tracked as a follow-up).

        # Exposure score — internet-facing host check (P1-09: query moved
        # inside the conn block above; compute from the result here).
        factors.exposure_score = min(exposed / 10, 1.0) if exposed else 0.0

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
                "anomaly_score": round(factors.anomaly_score, 2),
                "exposure_score": round(factors.exposure_score, 2),
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
            # Alerts involving user — correlated via host_name, NOT Cartesian JOIN
            user_alerts = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) FILTER (WHERE a.severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE a.severity = 'high') as high,
                    COUNT(*) FILTER (WHERE a.status = 'new') as open_count
                FROM alerts a
                WHERE a.host_name IN (
                    SELECT DISTINCT host_name FROM logs
                    WHERE user_name = $1 AND time > NOW() - INTERVAL '1 hour' * $2
                )
                AND a.time > NOW() - INTERVAL '1 hour' * $2
                """,
                username,
                hours,
            )

            # Privileged activity — use normalized JSONB for process_cmdline
            sudo_count = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM logs
                WHERE user_name = $1
                  AND (
                    normalized->>'process_cmdline' ILIKE '%sudo%'
                    OR process_name = 'sudo'
                  )
                  AND time > NOW() - INTERVAL '1 hour' * $2
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
        """Get highest risk assets.

        M-13 fix: Batch into single query instead of N+1 per-host calls.
        """
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                    h.host_name,
                    50.0 as base_risk,
                    COUNT(DISTINCT al.id) FILTER (WHERE al.severity = 'critical') as crit_alerts,
                    COUNT(DISTINCT al.id) FILTER (WHERE al.severity = 'high') as high_alerts,
                    COUNT(DISTINCT al.id) as total_alerts,
                    COALESCE(oc.outbound_conns, 0) as outbound_conns
                FROM (
                    SELECT DISTINCT host_name
                    FROM logs
                    WHERE time > NOW() - INTERVAL '24 hours'
                    LIMIT 50
                ) h
                LEFT JOIN alerts al
                    ON al.host_name = h.host_name
                    AND al.time > NOW() - INTERVAL '24 hours'
                LEFT JOIN (
                    SELECT host_name, COUNT(DISTINCT id) as outbound_conns
                    FROM logs
                    WHERE time > NOW() - INTERVAL '24 hours'
                      AND event_category = 'network'
                      AND source_ip IS NOT NULL
                    GROUP BY host_name
                ) oc ON oc.host_name = h.host_name
                GROUP BY h.host_name, oc.outbound_conns
                ORDER BY
                    50.0
                    + COUNT(DISTINCT al.id) FILTER (WHERE al.severity = 'critical') * 20
                    + COUNT(DISTINCT al.id) FILTER (WHERE al.severity = 'high') * 10
                    DESC
                LIMIT $1
                """,
                limit,
            )

        scored = []
        for r in rows:
            base_risk = float(r["base_risk"])
            crit_bonus = (r["crit_alerts"] or 0) * 20
            high_bonus = (r["high_alerts"] or 0) * 10
            risk_score = min(100.0, base_risk + crit_bonus + high_bonus)
            scored.append({
                "host_name": r["host_name"],
                "risk_score": risk_score,
                "total_alerts": r["total_alerts"] or 0,
                "critical_alerts": r["crit_alerts"] or 0,
                "high_alerts": r["high_alerts"] or 0,
            })

        return scored

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
    """Deprecated no-op (P2-8).

    The `assets` table was a never-populated placeholder and has been removed
    from the schema. This function previously SELECTed hostnames from `assets`
    and UPDATEd `assets.risk_score` -- both now reference a non-existent table.
    It had no callers in the production code path. Retained as a documented
    no-op so any external import does not crash; per-host risk is still
    available via RiskScorer.calculate_asset_risk(hostname).
    """
    log.info("update_asset_risk_scores_noop_assets_table_removed")
