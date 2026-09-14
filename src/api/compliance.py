"""Compliance & reporting API (V0.7 -- Group E).

The budget-justifying surface: incident evidence packs designed against
the UK CS&R 24h/72h reporting cadence, evidence-driven coverage and
posture reports, the versioned framework-mapping view, and the retention
policy AS EVIDENCE (truth, including 0 = keep forever).

Read-only + audited: reads are auth'd like every detection surface; the
evidence-pack EXPORT itself is audited (compliance.evidence_pack_export).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.audit import log_audit_action
from src.api.auth import get_current_user, require_role
from src.compliance.evidence import build_evidence_pack
from src.compliance.frameworks import CONFIG_PATH, load_frameworks_file
from src.compliance.outliers import compute_posture_outliers
from src.compliance.retention import retention_policy_evidence
from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.coverage import compute_coverage
from src.detection.scorecard import compute_rule_scorecard

router = APIRouter(tags=["compliance"], prefix="/compliance")
log = get_logger("api.compliance")


@router.get("/incidents/{alert_id}/evidence-pack")
async def incident_evidence_pack(
    alert_id: int,
    user: dict = Depends(require_role("analyst")),
):
    """The full incident chain as a regulator-consumable document.

    Alert -> correlation -> case + timeline -> response actions (four-eyes
    + verification trail) -> quarantine state -> audit receipts, with the
    reporting-cadence due dates computed from the detection timestamp.
    The export is itself audited.
    """
    pack = await build_evidence_pack(alert_id, datetime.now(timezone.utc))
    if pack is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    await log_audit_action(
        actor=user.get("sub", "unknown"),
        action="compliance.evidence_pack_export",
        target_type="alert",
        target_id=alert_id,
        new_values={"sections": list(pack.keys())},
    )
    return pack


@router.get("/reports/coverage")
async def coverage_report(
    lookback_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 168,
    user: dict = Depends(get_current_user),
):
    """Evidence-driven ATT&CK coverage report (the armed/dormant map)."""
    return await compute_coverage(
        lookback_hours=lookback_hours,
        as_of=datetime.now(timezone.utc),
    )


@router.get("/reports/posture")
async def posture_report(
    window_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
    user: dict = Depends(get_current_user),
):
    """Alert posture + MTTR + scorecard summary + UEBA-ready outliers.

    The outliers view (V0.7 delta) is per-window naive statistics computed
    read-only from alerts/logs -- the shape V0.8 UEBA baselines supersede;
    see src/compliance/outliers.py for the honest scope.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        posture = dict(
            await conn.fetchrow(
                """
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
                    COUNT(*) FILTER (WHERE severity = 'high') AS high,
                    COUNT(*) FILTER (WHERE status = 'new') AS new,
                    COUNT(*) FILTER (WHERE status = 'investigating') AS investigating,
                    COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) AS resolved,
                    COUNT(*) FILTER (WHERE status = 'false_positive') AS false_positives,
                    EXTRACT(EPOCH FROM AVG(
                        CASE WHEN resolved_at IS NOT NULL
                            THEN resolved_at - time END
                    )) AS mttr_seconds
                FROM alerts
                WHERE time > NOW() - INTERVAL '1 hour' * $1
                """,
                window_hours,
            )
        )
    mttr = posture.pop("mttr_seconds", None)
    summary = (
        await compute_rule_scorecard(window_hours=window_hours, as_of=datetime.now(timezone.utc))
    )["summary"]
    outliers = await compute_posture_outliers(window_hours, as_of=datetime.now(timezone.utc))
    return {
        "window_hours": window_hours,
        "alerts": posture,
        "mttr_seconds": float(mttr) if mttr is not None else None,
        "rule_scorecard_summary": summary,
        "outliers": outliers,
    }


@router.get("/frameworks")
async def framework_mappings(user: dict = Depends(get_current_user)):
    """The versioned framework mapping (surface-based, fail-closed).

    503 when the mapping file is missing/unparseable -- the API never
    fabricates compliance coverage.
    """
    document = load_frameworks_file(CONFIG_PATH)
    if not document["frameworks"]:
        raise HTTPException(
            status_code=503,
            detail="compliance framework mapping unavailable (missing or unparseable) "
            "-- fail-closed: no fabricated coverage",
        )
    return document


@router.get("/retention-policy")
async def retention_policy(user: dict = Depends(get_current_user)):
    """The retention policy AS EVIDENCE: configured windows per table +
    TimescaleDB policy state when available (fail-closed probe)."""
    return await retention_policy_evidence()
