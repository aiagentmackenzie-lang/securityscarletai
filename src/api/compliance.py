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
from src.compliance.retention import retention_policy_evidence
from src.config.logging import get_logger
from src.detection.coverage import compute_coverage

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
    from src.response.scheduled_reports import posture_report_data

    # One implementation shared with the W1.8 scheduled-report delivery
    # (the report can never drift from the endpoint).
    return await posture_report_data(window_hours, as_of=datetime.now(timezone.utc))


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
