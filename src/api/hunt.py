"""
Hunting Assistant API endpoints.

POST /api/v1/hunt/{hunt_id}/execute    — Execute a hunt template
GET  /api/v1/hunt/templates              — List available hunt templates
GET  /api/v1/hunt/gaps                   — MITRE ATT&CK gap analysis
POST /api/v1/hunt/from-alert/{alert_id}  — Suggest hunts from an alert
GET  /api/v1/hunt/history                — Get hunt execution history
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.api.auth import require_role
from src.ai.hunting_assistant import (
    execute_hunt,
    get_hunting_templates,
    hunt_from_alert,
    mitre_gap_analysis,
)
from src.config.logging import get_logger

log = get_logger("api.hunt")

router = APIRouter(tags=["hunt"])


class HuntExecuteResponse(BaseModel):
    """Hunt execution response."""
    success: bool
    hunt_id: str | None = None
    name: str | None = None
    category: str | None = None
    mitre: list | None = None
    results: list | None = None
    row_count: int | None = None
    truncated: bool | None = None
    analysis: str | None = None
    error: str | None = None


class HuntFromAlertResponse(BaseModel):
    """Hunt from alert response."""
    success: bool
    alert_id: int
    alert_rule: str | None = None
    alert_host: str | None = None
    matching_hunts: list | None = None
    llm_suggestions: list | None = None
    error: str | None = None


class GapAnalysisResponse(BaseModel):
    """MITRE ATT&CK gap analysis response."""
    total_critical_techniques: int
    covered_by_rules: int
    covered_by_hunts: int
    total_covered: int
    coverage_percentage: float
    gaps: list[str]
    gap_hunts: list
    rule_techniques: list[str]
    hunt_techniques: list[str]


@router.post(
    "/hunt/{hunt_id}/execute",
    response_model=HuntExecuteResponse,
    summary="Execute Hunt Template",
    description="Execute a pre-defined hunt template. Requires analyst role.",
)
async def execute_hunt_template(
    hunt_id: str,
    _user: dict = Depends(require_role("analyst")),
):
    """Execute a hunt template by ID."""
    log.info("hunt_execute_request", hunt_id=hunt_id, user=_user.get("sub"))

    result = await execute_hunt(hunt_id)

    return HuntExecuteResponse(
        success=result.get("success", False),
        hunt_id=result.get("hunt_id"),
        name=result.get("name"),
        category=result.get("category"),
        mitre=result.get("mitre"),
        results=result.get("results"),
        row_count=result.get("row_count"),
        truncated=result.get("truncated"),
        analysis=result.get("analysis"),
        error=result.get("error"),
    )


@router.get(
    "/hunt/templates",
    response_model=list,
    summary="Hunt Templates",
    description="List available pre-built hunt templates.",
)
async def list_hunt_templates(
    _user: dict = Depends(require_role("viewer")),
):
    """List available hunt templates."""
    return get_hunting_templates()


@router.get(
    "/hunt/gaps",
    response_model=GapAnalysisResponse,
    summary="MITRE ATT&CK Gap Analysis",
    description="Analyze which MITRE techniques are covered by rules and hunts.",
)
async def gap_analysis(
    _user: dict = Depends(require_role("analyst")),
):
    """Perform MITRE ATT&CK gap analysis."""
    result = await mitre_gap_analysis()
    return GapAnalysisResponse(**result)


@router.post(
    "/hunt/from-alert/{alert_id}",
    response_model=HuntFromAlertResponse,
    summary="Hunt From Alert",
    description="Suggest and execute hunting queries based on an alert.",
)
async def hunt_from_alert_endpoint(
    alert_id: int,
    _user: dict = Depends(require_role("analyst")),
):
    """Suggest hunting queries based on an alert."""
    log.info("hunt_from_alert", alert_id=alert_id, user=_user.get("sub"))

    result = await hunt_from_alert(alert_id)

    return HuntFromAlertResponse(
        success=result.get("success", False),
        alert_id=alert_id,
        alert_rule=result.get("alert_rule"),
        alert_host=result.get("alert_host"),
        matching_hunts=result.get("matching_hunts"),
        llm_suggestions=result.get("llm_suggestions"),
        error=result.get("error"),
    )
