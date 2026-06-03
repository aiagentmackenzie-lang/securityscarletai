"""
AI endpoints — model training, status, triage, and UEBA.

POST /api/v1/ai/train         — Trigger model training
GET  /api/v1/ai/status        — Get model status
POST /api/v1/ai/triage/{id}   — Get triage prediction for alert
GET  /api/v1/ai/ueba/{user}   — Get UEBA anomaly score for user
POST /api/v1/ai/explain/{id}  — Generate AI explanation for alert
"""
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.ai.alert_explanation import explain_alert
from src.ai.alert_triage import AlertTriageModel, check_auto_train, get_triage_model
from src.ai.ueba import get_ueba
from src.api.auth import require_role
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("api.ai")

router = APIRouter(tags=["ai"])


class TrainRequest(BaseModel):
    """Model training request."""
    min_samples: int = 50


class TrainResponse(BaseModel):
    """Model training response."""
    success: bool
    message: str
    samples: int | None = None
    accuracy: float | None = None


class StatusResponse(BaseModel):
    """Model status response."""
    triage: dict
    ueba: dict
    ollama_available: bool | None = None


class TriageResponse(BaseModel):
    """Alert triage prediction response."""
    alert_id: int
    prediction: str
    confidence: float | None = None
    priority_score: float | None = None
    features: dict | None = None
    reason: str | None = None


class UEBAResponse(BaseModel):
    """UEBA anomaly score response."""
    user_name: str
    anomaly_score: float | None = None
    is_anomaly: bool
    features: dict | None = None
    error: str | None = None


class ExplainResponse(BaseModel):
    """Alert explanation response."""
    alert_id: int
    explanation: str
    source: str | None = None
    model: str | None = None
    fallback_used: bool = False
    warning: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    prompt_version: str | None = None
    cost_recorded: bool = False


@router.post(
    "/ai/train",
    response_model=TrainResponse,
    summary="Train AI Models",
    description="Trigger training of triage and UEBA models. Requires admin role.",
)
async def train_models(
    request: TrainRequest = TrainRequest(),
    _user: dict = Depends(require_role("admin")),
):
    """Train triage model and UEBA baseline on historical data."""
    log.info("ai_train_request", min_samples=request.min_samples, user=_user.get("sub"))

    # Train triage model
    triage_model = await get_triage_model()
    triage_success = await triage_model.train(min_samples=request.min_samples)

    # Train UEBA model
    ueba = await get_ueba()
    ueba_success = await ueba.train()

    if triage_success or ueba_success:
        return TrainResponse(
            success=True,
            message="Models trained successfully",
            samples=triage_model.training_samples,
            accuracy=triage_model.training_accuracy,
        )
    else:
        return TrainResponse(
            success=False,
            message="Insufficient data for training. Need more resolved alerts and user activity.",
        )


@router.get(
    "/ai/status",
    response_model=StatusResponse,
    summary="AI Model Status",
    description="Get current status of all AI models.",
)
async def get_status(
    _user: dict = Depends(require_role("viewer")),
):
    """Get status of AI models."""
    # Triage model status
    triage = AlertTriageModel()
    triage_status = triage.get_status()

    # V2 (Epic 3) — attach latest triage_model_provenance row if reachable.
    # Best-effort: any DB error yields provenance=None and the call still
    # returns the existing triage_status keys for backward compatibility.
    try:
        provenance = await triage.latest_provenance()
    except Exception:  # noqa: BLE001
        provenance = None
    triage_status["provenance"] = provenance

    # UEBA model status
    ueba = await get_ueba()
    ueba_status = ueba.get_status()

    # Check Ollama availability
    from src.ai.ollama_client import is_ollama_available
    ollama_available = await is_ollama_available()

    return StatusResponse(
        triage=triage_status,
        ueba=ueba_status,
        ollama_available=ollama_available,
    )


@router.post(
    "/ai/triage/{alert_id}",
    response_model=TriageResponse,
    summary="Triage Alert",
    description="Get ML triage prediction for an alert. Requires analyst role.",
)
async def triage_alert(
    alert_id: int,
    _user: dict = Depends(require_role("analyst")),
):
    """Predict triage outcome for an alert."""
    # Verify alert exists
    pool = await get_pool()
    async with pool.acquire() as conn:
        alert = await conn.fetchrow(
            "SELECT id, rule_name, severity FROM alerts WHERE id = $1",
            alert_id,
        )
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    model = await get_triage_model()
    result = await model.predict(alert_id)

    return TriageResponse(
        alert_id=alert_id,
        prediction=result["prediction"],
        confidence=result.get("confidence"),
        priority_score=result.get("priority_score"),
        features=result.get("features"),
        reason=result.get("reason"),
    )


@router.get(
    "/ai/ueba/{user_name}",
    response_model=UEBAResponse,
    summary="UEBA Anomaly Score",
    description="Get UEBA anomaly score for a user. Requires analyst role.",
)
async def get_ueba_score(
    user_name: str,
    _user: dict = Depends(require_role("analyst")),
):
    """Get UEBA anomaly score for a user."""
    ueba = await get_ueba()
    result = await ueba.score_user(user_name)

    return UEBAResponse(
        user_name=user_name,
        anomaly_score=result.get("anomaly_score"),
        is_anomaly=result.get("is_anomaly", False),
        features=result.get("features"),
        error=result.get("error"),
    )


@router.post(
    "/ai/explain/{alert_id}",
    response_model=ExplainResponse,
    summary="Explain Alert",
    description="Generate AI explanation for an alert. Falls back to templates if LLM unavailable.",
)
async def explain_alert_endpoint(
    alert_id: int,
    _user: dict = Depends(require_role("analyst")),
):
    """Generate AI explanation for an alert."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        alert = await conn.fetchrow(
            """
            SELECT a.id, a.rule_name, a.severity, a.host_name,
                   a.mitre_techniques, a.evidence, r.description
            FROM alerts a
            LEFT JOIN rules r ON a.rule_id = r.id
            WHERE a.id = $1
            """,
            alert_id,
        )
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    # Get related log count
    pool = await get_pool()
    async with pool.acquire() as conn:
        related_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM logs
            WHERE host_name = $1
              AND time > NOW() - INTERVAL '1 hour'
            """,
            alert["host_name"],
        )

    # Parse evidence JSONB safely — asyncpg may return string, list, or dict
    raw_ev = alert.get("evidence")
    evidence_parsed = None
    if raw_ev is not None:
        if isinstance(raw_ev, str) and raw_ev.strip():
            try:
                evidence_parsed = json.loads(raw_ev)
            except Exception as e:  # pragma: no cover — defensive
                log.exception("ai_evidence_parse_failed", error=str(e))
                evidence_parsed = None
        elif isinstance(raw_ev, dict):
            evidence_parsed = raw_ev
        elif isinstance(raw_ev, list):
            evidence_parsed = raw_ev

    explanation = await explain_alert(
        rule_name=alert["rule_name"],
        rule_description=alert["description"] or "",
        severity=alert["severity"],
        host_name=alert["host_name"],
        mitre_techniques=alert["mitre_techniques"] or [],
        evidence=evidence_parsed,
        related_logs_count=related_count or 0,
        user=_user.get("sub"),
    )

    return ExplainResponse(
        alert_id=alert_id,
        explanation=explanation.get("explanation", ""),
        source=explanation.get("source"),
        model=explanation.get("model"),
        fallback_used=explanation.get("fallback_used", False),
        warning=explanation.get("warning"),
        tokens_in=explanation.get("tokens_in", 0),
        tokens_out=explanation.get("tokens_out", 0),
        latency_ms=explanation.get("latency_ms", 0),
        prompt_version=explanation.get("prompt_version"),
        cost_recorded=explanation.get("cost_recorded", False),
    )


# Periodically check auto-train (called from scheduler)
async def auto_train_check():
    """Check if auto-training should be triggered. Called by the scheduler."""
    log.info("checking_auto_train")
    trained = await check_auto_train()
    if trained:
        log.info("auto_train_completed")
    else:
        log.info("auto_train_skipped_insufficient_data")
