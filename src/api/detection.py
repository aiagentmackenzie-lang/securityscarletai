"""Detection-coverage API -- the evidence-driven detectability map (V0.3)
+ the rule lifecycle scorecard (V0.7b -- the detection-engineering loop)
+ rule backtesting (Wave 1 W1.1 -- author -> backtest -> arm -> measure).

GET /api/v1/detection/coverage -- per-rule armed/dormant status + the
technique rollup the MITRE heatmap renders. Armed = the rule's required
telemetry was SEEN in the lookback window (source exists to fire it);
dormant = rule exists but its source/vocabulary has not (surfaced honestly
instead of silently never firing -- the old title-driven heatmap counted
both identically).

GET /api/v1/detection/scorecard -- per-rule lifecycle metrics (fires,
dispositions, FP ratio, age) + retirement ADVICE. Read-only; retirement is
a HITL decision, never automatic.

POST /api/v1/detection/backtest -- would this rule have fired in the last
N days, on how many rows, at what false-positive cost? Compiles a draft or
existing Sigma rule through the PRODUCTION compiler and replays it
READ-ONLY against the stored logs window. Bounded (window <= 30d,
per-query timeout), never persists, never auto-arms; audited.
"""

from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator

from src.api.audit import log_audit_action
from src.api.auth import get_current_user, require_role
from src.detection.backtest import run_backtest
from src.detection.coverage import compute_coverage
from src.detection.navigator import build_navigator_layer
from src.detection.scorecard import compute_rule_scorecard

router = APIRouter(tags=["detection"], prefix="/detection")

# Draft YAML body bound: a multi-megabyte "rule" is not a rule, it is abuse.
MAX_BACKTEST_YAML_CHARS = 100_000


@router.get("/coverage")
async def detection_coverage(
    lookback_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 168,
    user: dict = Depends(get_current_user),
):
    """Per-rule armed/dormant coverage + technique rollup (evidence-driven)."""
    return await compute_coverage(
        lookback_hours=lookback_hours,
        as_of=datetime.now(timezone.utc),
    )


@router.get("/scorecard")
async def detection_scorecard(
    window_hours: Annotated[int, Query(ge=1, le=24 * 365)] = 720,
    user: dict = Depends(get_current_user),
):
    """Per-rule lifecycle scorecard + retirement advice (read-only, HITL)."""
    return await compute_rule_scorecard(
        window_hours=window_hours,
        as_of=datetime.now(timezone.utc),
    )


@router.get("/coverage/navigator")
async def detection_coverage_navigator(
    lookback_hours: Annotated[int, Query(ge=1, le=24 * 30)] = 168,
    user: dict = Depends(get_current_user),
):
    """ATT&CK Navigator layer export (v4.5): armed coverage scores + scorecard
    FP ratios per technique. Read-only; import the JSON into attack.mitre.org
    -- the analyst-standard coverage artifact."""
    return await build_navigator_layer(
        lookback_hours=lookback_hours,
        as_of=datetime.now(timezone.utc),
    )


class BacktestRequest(BaseModel):
    """Body for POST /detection/backtest.

    Exactly one of rule_id / sigma_yaml: backtest an existing rule from the
    registry, or a draft. The draft path never touches the rules table.
    """

    rule_id: Optional[int] = None
    sigma_yaml: Optional[str] = Field(default=None, max_length=MAX_BACKTEST_YAML_CHARS)
    window_hours: Annotated[int, Field(ge=1, le=24 * 30)] = 168

    @model_validator(mode="after")
    def _exactly_one_source(self) -> "BacktestRequest":
        if (self.rule_id is None) == (self.sigma_yaml is None):
            raise ValueError("provide exactly one of rule_id or sigma_yaml")
        return self


@router.post("/backtest")
async def detection_backtest(
    request: BacktestRequest,
    user: dict = Depends(require_role("analyst")),
):
    """Backtest a Sigma rule against the stored logs window (read-only).

    Analyst+ only, audited (rule.backtest). Compiles through the production
    Sigma->SQL compiler; replays the alert-dedup semantics for the alert
    estimate; reports unmeasured (never a fake 0) when the corpus cannot
    support a number. Never persists, never auto-arms.
    """
    actor = user.get("sub", "unknown")

    if request.rule_id is not None:
        from src.api.rules import get_rule_by_id

        rule_row = await get_rule_by_id(request.rule_id)
        if not rule_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
        sigma_yaml = rule_row["sigma_yaml"]
        rule_name = rule_row["name"]
    else:
        sigma_yaml = request.sigma_yaml
        rule_name = None

    try:
        report = await run_backtest(
            sigma_yaml=sigma_yaml,
            window_hours=request.window_hours,
            rule_id=request.rule_id,
            rule_name=rule_name,
            as_of=datetime.now(timezone.utc),
        )
    except ValueError as exc:
        # Compiler rejects the YAML/grammar -- author feedback, not a crash.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None

    results = report.get("results", {})
    await log_audit_action(
        actor=actor,
        action="rule.backtest",
        target_type="rule",
        target_id=request.rule_id,
        new_values={
            "source": report["rule"]["source"],
            "rule_title": report["rule"]["sigma_title"],
            "window_hours": request.window_hours,
            "measured": results.get("measured"),
            "total_rows": results.get("total_rows"),
            "estimated_alerts": results.get("estimated_alerts"),
        },
    )
    return report
