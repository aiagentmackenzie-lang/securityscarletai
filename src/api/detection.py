"""Detection-coverage API -- the evidence-driven detectability map (V0.3)
+ the rule lifecycle scorecard (V0.7b -- the detection-engineering loop).

GET /api/v1/detection/coverage -- per-rule armed/dormant status + the
technique rollup the MITRE heatmap renders. Armed = the rule's required
telemetry was SEEN in the lookback window (source exists to fire it);
dormant = rule exists but its source/vocabulary has not (surfaced honestly
instead of silently never firing -- the old title-driven heatmap counted
both identically).

GET /api/v1/detection/scorecard -- per-rule lifecycle metrics (fires,
dispositions, FP ratio, age) + retirement ADVICE. Read-only; retirement is
a HITL decision, never automatic.
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from src.api.auth import get_current_user
from src.detection.coverage import compute_coverage
from src.detection.scorecard import compute_rule_scorecard

router = APIRouter(tags=["detection"], prefix="/detection")


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
