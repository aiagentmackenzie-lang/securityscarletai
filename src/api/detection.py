"""Detection-coverage API — the evidence-driven detectability map (V0.3).

GET /api/v1/detection/coverage — per-rule armed/dormant status + the
technique rollup the MITRE heatmap renders. Armed = the rule's required
telemetry was SEEN in the lookback window (source exists to fire it);
dormant = rule exists but its source/vocabulary has not (surfaced honestly
instead of silently never firing — the old title-driven heatmap counted
both identically).
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from src.api.auth import get_current_user
from src.detection.coverage import compute_coverage

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
