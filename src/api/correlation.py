"""
Correlation detection API endpoints (Agent A, Epic 2).

- POST /api/v1/correlation/run         — Run all rules (with as_of, persist)
- POST /api/v1/correlation/run/{rule}  — Run a single rule
- GET  /api/v1/correlation/matches     — List persisted matches
- POST /api/v1/correlation/matches/{id}/seen — Mark a match as reviewed
- GET  /api/v1/correlation/rules       — List available rules
- GET  /api/v1/correlation/rules/{n}   — Rule details
- GET  /api/v1/correlation/sequences   — List sequence definitions
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.api.auth import get_current_user, require_role
from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.correlation import (
    detect_brute_force_then_success,
    detect_credential_theft_exfil,
    detect_data_exfiltration,
    detect_defense_evasion_cleanup,
    detect_payload_callback,
    detect_persistence_activated,
    detect_privilege_escalation_chain,
    get_correlation_rule_info,
    list_correlation_rules,
    list_matches,
    mark_match_seen,
    persist_match,
    run_all_correlations,
)
from src.detection.sequences import list_sequences

log = get_logger("api.correlation")

router = APIRouter(tags=["correlation"], prefix="/correlation")


# ───────────────────────────────────────────────────────────────
# Request/Response models
# ───────────────────────────────────────────────────────────────


class CorrelationRunRequest(BaseModel):
    """Request body for POST /correlation/run."""
    as_of: Optional[str] = Field(
        None,
        description="ISO-8601 timestamp. Defaults to now() if omitted.",
        examples=["2026-05-31T22:00:00Z"],
    )
    persist: bool = Field(
        False,
        description="If True, write matches to correlation_matches table.",
    )


class CorrelationResult(BaseModel):
    """Response for a single rule's matches (legacy shape)."""
    rule_name: str
    title: str
    description: str
    severity: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    matches: list[dict]


class CorrelationRunResponse(BaseModel):
    """Response for POST /correlation/run."""
    as_of: str
    total_matches: int
    persisted: int
    per_rule: Dict[str, List[dict]]


class CorrelationMatchSummary(BaseModel):
    """Response for GET /correlation/matches."""
    total: int
    limit: int
    offset: int
    matches: List[dict]


# ───────────────────────────────────────────────────────────────
# Rule metadata endpoints
# ───────────────────────────────────────────────────────────────


@router.get("/rules")
async def list_rules(user: dict = Depends(get_current_user)):
    """List all available correlation rules."""
    return list_correlation_rules()


@router.get("/rules/{rule_name}")
async def get_rule(rule_name: str, user: dict = Depends(get_current_user)):
    """Get details of a specific correlation rule."""
    info = get_correlation_rule_info(rule_name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Correlation rule '{rule_name}' not found")
    return {"name": rule_name, **info}


@router.get("/sequences")
async def list_sequence_rules(user: dict = Depends(get_current_user)):
    """List all available event sequence definitions."""
    return list_sequences()


# ───────────────────────────────────────────────────────────────
# Run endpoints (Epic 2)
# ───────────────────────────────────────────────────────────────


def _parse_as_of(as_of) -> Optional[datetime]:
    """Parse ISO-8601 string into datetime, or return current UTC time.

    Tolerates None, str, or FastAPI Query/inspect.Parameter objects.
    For non-string values that aren't None, returns current UTC time as
    a safe default (used when the endpoint is called from a test that
    doesn't supply the parameter).
    """
    if as_of is None:
        return datetime.now(tz=timezone.utc)
    if not isinstance(as_of, str):
        # FastAPI Query default or inspect.Parameter — return current time
        return datetime.now(tz=timezone.utc)
    s = as_of.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid as_of format. Expected ISO-8601 (e.g. 2026-05-31T22:00:00Z). Got: {as_of}",
        ) from e


def _unwrap(value, default=None):
    """Unwrap FastAPI Query/Parameter defaults. Returns the value as-is otherwise.

    FastAPI wraps default values in Query() or inspect.Parameter() when
    the endpoint is registered. When the function is called directly
    (e.g. from a unit test), those wrappers are still in the signature
    defaults. This helper extracts the underlying value.

    Args:
        value: The value to unwrap.
        default: Returned if value is None or a wrapper with no usable value.
    """
    if value is None:
        return default
    if isinstance(value, (str, bool, int, float)):
        return value
    # FastAPI Query/inspect.Parameter
    if hasattr(value, "default"):
        inner = value.default
        if inner is None or isinstance(inner, (str, bool, int, float)):
            return inner if inner is not None else default
    return default


@router.post(
    "/run",
    response_model=CorrelationRunResponse,
    summary="Run all correlation rules",
    description=(
        "Run all correlation rules as of a specific point in time. "
        "With persist=true, matches are written to the correlation_matches table. "
        "Default as_of is now()."
    ),
)
async def run_correlations_post(
    request: CorrelationRunRequest = CorrelationRunRequest(),
    user: dict = Depends(require_role("analyst")),
):
    """Run all correlation rules with as_of and optional persist."""
    parsed_as_of = _parse_as_of(request.as_of)
    log.info(
        "api_correlation_run",
        as_of=parsed_as_of.isoformat(),
        persist=request.persist,
        user=str(user.get("sub", "unknown")),
    )
    result = await run_all_correlations(as_of=parsed_as_of, persist=request.persist)
    return CorrelationRunResponse(
        as_of=result["as_of"],
        total_matches=result["total_matches"],
        persisted=result["persisted"],
        per_rule=result["per_rule"],
    )


# Legacy compat: POST /run with PersistFlags body (old shape)
class PersistFlags(BaseModel):
    persist_alerts: bool = False


@router.post("/run-legacy")
async def run_correlations_legacy(
    request: PersistFlags = None,
    user: str = Depends(require_role("analyst")),
):
    """Legacy: POST /run with PersistFlags (persist_alerts flag, no as_of)."""
    persist = request.persist_alerts if request else False
    result = await run_all_correlations(as_of=None, persist=persist)

    # Enrich with rule metadata (legacy shape: rule_name -> {title, ..., matches})
    enriched: Dict[str, Any] = {}
    for rule_name, matches in result["per_rule"].items():
        info = get_correlation_rule_info(rule_name)
        enriched[rule_name] = {
            "title": info["title"] if info else rule_name,
            "description": info["description"] if info else "",
            "severity": info["severity"] if info else "medium",
            "mitre_tactics": info.get("mitre_tactics", []) if info else [],
            "mitre_techniques": info.get("mitre_techniques", []) if info else [],
            "match_count": len(matches),
            "matches": matches,
        }

    return {
        "total_matches": result["total_matches"],
        "rules_run": len(result["per_rule"]),
        "results": enriched,
    }


@router.post("/run/{rule_name}")
async def run_single_correlation(
    rule_name: str,
    as_of: Optional[str] = Query(None, description="ISO-8601 timestamp"),
    user: dict = Depends(require_role("analyst")),
):
    """Run a single correlation rule by name."""
    rule_funcs = {
        "brute_force_success": detect_brute_force_then_success,
        "payload_callback": detect_payload_callback,
        "persistence_activated": detect_persistence_activated,
        "data_exfiltration": detect_data_exfiltration,
        "privilege_escalation_chain": detect_privilege_escalation_chain,
        "credential_theft_exfil": detect_credential_theft_exfil,
        "defense_evasion_cleanup": detect_defense_evasion_cleanup,
    }

    if rule_name not in rule_funcs:
        raise HTTPException(
            status_code=404,
            detail=f"Correlation rule '{rule_name}' not found",
        )

    parsed_as_of = _parse_as_of(as_of)
    pool = await get_pool()
    async with pool.acquire() as conn:
        matches = await rule_funcs[rule_name](conn, parsed_as_of)
    info = get_correlation_rule_info(rule_name)

    return {
        "rule_name": rule_name,
        "as_of": parsed_as_of.isoformat(),
        "title": info["title"] if info else rule_name,
        "description": info["description"] if info else "",
        "severity": info["severity"] if info else "medium",
        "mitre_tactics": info.get("mitre_tactics", []) if info else [],
        "mitre_techniques": info.get("mitre_techniques", []) if info else [],
        "match_count": len(matches),
        "matches": matches,
    }


# ───────────────────────────────────────────────────────────────
# Persistence endpoints (Epic 2)
# ───────────────────────────────────────────────────────────────


@router.get(
    "/matches",
    response_model=CorrelationMatchSummary,
    summary="List persisted correlation matches",
    description="Filter by rule, severity, time range, and seen status.",
)
async def get_correlation_matches(
    rule: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    seen: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    user: dict = Depends(get_current_user),
):
    """List persisted correlation matches with filters.

    Args can be plain Python values (when called from tests) or
    FastAPI Query objects (when called via the router). Both are
    tolerated; Query values are unwrapped via .default.
    """
    # Unwrap FastAPI Query/Parameter defaults when called directly
    rule = _unwrap(rule)
    severity = _unwrap(severity)
    since = _unwrap(since)
    until = _unwrap(until)
    seen = _unwrap(seen)
    limit = _unwrap(limit, default=100)
    offset = _unwrap(offset, default=0)

    since_dt = _parse_as_of(since) if since else None
    until_dt = _parse_as_of(until) if until else None
    rows = await list_matches(
        rule=rule,
        severity=severity,
        since=since_dt,
        until=until_dt,
        seen=seen,
        limit=limit,
        offset=offset,
    )
    # Serialize datetimes to ISO strings for JSON
    serialized: List[dict] = []
    for row in rows:
        s = dict(row)
        if "created_at" in s and hasattr(s["created_at"], "isoformat"):
            s["created_at"] = s["created_at"].isoformat()
        if "match_data" in s and not isinstance(s["match_data"], (dict, list)):
            # match_data is JSONB but asyncpg may return as str in some paths
            import json as _json
            try:
                s["match_data"] = _json.loads(s["match_data"]) if isinstance(s["match_data"], str) else s["match_data"]
            except Exception:
                pass
        serialized.append(s)
    return CorrelationMatchSummary(
        total=len(serialized),
        limit=limit,
        offset=offset,
        matches=serialized,
    )


@router.post(
    "/matches/{match_id}/seen",
    summary="Mark a correlation match as reviewed",
)
async def mark_seen(match_id: int, user: dict = Depends(require_role("analyst"))):
    """Mark a correlation match as seen (reviewed)."""
    ok = await mark_match_seen(match_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=f"Match {match_id} not found or could not be updated",
        )
    log.info(
        "api_correlation_match_seen",
        match_id=match_id,
        user=str(user.get("sub", "unknown")),
    )
    return {"id": match_id, "seen": True}


@router.post(
    "/matches/{match_id}/persist",
    summary="Persist a single match (used by ingestion path)",
)
async def persist_single_match(
    match_id: int,
    match: dict,
    user: dict = Depends(require_role("admin")),
):
    """Persist a single correlation match by direct dict insert.

    Note: normally the run endpoint with persist=true handles this. This
    endpoint is for ad-hoc insertion of pre-computed matches.
    """
    new_id = await persist_match(match, trigger_event_id=match_id)
    if new_id is None:
        raise HTTPException(
            status_code=500,
            detail="Failed to persist match",
        )
    return {"id": new_id, "correlation_id": match.get("correlation_id")}
