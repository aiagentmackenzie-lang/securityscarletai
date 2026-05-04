"""
Correlation detection API endpoints.

Run and manage sequence-based correlation rules.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.api.auth import require_role, verify_bearer_token
from src.config.logging import get_logger
from src.detection.correlation import (
    get_correlation_rule_info,
    list_correlation_rules,
    run_all_correlations,
)

router = APIRouter(tags=["correlation"], prefix="/correlation")
log = get_logger("api.correlation")


class CorrelationResult(BaseModel):
    rule_name: str
    title: str
    description: str
    severity: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    matches: list[dict]


@router.get("/rules")
async def list_rules(user: str = Depends(verify_bearer_token)):
    """List all available correlation rules."""
    return list_correlation_rules()


@router.get("/rules/{rule_name}")
async def get_rule(rule_name: str, user: str = Depends(verify_bearer_token)):
    """Get details of a specific correlation rule."""
    info = get_correlation_rule_info(rule_name)
    if not info:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Correlation rule '{rule_name}' not found")
    return {"name": rule_name, **info}


@router.post("/run")
async def run_correlations(
    user: str = Depends(require_role("analyst")),
):
    """Run all correlation rules and return results."""
    results = await run_all_correlations()

    # Enrich with rule metadata
    enriched = {}
    for rule_name, matches in results.items():
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

    total_matches = sum(len(v) for v in results.values())
    log.info("api_correlation_run", total_matches=total_matches, user=str(user))

    return {
        "total_matches": total_matches,
        "rules_run": len(results),
        "results": enriched,
    }


@router.post("/run/{rule_name}")
async def run_single_correlation(
    rule_name: str,
    user: str = Depends(require_role("analyst")),
):
    """Run a single correlation rule by name."""
    from fastapi import HTTPException

    from src.detection.correlation import (
        detect_brute_force_then_success,
        detect_data_exfiltration,
        detect_payload_callback,
        detect_persistence_activated,
        detect_privilege_escalation_chain,
    )

    rule_funcs = {
        "brute_force_success": detect_brute_force_then_success,
        "payload_callback": detect_payload_callback,
        "persistence_activated": detect_persistence_activated,
        "data_exfiltration": detect_data_exfiltration,
        "privilege_escalation_chain": detect_privilege_escalation_chain,
    }

    if rule_name not in rule_funcs:
        raise HTTPException(status_code=404, detail=f"Correlation rule '{rule_name}' not found")

    matches = await rule_funcs[rule_name]()
    info = get_correlation_rule_info(rule_name)

    return {
        "rule_name": rule_name,
        "title": info["title"] if info else rule_name,
        "description": info["description"] if info else "",
        "severity": info["severity"] if info else "medium",
        "mitre_tactics": info.get("mitre_tactics", []) if info else [],
        "mitre_techniques": info.get("mitre_techniques", []) if info else [],
        "match_count": len(matches),
        "matches": matches,
    }
