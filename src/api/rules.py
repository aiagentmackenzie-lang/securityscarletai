"""
Detection rules API endpoints.

CRUD operations for Sigma detection rules.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.auth import verify_bearer_token
from src.config.logging import get_logger
from src.db.connection import get_pool
from src.detection.scheduler import reload_rules
from src.detection.sigma import parse_sigma_rule

router = APIRouter(tags=["detection"], prefix="/rules")
log = get_logger("api.rules")


class RuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    sigma_yaml: str
    severity: str = "medium"  # info, low, medium, high, critical
    enabled: bool = True
    run_interval: int = 60  # seconds
    lookback: int = 300  # seconds (5 minutes)
    threshold: int = 1


class RuleResponse(BaseModel):
    id: int
    name: str
    description: str
    severity: str
    enabled: bool
    last_run: Optional[str]
    last_match: Optional[str]
    match_count: int


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: RuleCreate,
    user: str = Depends(verify_bearer_token),
):
    """Create a new detection rule."""
    # Validate Sigma YAML
    try:
        parsed = parse_sigma_rule(rule.sigma_yaml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Sigma rule: {str(e)}")

    pool = await get_pool()
    async with pool.acquire() as conn:
        rule_id = await conn.fetchval(
            """
            INSERT INTO rules (
                name, description, sigma_yaml, severity, enabled,
                run_interval, lookback, threshold, mitre_tactics, mitre_techniques
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
            """,
            rule.name,
            rule.description,
            rule.sigma_yaml,
            rule.severity,
            rule.enabled,
            f"{rule.run_interval} seconds",
            f"{rule.lookback} seconds",
            rule.threshold,
            parsed.mitre_tactics,
            parsed.mitre_techniques,
        )

        log.info("rule_created", rule_id=rule_id, name=rule.name, user=str(user))

        # Reload scheduler to pick up new rule
        await reload_rules()

        return await get_rule_by_id(rule_id)


@router.get("", response_model=List[RuleResponse])
async def list_rules(
    enabled_only: bool = False,
    user: str = Depends(verify_bearer_token),
):
    """List all detection rules."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        if enabled_only:
            rows = await conn.fetch("SELECT * FROM rules WHERE enabled = TRUE ORDER BY id")
        else:
            rows = await conn.fetch("SELECT * FROM rules ORDER BY id")

        return [dict(r) for r in rows]


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: int,
    user: str = Depends(verify_bearer_token),
):
    """Get a specific rule by ID."""
    rule = await get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: int,
    updates: RuleCreate,
    user: str = Depends(verify_bearer_token),
):
    """Update a detection rule."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Check if rule exists
        existing = await conn.fetchrow("SELECT id FROM rules WHERE id = $1", rule_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Rule not found")

        await conn.execute(
            """
            UPDATE rules SET
                name = $1,
                description = $2,
                sigma_yaml = $3,
                severity = $4,
                enabled = $5,
                run_interval = $6,
                lookback = $7,
                threshold = $8,
                updated_at = NOW()
            WHERE id = $9
            """,
            updates.name,
            updates.description,
            updates.sigma_yaml,
            updates.severity,
            updates.enabled,
            f"{updates.run_interval} seconds",
            f"{updates.lookback} seconds",
            updates.threshold,
            rule_id,
        )

        log.info("rule_updated", rule_id=rule_id, user=str(user))

        # Reload scheduler
        await reload_rules()

        return await get_rule_by_id(rule_id)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    user: str = Depends(verify_bearer_token),
):
    """Delete a detection rule."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM rules WHERE id = $1", rule_id)
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Rule not found")

        log.info("rule_deleted", rule_id=rule_id, user=str(user))

        # Reload scheduler
        await reload_rules()


async def get_rule_by_id(rule_id: int) -> Optional[dict]:
    """Helper to fetch rule by ID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM rules WHERE id = $1", rule_id)
        return dict(row) if row else None
