"""
Detection rules API endpoints.

CRUD operations for Sigma detection rules.
"""
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.audit import log_audit_action
from src.api.auth import get_current_user, require_role
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


class RulePatch(BaseModel):
    """Partial update for a rule (P1-15/P2-43). All fields optional; only the
    provided fields are updated. sigma_yaml is re-parsed and MITRE re-extracted
    only when provided."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    sigma_yaml: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    run_interval: Optional[int] = None  # seconds
    lookback: Optional[int] = None  # seconds
    threshold: Optional[int] = None


class RuleResponse(BaseModel):
    id: int
    name: str
    description: str
    severity: str
    enabled: bool
    last_run: Optional[str] = None
    last_match: Optional[str] = None
    match_count: int = 0
    # P1-15: expose MITRE + full fields so the dashboard MITRE heatmap and
    # rule detail populate (previously dropped by from_row).
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    sigma_yaml: Optional[str] = None
    run_interval: Optional[str] = None
    lookback: Optional[str] = None
    threshold: Optional[int] = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_row(cls, row: dict) -> "RuleResponse":
        """Convert a DB row to RuleResponse, serializing datetimes/intervals."""
        last_run = row.get("last_run")
        row["last_run"] = last_run.isoformat() if last_run else None
        last_match = row.get("last_match")
        row["last_match"] = last_match.isoformat() if last_match else None
        # Serialize intervals (timedelta) to strings for the JSON response.
        for interval_field in ("run_interval", "lookback"):
            val = row.get(interval_field)
            if hasattr(val, "total_seconds"):
                row[interval_field] = str(val)
            elif val is not None:
                row[interval_field] = str(val)
        # Only pass fields that the model accepts
        fields = set(cls.model_fields.keys())
        filtered = {k: v for k, v in row.items() if k in fields}
        return cls(**filtered)


@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: RuleCreate,
    user: dict = Depends(require_role("admin")),
):
    """Create a new detection rule (admin-only, P1-12)."""
    # Validate Sigma YAML
    try:
        parsed = parse_sigma_rule(rule.sigma_yaml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Sigma rule: {str(e)}") from None

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
            timedelta(seconds=rule.run_interval),
            timedelta(seconds=rule.lookback),
            rule.threshold,
            parsed.mitre_tactics,
            parsed.mitre_techniques,
        )

        log.info("rule_created", rule_id=rule_id, name=rule.name, user=user.get("sub"))

        # P2-23: audit rule mutations (previously only structlog, never audit_log).
        await log_audit_action(
            actor=user.get("sub", "unknown"),
            action="rule.create",
            target_type="rule",
            target_id=rule_id,
            new_values={"name": rule.name, "severity": rule.severity, "enabled": rule.enabled},
        )

        # Reload scheduler to pick up new rule
        await reload_rules()

        return await get_rule_by_id(rule_id)


@router.get("", response_model=List[RuleResponse])
async def list_rules(
    enabled_only: bool = False,
    user: dict = Depends(get_current_user),
):
    """List all detection rules."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        if enabled_only:
            rows = await conn.fetch("SELECT * FROM rules WHERE enabled = TRUE ORDER BY id")
        else:
            rows = await conn.fetch("SELECT * FROM rules ORDER BY id")

        return [RuleResponse.from_row(dict(r)) for r in rows]


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: int,
    user: dict = Depends(get_current_user),
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
    user: dict = Depends(require_role("admin")),
):
    """Update a detection rule (admin-only, P1-12)."""
    # P2-20: re-parse the YAML so invalid YAML is rejected here (not at runtime)
    # and MITRE tactics/techniques are refreshed when sigma_yaml changes.
    try:
        parsed = parse_sigma_rule(updates.sigma_yaml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Sigma rule: {str(e)}") from None

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
                mitre_tactics = $9,
                mitre_techniques = $10,
                updated_at = NOW()
            WHERE id = $11
            """,
            updates.name,
            updates.description,
            updates.sigma_yaml,
            updates.severity,
            updates.enabled,
            timedelta(seconds=updates.run_interval),
            timedelta(seconds=updates.lookback),
            updates.threshold,
            parsed.mitre_tactics,
            parsed.mitre_techniques,
            rule_id,
        )

        log.info("rule_updated", rule_id=rule_id, user=user.get("sub"))

        # P2-23: audit rule mutations.
        await log_audit_action(
            actor=user.get("sub", "unknown"),
            action="rule.update",
            target_type="rule",
            target_id=rule_id,
            new_values={"name": updates.name, "enabled": updates.enabled,
                       "severity": updates.severity},
        )

        # Reload scheduler
        await reload_rules()

        return await get_rule_by_id(rule_id)


@router.patch("/{rule_id}", response_model=RuleResponse)
async def patch_rule(
    rule_id: int,
    patch: RulePatch,
    user: dict = Depends(require_role("admin")),
):
    """Partially update a detection rule (admin-only, P1-15/P2-43).

    Only the provided fields are updated. sigma_yaml, when provided, is
    re-parsed/validated and MITRE tactics/techniques are re-extracted. This
    fixes the dashboard Enable/Disable toggle (which sends {"enabled": false})
    hitting the full-replace PUT and getting a 422.
    """
    # Build the SET clause + params dynamically from provided (non-None) fields.
    set_parts: list[str] = []
    params: list = []
    idx = 1

    field_map = {
        "name": patch.name,
        "description": patch.description,
        "sigma_yaml": patch.sigma_yaml,
        "severity": patch.severity,
        "enabled": patch.enabled,
        "threshold": patch.threshold,
    }
    for col, val in field_map.items():
        if val is not None:
            set_parts.append(f"{col} = ${idx}")
            params.append(val)
            idx += 1
    if patch.run_interval is not None:
        set_parts.append(f"run_interval = ${idx}")
        params.append(timedelta(seconds=patch.run_interval))
        idx += 1
    if patch.lookback is not None:
        set_parts.append(f"lookback = ${idx}")
        params.append(timedelta(seconds=patch.lookback))
        idx += 1

    # Re-parse sigma_yaml + re-extract MITRE only when sigma_yaml is provided.
    if patch.sigma_yaml is not None:
        try:
            parsed = parse_sigma_rule(patch.sigma_yaml)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid Sigma rule: {str(e)}") from None
        set_parts.append(f"mitre_tactics = ${idx}")
        params.append(parsed.mitre_tactics)
        idx += 1
        set_parts.append(f"mitre_techniques = ${idx}")
        params.append(parsed.mitre_techniques)
        idx += 1

    if not set_parts:
        # Nothing to update — return the current rule.
        return await get_rule_by_id(rule_id)

    set_parts.append("updated_at = NOW()")
    params.append(rule_id)
    sql = f"UPDATE rules SET {', '.join(set_parts)} WHERE id = ${idx}"

    pool = await get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM rules WHERE id = $1", rule_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Rule not found")
        await conn.execute(sql, *params)

    username = user.get("sub", "unknown")
    log.info("rule_patched", rule_id=rule_id, user=username)
    await log_audit_action(
        actor=username,
        action="rule.update",
        target_type="rule",
        target_id=rule_id,
        new_values={k: v for k, v in patch.model_dump(exclude_none=True).items()},
    )

    await reload_rules()
    return await get_rule_by_id(rule_id)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    user: dict = Depends(require_role("admin")),
):
    """Delete a detection rule (admin-only, P1-12)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM rules WHERE id = $1", rule_id)
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Rule not found")

        log.info("rule_deleted", rule_id=rule_id, user=user.get("sub"))

        # P2-23: audit rule mutations.
        await log_audit_action(
            actor=user.get("sub", "unknown"),
            action="rule.delete",
            target_type="rule",
            target_id=rule_id,
        )

        # Reload scheduler
        await reload_rules()


async def get_rule_by_id(rule_id: int) -> Optional[dict]:
    """Helper to fetch rule by ID, serializing datetimes."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM rules WHERE id = $1", rule_id)
        if not row:
            return None
        d = dict(row)
        for dt_field in ("last_run", "last_match", "created_at", "updated_at"):
            if d.get(dt_field):
                val = d[dt_field]
                d[dt_field] = val.isoformat() if hasattr(val, "isoformat") else str(val)
        return d
