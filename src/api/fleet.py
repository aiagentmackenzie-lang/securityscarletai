"""Fleet enrollment API — admin-only (V0.5a "Fleet & Scale", roadmap group C).

POST   /api/v1/fleet/enroll        - enroll a host, returns the ONE-TIME token
GET    /api/v1/fleet/hosts         - list enrollments (never token hashes)
POST   /api/v1/fleet/revoke        - kill a host's token immediately
POST   /api/v1/fleet/rotate        - replace a host's token (re-enroll alias)

Security properties:
- Every endpoint requires the admin role (require_role("admin")).
- Plaintext tokens are generated with secrets.token_urlsafe(32) and stored
  ONLY as sha256(token) hex — the plaintext appears exactly once, in the
  enrollment/rotation HTTP response (never in audit rows, never in logs).
- Revocation is immediate: the ingest path resolves fleet tokens per call,
  so a revoked token is dead before the response returns.
- Host identity is bound at ingest time (src/api/ingest.py): a fleet token
  can only deliver events for ITS host_name. The enrollment is the
  convenience record; the audit chain is the tamper-evident truth.
- Re-enrolling an existing host rotates its token (hash replaced, audited).
"""

import hashlib
import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.audit import log_audit_action
from src.api.auth import require_role
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("api.fleet")

router = APIRouter(tags=["fleet"], prefix="/fleet")


# ───────────────────────────────────────────────────────────────
# Models
# ───────────────────────────────────────────────────────────────


class EnrollRequest(BaseModel):
    host_name: str = Field(min_length=1, max_length=253)
    notes: Optional[str] = Field(None, max_length=500)


class EnrollResponse(BaseModel):
    host_name: str
    token: str  # plaintext, shown ONCE
    rotated: bool  # True if this enrollment replaced an existing token


class FleetHost(BaseModel):
    """Fleet listing entry. NEVER carries the token hash."""

    host_name: str
    enrolled_at: datetime
    last_seen_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    notes: Optional[str] = None


class RevokeRequest(BaseModel):
    host_name: str = Field(min_length=1, max_length=253)


class RevokeResponse(BaseModel):
    host_name: str
    revoked_at: datetime


def _hash_token(token: str) -> str:
    """sha256 hex of the bearer token — the ONLY thing we persist."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _sanitize_hostname(v: str) -> str:
    """Same log-injection hygiene the ingest contract applies to host_name."""
    return "".join(c for c in v if c.isprintable() and c not in "\n\r\t")


# ───────────────────────────────────────────────────────────────
# Endpoints
# ───────────────────────────────────────────────────────────────


@router.post("/enroll", response_model=EnrollResponse, status_code=status.HTTP_201_CREATED)
async def enroll_host(
    body: EnrollRequest,
    admin: dict = Depends(require_role("admin")),
):
    """Enroll a fleet host. Returns the plaintext token ONCE.

    Re-enrollment of an existing host rotates its token (the old token dies
    the moment the new hash lands) — audited as fleet.rotate.
    """
    host = _sanitize_hostname(body.host_name.strip())
    if not host:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "host_name is empty")

    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    actor = admin.get("username") or admin.get("sub") or "unknown"

    pool = await get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchval("SELECT 1 FROM fleet_enrollments WHERE host_name = $1", host)
        if existing:
            await conn.execute(
                """
                UPDATE fleet_enrollments
                   SET token_hash = $2, enrolled_by = $3,
                       enrolled_at = NOW(), revoked_at = NULL
                 WHERE host_name = $1
                """,
                host,
                token_hash,
                actor,
            )
        else:
            await conn.execute(
                """
                INSERT INTO fleet_enrollments (host_name, token_hash, enrolled_by, notes)
                VALUES ($1, $2, $3, $4)
                """,
                host,
                token_hash,
                actor,
                body.notes,
            )

    rotated = bool(existing)
    await log_audit_action(
        actor=actor,
        action="fleet.rotate" if rotated else "fleet.enroll",
        target_type="fleet_enrollment",
        new_values={"host_name": host},
    )
    log.info(
        "fleet_enrolled" if not rotated else "fleet_rotated",
        host=host,
        actor=actor,
    )
    # NOTE: the plaintext token NEVER enters audit or logs — response only.
    return EnrollResponse(host_name=host, token=token, rotated=rotated)


@router.get("/hosts", response_model=list[FleetHost])
async def list_hosts(admin: dict = Depends(require_role("admin"))):
    """List fleet enrollments. Token hashes are intentionally excluded."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT host_name, enrolled_at, last_seen_at, revoked_at, notes
              FROM fleet_enrollments
          ORDER BY enrolled_at DESC
            """
        )
    return [dict(r) for r in rows]


@router.post("/revoke", response_model=RevokeResponse)
async def revoke_host(
    body: RevokeRequest,
    admin: dict = Depends(require_role("admin")),
):
    """Revoke a host's fleet token. Takes effect on the next ingest call."""
    host = _sanitize_hostname(body.host_name.strip())
    actor = admin.get("username") or admin.get("sub") or "unknown"

    pool = await get_pool()
    async with pool.acquire() as conn:
        revoked_at = await conn.fetchval(
            """
            UPDATE fleet_enrollments
               SET revoked_at = NOW()
             WHERE host_name = $1 AND revoked_at IS NULL
         RETURNING revoked_at
            """,
            host,
        )
    if revoked_at is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=f"host '{host}' not enrolled or already revoked",
        )

    await log_audit_action(
        actor=actor,
        action="fleet.revoke",
        target_type="fleet_enrollment",
        new_values={"host_name": host},
    )
    log.info("fleet_revoked", host=host, actor=actor)
    return RevokeResponse(host_name=host, revoked_at=revoked_at)
