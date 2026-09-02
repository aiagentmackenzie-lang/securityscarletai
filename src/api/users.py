"""
User management API — admin-only (Phase 3.1).

POST   /api/v1/users                      - create user (must_change_password=True)
GET    /api/v1/users                      - list users (never password_hash)
PATCH  /api/v1/users/{user_id}            - role change / is_active toggle
POST   /api/v1/users/{user_id}/reset-password - one-time random password

Security properties:
- Every endpoint requires the admin role (require_role("admin")).
- Deactivating a user, changing a user's role, or resetting their password
  sets the Redis user_revoke marker (same mechanism as /auth/change-password)
  so tokens issued before the mutation are invalid immediately. A role change
  must revoke: the JWT carries the role claim, so an old token would keep the
  pre-change role until natural expiry.
- Self-protection: an admin cannot deactivate themselves or change their own
  role — that could disable the last admin and lock the SIEM. Resetting your
  own password is allowed (equivalent to /auth/change-password, minus the
  current-password check).
- Every mutation is audit-logged via log_audit_action. The one-time password
  from reset-password appears ONLY in the HTTP response — never in audit
  entries, never in logs.
- Passwords are hashed with hash_password() (bcrypt, SHA-256 pre-hash, pepper).
"""
import secrets
from datetime import datetime, timezone
from typing import Literal, Optional

from asyncpg.exceptions import UniqueViolationError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from src.api.audit import log_audit_action
from src.api.auth import hash_password, require_role
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("api.users")

router = APIRouter(tags=["users"], prefix="/users")

# Revoke-marker TTL: cover the longest-lived token (refresh) plus slack,
# identical to /auth/change-password.
_REVOKE_TTL_S = None  # resolved lazily from settings (avoids import at module load)


def _revoke_ttl_seconds() -> int:
    from src.config.settings import settings

    return (settings.refresh_token_ttl_days + 1) * 24 * 3600


# ───────────────────────────────────────────────────────────────
# Request / Response models
# ───────────────────────────────────────────────────────────────

Role = Literal["admin", "analyst", "viewer"]


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: Optional[str] = Field(None, max_length=320)
    password: str = Field(..., min_length=8, max_length=200)
    role: Role = "analyst"


class UserPatchRequest(BaseModel):
    role: Optional[Role] = None
    is_active: Optional[bool] = None


class UserSummary(BaseModel):
    """User listing entry. Deliberately excludes password_hash."""

    id: int
    username: str
    email: Optional[str] = None
    role: str
    is_active: bool
    must_change_password: bool
    last_login: Optional[datetime] = None
    created_at: Optional[datetime] = None


class UserCreateResponse(UserSummary):
    must_change_password: bool = True


class UserPatchResponse(UserSummary):
    revoked_older_tokens: bool


class ResetPasswordResponse(BaseModel):
    user_id: int
    username: str
    # One-time password: the operator hands this to the user out-of-band.
    # The user must change it on first login (must_change_password=True).
    temporary_password: str
    must_change_password: bool = True
    revoked_older_tokens: bool


# ───────────────────────────────────────────────────────────────
# Endpoints
# ───────────────────────────────────────────────────────────────


@router.get("", response_model=list[UserSummary])
async def list_users(user: dict = Depends(require_role("admin"))):
    """List all users. Admin-only. Never returns password_hash."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, username, email, role, is_active,
                   must_change_password, last_login, created_at
            FROM siem_users
            ORDER BY id
            """
        )
    return [UserSummary(**dict(r)) for r in rows]


@router.post("", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    """Create a user. Admin-only. The user must change their password on
    first login (must_change_password=True)."""
    pool = await get_pool()
    password_hash = hash_password(body.password)
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO siem_users (username, email, password_hash, role, must_change_password)
                VALUES ($1, $2, $3, $4, TRUE)
                RETURNING id, username, email, role, is_active,
                          must_change_password, last_login, created_at
                """,
                body.username,
                body.email,
                password_hash,
                body.role,
            )
        except UniqueViolationError as e:
            constraint = getattr(e, "constraint_name", "") or ""
            field = "email" if "email" in constraint else "username"
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{field} already exists",
            ) from None

    log.info("user_created", username=body.username, role=body.role, actor=user.get("sub"))
    await log_audit_action(
        actor=user.get("sub", "unknown"),
        action="user.create",
        target_type="user",
        target_id=row["id"],
        new_values={"username": body.username, "role": body.role, "email": body.email},
        ip_address=request.client.host if request.client else None,
    )
    return UserCreateResponse(**dict(row))


async def _fetch_user(pool, user_id: int):
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT id, username, role, is_active FROM siem_users WHERE id = $1",
            user_id,
        )


async def _revoke_user_tokens(username: str) -> bool:
    """Set the user_revoke marker: tokens issued before now are invalid."""
    from src.api.redis_client import set_user_revoke_marker

    return await set_user_revoke_marker(
        username, datetime.now(tz=timezone.utc), _revoke_ttl_seconds()
    )


@router.patch("/{user_id}", response_model=UserPatchResponse)
async def patch_user(
    user_id: int,
    body: UserPatchRequest,
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    """Change a user's role and/or active state. Admin-only.

    Deactivating a user sets the user_revoke marker (their existing tokens are
    rejected immediately). Role changes also set the marker — the JWT carries
    the role claim, so pre-change tokens must not survive a demotion.
    Self-protection: you cannot deactivate yourself or change your own role
    (that could disable the last admin account).
    """
    if body.role is None and body.is_active is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide at least one of: role, is_active",
        )

    pool = await get_pool()
    existing = await _fetch_user(pool, user_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    actor = user.get("sub", "unknown")
    if user_id == existing["id"] and actor == existing["username"]:
        if body.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot deactivate your own account",
            )
        if body.role is not None and body.role != existing["role"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot change your own role",
            )

    sets: list[str] = []
    params: list[object] = []
    if body.role is not None:
        sets.append(f"role = ${len(params) + 1}")
        params.append(body.role)
    if body.is_active is not None:
        sets.append(f"is_active = ${len(params) + 1}")
        params.append(body.is_active)
    params.append(user_id)

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""
            UPDATE siem_users SET {", ".join(sets)}
            WHERE id = ${len(params)}
            RETURNING id, username, email, role, is_active,
                      must_change_password, last_login, created_at
            """,  # noqa: S608 — no user input in the SET clause (parameterized values only)
            *params,
        )

    # Revoke older tokens on deactivation AND role change (see docstring).
    revoked = False
    if body.is_active is False or (body.role is not None and body.role != existing["role"]):
        revoked = await _revoke_user_tokens(existing["username"])

    log.info(
        "user_patched",
        target=existing["username"],
        role=body.role,
        is_active=body.is_active,
        revoked_older_tokens=revoked,
        actor=actor,
    )
    await log_audit_action(
        actor=actor,
        action="user.update",
        target_type="user",
        target_id=user_id,
        old_values={"role": existing["role"], "is_active": existing["is_active"]},
        new_values={"role": body.role, "is_active": body.is_active,
                    "revoked_older_tokens": revoked},
        ip_address=request.client.host if request.client else None,
    )
    return UserPatchResponse(**dict(row), revoked_older_tokens=revoked)


@router.post("/{user_id}/reset-password", response_model=ResetPasswordResponse)
async def reset_password(
    user_id: int,
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    """Reset a user's password to a random one-time value. Admin-only.

    The temporary password is returned ONCE in this response — the operator
    delivers it out-of-band; the user is forced to change it on first login
    (must_change_password=True). The plaintext is never logged and never
    stored in the audit log (the audit entry records the action, not the
    secret). Older tokens for the user are revoked immediately.
    """
    pool = await get_pool()
    existing = await _fetch_user(pool, user_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    temporary_password = secrets.token_urlsafe(16)
    password_hash = hash_password(temporary_password)

    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE siem_users
            SET password_hash = $1,
                must_change_password = TRUE,
                failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = $2
            """,
            password_hash,
            user_id,
        )

    revoked = await _revoke_user_tokens(existing["username"])

    log.info(
        "user_password_reset",
        target=existing["username"],
        actor=user.get("sub"),
        revoked_older_tokens=revoked,
    )
    await log_audit_action(
        actor=user.get("sub", "unknown"),
        action="user.reset_password",
        target_type="user",
        target_id=user_id,
        new_values={"username": existing["username"], "must_change_password": True},
        ip_address=request.client.host if request.client else None,
    )
    return ResetPasswordResponse(
        user_id=user_id,
        username=existing["username"],
        temporary_password=temporary_password,
        must_change_password=True,
        revoked_older_tokens=revoked,
    )
