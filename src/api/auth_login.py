"""
Authentication endpoints for dashboard users.

POST /api/v1/auth/login   - Authenticate and get JWT
POST /api/v1/auth/change-password - Change own password (requires JWT)
GET  /api/v1/auth/me      - Get current user info (requires JWT)

Users are stored in the siem_users table with bcrypt-hashed passwords.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.auth import (
    create_jwt,
    hash_password,
    require_role,
    verify_jwt,
    verify_password,
)
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("api.auth_login")

router = APIRouter(tags=["auth"], prefix="/auth")


# ───────────────────────────────────────────────────────────────
# Request / Response models
# ───────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    username: str
    role: str
    expires_in: int  # seconds


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=200)


class UserInfoResponse(BaseModel):
    username: str
    role: str
    email: str | None
    is_active: bool
    last_login: datetime | None
    must_change_password: bool = False


class ForceChangePasswordRequest(BaseModel):
    """Used when must_change_password is true - no current password required."""
    new_password: str = Field(..., min_length=8, max_length=200)


# ───────────────────────────────────────────────────────────────
# Endpoints
# ───────────────────────────────────────────────────────────────


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Authenticate a user and return a JWT token."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash, role, is_active, must_change_password FROM siem_users WHERE username = $1",  # noqa: E501
            request.username,
        )

        if row is None:
            # Don't reveal whether user exists - constant-time check
            hash_password("dummy")  # Burn equivalent CPU time
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled",
            )

        if not verify_password(request.password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        # M-10 migration: enforce password change if flagged
        if row.get("must_change_password", False):
            # Issue a short-lived token that can ONLY be used for password change
            force_token = create_jwt(
                row["username"],
                row["role"],
                extra={"force_password_change": True},
            )
            log.warning(
                "login_blocked_password_reset_required",
                username=row["username"],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": "Password change required before login",
                    "code": "PASSWORD_CHANGE_REQUIRED",
                    "force_change_token": force_token,
                },
            )

        # M-21 fix: Update last_login in same connection/transaction
        await conn.execute(
            "UPDATE siem_users SET last_login = NOW() WHERE id = $1",
            row["id"],
        )

    from src.api.auth import JWT_EXPIRY_HOURS

    token = create_jwt(row["username"], row["role"])

    log.info(
        "user_login",
        username=row["username"],
        role=row["role"],
    )

    return LoginResponse(
        access_token=token,
        username=row["username"],
        role=row["role"],
        expires_in=JWT_EXPIRY_HOURS * 3600,
    )


@router.get("/me", response_model=UserInfoResponse)
async def get_current_user(payload: dict = Depends(verify_jwt)):
    """Get current authenticated user info."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, role, email, is_active, last_login, must_change_password FROM siem_users WHERE username = $1",  # noqa: E501
            payload["sub"],
        )

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return UserInfoResponse(**dict(row))


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    payload: dict = Depends(verify_jwt),
):
    """Change own password. Requires current password verification."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash FROM siem_users WHERE username = $1",
            payload["sub"],
        )

    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not verify_password(request.current_password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    new_hash = hash_password(request.new_password)
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE siem_users SET password_hash = $1, must_change_password = false WHERE id = $2",
            new_hash,
            row["id"],
        )

    log.info("password_changed", username=payload["sub"])
    return {"message": "Password changed successfully"}


@router.post("/force-change-password")
async def force_change_password(
    request: ForceChangePasswordRequest,
    payload: dict = Depends(verify_jwt),
):
    """Force password change when must_change_password is true.

    This endpoint is called with the force_change_token from the 403 response.
    It does NOT require the current password - used for migration flow only.
    The token must contain 'force_password_change': True.
    """
    if not payload.get("force_password_change"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires a force_password_change token",
        )

    new_hash = hash_password(request.new_password)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            (
                "UPDATE siem_users"
                " SET password_hash = $1, must_change_password = false"
                " WHERE username = $2"
            ),
            new_hash,
            payload["sub"],
        )

    log.info("force_password_changed", username=payload["sub"])
    return {"message": "Password changed successfully. You can now log in normally."}

@router.post("/seed-admin", dependencies=[Depends(require_role("admin"))])
async def seed_admin_user(
    _user: dict = Depends(require_role("admin")),
):
    """
    Create an initial admin user if no users exist.

    Race-condition safe: uses advisory lock + INSERT ... ON CONFLICT DO NOTHING
    so concurrent requests cannot create duplicate admin accounts.
    Default credentials: admin / admin (must be changed after first login).
    """
    pool = await get_pool()
    admin_hash = hash_password("admin")

    async with pool.acquire() as conn:
        # Advisory lock prevents race condition: only one seed at a time
        await conn.execute("SELECT pg_advisory_lock(12345)")
        try:
            # Check + insert atomically within the same transaction + lock
            result = await conn.fetchrow(
                """
                INSERT INTO siem_users (username, email, password_hash, role)
                SELECT $1, $2, $3, $4
                WHERE NOT EXISTS (SELECT 1 FROM siem_users)
                ON CONFLICT DO NOTHING
                RETURNING username
                """,
                "admin",
                "admin@localhost",
                admin_hash,
                "admin",
            )
        finally:
            await conn.execute("SELECT pg_advisory_unlock(12345)")

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Users already exist. Use the login endpoint.",
        )

    log.warning("seed_admin_created", message="Default admin user created - CHANGE PASSWORD IMMEDIATELY")  # noqa: E501
    return {
        "message": "Admin user created. Username: admin, Password: admin - CHANGE PASSWORD IMMEDIATELY",  # noqa: E501
        "username": "admin",
    }
