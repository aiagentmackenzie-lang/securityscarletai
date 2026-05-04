"""
Authentication endpoints for dashboard users.

POST /api/v1/auth/login   — Authenticate and get JWT
POST /api/v1/auth/change-password — Change own password (requires JWT)
GET  /api/v1/auth/me      — Get current user info (requires JWT)

Users are stored in the siem_users table with bcrypt-hashed passwords.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.auth import (
    create_jwt,
    hash_password,
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


# ───────────────────────────────────────────────────────────────
# Endpoints
# ───────────────────────────────────────────────────────────────


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Authenticate a user and return a JWT token."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash, role, is_active FROM siem_users WHERE username = $1",  # noqa: E501
            request.username,
        )

    if row is None:
        # Don't reveal whether user exists — constant-time check
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

    # Update last_login
    async with pool.acquire() as conn:
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
            "SELECT username, role, email, is_active, last_login FROM siem_users WHERE username = $1",  # noqa: E501
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
            "UPDATE siem_users SET password_hash = $1 WHERE id = $2",
            new_hash,
            row["id"],
        )

    log.info("password_changed", username=payload["sub"])
    return {"message": "Password changed successfully"}


@router.post("/seed-admin")
async def seed_admin_user():
    """
    Create an initial admin user if no users exist.
    This endpoint is only available when the siem_users table is empty.
    Default credentials: admin / admin (must be changed after first login).
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        user_count = await conn.fetchval("SELECT COUNT(*) FROM siem_users")

    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Users already exist. Use the login endpoint.",
        )

    # Create default admin user
    admin_hash = hash_password("admin")
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO siem_users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)",
            "admin",
            "admin@localhost",
            admin_hash,
            "admin",
        )

    log.warning("seed_admin_created", message="Default admin user created — CHANGE PASSWORD IMMEDIATELY")  # noqa: E501
    return {
        "message": "Admin user created. Username: admin, Password: admin — CHANGE PASSWORD IMMEDIATELY",  # noqa: E501
        "username": "admin",
    }
