"""
Authentication endpoints for dashboard users.

POST /api/v1/auth/login         - Authenticate and get JWT (access + refresh)
POST /api/v1/auth/refresh       - Exchange refresh token for new access token
POST /api/v1/auth/logout        - Blacklist current access token's jti
POST /api/v1/auth/change-password - Change own password (requires JWT)
GET  /api/v1/auth/me            - Get current user info (requires JWT)

Users are stored in the siem_users table with bcrypt-hashed passwords.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.auth import (
    JWT_ALGORITHM,
    create_jwt,
    create_refresh_token,
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
    refresh_token: str | None = None
    token_type: str = "bearer"  # noqa: S105
    username: str
    role: str
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class LogoutResponse(BaseModel):
    message: str = "Logged out"


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
            "SELECT id, username, password_hash, role, is_active, locked_until, failed_login_attempts, must_change_password FROM siem_users WHERE username = $1",  # noqa: E501
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

        # M-06 fix: Check account lockout from too many failed attempts
        if row.get("locked_until") and row["locked_until"] > datetime.now(tz=timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked due to too many failed login attempts. Try again later.",
            )

        if not verify_password(request.password, row["password_hash"]):
            # M-06 fix: Increment failed login attempts, lock after 5 failures for 15 min
            new_attempts = (row.get("failed_login_attempts", 0) or 0) + 1
            lock_until = None
            if new_attempts >= 5:
                lock_until = datetime.now(tz=timezone.utc) + timedelta(minutes=15)
                log.warning("account_locked", username=row["username"], attempts=new_attempts)
            await conn.execute(
                "UPDATE siem_users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3",
                new_attempts,
                lock_until,
                row["id"],
            )
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
            "UPDATE siem_users SET last_login = NOW(), failed_login_attempts = 0, locked_until = NULL WHERE id = $1",
            row["id"],
        )

    from src.config.settings import settings

    access_token = create_jwt(row["username"], row["role"])
    refresh_token = create_refresh_token(row["username"], row["role"])

    log.info(
        "user_login",
        username=row["username"],
        role=row["role"],
    )

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        username=row["username"],
        role=row["role"],
        expires_in=settings.access_token_ttl_minutes * 60,
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

    # Epic 5: invalidate all tokens issued before this point for this user.
    # Best-effort: if Redis is down, the password is changed in DB but old
    # tokens remain valid until natural expiry.
    from src.api.redis_client import set_user_revoke_marker
    from src.config.settings import settings
    revoke_ttl = (settings.refresh_token_ttl_days + 1) * 24 * 3600
    set_user_revoke_marker(payload["sub"], datetime.now(tz=timezone.utc), revoke_ttl)

    log.info("password_changed", username=payload["sub"])
    return {"message": "Password changed successfully. All existing sessions invalidated."}


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

@router.post("/seed-admin")
async def seed_admin_user():
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


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(request: RefreshRequest):
    """Exchange a refresh token for a new access token (+ new refresh token rotation).

    Returns 401 if the refresh token is invalid, expired, blocked, or has
    type != 'refresh'.
    """
    from jose import JWTError, jwt

    from src.config.settings import settings as _settings
    try:
        payload = jwt.decode(
            request.refresh_token,
            _settings.api_secret_key.get_secret_value(),
            algorithms=[JWT_ALGORITHM],
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from None

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not a refresh token",
        )

    from src.api.redis_client import get_latest_user_revoke_ts, is_jti_blocked

    jti = payload.get("jti")
    if jti and is_jti_blocked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )
    sub = payload.get("sub")
    iat = payload.get("iat")
    if sub and iat is not None:
        revoke_ts = get_latest_user_revoke_ts(sub)
        if revoke_ts is not None and float(iat) < revoke_ts:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token issued before password change",
            )

    # Verify user still exists and is active
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT username, role, is_active FROM siem_users WHERE username = $1",
            sub,
        )
    if row is None or not row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer active",
        )

    # Rotate: block old refresh, issue new pair.
    from src.api.redis_client import blocklist_jti
    if jti:
        blocklist_jti(jti, _settings.refresh_token_ttl_days * 24 * 3600)

    new_access = create_jwt(row["username"], row["role"])
    new_refresh = create_refresh_token(row["username"], row["role"])

    log.info("token_refreshed", username=row["username"])
    return LoginResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        username=row["username"],
        role=row["role"],
        expires_in=_settings.access_token_ttl_minutes * 60,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(payload: dict = Depends(verify_jwt)):
    """Logout — blacklist the current access token's jti in Redis until natural expiry.

    Subsequent calls with the same token return 401.
    """
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has no jti — please re-login (pre-hardening token)",
        )

    from src.api.redis_client import blocklist_jti
    from src.config.settings import settings as _settings

    ttl = _settings.access_token_ttl_minutes * 60
    blocklist_jti(jti, ttl)

    log.info("user_logout", username=payload.get("sub"))
    return LogoutResponse()
