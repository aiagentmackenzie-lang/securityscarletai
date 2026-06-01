"""
API authentication — unified auth for both JWT and static bearer tokens.

Security notes:
- Bearer tokens are compared with constant-time comparison (secrets.compare_digest)
  to prevent timing attacks.
- JWT tokens are signed with HS256 using the API_SECRET_KEY.
- Passwords are hashed with bcrypt (12 rounds minimum).
- RBAC: JWT tokens carry a 'role' claim used by require_role() for authorization.
- Unified auth: All endpoints accept both JWT (dashboard) and static bearer (API clients).
- Epic 5 hardening: jti claim, Redis blocklist, user_revoke markers, refresh tokens.
"""
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt as _bcrypt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from src.config.settings import settings

log = logging.getLogger(__name__)

bearer_scheme = HTTPBearer()

# bcrypt rounds (12 = good security vs. performance balance)
BCRYPT_ROUNDS = 12

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 8

# Role hierarchy: admin > analyst > viewer
ROLE_HIERARCHY = {"admin": 3, "analyst": 2, "viewer": 1}


def verify_bearer_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> str:
    """Verify the static bearer token for API ingestion endpoints."""
    if not secrets.compare_digest(credentials.credentials, settings.api_bearer_token.get_secret_value()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return credentials.credentials


def verify_jwt(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """Verify JWT token and return the payload.

    Epic 5 hardening:
    - Checks Redis blocklist for the jti (logout invalidates).
    - Checks user_revoke markers (password change invalidates older tokens).
    """
    try:
        payload = jwt.decode(
            credentials.credentials, settings.api_secret_key.get_secret_value(), algorithms=[JWT_ALGORITHM]
        )
    except JWTError as e:
        log.warning("jwt_verify_failed", error=str(e), token_preview=credentials.credentials[:20])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from None

    # Epic 5: check blocklist (logout) and user_revoke (password change).
    # Fail-closed only if Redis is up AND confirms invalid; Redis being down = fail-open
    # (degraded auth, but service stays available).
    jti = payload.get("jti")
    if jti:
        from src.api.redis_client import is_jti_blocked
        if is_jti_blocked(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )

    sub = payload.get("sub")
    iat = payload.get("iat")
    if sub and iat is not None:
        from src.api.redis_client import get_latest_user_revoke_ts
        revoke_ts = get_latest_user_revoke_ts(sub)
        if revoke_ts is not None and float(iat) < revoke_ts:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token issued before password change",
            )

    return payload


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """Unified auth dependency — accepts both JWT and static bearer tokens.

    Tries JWT decode first. If that fails, checks against the static bearer token.
    Returns a dict with user info: {'sub': username, 'role': role}.

    This ensures dashboard (JWT) and external API clients (bearer) both work
    on every endpoint.
    """
    token = credentials.credentials
    secret = settings.api_secret_key.get_secret_value()

    # Try JWT first (dashboard users)
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        pass

    # Fallback: static bearer token (API / ingestion clients)
    if secrets.compare_digest(token, settings.api_bearer_token.get_secret_value()):
        return {"sub": "api-client", "role": "admin"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
    )


def require_role(min_role: str):
    """
    FastAPI dependency factory for RBAC enforcement.

    Usage:
        @router.post("/rules", dependencies=[Depends(require_role("analyst"))])

    Checks that the JWT token's role is at least min_role.
    Admin can do everything. Analyst can do analyst+viewer. Viewer is read-only.
    Now accepts both JWT and static bearer tokens via get_current_user.
    """
    min_level = ROLE_HIERARCHY.get(min_role, 1)

    async def _check_role(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    ) -> dict:
        payload = get_current_user(credentials)
        user_role = payload.get("role", "viewer")
        user_level = ROLE_HIERARCHY.get(user_role, 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {min_role}, Have: {user_role}",
            )
        return payload

    return _check_role


def create_jwt(username: str, role: str, extra: dict | None = None) -> str:
    """Create a JWT token for dashboard authentication.

    Args:
        username: Subject claim
        role: User role (admin, analyst, viewer)
        extra: Optional extra claims to include (e.g. force_password_change)
    """
    payload = {
        "sub": username,
        "role": role,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "iat": datetime.now(tz=timezone.utc),
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=settings.access_token_ttl_minutes),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.api_secret_key.get_secret_value(), algorithm=JWT_ALGORITHM)


def create_refresh_token(username: str, role: str) -> str:
    """Create a refresh JWT (7-day TTL by default). Identified by type=refresh."""
    payload = {
        "sub": username,
        "role": role,
        "jti": str(uuid.uuid4()),
        "type": "refresh",
        "iat": datetime.now(tz=timezone.utc),
        "exp": datetime.now(tz=timezone.utc) + timedelta(days=settings.refresh_token_ttl_days),
    }
    return jwt.encode(payload, settings.api_secret_key.get_secret_value(), algorithm=JWT_ALGORITHM)


def hash_password(plain: str) -> str:
    """Hash a password using bcrypt.

    M-10 fix: SHA-256 pre-hash before bcrypt to handle passwords >72 bytes.
    This prevents silent truncation while keeping bcrypt's salt + cost factor.
    """
    # SHA-256 pre-hash: always 32 bytes regardless of input length
    prehashed = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    password_bytes = prehashed.encode("utf-8")[:72]  # hex digest is 64 chars, well under 72
    salt = _bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return _bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash.

    M-10 fix: Must use same SHA-256 pre-hash as hash_password().
    """
    prehashed = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    password_bytes = prehashed.encode("utf-8")[:72]
    hashed_bytes = hashed.encode("utf-8")
    return _bcrypt.checkpw(password_bytes, hashed_bytes)
