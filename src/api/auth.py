"""
API authentication — unified auth for both JWT and static bearer tokens.

Security notes:
- Bearer tokens are compared with constant-time comparison (secrets.compare_digest)
  to prevent timing attacks.
- JWT tokens are signed with HS256 using the API_SECRET_KEY.
- Passwords are hashed with bcrypt (12 rounds minimum).
- RBAC: JWT tokens carry a 'role' claim used by require_role() for authorization.
- Unified auth: All endpoints accept both JWT (dashboard) and static bearer (API clients).
"""
import hashlib
import logging
import secrets
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
    if not secrets.compare_digest(credentials.credentials, settings.api_bearer_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return credentials.credentials


def verify_jwt(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """Verify JWT token and return the payload."""
    try:
        payload = jwt.decode(
            credentials.credentials, settings.api_secret_key, algorithms=[JWT_ALGORITHM]
        )
        return payload
    except JWTError as e:
        log.warning("jwt_verify_failed", error=str(e), token_preview=credentials.credentials[:20])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from None


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

    # Try JWT first (dashboard users)
    try:
        payload = jwt.decode(token, settings.api_secret_key, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        pass

    # Fallback: static bearer token (API / ingestion clients)
    if secrets.compare_digest(token, settings.api_bearer_token):
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
        "exp": datetime.now(tz=timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(tz=timezone.utc),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.api_secret_key, algorithm=JWT_ALGORITHM)


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
