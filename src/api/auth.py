"""
API authentication — Bearer token for ingestion, JWT for dashboard users.

Security notes:
- Bearer tokens are compared with constant-time comparison (secrets.compare_digest)
  to prevent timing attacks.
- JWT tokens are signed with HS256 using the API_SECRET_KEY.
- Passwords are hashed with bcrypt (12 rounds minimum).
- RBAC: JWT tokens carry a 'role' claim used by require_role() for authorization.
"""
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import bcrypt as _bcrypt

from src.config.settings import settings

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
    """Verify the bearer token for API ingestion endpoints."""
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
    except JWTError:
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
    """
    min_level = ROLE_HIERARCHY.get(min_role, 1)

    async def _check_role(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    ) -> dict:
        payload = verify_jwt(credentials)
        user_role = payload.get("role", "viewer")
        user_level = ROLE_HIERARCHY.get(user_role, 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {min_role}, Have: {user_role}",
            )
        return payload

    return _check_role


def create_jwt(username: str, role: str) -> str:
    """Create a JWT token for dashboard authentication."""
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(tz=timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(tz=timezone.utc),
    }
    return jwt.encode(payload, settings.api_secret_key, algorithm=JWT_ALGORITHM)


def hash_password(plain: str) -> str:
    """Hash a password using bcrypt. Truncates to 72 bytes per bcrypt spec."""
    password_bytes = plain.encode("utf-8")[:72]
    salt = _bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return _bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    password_bytes = plain.encode("utf-8")[:72]
    hashed_bytes = hashed.encode("utf-8")
    return _bcrypt.checkpw(password_bytes, hashed_bytes)
