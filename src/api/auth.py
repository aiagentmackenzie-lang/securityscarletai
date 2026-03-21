"""
API authentication — Bearer token for ingestion, JWT for dashboard users.

Security notes:
- Bearer tokens are compared with constant-time comparison (secrets.compare_digest)
  to prevent timing attacks.
- JWT tokens are signed with HS256 using the API_SECRET_KEY.
- Passwords are hashed with bcrypt (12 rounds minimum).
"""
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext

from src.config.settings import settings

bearer_scheme = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 8


def verify_bearer_token(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> str:
    """Verify the bearer token for API ingestion endpoints."""
    if not secrets.compare_digest(credentials.credentials, settings.api_bearer_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return credentials.credentials


def create_jwt(username: str, role: str) -> str:
    """Create a JWT token for dashboard authentication."""
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(tz=timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(tz=timezone.utc),
    }
    return jwt.encode(payload, settings.api_secret_key, algorithm=JWT_ALGORITHM)


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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
