"""
API middleware — rate limiting, request size validation, content-type enforcement.

Uses slowapi for rate limiting with in-memory storage (suitable for single-instance).
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from src.config.logging import get_logger

log = get_logger("api.middleware")

# Rate limiter — uses client IP as the key
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for request validation:
    - Max body size (1MB default)
    - Content-Type enforcement on ingestion endpoints
    - Request logging
    """

    MAX_BODY_SIZE = 1_000_000  # 1MB

    async def dispatch(self, request: Request, call_next):
        # Check body size for POST/PUT/PATCH
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large. Max {self.MAX_BODY_SIZE} bytes."},
                )

            # Content-Type enforcement for ingest endpoint
            if request.url.path.endswith("/ingest"):
                content_type = request.headers.get("content-type", "")
                if "application/json" not in content_type:
                    return JSONResponse(
                        status_code=415,
                        content={"detail": "Content-Type must be application/json"},
                    )

        response = await call_next(request)
        return response


class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware for auditing state-changing requests.
    Logs POST/PUT/PATCH/DELETE to the audit log.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Audit state-changing requests
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # Skip health checks and auth
            path = request.url.path
            if "/health" not in path and "/docs" not in path:
                log.info(
                    "api_request",
                    method=request.method,
                    path=path,
                    status=response.status_code,
                    ip=get_remote_address(request),
                )

        return response
