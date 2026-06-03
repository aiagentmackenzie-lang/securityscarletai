"""
API middleware — rate limiting, request size validation, content-type enforcement.

Rate limiting is now Redis-backed (via slowapi) with per-endpoint overrides
configured in src/api/rate_limit.py. The Limiter singleton lives there;
this module re-exports it for backward compat with existing imports.
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter  # noqa: F401  (re-exported for tests)
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.rate_limit import limiter  # noqa: F401  (re-exported for tests)
from src.config.logging import get_logger

log = get_logger("api.middleware")


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for request validation:
    - Max body size (1MB default) — works with both Content-Length and chunked transfer
    - Content-Type enforcement on ingestion endpoints
    - Request logging
    """

    MAX_BODY_SIZE = 1_000_000  # 1MB

    async def dispatch(self, request: Request, call_next):
        # Check body size for POST/PUT/PATCH
        if request.method in ("POST", "PUT", "PATCH"):
            # 1. Content-Length header check (fast, for non-chunked requests)
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large. Max {self.MAX_BODY_SIZE} bytes."},
                )

            # 2. Chunked transfer encoding — Content-Length absent, must read body
            #    Starlette streams chunked bodies; we must consume and check size.
            transfer_encoding = request.headers.get("transfer-encoding", "").lower()
            if "chunked" in transfer_encoding or not content_length:
                try:
                    body = await request.body()
                    if len(body) > self.MAX_BODY_SIZE:
                        return JSONResponse(
                            status_code=413,
                            content={
                            "detail": f"Request body too large. Max {self.MAX_BODY_SIZE} bytes."
                        },
                        )
                    # Re-inject body so downstream handlers can read it
                    async def receive():
                        return {"type": "http.request", "body": body}
                    request._receive = receive
                except Exception as e:  # pragma: no cover — defensive
                    log.exception(
                        "request_body_read_failed", error=str(e)
                    )  # Let downstream handle it

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
    Middleware for auditing state-changing HTTP requests.

    Epic 6: every POST/PUT/PATCH/DELETE writes one row to the audit_logs
    table (user, method, path, status, duration). Failures here MUST NOT
    break the request — the response has already been sent by the time we
    audit, and a stuck audit pipeline would create a silent DoS.
    """

    async def dispatch(self, request: Request, call_next):
        import time as _time

        start = _time.monotonic()
        response = await call_next(request)
        duration_ms = int((_time.monotonic() - start) * 1000)

        # Audit state-changing requests
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            path = request.url.path
            # Skip health checks and docs
            if "/health" not in path and "/docs" not in path and "/redoc" not in path:
                # Best-effort: try to extract user from response state if
                # verify_jwt() set it; otherwise leave user as None.
                user = getattr(request.state, "user", None) or None
                role = None
                if isinstance(user, dict):
                    role = user.get("role")
                    user = user.get("sub") or user.get("user")

                # Fire-and-forget the DB write. If it fails, the response is
                # already on the wire, and we'd rather log the failure than
                # crash the request.
                try:
                    from src.api.audit import log_request_audit

                    await log_request_audit(
                        user=user,
                        role=role,
                        method=request.method,
                        path=path,
                        ip=get_remote_address(request),
                        status_code=response.status_code,
                        duration_ms=duration_ms,
                    )
                except Exception as e:  # pragma: no cover — defensive
                    log.warning("audit_middleware_write_failed", path=path, error=str(e))

        return response
