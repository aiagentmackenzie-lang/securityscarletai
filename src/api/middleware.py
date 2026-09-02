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


def _decode_actor_from_request(request: Request) -> tuple[dict | None, str | None]:
    """Best-effort decode the JWT from the Authorization header (P2-15).

    Returns (payload, role) or (None, None). Used by AuditLogMiddleware to
    attribute the actor when no auth dependency set request.state.user. Never
    raises — audit must never break the request.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    token = auth[7:]

    # F-21 (plan phase 4): the STATIC bearer used to produce user=NULL audit
    # rows — an attribution gap for exactly the account with admin rights.
    # Attribute service-token calls explicitly: "static-bearer" / admin, via
    # the conventional service-account convention. Constant-time compare.
    try:
        import hmac as _hmac

        from src.config.settings import settings

        api_bearer = settings.api_bearer_token.get_secret_value()
        if token and _hmac.compare_digest(token, api_bearer):
            return {"sub": "static-bearer", "role": "admin"}, "admin"
    except Exception as e:  # pragma: no cover — defensive; audit must not break
        log.debug('static_bearer_check_failed', error=str(e))

    try:
        from jose import jwt

        from src.api.auth import JWT_ALGORITHM
        from src.config.settings import settings

        payload = jwt.decode(
            token,
            settings.api_secret_key.get_secret_value(),
            algorithms=[JWT_ALGORITHM],
        )
        return payload, payload.get("role") if isinstance(payload, dict) else None
    except Exception:
        return None, None


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
            # 1. Content-Length header check (fast, for non-chunked requests).
            # P2.2: garbage headers must 4xx — int() on junk used to raise
            # ValueError → 500.
            content_length = request.headers.get("content-length")
            declared: int | None = None
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length header."},
                    )
                if declared < 0:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length header."},
                    )
                if declared > self.MAX_BODY_SIZE:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Request body too large. Max {self.MAX_BODY_SIZE} bytes."
                        },
                    )

            # 2. Chunked transfer encoding — Content-Length absent, must read body.
            # P2.2: stream in chunks and abort with 413 the MOMENT the cap is
            # exceeded. The old code awaited request.body() — which buffers the
            # ENTIRE body in RAM before the size check — so a chunked uploader
            # could pin unbounded memory per request (memory-DoS vector). What
            # was read before the abort is NOT re-injected; the connection is
            # rejected, so downstream never needs it.
            transfer_encoding = request.headers.get("transfer-encoding", "").lower()
            if "chunked" in transfer_encoding or declared is None:
                chunks: list[bytes] = []
                total = 0
                over_limit = False
                receive = request._receive  # noqa: SLF001
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        break
                    part = message.get("body", b"")
                    total += len(part)
                    if total > self.MAX_BODY_SIZE:
                        over_limit = True
                        break
                    chunks.append(part)
                    if not message.get("more_body", False):
                        break
                if over_limit:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Request body too large. Max {self.MAX_BODY_SIZE} bytes."
                        },
                    )

                # Re-inject the (bounded) body so downstream handlers can read it
                body = b"".join(chunks)

                async def receive():
                    return {"type": "http.request", "body": body}

                request._receive = receive  # noqa: SLF001

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
                # P2-15: attribute the actor. request.state.user may be set by an
                # auth dependency; otherwise best-effort decode the JWT from the
                # Authorization header so audit_logs.user/role are populated.
                user = getattr(request.state, "user", None) or None
                role = None
                if not isinstance(user, dict):
                    user, role = _decode_actor_from_request(request)
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
