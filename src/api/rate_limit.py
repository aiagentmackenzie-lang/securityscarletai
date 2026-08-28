"""
Rate limiting setup (Epic 4) — Redis-backed, IP-keyed, with per-endpoint overrides.

Why a separate module:
- The Limiter instance must be importable from BOTH middleware.py and the
  per-endpoint decorators (auth_login.py, ingest.py) without circular imports.
- Custom 429 handler is registered once on the FastAPI app in main.py.
- X-RateLimit-* headers are added via a small middleware so every response
  carries the same shape (including successful ones).

Degradation:
- If Redis is unreachable at startup, slowapi falls back to in-memory storage.
  We log a warning. This is the same trade-off as auth: service stays up,
  rate limit accuracy degrades.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Request, Response
from jose import jwt
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("api.rate_limit")

# ───────────────────────────────────────────────────────────────
# Limiter singleton — used by decorators and the exception handler
# ───────────────────────────────────────────────────────────────


def _build_limiter() -> Limiter:
    """Construct the Limiter. Tries Redis first; warns + falls back to memory on error."""
    storage_uri = settings.redis_url
    try:
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["200/minute"],
            storage_uri=storage_uri,
            # headers_enabled is True by default in slowapi 0.1.9+, but
            # the slowapi middleware only injects headers for rate-limited
            # paths. We add our own middleware below for consistent coverage.
            headers_enabled=True,
        )
        log.info("rate_limiter_redis")
        return limiter
    except Exception as e:
        log.warning("rate_limiter_redis_init_failed", error=str(e))
        return Limiter(
            key_func=get_remote_address,
            default_limits=["200/minute"],
            headers_enabled=True,
        )


limiter = _build_limiter()


# Per-endpoint limit strings — referenced by decorators in auth_login.py
# and ingest.py. Env-configurable via settings (LOGIN_RATE_LIMIT /
# INGEST_RATE_LIMIT); defaults stay aggressive for production.
LIMIT_LOGIN = settings.login_rate_limit
LIMIT_INGEST = settings.ingest_rate_limit

# Per-USER LLM quota (F-14) — /ai/*, /query, hunt execute. Keyed by the
# authenticated sub (unverified parse for KEYING only — FastAPI's require_role
# dependency runs before the limiter and enforces the signature), falling
# back to IP. Without this, one analyst can pin the single local model
# (OWASP LLM Top 10 2026: LLM10 unbounded consumption).
LIMIT_LLM = settings.llm_rate_limit


def user_or_ip_key(request: Request) -> str:
    """Rate-key: authenticated username when a bearer token carries a sub
    claim, else the client IP.

    The sub is parsed UNVERIFIED — strictly for keying/quota separation, not
    authorization: the request still has to pass require_role dependencies
    (signature-verified) before the endpoint runs. This gives per-user
    fairness without a live DB lookup in the hot path.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):].strip()
        try:
            # Unverified parse strictly for KEYING — the throwaway key plus
            # signature/expire checks disabled mean we never trust this for
            # authorization (require_role deps run before the limiter).
            payload = jwt.decode(
                token,
                "",
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_aud": False,
                },
            )
            sub = payload.get("sub")
            if sub:
                return f"user:{sub}"
        except Exception:
            log.debug("rate_limit_key_jwt_parse_failed")
    return get_remote_address(request)


# ───────────────────────────────────────────────────────────────
# Custom 429 handler — JSON shape + Retry-After header
# ───────────────────────────────────────────────────────────────


def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> Response:
    """Return a JSON 429 with structured body and Retry-After header.

    Default slowapi handler returns plain text; SOC tooling expects JSON.
    """
    # Extract retry-after seconds from the limit string when possible.
    # Format examples: "5/minute", "100/minute", "30/5minutes" (compound).
    retry_after = 60  # default
    try:
        import re as _re

        limit_str = str(exc.detail) if exc.detail else "60"
        n_str, _, unit = limit_str.partition("/")
        n = int(n_str.strip())
        # limits library normalizes compound strings to 'N per X minutes'
        # (slowapi's RateLimitExceeded.detail) — parse that FIRST, then the
        # raw decorator form 'N/Xminutes'.
        normalized = _re.match(r"\d+\s+per\s+(\d+)\s*(seconds?|minutes?|hours?)", limit_str)
        compound = _re.match(r"(\d+)(minutes?|seconds?|hours?)", unit.strip())
        if normalized:
            factor = {"s": 1, "m": 60, "h": 3600}[normalized.group(2)[0]]
            retry_after = max(1, int(normalized.group(1)) * factor)
        elif compound:
            factor = {"s": 1, "m": 60, "h": 3600}[compound.group(2)[0]]
            retry_after = max(1, int(compound.group(1)) * factor)
        elif "second" in unit:
            retry_after = max(1, 60 // max(n, 1))
        elif "hour" in unit:
            retry_after = 3600
        elif "minute" in unit:
            retry_after = 60
    except Exception:
        retry_after = 60

    log.warning(
        "rate_limited",
        path=request.url.path,
        method=request.method,
        ip=get_remote_address(request),
        limit=str(exc.detail) if exc.detail else None,
    )

    return Response(
        content=(
            '{"error":"rate_limited","detail":"Too many requests",'
            f'"retry_after":{retry_after}}}'
        ),
        status_code=429,
        media_type="application/json",
        headers={"Retry-After": str(retry_after)},
    )


# ───────────────────────────────────────────────────────────────
# Middleware that adds X-RateLimit-* headers to every response
# ───────────────────────────────────────────────────────────────


class RateLimitHeadersMiddleware(BaseHTTPMiddleware):
    """Add X-RateLimit-Remaining and X-RateLimit-Reset to every response.

    Strategy: defer to slowapi's own header injection for rate-limited paths
    (it sets them when limits are hit) and only try to add a soft hint on
    successful responses. Reading the storage backend in detail is brittle
    across slowapi versions, so we expose the reset window length instead.
    """

    DEFAULT_LIMIT_SECONDS = 60  # matches the "200/minute" default window

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        # Don't clobber headers slowapi already set
        if "X-RateLimit-Remaining" in response.headers:
            return response

        # Best-effort: a small constant reset hint so clients can implement
        # sliding-window backoff. The actual remaining count requires reading
        # slowapi's internal storage which is brittle across versions; clients
        # that need exact counts can use the Retry-After header on 429.
        if "X-RateLimit-Reset" not in response.headers:
            import time as _time
            response.headers["X-RateLimit-Reset"] = str(
                int(_time.time()) + self.DEFAULT_LIMIT_SECONDS
            )
        if "X-RateLimit-Remaining" not in response.headers:
            response.headers["X-RateLimit-Remaining"] = "n/a (see Retry-After on 429)"

        return response
