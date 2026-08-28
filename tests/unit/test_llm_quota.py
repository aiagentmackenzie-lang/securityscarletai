"""Per-USER LLM quota tests (remediation Phase 2B — F-14).

One analyst could pin the single local Ollama model (OWASP LLM Top 10 2026:
LLM10 — unbounded consumption) because /ai/*, /query and hunt-execute only
carried the global per-IP limit. These tests pin:
- the env-configurable limit string (default 30 per 5 minutes per user),
- the user-or-IP key function (sub-keyed, unverified parse for KEYING only,
  authz still enforced by require_role deps),
- decorator wiring on all four LLM-consuming endpoints.
"""

from __future__ import annotations

from jose import jwt as jose_jwt

from src.api import ai as ai_router  # noqa: F401
from src.api import chat as chat_router  # noqa: F401
from src.api import hunt as hunt_router  # noqa: F401
from src.api import query as query_router  # noqa: F401
from src.api import rate_limit  # noqa: F401
from src.api.rate_limit import (
    LIMIT_LLM,
    limiter,
    rate_limit_exceeded_handler,
    user_or_ip_key,
)
from src.config.settings import settings
from tests.unit._test_request import make_test_request

TESTING_SECRET = "test-secret-key-for-thin-tokens-0123456789"


def _request_with_auth(token: str | None):
    """make_test_request for /ai/chat, optionally with an Authorization header."""
    req = make_test_request(path="/api/v1/ai/chat")
    headers = [(k, v) for k, v in req.scope["headers"] if k != b"authorization"]
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    req.scope["headers"] = headers
    return req


class TestLLMQuotaConfig:
    def test_limit_constant_wired_to_settings(self):
        assert LIMIT_LLM == settings.llm_rate_limit

    def test_default_is_30_per_5_minutes_compound(self):
        """Pin the plan's default: 30 LLM calls / 5 min / user, env-override
        via LLM_RATE_LIMIT."""
        assert settings.llm_rate_limit == "30/5minutes"
        from limits import parse_many

        parsed = parse_many(LIMIT_LLM)
        assert any(x.amount == 30 and x.multiples == (5, "minute") or
                   "5 minute" in str(x) for x in parsed)

    def test_env_override(self, monkeypatch):
        from src.config.settings import Settings

        monkeypatch.setenv("LLM_RATE_LIMIT", "5/minute")
        fresh = Settings()
        assert fresh.llm_rate_limit == "5/minute"
        assert LIMIT_LLM == "30/5minutes"  # module constant, not clobbered


class TestUserOrIpKey:
    def test_sub_claim_keys_per_user(self):
        token = jose_jwt.encode(
            {"sub": "demo_analyst", "role": "analyst", "exp": 4102444800},
            TESTING_SECRET,
            algorithm="HS256",
        )
        req = _request_with_auth(token)
        assert user_or_ip_key(req) == "user:demo_analyst"

    def test_no_token_falls_back_to_ip(self):
        req = make_test_request(path="/api/v1/ai/chat")
        assert user_or_ip_key(req) == "127.0.0.1"

    def test_garbage_token_falls_back_to_ip(self):
        req = _request_with_auth("not-a-real-jwt")
        assert user_or_ip_key(req) == "127.0.0.1"

    def test_token_without_sub_falls_back_to_ip(self):
        token = jose_jwt.encode(
            {"role": "analyst", "exp": 4102444800},
            TESTING_SECRET,
            algorithm="HS256",
        )
        req = _request_with_auth(token)
        assert user_or_ip_key(req) == "127.0.0.1"


class TestLLMQuotaWiring:
    """All four LLM-consuming endpoints must carry the per-user limit."""

    def _limit_strs_for(self, fq_name: str) -> list[str]:
        limits = limiter._route_limits.get(fq_name)
        assert limits is not None, f"{fq_name} must carry @limiter.limit"
        return [str(lim.limit) for lim in limits]

    def test_ai_chat_endpoint_marked(self):
        assert "src.api.chat.chat_endpoint" in limiter._route_limits
        assert "30 per 5 minute" in self._limit_strs_for("src.api.chat.chat_endpoint")

    def test_ai_explain_endpoint_marked(self):
        assert "src.api.ai.explain_alert_endpoint" in limiter._route_limits
        assert "30 per 5 minute" in self._limit_strs_for(
            "src.api.ai.explain_alert_endpoint"
        )

    def test_query_endpoint_marked(self):
        assert "src.api.query.query_nl" in limiter._route_limits
        assert "30 per 5 minute" in self._limit_strs_for("src.api.query.query_nl")

    def test_hunt_execute_endpoint_marked(self):
        assert "src.api.hunt.execute_hunt_template" in limiter._route_limits
        assert "30 per 5 minute" in self._limit_strs_for(
            "src.api.hunt.execute_hunt_template"
        )


class TestCompound429RetryAfter:
    """'30/5minutes' must yield a 300s Retry-After, not the flat 60."""

    def _limit(self, limit_str: str):
        from slowapi.extension import Limit
        from slowapi.util import get_remote_address

        return Limit(
            limit_str,
            key_func=get_remote_address,
            scope="",
            per_method=False,
            methods=None,
            error_message=None,
            exempt_when=None,
            cost=1,
            override_defaults=True,
        )

    def test_compound_minutes_retry_after(self):
        from slowapi.errors import RateLimitExceeded

        req = make_test_request()
        exc = RateLimitExceeded(self._limit("30/5minutes"))
        response = rate_limit_exceeded_handler(req, exc)
        assert '"retry_after":300' in response.body.decode()

    def test_plain_minute_retry_after_unchanged(self):
        from slowapi.errors import RateLimitExceeded

        req = make_test_request()
        exc = RateLimitExceeded(self._limit("5/minute"))
        response = rate_limit_exceeded_handler(req, exc)
        assert '"retry_after":60' in response.body.decode()
