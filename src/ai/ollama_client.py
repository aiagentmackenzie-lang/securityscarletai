"""
Ollama LLM client with explicit LLMResult contract.

Every LLM call returns an LLMResult — never a bare string. This makes
fallback behavior visible to callers and to the end user. If Ollama is
down, the result still resolves successfully with `source="template_library"`
and `fallback_used=True`, so the SIEM keeps working.
"""
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Optional

import httpx

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("ai.ollama")

# Kept for backward compatibility with existing callers/tests that
# import the constant directly. New callers should branch on
# LLMResult.source == "template_library" instead.
FALLBACK_MESSAGE = "[AI unavailable — Ollama is not responding. Feature degraded gracefully.]"

SourceType = Literal["ollama", "template_library", "error"]


@dataclass
class LLMResult:
    """Structured return value for every LLM call.

    `ok` is True when the caller can safely use `text`. `source` is the
    origin of the text (ollama response, template library, or hard error).
    `fallback_used` is True iff Ollama was unreachable and we served a
    template. `warning` is a user-facing message when fallback fires.
    """
    ok: bool
    text: str
    source: SourceType
    model_used: Optional[str]
    tokens_in: int
    tokens_out: int
    latency_ms: int
    fallback_used: bool
    warning: Optional[str] = None
    error: Optional[str] = None
    prompt_version: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ollama_unavailable_result(
    fallback_text: str,
    prompt_version: Optional[str] = None,
    error: Optional[str] = None,
) -> "LLMResult":
    """Build a template-library result (Ollama is down)."""
    return LLMResult(
        ok=True,
        text=fallback_text,
        source="template_library",
        model_used=None,
        tokens_in=0,
        tokens_out=0,
        latency_ms=0,
        fallback_used=True,
        warning="Ollama not responding — using local analysis rules",
        error=error,
        prompt_version=prompt_version,
    )


def _ollama_error_result(
    error: str,
    prompt_version: Optional[str] = None,
) -> "LLMResult":
    """Build a hard-error result (caller must not use text)."""
    return LLMResult(
        ok=False,
        text="",
        source="error",
        model_used=None,
        tokens_in=0,
        tokens_out=0,
        latency_ms=0,
        fallback_used=False,
        warning="LLM call failed",
        error=error,
        prompt_version=prompt_version,
    )


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars per token)."""
    return max(1, len(text) // 4)


async def query_llm(
    prompt: str,
    system_prompt: str = "You are a cybersecurity analyst assistant.",
    temperature: float = 0.1,
    max_tokens: int = 1024,
    prompt_version: Optional[str] = None,
    fallback_text: Optional[str] = None,
) -> LLMResult:
    """Query the local Ollama LLM. NEVER returns a bare string.

    On any failure (timeout, connect error, HTTP error, missing key),
    returns a populated LLMResult with `source="template_library"` if
    `fallback_text` is provided, otherwise `source="error"`.

    Args:
        prompt: User prompt
        system_prompt: System message
        temperature: LLM temperature
        max_tokens: Max tokens to generate
        prompt_version: Optional version tag for cost tracking
        fallback_text: Text to serve if Ollama is down. If None, an
            error result is returned.

    Returns:
        LLMResult — never None, never raises.
    """
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
            response = await client.post(
                f"{settings.ollama_base_url}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": prompt,
                    "system": system_prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

        latency_ms = int((time.monotonic() - start) * 1000)
        text = data.get("response", "")
        if not text:
            log.warning("ollama_empty_response")
            if fallback_text is not None:
                result = _ollama_unavailable_result(
                    fallback_text, prompt_version, error="empty response"
                )
                result.latency_ms = latency_ms
                return result
            return _ollama_error_result("empty response", prompt_version)

        # Ollama's /api/generate returns eval_count and prompt_eval_count
        # in newer versions. Fall back to estimates if absent.
        tokens_out = int(data.get("eval_count", 0)) or _estimate_tokens(text)
        tokens_in = int(data.get("prompt_eval_count", 0)) or _estimate_tokens(prompt)

        log.info(
            "ollama_query_success",
            model=settings.ollama_model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
        )
        return LLMResult(
            ok=True,
            text=text,
            source="ollama",
            model_used=settings.ollama_model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            fallback_used=False,
            warning=None,
            prompt_version=prompt_version,
        )

    except httpx.TimeoutException:
        latency_ms = int((time.monotonic() - start) * 1000)
        log.warning("ollama_timeout", timeout=settings.ollama_timeout, latency_ms=latency_ms)
        if fallback_text is not None:
            result = _ollama_unavailable_result(fallback_text, prompt_version, error="timeout")
            result.latency_ms = latency_ms
            return result
        return _ollama_error_result("timeout", prompt_version)

    except httpx.ConnectError as e:
        latency_ms = int((time.monotonic() - start) * 1000)
        log.warning("ollama_unreachable", url=settings.ollama_base_url, error=str(e))
        if fallback_text is not None:
            result = _ollama_unavailable_result(fallback_text, prompt_version, error=str(e))
            result.latency_ms = latency_ms
            return result
        return _ollama_error_result(f"connect error: {e}", prompt_version)

    except Exception as e:
        latency_ms = int((time.monotonic() - start) * 1000)
        log.error("ollama_error", error=str(e), latency_ms=latency_ms)
        if fallback_text is not None:
            result = _ollama_unavailable_result(fallback_text, prompt_version, error=str(e))
            result.latency_ms = latency_ms
            return result
        return _ollama_error_result(str(e), prompt_version)


async def is_ollama_available() -> bool:
    """Quick health check — is Ollama responding?"""
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


async def validate_ollama_model() -> tuple[bool, Optional[str], Optional[str]]:
    """Check if the configured Ollama model is installed.

    Returns:
        (available, model_name, error_string)
        - available: True if Ollama is reachable AND the configured model is installed
        - model_name: The model name that was checked (always settings.ollama_model)
        - error_string: Human-readable error if available=False, else None
    """
    configured = settings.ollama_model
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code != 200:
                msg = f"HTTP {resp.status_code}"
                log.warning("ollama_model_check_failed", status=resp.status_code)
                return False, configured, msg

            data = resp.json()
            available = [m.get("name", "") for m in data.get("models", [])]

            if configured not in available:
                msg = (
                    f"Configured model '{configured}' not in Ollama. "
                    f"Available: {available[:10]}. "
                    f"Set OLLAMA_MODEL in .env to match an installed model."
                )
                log.warning(
                    "ollama_model_not_found",
                    configured=configured,
                    available=available[:10],
                )
                return False, configured, msg

            log.info("ollama_model_validated", model=configured)
            return True, configured, None
    except httpx.ConnectError as e:
        msg = f"Ollama unreachable at {settings.ollama_base_url}: {e}"
        log.warning("ollama_model_check_unreachable", error=str(e))
        return False, configured, msg
    except Exception as e:
        msg = f"Validation error: {e}"
        log.warning("ollama_model_check_error", error=str(e))
        return False, configured, msg
