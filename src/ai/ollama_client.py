"""
Ollama LLM client with graceful degradation.

If Ollama is down or slow, AI features return a fallback message
instead of crashing. The SIEM must work without AI — AI is an enhancement,
not a dependency.
"""

import httpx

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("ai.ollama")

FALLBACK_MESSAGE = "[AI unavailable — Ollama is not responding. Feature degraded gracefully.]"


async def query_llm(
    prompt: str,
    system_prompt: str = "You are a cybersecurity analyst assistant.",
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> str:
    """Query the local Ollama LLM. Returns fallback string on any failure."""
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
            return data.get("response", FALLBACK_MESSAGE)

    except httpx.TimeoutException:
        log.warning("ollama_timeout", timeout=settings.ollama_timeout)
        return FALLBACK_MESSAGE
    except httpx.ConnectError:
        log.warning("ollama_unreachable", url=settings.ollama_base_url)
        return FALLBACK_MESSAGE
    except Exception as e:
        log.error("ollama_error", error=str(e))
        return FALLBACK_MESSAGE


async def is_ollama_available() -> bool:
    """Quick health check — is Ollama responding?"""
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


# M-01 fix: Validate that the configured model exists in Ollama at startup
async def validate_ollama_model() -> bool:
    """Check if the configured Ollama model is available.

    Logs a warning if the model name in settings doesn't match what Ollama has.
    This catches the common misconfiguration where .env has 'mistral:7b'
    but settings.py defaults to 'llama3.2:8b'.
    """
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code != 200:
                log.warning("ollama_model_check_failed", status=resp.status_code)
                return False

            data = resp.json()
            available = [m.get("name", "") for m in data.get("models", [])]

            if settings.ollama_model not in available:
                log.warning(
                    "ollama_model_not_found",
                    configured=settings.ollama_model,
                    available=available[:10],
                    hint="Set OLLAMA_MODEL in .env to match an installed model",
                )
                return False

            log.info("ollama_model_validated", model=settings.ollama_model)
            return True
    except Exception as e:
        log.warning("ollama_model_check_error", error=str(e))
        return False
