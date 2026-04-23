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
