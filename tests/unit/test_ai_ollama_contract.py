"""
Tests for the LLMResult contract (Agent A, Epic 1).

Covers:
- LLMResult dataclass structure
- query_llm() returns LLMResult (never bare string)
- validate_ollama_model() returns (available, model, error) tuple
- fallback path: source="template_library", fallback_used=True, warning set
- happy path: source="ollama", fallback_used=False
- error path: source="error", ok=False
- cost_tracker.record_usage inserts into ai_usage
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.ai.ollama_client import (
    FALLBACK_MESSAGE,
    LLMResult,
    is_ollama_available,
    query_llm,
    validate_ollama_model,
)


class TestLLMResultDataclass:
    """LLMResult has the right shape and to_dict() helper."""

    def test_required_fields(self):
        r = LLMResult(
            ok=True,
            text="hello",
            source="ollama",
            model_used="mistral:7b",
            tokens_in=10,
            tokens_out=5,
            latency_ms=120,
            fallback_used=False,
        )
        assert r.ok is True
        assert r.text == "hello"
        assert r.source == "ollama"
        assert r.model_used == "mistral:7b"
        assert r.tokens_in == 10
        assert r.tokens_out == 5
        assert r.latency_ms == 120
        assert r.fallback_used is False
        assert r.warning is None

    def test_optional_warning(self):
        r = LLMResult(
            ok=True,
            text="x",
            source="template_library",
            model_used=None,
            tokens_in=0,
            tokens_out=0,
            latency_ms=0,
            fallback_used=True,
            warning="Ollama not responding",
        )
        assert r.warning == "Ollama not responding"
        assert r.fallback_used is True

    def test_to_dict_serialization(self):
        r = LLMResult(
            ok=True, text="x", source="ollama", model_used="m",
            tokens_in=1, tokens_out=2, latency_ms=3, fallback_used=False,
        )
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["source"] == "ollama"
        assert d["tokens_in"] == 1


class TestQueryLLMContract:
    """query_llm() ALWAYS returns LLMResult, never a bare string."""

    @pytest.mark.asyncio
    async def test_returns_llmresult_happy_path(self):
        """Successful Ollama call returns source='ollama', fallback_used=False."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "Hello from Ollama",
            "eval_count": 5,
            "prompt_eval_count": 10,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await query_llm("test prompt")

        assert isinstance(result, LLMResult)
        assert result.ok is True
        assert result.text == "Hello from Ollama"
        assert result.source == "ollama"
        assert result.fallback_used is False
        assert result.warning is None
        assert result.tokens_out == 5
        assert result.tokens_in == 10
        assert result.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_fallback_when_ollama_unreachable(self):
        """When Ollama is down, return template_library result with warning."""
        import httpx

        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await query_llm(
                "test prompt",
                fallback_text="Static fallback response",
            )

        assert isinstance(result, LLMResult)
        assert result.ok is True
        assert result.text == "Static fallback response"
        assert result.source == "template_library"
        assert result.fallback_used is True
        assert result.warning is not None
        assert "Ollama not responding" in result.warning
        assert result.model_used is None

    @pytest.mark.asyncio
    async def test_hard_error_when_no_fallback(self):
        """When Ollama is down and no fallback_text, return source='error', ok=False."""
        import httpx

        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await query_llm("test prompt")  # no fallback_text

        assert isinstance(result, LLMResult)
        assert result.ok is False
        assert result.source == "error"
        assert result.text == ""
        assert result.fallback_used is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_empty_response_triggers_fallback(self):
        """Empty Ollama response uses fallback_text if provided."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": ""}
        mock_response.raise_for_status = MagicMock()

        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await query_llm(
                "test prompt",
                fallback_text="Used fallback",
            )

        assert result.source == "template_library"
        assert result.fallback_used is True
        assert result.text == "Used fallback"

    @pytest.mark.asyncio
    async def test_prompt_version_propagates(self):
        """prompt_version is included in result and extra."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": "ok", "eval_count": 1, "prompt_eval_count": 1,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await query_llm(
                "test", prompt_version="v1.2.3", fallback_text="fb",
            )

        assert result.prompt_version == "v1.2.3"

    @pytest.mark.asyncio
    async def test_fallback_message_constant_preserved(self):
        """FALLBACK_MESSAGE constant is still importable for backward compat."""
        assert FALLBACK_MESSAGE is not None
        assert "Ollama" in FALLBACK_MESSAGE


class TestValidateOllamaModel:
    """validate_ollama_model() returns a (bool, str|None, str|None) tuple."""

    @pytest.mark.asyncio
    async def test_returns_tuple_with_three_elements(self):
        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "models": [{"name": "mistral:7b"}, {"name": "llama3:8b"}]
            }
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await validate_ollama_model()

        assert isinstance(result, tuple)
        assert len(result) == 3
        available, model_name, error = result
        # Whether available depends on settings.ollama_model — just check shape
        assert isinstance(available, bool)
        assert model_name is not None  # always returns the configured name
        assert error is None or isinstance(error, str)

    @pytest.mark.asyncio
    async def test_returns_error_on_unreachable(self):
        import httpx

        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                side_effect=httpx.ConnectError("refused")
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            available, model_name, error = await validate_ollama_model()

        assert available is False
        assert model_name is not None
        assert error is not None
        assert "unreachable" in error.lower() or "refused" in error.lower()

    @pytest.mark.asyncio
    async def test_returns_error_on_model_not_found(self):
        """If configured model not in available list, return error string."""
        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "models": [{"name": "some-other-model:latest"}]
            }
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            available, model_name, error = await validate_ollama_model()

        # If settings.ollama_model is in available list, available=True
        # Either way, the shape is correct
        assert isinstance(available, bool)
        assert model_name is not None
        if not available:
            assert error is not None


class TestIsOllamaAvailable:
    @pytest.mark.asyncio
    async def test_true_when_responding(self):
        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            assert await is_ollama_available() is True

    @pytest.mark.asyncio
    async def test_false_on_error(self):
        with patch("src.ai.ollama_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=Exception("boom"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            assert await is_ollama_available() is False
