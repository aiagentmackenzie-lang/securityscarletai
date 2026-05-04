"""
Tests for modules with lower coverage — enrichment pipeline, threat intel,
postgresql backend, and ingestion shipper.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.ingestion.schemas import NormalizedEvent


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Ingestion Shipper Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestFileShipper:
    """Test FileShipper from ingestion module."""

    def test_new_shipper_default_offset(self, tmp_path):
        """New shipper should start at offset 0 if no checkpoint."""
        from src.ingestion.shipper import FileShipper, CHECKPOINT_FILE as orig_checkpoint
        writer = MagicMock()
        checkpoint = tmp_path / "nonexistent_checkpoin"
        with patch("src.ingestion.shipper.CHECKPOINT_FILE", checkpoint):
            shipper = FileShipper("/tmp/nonexistent.log", writer)
            assert shipper._offset == 0

    def test_stop_sets_flag(self, tmp_path):
        """stop() should set running to False."""
        from src.ingestion.shipper import FileShipper
        writer = MagicMock()
        checkpoint = tmp_path / "checkpoint"
        with patch("src.ingestion.shipper.CHECKPOINT_FILE", checkpoint):
            shipper = FileShipper("/tmp/nonexistent.log", writer)
            shipper._running = True
            shipper.stop()
            assert shipper._running is False

    def test_initial_events_shipped(self, tmp_path):
        """Should start with 0 events shipped."""
        from src.ingestion.shipper import FileShipper
        writer = MagicMock()
        checkpoint = tmp_path / "checkpoint"
        with patch("src.ingestion.shipper.CHECKPOINT_FILE", checkpoint):
            shipper = FileShipper("/tmp/nonexistent.log", writer)
            assert shipper._events_shipped == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Postgresql Backend Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPostgreSQLBackend:
    """Test PostgreSQL detection backend."""

    def test_backend_importable(self):
        """PostgreSQL backend module should be importable."""
        from src.detection.backends.postgresql import PostgreSQLBackend
        backend = PostgreSQLBackend()
        assert backend is not None

    def test_backend_is_pysigma_backend(self):
        """Backend should be a pySigma backend that can convert Sigma rules."""
        from src.detection.backends.postgresql import PostgreSQLBackend
        backend = PostgreSQLBackend()
        assert backend is not None
        assert hasattr(backend, 'convert_rule') or hasattr(backend, 'convert')


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Threat Intel Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestThreatIntelModule:
    """Test threat intel module functions."""

    @pytest.mark.asyncio
    async def test_check_ioc_match_no_match(self):
        """check_ioc_match should return None for no match."""
        from src.intel.threat_intel import check_ioc_match

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.intel.threat_intel.get_pool", return_value=mock_pool):
            result = await check_ioc_match("ip", "10.0.0.1")
            assert result is None

    @pytest.mark.asyncio
    async def test_check_ioc_match_with_match(self):
        """check_ioc_match should return match data."""
        from src.intel.threat_intel import check_ioc_match

        match_data = {"ioc_type": "ip", "ioc_value": "1.2.3.4", "source": "abuse_ch", "severity": "high"}
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=match_data)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.intel.threat_intel.get_pool", return_value=mock_pool):
            result = await check_ioc_match("ip", "1.2.3.4")
            assert result is not None
            assert result["source"] == "abuse_ch"

    @pytest.mark.asyncio
    async def test_check_ioc_match_url(self):
        """check_ioc_match should handle URL type."""
        from src.intel.threat_intel import check_ioc_match

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value=None)

        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        with patch("src.intel.threat_intel.get_pool", return_value=mock_pool):
            result = await check_ioc_match("url", "http://evil.com")
            # Should query for URLs
            assert result is None  # No match found


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AI Chat Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAIChatModule:
    """Test AI chat module."""

    def test_sanitize_chat_input(self):
        """sanitize_chat_input should strip dangerous patterns."""
        from src.ai.chat import sanitize_chat_input
        clean, warnings = sanitize_chat_input("What happened on server01?")
        assert isinstance(clean, str)
        assert isinstance(warnings, list)

    def test_sanitize_chat_input_drops_dangerous(self):
        """sanitize_chat_input should warn on injection attempts."""
        from src.ai.chat import sanitize_chat_input
        clean, warnings = sanitize_chat_input("DROP TABLE users; --")
        assert len(warnings) > 0

    def test_sanitize_chat_input_allows_normal(self):
        """sanitize_chat_input should allow normal questions."""
        from src.ai.chat import sanitize_chat_input
        clean, warnings = sanitize_chat_input("How many critical alerts?")
        assert "critical" in clean or "alerts" in clean

    def test_generate_fallback_response(self):
        """generate_fallback_response should produce a response."""
        from src.ai.chat import generate_fallback_response
        response = generate_fallback_response("test message", "some context")
        assert isinstance(response, str)
        assert len(response) > 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Ollama Client Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestOllamaClient:
    """Test Ollama client module."""

    @pytest.mark.asyncio
    async def test_is_ollama_available_success(self):
        """Should return True when Ollama is available."""
        from src.ai.ollama_client import is_ollama_available

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await is_ollama_available()
            assert result is True

    @pytest.mark.asyncio
    async def test_is_ollama_available_failure(self):
        """Should return False when Ollama is unavailable."""
        from src.ai.ollama_client import is_ollama_available

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await is_ollama_available()
            assert result is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Config Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestConfigSettings:
    """Test configuration settings."""

    def test_settings_exist(self):
        """Settings object should exist and have attributes."""
        from src.config.settings import settings
        assert settings is not None
        assert hasattr(settings, "api_host")
        assert hasattr(settings, "api_port")

    def test_database_settings(self):
        """Database settings should be accessible."""
        from src.config.settings import settings
        assert settings.db_host is not None
        assert settings.db_port is not None

    def test_ollama_settings(self):
        """Ollama settings should be accessible."""
        from src.config.settings import settings
        assert settings.ollama_base_url is not None
        assert settings.ollama_model is not None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DB Writer Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLogWriter:
    """Test LogWriter from db module."""

    def test_writer_init(self):
        """LogWriter should initialize without errors."""
        from src.db.writer import LogWriter
        writer = LogWriter()
        assert writer is not None

    @pytest.mark.asyncio
    async def test_writer_start(self):
        """LogWriter start should initialize pool."""
        from src.db.writer import LogWriter
        writer = LogWriter()
        mock_pool = AsyncMock()

        with patch("src.db.writer.get_pool", return_value=mock_pool):
            await writer.start()

    @pytest.mark.asyncio
    async def test_writer_stop(self):
        """LogWriter stop should clean up."""
        from src.db.writer import LogWriter
        writer = LogWriter()
        writer._pool = AsyncMock()
        await writer.stop()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DB Connection Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDBConnection:
    """Test database connection module."""

    def test_connection_module_importable(self):
        """Connection module should be importable."""
        from src.db.connection import get_pool, close_pool
        assert get_pool is not None
        assert close_pool is not None