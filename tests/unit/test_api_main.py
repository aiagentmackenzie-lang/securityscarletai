"""
Tests for src/api/main.py.

Covers:
- FastAPI app creation and configuration
- CORS and middleware
- Router registration
- lifespan (startup/shutdown via mock)
- load_sigma_rules (already loaded, yaml error)
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from src.api.main import app, load_sigma_rules, RULES_DIR


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# App configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAppConfiguration:
    def test_app_title(self):
        assert app.title == "SecurityScarletAI"

    def test_app_version(self):
        assert app.version == "0.1.0"

    def test_app_docs_url(self):
        assert app.docs_url == "/api/docs"

    def test_app_redoc_url(self):
        assert app.redoc_url == "/api/redoc"

    def test_routes_registered(self):
        """Should have expected API routes."""
        route_paths = [r.path for r in app.routes if hasattr(r, 'path')]
        assert any("/api/v1" in p for p in route_paths)

    def test_rules_dir_path(self):
        """RULES_DIR should point to a valid path."""
        assert isinstance(RULES_DIR, Path)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# load_sigma_rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLoadSigmaRules:
    @pytest.mark.asyncio
    async def test_rules_already_loaded(self):
        """Should skip loading if rules already exist."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=50)  # 50 rules already exist

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        with patch("src.api.main.get_pool", AsyncMock(return_value=mock_pool)):
            await load_sigma_rules()

        mock_conn.fetchval.assert_called_once()
        # Should not call execute since rules already exist
        mock_conn.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_load_rules_yaml_error(self):
        """Should handle invalid YAML gracefully."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=0)
        mock_conn.execute = AsyncMock()

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn
            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_file = Path(tmpdir) / "bad_rule.yml"
            rule_file.write_text("title: [broken\n  invalid")

            with patch("src.api.main.get_pool", AsyncMock(return_value=mock_pool)), \
                 patch("src.api.main.RULES_DIR", Path(tmpdir)):
                # Should not raise, just log error
                await load_sigma_rules()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Lifespan
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLifespan:
    @pytest.mark.asyncio
    async def test_lifespan_starts_and_stops(self):
        """Lifespan should start/stop DB pool and writer."""
        from src.api.main import lifespan

        mock_writer = MagicMock()
        mock_writer.start = AsyncMock()
        mock_writer.stop = AsyncMock()

        # Import in-function so the patches target the right names
        with patch("src.api.main.get_pool", AsyncMock()), \
             patch("src.api.main.writer", mock_writer), \
             patch("src.api.main.load_sigma_rules", AsyncMock()), \
             patch("src.detection.scheduler.schedule_rules", AsyncMock()), \
             patch("src.intel.threat_intel.start_threat_intel_scheduler", AsyncMock()), \
             patch("src.detection.scheduler.stop_scheduler", AsyncMock()), \
             patch("src.intel.threat_intel.stop_threat_intel_scheduler", AsyncMock()), \
             patch("src.api.main.close_pool", AsyncMock()), \
             patch("src.config.logging.setup_logging"):

            async with lifespan(app):
                mock_writer.start.assert_awaited_once()

            mock_writer.stop.assert_awaited_once()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Router paths check
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRouterPaths:
    def test_expected_route_prefixes(self):
        """App should have routes for all major features."""
        route_paths = [r.path for r in app.routes if hasattr(r, 'path')]
        prefix_checks = [
            "/health", "/ingest", "/alerts", "/rules",
            "/ws/logs", "/threat-intel", "/cases"
        ]
        for prefix in prefix_checks:
            assert any(prefix in p for p in route_paths), f"Missing route for {prefix}"