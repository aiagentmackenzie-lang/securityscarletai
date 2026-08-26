"""
Tests for src/api/main.py.

Covers:
- FastAPI app creation and configuration
- CORS and middleware
- Router registration
- lifespan (startup/shutdown via mock)
- load_sigma_rules (reconcile/upsert every boot, yaml error)
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api.main import RULES_DIR, app, load_sigma_rules, _docs_urls

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
        route_paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert any("/api/v1" in p for p in route_paths)

    def test_rules_dir_path(self):
        """RULES_DIR should point to a valid path."""
        assert isinstance(RULES_DIR, Path)

    def test_cors_allow_headers_restricted(self):
        """P2-5: CORS must not advertise allow_headers=['*']. Only the two
        headers the API actually uses (Authorization for bearer tokens,
        Content-Type for JSON bodies) should be permitted."""
        cors = next(
            (m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware"),
            None,
        )
        assert cors is not None, "CORSMiddleware not registered"
        assert cors.kwargs["allow_headers"] == ["Authorization", "Content-Type"]

    def test_docs_enabled_default_true_serves_docs(self):
        """P2-6: by default (dev/CI) the interactive docs ARE served."""
        assert app.docs_url == "/api/docs"
        assert app.redoc_url == "/api/redoc"
        assert app.openapi_url == "/openapi.json"

    def test_docs_urls_helper_disabled(self):
        """When docs are disabled, all three URLs are None — no Swagger/ReDoc,
        no openapi.json schema. The helper gates the app construction; test it
        directly so the disabled branch is exercised without rebuilding app."""
        with patch("src.api.main.settings") as mock_settings:
            mock_settings.docs_enabled = False
            assert _docs_urls() == (None, None, None)

    def test_docs_urls_helper_enabled(self):
        with patch("src.api.main.settings") as mock_settings:
            mock_settings.docs_enabled = True
            assert _docs_urls() == ("/api/docs", "/api/redoc", "/openapi.json")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# load_sigma_rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLoadSigmaRules:
    @pytest.mark.asyncio
    async def test_rules_reconcile_upserts_every_boot(self):
        """P1-05: rules are reconciled (upserted) even when rules already exist —
        no early return. execute is called once per disk file; fetch is called
        once for orphan (db-only) detection; the COUNT(*) fetchval probe is gone."""
        mock_conn = AsyncMock()
        # asyncpg-style command tag for a fresh insert.
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")
        mock_conn.fetch = AsyncMock(return_value=[])

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())

        import tempfile

        rule_yaml = (
            "title: Test Rule\n"
            "description: a test rule\n"
            "level: high\n"
            "tags:\n"
            "  - attack.t1059\n"
            "logsource:\n"
            "  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    process_name: test.exe\n"
            "  condition: selection\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rule_a.yml").write_text(rule_yaml)
            (Path(tmpdir) / "rule_b.yml").write_text(rule_yaml)
            with (
                patch("src.api.main.get_pool", AsyncMock(return_value=mock_pool)),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                await load_sigma_rules()

        # one upsert execute per disk rule
        assert mock_conn.execute.await_count == 2
        # orphan-detection fetch runs once after the loop
        mock_conn.fetch.assert_awaited_once()
        # the old early-return COUNT(*) probe is gone
        mock_conn.fetchval.assert_not_called()

    @pytest.mark.asyncio
    async def test_load_rules_yaml_error(self):
        """Should handle invalid YAML gracefully (per-file try/except)."""
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")
        mock_conn.fetch = AsyncMock(return_value=[])

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

            with (
                patch("src.api.main.get_pool", AsyncMock(return_value=mock_pool)),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                # Should not raise, just log error
                await load_sigma_rules()

        # bad file skipped — no execute for it
        assert mock_conn.execute.await_count == 0
        # but the orphan-detection fetch still runs after the loop
        mock_conn.fetch.assert_awaited_once()


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
        with (
            patch("src.api.main.get_pool", AsyncMock()),
            patch("src.api.main.writer", mock_writer),
            patch("src.api.main.load_sigma_rules", AsyncMock()),
            patch("src.detection.scheduler.schedule_rules", AsyncMock()),
            patch("src.intel.threat_intel.start_threat_intel_scheduler", AsyncMock()),
            patch("src.detection.scheduler.stop_scheduler", AsyncMock()),
            patch("src.intel.threat_intel.stop_threat_intel_scheduler", AsyncMock()),
            patch("src.api.main.close_pool", AsyncMock()),
            patch("src.config.logging.setup_logging"),
        ):
            async with lifespan(app):
                mock_writer.start.assert_awaited_once()

            mock_writer.stop.assert_awaited_once()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Router paths check
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestRouterPaths:
    def test_expected_route_prefixes(self):
        """App should have routes for all major features."""
        route_paths = [r.path for r in app.routes if hasattr(r, "path")]
        prefix_checks = [
            "/health",
            "/ingest",
            "/alerts",
            "/rules",
            "/ws/logs",
            "/threat-intel",
            "/cases",
        ]
        for prefix in prefix_checks:
            assert any(prefix in p for p in route_paths), f"Missing route for {prefix}"
