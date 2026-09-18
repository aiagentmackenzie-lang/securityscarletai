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

from src.api.main import RULES_DIR, _docs_urls, app, load_sigma_rules
from src.config.version import APP_VERSION

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# App configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAppConfiguration:
    def test_app_title(self):
        assert app.title == "SecurityScarletAI"

    def test_app_version(self):
        # AUD-010: the version is the single-sourced APP_VERSION (the Wave-5
        # seam; pyproject-sync is CI-enforced by test_version.py). The old
        # pin asserted the stale literal "0.2.0" while pyproject was 0.8.0 —
        # the pin itself was the drift.
        assert app.version == APP_VERSION

    def test_app_docs_url(self):
        assert app.docs_url == "/api/docs"

    def test_app_redoc_url(self):
        assert app.redoc_url == "/api/redoc"

    def test_routes_registered(self):
        """Should have expected API routes."""
        from tests.unit._route_walker import iter_route_paths

        route_paths = list(iter_route_paths(app.routes))
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
    @staticmethod
    def _mock_pool(mock_conn: AsyncMock) -> AsyncMock:
        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())
        return mock_pool

    @pytest.mark.asyncio
    async def test_rules_reconcile_upserts_every_boot(self):
        """P1-05: rules are reconciled (upserted) even when rules already exist —
        no early return. AUD-012: the batch goes through ONE executemany call
        (was one sequential execute per rule); fetch runs twice (pre-state
        name+sigma_yaml, post-state orphans)."""
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(return_value=None)
        mock_conn.fetch = AsyncMock(return_value=[])

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
                patch("src.api.main.get_pool", AsyncMock(return_value=self._mock_pool(mock_conn))),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                await load_sigma_rules()

        # ONE executemany round-trip for the whole batch (AUD-012)
        assert mock_conn.executemany.await_count == 1
        assert len(mock_conn.executemany.await_args.args[1]) == 2
        # fetch runs TWICE: pre-loop (name+sigma_yaml) + post-loop (orphans)
        assert mock_conn.fetch.await_count == 2
        # the old early-return COUNT(*) probe is gone
        mock_conn.fetchval.assert_not_called()

    @pytest.mark.asyncio
    async def test_unchanged_rules_are_not_rewritten(self):
        """AUD-012: a rule whose sigma_yaml is byte-identical to the DB row is
        SKIPPED — no upsert, no updated_at churn, on every boot."""
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
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(return_value=None)
        # pre-fetch: the rule already in the DB with IDENTICAL yaml
        mock_conn.fetch = AsyncMock(
            side_effect=[[{"name": "Test Rule", "sigma_yaml": rule_yaml}], []]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rule_a.yml").write_text(rule_yaml)
            with (
                patch("src.api.main.get_pool", AsyncMock(return_value=self._mock_pool(mock_conn))),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                await load_sigma_rules()

        # nothing changed → no write at all (no executemany, no empty batch)
        mock_conn.executemany.assert_not_awaited()
        mock_conn.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_load_rules_yaml_error(self):
        """Should handle invalid YAML gracefully (per-file try/except)."""
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(return_value=None)
        mock_conn.fetch = AsyncMock(return_value=[])

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            rule_file = Path(tmpdir) / "bad_rule.yml"
            rule_file.write_text("title: [broken\n  invalid")

            with (
                patch("src.api.main.get_pool", AsyncMock(return_value=self._mock_pool(mock_conn))),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                # Should not raise, just log error
                await load_sigma_rules()

        # bad file skipped — empty batch, so no executemany call
        assert mock_conn.executemany.await_count == 0
        # but both name fetches (pre + post) still run
        assert mock_conn.fetch.await_count == 2

    @pytest.mark.asyncio
    async def test_bulk_failure_falls_back_per_row(self):
        """AUD-012: an executemany failure falls back to per-row executes so
        one malformed row costs its row, never the whole reconcile (the
        Wave-7 cache_iocs_bulk shape)."""
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
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(side_effect=RuntimeError("bulk failed"))
        mock_conn.execute = AsyncMock(return_value="INSERT 0 1")
        mock_conn.fetch = AsyncMock(return_value=[])

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rule_a.yml").write_text(rule_yaml)
            with (
                patch("src.api.main.get_pool", AsyncMock(return_value=self._mock_pool(mock_conn))),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                await load_sigma_rules()

        # bulk failed once, then the row was retried per-row
        mock_conn.executemany.assert_awaited_once()
        assert mock_conn.execute.await_count == 1

    @pytest.mark.asyncio
    async def test_rules_reconcile_counts_from_set_arithmetic(self, monkeypatch):
        """2026-09-10: counts come from set arithmetic over pre/post name sets
        (asyncpg command tags proven unreliable on PG17). AUD-012: the batch
        holds only NEW/CHANGED rules — inserted = new names, updated = batch
        minus new, unchanged = skipped byte-identical rows."""
        # structlog writes via PrintLoggerFactory — caplog can't see it;
        # capture via the module logger seam (house pattern).
        events: list[tuple] = []

        class _Recorder:
            @staticmethod
            def info(event, **kw):
                events.append((event, kw))

            @staticmethod
            def error(event, **kw):
                events.append((event, kw))

            @staticmethod
            def warning(event, **kw):
                events.append((event, kw))

        monkeypatch.setattr("src.api.main.log", _Recorder())
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(return_value=None)
        # pre-fetch: one rule already in DB (yaml DIFFERS from disk → it must
        # be re-upserted); post-fetch: both + one orphan.
        stored_yaml = (
            "title: Test Rule\ndescription: STALE\nlevel: high\n"
            "logsource:\n  category: process_creation\n"
        )
        mock_conn.fetch = AsyncMock(
            side_effect=[
                [{"name": "Test Rule", "sigma_yaml": stored_yaml}],
                [{"name": "Test Rule"}, {"name": "Second Rule"}, {"name": "Only In DB"}],
            ]
        )

        import tempfile

        rule_yaml_a = (
            "title: Test Rule\ndescription: a\nlevel: high\n"
            "logsource:\n  category: process_creation\n"
        )
        rule_yaml_b = rule_yaml_a.replace("Test Rule", "Second Rule")
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rule_a.yml").write_text(rule_yaml_a)
            (Path(tmpdir) / "rule_b.yml").write_text(rule_yaml_b)
            with (
                patch("src.api.main.get_pool", AsyncMock(return_value=self._mock_pool(mock_conn))),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                await load_sigma_rules()

        reconciled = [kw for ev, kw in events if ev == "rules_reconciled"]
        assert reconciled, "rules_reconciled log line missing"
        kw = reconciled[0]
        # Test Rule's yaml DIFFERS from the stored row → updated (in batch);
        # Second Rule is new → inserted; Only In DB → orphan.
        assert kw["inserted"] == 1
        assert kw["updated"] == 1
        assert kw["unchanged"] == 0
        assert kw["db_only"] == 1

    @pytest.mark.asyncio
    async def test_unchanged_counted_not_rewritten(self, monkeypatch):
        """AUD-012: byte-identical rules are counted as `unchanged` in the
        reconcile log and never written."""
        events: list[tuple] = []

        class _Recorder:
            @staticmethod
            def info(event, **kw):
                events.append((event, kw))

            @staticmethod
            def error(event, **kw):
                events.append((event, kw))

            @staticmethod
            def warning(event, **kw):
                events.append((event, kw))

        monkeypatch.setattr("src.api.main.log", _Recorder())
        import tempfile

        rule_yaml = (
            "title: Same Rule\ndescription: a\nlevel: high\n"
            "logsource:\n  category: process_creation\n"
        )
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(return_value=None)
        mock_conn.fetch = AsyncMock(
            side_effect=[[{"name": "Same Rule", "sigma_yaml": rule_yaml}], []]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rule_a.yml").write_text(rule_yaml)
            with (
                patch("src.api.main.get_pool", AsyncMock(return_value=self._mock_pool(mock_conn))),
                patch("src.api.main.RULES_DIR", Path(tmpdir)),
            ):
                await load_sigma_rules()

        reconciled = [kw for ev, kw in events if ev == "rules_reconciled"]
        kw = reconciled[0]
        assert kw["unchanged"] == 1
        assert kw["inserted"] == 0
        assert kw["updated"] == 0
        mock_conn.executemany.assert_not_awaited()


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
        from tests.unit._route_walker import iter_route_paths

        route_paths = list(iter_route_paths(app.routes))
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


class TestShutdownDrainOrder:
    """AUD-019: the durable consumer stops BEFORE the writer (the drain
    order the comment documents); the redundant
    `except (asyncio.TimeoutError, Exception)` tuple is gone (TimeoutError
    IS an Exception subclass — the tuple claimed a distinction the code
    never made)."""

    def test_durable_consumer_stops_before_writer(self):
        source = (Path(__file__).resolve().parents[2] / "src" / "api" / "main.py").read_text()
        consumer_stop = source.index("durable_stop.set()")
        writer_stop = source.index("await writer.stop()")
        assert consumer_stop < writer_stop, (
            "the durable consumer must stop BEFORE the writer (drain order)"
        )

    def test_no_redundant_timeout_exception_tuple(self):
        source = (Path(__file__).resolve().parents[2] / "src" / "api" / "main.py").read_text()
        assert "(asyncio.TimeoutError, Exception)" not in source
