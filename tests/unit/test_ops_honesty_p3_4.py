"""
Phase 3.4 — ops honesty sweep.

- notifications dashboard URL comes from DASHBOARD_PUBLIC_URL (no hardcoded
  localhost:8501 in the payload)
- /ai/status uses the CACHED Ollama probe (same cache as /health, P2-34)
- migrate_passwords derives its DSN from settings (+asyncpg stripped);
  DATABASE_URL env still wins as an explicit override
- PersistFlags-era /correlation/run-legacy removed (verified no callers in
  dashboard/api_client.py, docs, or tests before removal)
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestDashboardUrlFromSettings:
    @pytest.mark.asyncio
    async def test_notification_uses_configured_url(self):
        from src.response.notifications import send_alert_notification

        sent = {}

        class FakeResp:
            def raise_for_status(self):
                return None

        async def fake_post(self, url, **kwargs):
            sent["url_target"] = url
            sent["payload"] = kwargs.get("json", {})
            return FakeResp()

        alert = {
            "severity": "high",
            "rule_name": "brute_force",
            "host_name": "macmini",
            "time": "2026-09-02T08:00:00Z",
            "description": "test",
        }
        with (
            patch("src.config.settings.settings.slack_webhook_url", "https://hooks.slack/x"),
            patch("src.config.settings.settings.dashboard_public_url", "https://siem.example.com"),
            patch("httpx.AsyncClient.post", new=fake_post),
        ):
            ok = await send_alert_notification(alert)

        assert ok is True
        assert "https://siem.example.com" in sent["payload"]["text"]
        assert "localhost:8501" not in sent["payload"]["text"]

    def test_default_url_is_local_dashboard(self):
        from src.config.settings import settings

        assert settings.dashboard_public_url == "http://localhost:8501"


class TestAiStatusCachedProbe:
    @pytest.mark.asyncio
    async def test_get_status_uses_cached_probe_not_fresh_call(self):
        with (
            patch("src.api.ai.AlertTriageModel") as MockModel,
            patch("src.api.ai.get_ueba") as mock_ueba,
            patch(
                "src.api.health._cached_ollama_check",
                new_callable=AsyncMock,
                return_value=(True, "mistral:7b", None),
            ) as probe,
            patch("src.ai.ollama_client.is_ollama_available", new_callable=AsyncMock) as fresh,
        ):
            instance = MockModel.return_value
            instance.get_status.return_value = {"is_trained": False}
            instance.latest_provenance = AsyncMock(return_value=None)
            ueba_instance = MagicMock()
            ueba_instance.get_status.return_value = {"is_trained": False}
            mock_ueba.return_value = ueba_instance

            from src.api.ai import get_status

            resp = await get_status(_user={"sub": "t", "role": "viewer"})

        assert resp.ollama_available is True
        probe.assert_awaited_once()
        fresh.assert_not_awaited()  # the fresh call must be gone

    @pytest.mark.asyncio
    async def test_get_status_reflects_probe_false(self):
        with (
            patch("src.api.ai.AlertTriageModel") as MockModel,
            patch("src.api.ai.get_ueba") as mock_ueba,
            patch(
                "src.api.health._cached_ollama_check",
                new_callable=AsyncMock,
                return_value=(False, None, "unreachable"),
            ),
        ):
            instance = MockModel.return_value
            instance.get_status.return_value = {"is_trained": False}
            instance.latest_provenance = AsyncMock(return_value=None)
            ueba_instance = MagicMock()
            ueba_instance.get_status.return_value = {}
            mock_ueba.return_value = ueba_instance

            from src.api.ai import get_status

            resp = await get_status(_user={"sub": "t", "role": "viewer"})
        assert resp.ollama_available is False


class TestMigratePasswordsDsn:
    def test_derive_dsn_strips_asyncpg_suffix(self):
        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location(
            "migrate_passwords",
            __import__("pathlib").Path(__file__).parent.parent.parent
            / "scripts/migrate_passwords.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["migrate_passwords"] = mod
        spec.loader.exec_module(mod)

        from src.config.settings import settings

        dsn = mod._derive_dsn()
        assert dsn == settings.database_url.replace("+asyncpg", "")
        assert "+asyncpg" not in dsn


class TestRunLegacyRemoved:
    def test_endpoint_and_model_gone(self):
        from src.api import correlation as corr_mod

        assert not hasattr(corr_mod, "run_correlations_legacy")
        assert not hasattr(corr_mod, "PersistFlags")

    def test_route_not_registered(self):
        from src.api.main import app
        from tests.unit._route_walker import iter_route_paths

        paths = set(iter_route_paths(app.routes))
        assert "/api/v1/correlation/run-legacy" not in paths

    def test_current_run_endpoint_still_registered(self):
        from src.api.main import app
        from tests.unit._route_walker import iter_route_paths

        paths = set(iter_route_paths(app.routes))
        assert "/api/v1/correlation/run" in paths
        assert "/api/v1/correlation/run/{rule_name}" in paths
