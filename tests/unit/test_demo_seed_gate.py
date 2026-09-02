"""
Phase 1.2 (trust & truth), 2026-09-01: demo seed gate.

scripts/seed_demo_data.py previously ran unconditionally from the Docker
entrypoint on any first boot (empty alerts table), seeding synthetic alerts
AND the publicly documented demo credential into production deployments.
Demo seeding is now opt-in via DEMO_SEED_ENABLED (settings.demo_seed_enabled,
default False).
"""
from __future__ import annotations

from pathlib import Path

from src.config.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "scripts" / "entrypoint.sh"


class TestDemoSeedGateSettings:
    def test_default_is_off(self, monkeypatch):
        monkeypatch.delenv("DEMO_SEED_ENABLED", raising=False)
        fresh = Settings()
        assert fresh.demo_seed_enabled is False

    def test_env_true_flips_it(self, monkeypatch):
        monkeypatch.setenv("DEMO_SEED_ENABLED", "true")
        fresh = Settings()
        assert fresh.demo_seed_enabled is True

    def test_entrypoint_contains_gate(self):
        contents = ENTRYPOINT.read_text()
        assert '[ "${DEMO_SEED_ENABLED:-false}" = "true" ]' in contents


class TestSeedShortCircuit:
    async def test_seed_skips_without_db(self, monkeypatch, capsys):
        import scripts.seed_demo_data as sdd

        monkeypatch.setattr(sdd.settings, "demo_seed_enabled", False)

        async def _forbidden_connect(*args, **kwargs):
            raise AssertionError(
                "asyncpg.connect must not be called when demo seed is disabled"
            )

        monkeypatch.setattr(sdd.asyncpg, "connect", _forbidden_connect)

        await sdd.seed()

        out = capsys.readouterr().out
        assert "DEMO_SEED_ENABLED is not true" in out
        assert "skipping demo seed" in out
