"""Local production overlay contract (docker-compose.local-prod.yml, P4 phase 3).

Structural pins, matching the test_prod_deploy_hardening house style, so a
posture revert is caught in CI:

- ONLY loopback binds publish (postgres :5433, api :8000, dashboard :8501);
  redis publishes NOTHING (F-04 local variant).
- redis runs --requirepass (required, fail-fast).
- api: docs disabled, requirepass'd REDIS_URL, PASSWORD_PEPPER required.
- api + dashboard: no-new-privileges + cap_drop ALL; dashboard live-reload
  mount removed.
- No Caddy here — loopback needs no TLS; the internet path is the OTHER
  overlay (docker-compose.prod.yml).
- Base compose carries the PASSWORD_PEPPER pass-through (empty = disabled).
"""

from __future__ import annotations

import re
from pathlib import Path

_repo = Path(__file__).resolve().parents[2]
_LOCAL = _repo / "docker-compose.local-prod.yml"
_BASE = _repo / "docker-compose.yml"

LOOPBACK_PORTS = {
    "postgres": "127.0.0.1:5433:5432",
    "api": "127.0.0.1:8000:8000",
    "dashboard": "127.0.0.1:8501:8501",
}


def _service(s: str, name: str) -> str:
    """Extract one top-level service's YAML block (boundary = next 2-space key
    followed by a non-space char; 4+ space indents stay inside the block)."""
    parts = re.split(r"\n  (?=\S)", s)
    for p in parts:
        if p.strip().startswith(f"{name}:"):
            return p
    raise AssertionError(f"service {name} not found")


class TestLoopbackOnlyPublishing:
    def test_no_lan_binds_anywhere(self):
        s = _LOCAL.read_text()
        assert "0.0.0.0" not in s  # noqa: S104 — asserting its ABSENCE is the point
        # Every published port is an explicit loopback bind.
        for name, bind in LOOPBACK_PORTS.items():
            assert f'"{bind}"' in _service(s, name), name

    def test_redis_publishes_nothing(self):
        s = _service(_LOCAL.read_text(), "redis")
        assert "ports: !reset []" in s

    def test_redis_requirepass_required(self):
        s = _service(_LOCAL.read_text(), "redis")
        assert "--requirepass" in s
        assert "${REDIS_PASSWORD:?" in s

    def test_no_caddy_in_local_overlay(self):
        assert "  caddy:" not in _LOCAL.read_text()


class TestApiPosture:
    def test_docs_disabled(self):
        s = _service(_LOCAL.read_text(), "api")
        assert 'DOCS_ENABLED: "false"' in s

    def test_redis_url_carries_password(self):
        s = _service(_LOCAL.read_text(), "api")
        assert "redis://:${REDIS_PASSWORD:?" in s

    def test_password_pepper_required(self):
        s = _service(_LOCAL.read_text(), "api")
        assert 'PASSWORD_PEPPER: "${PASSWORD_PEPPER:?' in s

    def test_no_new_privileges_and_cap_drop(self):
        s = _service(_LOCAL.read_text(), "api")
        assert "no-new-privileges:true" in s
        assert "- ALL" in s


class TestDashboardPosture:
    def test_live_reload_mount_removed(self):
        s = _service(_LOCAL.read_text(), "dashboard")
        assert "volumes: !reset []" in s
        assert "./dashboard" not in s

    def test_jwt_login_default(self):
        s = _service(_LOCAL.read_text(), "dashboard")
        assert "DASHBOARD_API_TOKEN: ${DASHBOARD_API_TOKEN:-}" in s

    def test_no_new_privileges_and_cap_drop(self):
        s = _service(_LOCAL.read_text(), "dashboard")
        assert "no-new-privileges:true" in s
        assert "- ALL" in s


class TestBaseComposePepperPassthrough:
    def test_base_api_env_carries_pepper_passthrough(self):
        s = _BASE.read_text()
        assert "PASSWORD_PEPPER: ${PASSWORD_PEPPER:-}" in s
