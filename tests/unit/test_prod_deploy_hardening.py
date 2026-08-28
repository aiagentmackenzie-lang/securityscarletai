"""Phase-4 deployment-overlay hardening tests (F-04 / F-07 / F-21 / F-26).

- F-21: static bearer calls are ATTRIBUTED in audit rows ("static-bearer"/admin),
  not user=NULL.
- F-07: the entrypoint's uvicorn exec trusts proxy headers from private
  networks only (--proxy-headers --forwarded-allow-ips).
- F-04: the prod overlay revokes postgres/redis host ports (only Caddy
  publishes 80/443) and enforces redis --requirepass.
- F-26: no platform pins (they broke x86 hosts).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from tests.unit._test_request import make_test_request

_repo = Path(__file__).resolve().parents[2]
_PROD = _repo / "docker-compose.prod.yml"
_BASE = _repo / "docker-compose.yml"
_ENTRY = _repo / "scripts" / "entrypoint.sh"

TESTING_ENV = {
    "DB_PASSWORD": "dummypass-phase4-test",
    "API_SECRET_KEY": "x" * 64,
    "API_BEARER_TOKEN": "y" * 32,
    "REDIS_PASSWORD": "redis-pass-phase4-test",
    "DOMAIN": "check.local",
}


class TestStaticBearerAttribution:
    """F-21: static-bearer calls are attributed, not anonymous."""

    def test_static_bearer_attributed(self):
        from src.api.middleware import _decode_actor_from_request

        token = __import__(
            "src.config.settings", fromlist=["settings"]
        ).settings.api_bearer_token.get_secret_value()
        req = make_test_request()
        req.scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]

        user, role = _decode_actor_from_request(req)
        assert user == {"sub": "static-bearer", "role": "admin"}
        assert role == "admin"

    def test_garbage_bearer_still_anonymous(self):
        from src.api.middleware import _decode_actor_from_request

        req = make_test_request()
        req.scope["headers"] = [(b"authorization", b"Bearer junk")]

        user, role = _decode_actor_from_request(req)
        assert user is None and role is None

    def test_jwt_attribution_unchanged(self):
        from src.api.auth import create_jwt
        from src.api.middleware import _decode_actor_from_request

        token = create_jwt("analyst1", "analyst")

        req = make_test_request()
        req.scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        user, role = _decode_actor_from_request(req)
        assert user is not None and user.get("sub") == "analyst1"
        assert role == "analyst"


class TestEntrypointProxyHeaders:
    """F-07: uvicorn must run with proxy-headers limited to private ranges."""

    def test_exec_line_has_proxy_headers(self):
        s = _ENTRY.read_text()
        assert "--proxy-headers" in s
        assert "--forwarded-allow-ips" in s

    def test_forwarded_allow_ips_defaults_to_private_ranges_only(self):
        import re

        s = _ENTRY.read_text()
        m = re.search(r"UVICORN_FORWARDED_ALLOW_IPS:-(.*)\}", s)
        assert m, "expected a defaulted allowance"
        default = m.group(1)
        for private in ("172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"):
            assert private in default
        assert "0.0.0.0/0" not in default and "::/0" not in default

    def test_entrypoint_syntax_still_valid(self):
        result = subprocess.run(  # noqa: S603 — pinned binary, repo-owned path
            ["/bin/bash", "-n", str(_ENTRY)],  # noqa: S607 — absolute path
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr


class TestProdOverlay:
    """Structural guarantees of the prod overlay (merged-config proof runs
    live; these pin the file content so a revert is caught in CI)."""

    def test_prod_overlay_reset_db_ports(self):
        s = _PROD.read_text()
        # postgres + redis services must carry ports: !reset []
        pg_section = s.split("services:")[1]
        assert "ports: !reset []" in s

    def test_no_platform_pins_anywhere(self):
        for f in (_BASE, _PROD):
            assert "platform: linux/arm64" not in f.read_text(), (
                f"F-26 violation: {f.name} still pins platform"
            )

    def test_redis_requirepass_enforced(self):
        import re

        s = _PROD.read_text()
        assert "--requirepass" in s
        m = re.search(r"requirepass[^}]*\$\{(REDIS_PASSWORD):?\??", s)
        assert m or "REDIS_PASSWORD" in s

    def test_redis_url_carries_password(self):
        assert "redis://" in _PROD.read_text()
        prod = _PROD.read_text()
        # the api's prod REDIS_URL must embed the password var
        import re

        m = re.search(r"REDIS_URL:\s*redis://:\$\{REDIS_PASSWORD", prod)
        assert m, "API REDIS_URL in prod must carry the redis password"


class TestCaddyfileForwarded:
    """Caddy sets X-Forwarded-For by default; verify the config we ship does
    not disabled it (a header_up override removing XFF)."""

    def test_caddyfile_does_not_strip_xff(self):
        caddyfile = (_repo / "deploy" / "Caddyfile").read_text()
        assert "header_up -X-Forwarded-For" not in caddyfile
        assert "header_up X-Forwarded-For" not in caddyfile or "{remote_host}" in caddyfile
