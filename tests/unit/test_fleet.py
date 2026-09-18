"""Fleet enrollment + per-host ingest binding (V0.5a "Fleet & Scale").

Covers:
- enrollment stores sha256(token), NEVER the plaintext; plaintext shown once
- re-enrollment rotates (rotated=True, hash replaced, revoked_at cleared)
- listing never exposes the token hash
- revocation is immediate: revoked token resolves to None (401 downstream)
- get_ingest_client resolves fleet tokens to kind="fleet" identities
- fleet identity cannot authenticate on non-ingest endpoints (get_current_user)
- the ingest endpoint enforces host binding: a fleet token delivering
  events for ANY other host refuses the WHOLE batch with 403 + audits
- correct-host fleet batches ingest fine (202)

DB seams: every get_pool import is patched per LRN-20260911-004 (endpoint
module AND src.db.connection for the function-level import in auth).
Admin-only endpoint tests call the functions directly with an admin payload
(the test_users_admin.py house pattern).
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from jose import JWTError
from pydantic import ValidationError

os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
os.environ.setdefault("API_SECRET_KEY", "x" * 64)
os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)

FLEET_TOKEN = "fleet-plaintext-token-0123456789abcdef"

ADMIN = {"sub": "admin-x", "username": "admin-x", "role": "admin"}


def _mock_pool():
    pool = AsyncMock()
    conn = AsyncMock()
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquirer)
    return pool, conn


def _fleet_identity(host: str) -> dict:
    return {
        "sub": f"fleet:{host}",
        "username": f"fleet:{host}",
        "role": "ingest",
        "kind": "fleet",
        "fleet_host": host,
    }


def _ingest_app(fleet_host: str) -> TestClient:
    from src.api.auth import get_ingest_client
    from src.api.ingest import router
    from src.api.rate_limit import limiter, rate_limit_exceeded_handler

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.state.limiter = limiter
    from slowapi.errors import RateLimitExceeded

    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    app.dependency_overrides[get_ingest_client] = lambda: _fleet_identity(fleet_host)
    return TestClient(app, raise_server_exceptions=False)


def _ingest_event(host: str = "s1") -> dict:
    return {
        "@timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "host_name": host,
        "source": "syslog",
        "event_category": "process",
        "event_type": "start",
    }


# ───────────────────────────────────────────────────────────────
# Enrollment API (direct calls, admin payload)
# ───────────────────────────────────────────────────────────────


class TestFleetEnrollment:
    @pytest.mark.asyncio
    async def test_enroll_stores_hash_not_plaintext(self):
        from src.api.fleet import EnrollRequest, enroll_host

        pool, conn = _mock_pool()
        conn.fetchval.return_value = None  # fresh host, not a rotation
        with (
            patch("src.api.fleet.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.fleet.log_audit_action", AsyncMock(return_value=1)),
        ):
            resp = await enroll_host(EnrollRequest(host_name="workstation-1"), ADMIN)

        token = resp.token
        assert resp.host_name == "workstation-1"
        assert resp.rotated is False
        assert token
        # stored value = sha256(token) hex; plaintext NEVER persisted
        expected = hashlib.sha256(token.encode()).hexdigest()
        args, kwargs = conn.execute.call_args
        flat = " ".join([str(a) for a in args] + [str(v) for v in kwargs.values()])
        assert expected in flat
        assert token not in flat
        assert conn.execute.await_count == 1  # INSERT path

    @pytest.mark.asyncio
    async def test_reenroll_rotates(self):
        from src.api.fleet import EnrollRequest, enroll_host

        pool, conn = _mock_pool()
        conn.fetchval.return_value = 1  # existing enrollment -> rotation
        with (
            patch("src.api.fleet.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.fleet.log_audit_action", AsyncMock(return_value=1)),
        ):
            resp = await enroll_host(EnrollRequest(host_name="s1"), ADMIN)
        assert resp.rotated is True
        # the UPDATE path fired, not the INSERT
        assert "UPDATE fleet_enrollments" in conn.execute.call_args.args[0]


class TestFleetPlatform:
    """V0.6a cross-platform fleet: enrollment records the host's OS family.

    Closed vocabulary (darwin|linux|windows|unknown) -- an unvalidated
    platform string would poison the fleet inventory the deploy kit relies
    on. Fail-closed (ValidationError), never coerced.
    """

    @pytest.mark.asyncio
    async def test_enroll_records_platform(self):
        from src.api.fleet import EnrollRequest, enroll_host

        pool, conn = _mock_pool()
        conn.fetchval.return_value = None
        with (
            patch("src.api.fleet.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.fleet.log_audit_action", AsyncMock(return_value=1)),
        ):
            resp = await enroll_host(
                EnrollRequest(host_name="win-fleet-01", platform="windows"), ADMIN
            )
        assert resp.platform == "windows"
        flat = " ".join(str(a) for a in conn.execute.call_args.args)
        assert "windows" in flat

    @pytest.mark.asyncio
    async def test_enroll_defaults_to_unknown(self):
        from src.api.fleet import EnrollRequest, enroll_host

        pool, conn = _mock_pool()
        conn.fetchval.return_value = None
        with (
            patch("src.api.fleet.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.fleet.log_audit_action", AsyncMock(return_value=1)),
        ):
            resp = await enroll_host(EnrollRequest(host_name="legacy-host"), ADMIN)
        assert resp.platform == "unknown"

    @pytest.mark.asyncio
    async def test_invalid_platform_fails_closed(self):
        from src.api.fleet import EnrollRequest

        with pytest.raises(ValidationError):
            EnrollRequest(host_name="s1", platform="solaris")

    @pytest.mark.asyncio
    async def test_platform_normalized_and_vocabulary_closed(self):
        from src.api.fleet import VALID_PLATFORMS, EnrollRequest

        req = EnrollRequest(host_name="s1", platform=" Linux ")
        assert req.platform == "linux"  # case/space normalized
        assert VALID_PLATFORMS == frozenset({"darwin", "linux", "windows", "unknown"})

    @pytest.mark.asyncio
    async def test_enroll_sanitizes_hostname(self):
        from src.api.fleet import EnrollRequest, enroll_host

        pool, conn = _mock_pool()
        conn.fetchval.return_value = None
        with (
            patch("src.api.fleet.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.fleet.log_audit_action", AsyncMock(return_value=1)),
        ):
            resp = await enroll_host(EnrollRequest(host_name="host\nwith\tjunk"), ADMIN)
        assert "\n" not in resp.host_name
        assert "\t" not in resp.host_name

    @pytest.mark.asyncio
    async def test_list_never_exposes_token_hash(self):
        from src.api.fleet import list_hosts

        pool, conn = _mock_pool()
        conn.fetch.return_value = [
            {
                "host_name": "s1",
                "enrolled_at": datetime.now(tz=timezone.utc),
                "last_seen_at": None,
                "revoked_at": None,
                "notes": None,
            }
        ]
        with patch("src.api.fleet.get_pool", AsyncMock(return_value=pool)):
            result = await list_hosts(admin=ADMIN)
        assert len(result) == 1
        assert "token_hash" not in json.dumps(result, default=str)

    @pytest.mark.asyncio
    async def test_revoke_then_revoke_404(self):
        from fastapi import HTTPException

        from src.api.fleet import RevokeRequest, revoke_host

        pool, conn = _mock_pool()
        conn.fetchval.side_effect = [datetime.now(tz=timezone.utc), None]
        with (
            patch("src.api.fleet.get_pool", AsyncMock(return_value=pool)),
            patch("src.api.fleet.log_audit_action", AsyncMock(return_value=1)),
        ):
            r1 = await revoke_host(RevokeRequest(host_name="s1"), ADMIN)
            with pytest.raises(HTTPException) as exc:
                await revoke_host(RevokeRequest(host_name="s1"), ADMIN)
        assert r1.revoked_at is not None
        assert exc.value.status_code == 404


# ───────────────────────────────────────────────────────────────
# Fleet token resolution (auth path)
# ───────────────────────────────────────────────────────────────


class TestFleetTokenResolution:
    @pytest.mark.asyncio
    async def test_live_token_resolves_to_fleet_identity(self):
        import src.api.auth as auth_mod

        pool = AsyncMock()
        pool.fetchrow.return_value = {"host_name": "s1"}
        with patch("src.db.connection.get_pool", AsyncMock(return_value=pool)):
            identity = await auth_mod._resolve_fleet_token(FLEET_TOKEN)
        assert identity is not None
        assert identity["kind"] == "fleet"
        assert identity["fleet_host"] == "s1"
        assert identity["role"] == "ingest"

    @pytest.mark.asyncio
    async def test_unknown_token_resolves_none(self):
        import src.api.auth as auth_mod

        pool = AsyncMock()
        pool.fetchrow.return_value = None
        with patch("src.db.connection.get_pool", AsyncMock(return_value=pool)):
            identity = await auth_mod._resolve_fleet_token("nope")
        assert identity is None

    @pytest.mark.asyncio
    async def test_db_outage_fails_closed(self):
        import src.api.auth as auth_mod

        with patch(
            "src.db.connection.get_pool",
            AsyncMock(side_effect=RuntimeError("db down")),
        ):
            identity = await auth_mod._resolve_fleet_token(FLEET_TOKEN)
        assert identity is None  # no fleet identity -> 401 downstream

    @pytest.mark.asyncio
    async def test_fleet_token_rejected_on_other_endpoints(self):
        """get_current_user never consults fleet tokens (blast radius = ingest)."""

        from src.api.auth import get_current_user

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=FLEET_TOKEN)

        async def _reject(_t):
            raise JWTError()

        with (
            patch("src.api.auth._decode_access_jwt", _reject),
            patch("src.api.auth._static_bearer_identity", return_value=None),
            pytest.raises(Exception) as exc,
        ):
            await get_current_user(creds)
        assert getattr(exc.value, "status_code", None) == 401

    @pytest.mark.asyncio
    async def test_last_seen_throttled_inside_window(self):
        import src.api.auth as auth_mod

        pool = AsyncMock()
        pool.fetchrow.return_value = {"host_name": "s1"}
        auth_mod._fleet_last_seen.clear()
        with patch("src.db.connection.get_pool", AsyncMock(return_value=pool)):
            await auth_mod._resolve_fleet_token(FLEET_TOKEN)
            first = auth_mod._fleet_last_seen.get("s1")
            await auth_mod._resolve_fleet_token(FLEET_TOKEN)
            second = auth_mod._fleet_last_seen.get("s1")
        assert first == second  # inside the window -> no repeated UPDATE
        assert pool.execute.await_count == 1


# ───────────────────────────────────────────────────────────────
# Host binding at the ingest endpoint (TestClient + override)
# ───────────────────────────────────────────────────────────────


class TestFleetHostBinding:
    def test_wrong_host_refuses_whole_batch_403(self):
        client = _ingest_app(fleet_host="s1")
        write_mock = AsyncMock()
        with (
            patch(
                "src.db.connection.get_pool",
                AsyncMock(side_effect=RuntimeError("no db")),
            ),
            patch("src.api.ingest.log_audit_action", AsyncMock(return_value=1)),
            patch("src.services.writer.writer.write", write_mock),
        ):
            r = client.post(
                "/api/v1/ingest",
                json=[_ingest_event("s1"), _ingest_event("evil-host")],
                headers={"Authorization": "Bearer fleet-token"},
            )
        assert r.status_code == 403
        # fail-closed: NOTHING from a refused batch is written
        write_mock.assert_not_called()

    def test_correct_host_ingests(self):
        client = _ingest_app(fleet_host="s1")
        write_mock = AsyncMock()
        # AUD-001: the quarantine lookup is fail-closed now — a healthy 202
        # requires a healthy lookup. (This test previously relied on the
        # fail-open swallow of a deliberately-broken pool: the exact bug.)
        qpool, qconn = _mock_pool()
        qconn.fetch.return_value = []  # empty quarantine list
        with (
            patch("src.api.ingest.get_pool", AsyncMock(return_value=qpool)),
            patch(
                "src.db.connection.get_pool",
                AsyncMock(side_effect=RuntimeError("no db")),
            ),
            patch("src.detection.correlation.run_all_correlations", AsyncMock()),
            patch("src.api.websocket.broadcast_event", AsyncMock()),
            patch("src.api.ingest.log_audit_action", AsyncMock(return_value=1)),
            patch("src.services.writer.writer.write", write_mock),
        ):
            r = client.post(
                "/api/v1/ingest",
                json=[_ingest_event("s1"), _ingest_event("s1")],
                headers={"Authorization": "Bearer fleet-token"},
            )
        assert r.status_code == 202
        assert r.json()["accepted"] == 2

    def test_spoof_attempt_is_audited(self):
        client = _ingest_app(fleet_host="s1")
        write_mock = AsyncMock()
        audit = AsyncMock(return_value=1)
        with (
            patch(
                "src.db.connection.get_pool",
                AsyncMock(side_effect=RuntimeError("no db")),
            ),
            patch("src.api.ingest.log_audit_action", audit),
            patch("src.services.writer.writer.write", write_mock),
        ):
            client.post(
                "/api/v1/ingest",
                json=[_ingest_event("evil-host")],
                headers={"Authorization": "Bearer fleet-token"},
            )
        # the refusal was audited with the claimed rogue host recorded
        assert audit.await_count == 1
        kwargs = audit.await_args.kwargs
        assert kwargs.get("action") == "fleet.host_spoof_refused"
        assert "evil-host" in json.dumps(kwargs.get("new_values"))

    def test_audit_outage_does_not_block_refusal(self):
        """Fail-closed on binding even if the audit write itself fails."""
        client = _ingest_app(fleet_host="s1")
        write_mock = AsyncMock()
        with (
            patch(
                "src.db.connection.get_pool",
                AsyncMock(side_effect=RuntimeError("no db")),
            ),
            patch(
                "src.api.ingest.log_audit_action",
                AsyncMock(side_effect=RuntimeError("audit db down")),
            ),
            patch("src.services.writer.writer.write", write_mock),
        ):
            r = client.post(
                "/api/v1/ingest",
                json=[_ingest_event("evil-host")],
                headers={"Authorization": "Bearer fleet-token"},
            )
        assert r.status_code == 403
        write_mock.assert_not_called()


# ───────────────────────────────────────────────────────────────
# /ingest/osquery — raw osquery lines from fleet shippers (V0.5b)
# ───────────────────────────────────────────────────────────────


def _osquery_app(fleet_host: str | None) -> TestClient:
    """The ingest app with BOTH ingest routes and a fleet (or admin) identity."""
    from src.api.auth import get_ingest_client
    from src.api.ingest import router
    from src.api.rate_limit import limiter, rate_limit_exceeded_handler

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.state.limiter = limiter
    from slowapi.errors import RateLimitExceeded

    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    if fleet_host:
        app.dependency_overrides[get_ingest_client] = lambda: _fleet_identity(fleet_host)
    else:
        app.dependency_overrides[get_ingest_client] = lambda: {
            "sub": "admin-x",
            "username": "admin-x",
            "role": "admin",
        }
    return TestClient(app, raise_server_exceptions=False)


def _raw_osquery_line(host: str = "Raphaels-Mac-mini.local") -> str:
    return json.dumps(
        {
            "name": "processes",
            "hostIdentifier": host,
            "calendarTime": "Sat Sep 12 00:00:00 2026 UTC",
            "unixTime": 1789171200,
            "action": "added",
            "columns": {
                "pid": "4242",
                "name": "curl",
                "cmdline": "curl https://example.com",
                "path": "/usr/bin/curl",
            },
        }
    )


def _ingest_mock_pool():
    """Mock pool for the quarantine lookup (empty list = nothing quarantined)."""
    pool = AsyncMock()
    conn = AsyncMock()
    conn.fetch.return_value = []
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    pool.acquire = MagicMock(return_value=acquirer)
    return pool, conn


class TestIngestOsqueryEndpoint:
    def test_parses_lines_and_accepts(self):
        client = _osquery_app(fleet_host=None)
        write_mock = AsyncMock()
        pool, _ = _ingest_mock_pool()
        with (
            patch("src.api.ingest.get_pool", AsyncMock(return_value=pool)),
            patch("src.services.writer.writer.write", write_mock),
            patch("src.detection.correlation.run_all_correlations", AsyncMock()),
            patch("src.api.websocket.broadcast_event", AsyncMock()),
        ):
            r = client.post(
                "/api/v1/ingest/osquery",
                json={"lines": [_raw_osquery_line(), _raw_osquery_line()]},
                headers={"Authorization": "Bearer t"},
            )
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 2
        assert body["rejected_parse"] == 0
        assert write_mock.await_count == 2

    def test_parse_failures_reported_not_fatal(self):
        client = _osquery_app(fleet_host=None)
        write_mock = AsyncMock()
        pool, _ = _ingest_mock_pool()
        with (
            patch("src.api.ingest.get_pool", AsyncMock(return_value=pool)),
            patch("src.services.writer.writer.write", write_mock),
            patch("src.detection.correlation.run_all_correlations", AsyncMock()),
            patch("src.api.websocket.broadcast_event", AsyncMock()),
        ):
            r = client.post(
                "/api/v1/ingest/osquery",
                json={"lines": [_raw_osquery_line(), "not json at all", "{}"]},
                headers={"Authorization": "Bearer t"},
            )
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 1
        assert body["rejected_parse"] == 2

    def test_empty_lines_ok(self):
        client = _osquery_app(fleet_host=None)
        r = client.post(
            "/api/v1/ingest/osquery",
            json={"lines": []},
            headers={"Authorization": "Bearer t"},
        )
        assert r.status_code == 202
        assert r.json()["accepted"] == 0

    def test_fleet_binding_enforced_on_parsed_identity(self):
        """The binding checks the PARSED hostIdentifier, not any claimed field."""
        client = _osquery_app(fleet_host="s1")
        write_mock = AsyncMock()
        with (
            patch(
                "src.db.connection.get_pool",
                AsyncMock(side_effect=RuntimeError("no db")),
            ),
            patch("src.api.ingest.log_audit_action", AsyncMock(return_value=1)),
            patch("src.services.writer.writer.write", write_mock),
        ):
            r = client.post(
                "/api/v1/ingest/osquery",
                json={"lines": [_raw_osquery_line("evil-host")]},
                headers={"Authorization": "Bearer fleet-token"},
            )
        assert r.status_code == 403
        write_mock.assert_not_called()

    def test_fleet_correct_host_accepted(self):
        client = _osquery_app(fleet_host="Raphaels-Mac-mini.local")
        write_mock = AsyncMock()
        pool, _ = _ingest_mock_pool()
        with (
            patch("src.api.ingest.get_pool", AsyncMock(return_value=pool)),
            patch("src.services.writer.writer.write", write_mock),
            patch("src.detection.correlation.run_all_correlations", AsyncMock()),
            patch("src.api.websocket.broadcast_event", AsyncMock()),
        ):
            r = client.post(
                "/api/v1/ingest/osquery",
                json={"lines": [_raw_osquery_line()]},
                headers={"Authorization": "Bearer fleet-token"},
            )
        assert r.status_code == 202
        assert r.json()["accepted"] == 1

    def test_quarantine_lookup_outage_refuses_whole_batch(self):
        """Fail-closed: a DB outage must NOT silently accept telemetry."""
        client = _osquery_app(fleet_host=None)
        write_mock = AsyncMock()
        with (
            patch(
                "src.api.ingest.get_pool",
                AsyncMock(side_effect=RuntimeError("db down")),
            ),
            patch("src.services.writer.writer.write", write_mock),
        ):
            r = client.post(
                "/api/v1/ingest/osquery",
                json={"lines": [_raw_osquery_line()]},
                headers={"Authorization": "Bearer t"},
            )
        assert r.status_code == 503
        write_mock.assert_not_called()

    def test_quarantined_host_refused(self):
        client = _osquery_app(fleet_host=None)
        write_mock = AsyncMock()
        pool, conn = _ingest_mock_pool()
        conn.fetch.return_value = [{"host_name": "bad-host"}]
        with (
            patch("src.api.ingest.get_pool", AsyncMock(return_value=pool)),
            patch("src.services.writer.writer.write", write_mock),
        ):
            r = client.post(
                "/api/v1/ingest/osquery",
                json={
                    "lines": [
                        _raw_osquery_line("bad-host"),
                        _raw_osquery_line("good-host"),
                    ]
                },
                headers={"Authorization": "Bearer t"},
            )
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 1
        assert body["rejected_quarantine"] == 1


class TestFleetDocstringHonesty:
    def test_no_phantom_rotate_endpoint(self):
        """AUD-046: the module docstring used to advertise POST /fleet/rotate
        — no such endpoint exists (rotation = re-enroll, audited as
        fleet.rotate). Pinned: the old advertising LINE is gone, no such
        route exists, and the real rotation path is documented."""
        import src.api.fleet as fleet_module
        from tests.unit._route_walker import iter_route_paths

        # The exact old advertising line (the docstring still legitimately
        # contains the words "rotate"/"fleet.rotate" when describing the
        # re-enroll path).
        assert "POST   /api/v1/fleet/rotate" not in fleet_module.__doc__
        route_paths = list(iter_route_paths(fleet_module.router.routes))
        assert not any("/fleet/rotate" in p for p in route_paths)
        # the real rotation path is documented: enroll on an existing host
        assert "re-enroll" in fleet_module.__doc__
