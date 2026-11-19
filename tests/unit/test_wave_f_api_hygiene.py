"""Wave F regressions: config, ops, API hygiene."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_repo = Path(__file__).resolve().parents[2]


# ───────────────────────────────────────────────────────────────
# SS-001 — database_url must not encode a space as '+'
# ───────────────────────────────────────────────────────────────


class TestDatabaseUrlEncoding:
    def test_space_is_percent_encoded_not_plus(self):
        """quote_plus is query-string encoding: a password with a space became
        '+', which asyncpg treats literally, so every DSN consumer failed auth."""
        from src.config.settings import Settings

        s = Settings(
            db_password="pa ss/word",  # type: ignore[call-arg]
            api_secret_key="x" * 64,  # type: ignore[call-arg]
            api_bearer_token="y" * 32,  # type: ignore[call-arg]
        )
        url = s.database_url
        assert "pa+ss" not in url
        assert "pa%20ss" in url
        assert "%2F" in url  # the '/' too

    def test_url_parses_back_to_the_original_credentials(self):
        from urllib.parse import unquote, urlsplit

        from src.config.settings import Settings

        s = Settings(
            db_password="pa ss/word:@",  # type: ignore[call-arg]
            api_secret_key="x" * 64,  # type: ignore[call-arg]
            api_bearer_token="y" * 32,  # type: ignore[call-arg]
        )
        parts = urlsplit(s.database_url.replace("+asyncpg", ""))
        assert unquote(parts.password or "") == "pa ss/word:@"
        # the default user (env may override it in CI)
        assert unquote(parts.username or "")


# ───────────────────────────────────────────────────────────────
# SS-031 — calculation_time must be UTC
# ───────────────────────────────────────────────────────────────


class TestRiskCalculationTimeIsUtc:
    def test_calculation_time_carries_a_timezone(self):
        src = (_repo / "src" / "ai" / "risk_scoring.py").read_text()
        assert (
            'calculation_time": datetime.now(timezone.utc).isoformat()'
            in src.replace("\n", "").replace("            ", "")
            or "datetime.now(timezone.utc).isoformat()" in src
        )


# ───────────────────────────────────────────────────────────────
# SS-028 — server-side statement timeout
# ───────────────────────────────────────────────────────────────


class TestStatementTimeout:
    def test_pool_sets_a_server_side_statement_timeout(self):
        src = (_repo / "src" / "db" / "connection.py").read_text()
        assert "statement_timeout" in src

    def test_timeout_is_configurable(self):
        from src.config.settings import settings

        assert getattr(settings, "db_statement_timeout_ms", 0) >= 1000


# ───────────────────────────────────────────────────────────────
# SS-002 — DOCS_ENABLED must be asserted by the posture gate
# ───────────────────────────────────────────────────────────────


class TestDocsPosture:
    @pytest.mark.asyncio
    async def test_prod_boot_with_docs_enabled_is_a_problem(self):
        from scripts.posture_check import run_checks

        problems = await run_checks(
            {
                "PASSWORD_PEPPER": "x" * 64,
                "DATABASE_SUPERUSER_URL": "postgresql://o@db/x",
                "DOCS_ENABLED": "true",
            }
        )
        assert any("docs" in p.detail.lower() for p in problems)

    @pytest.mark.asyncio
    async def test_prod_boot_with_docs_disabled_is_clean(self):
        from scripts.posture_check import run_checks

        problems = await run_checks(
            {
                "PASSWORD_PEPPER": "x" * 64,
                "DATABASE_SUPERUSER_URL": "postgresql://o@db/x",
                "DOCS_ENABLED": "false",
            }
        )
        assert not any("docs" in p.detail.lower() for p in problems)


# ───────────────────────────────────────────────────────────────
# SS-027 — retention is bounded by a wall-clock budget, backlog is visible
# ───────────────────────────────────────────────────────────────


class TestRetentionBacklog:
    @pytest.mark.asyncio
    async def test_budget_stops_the_loop_and_reports_backlog(self):
        from src.services import retention

        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="DELETE 5000")  # always a full batch
        acq = MagicMock()
        acq.__aenter__ = AsyncMock(return_value=conn)
        acq.__aexit__ = AsyncMock(return_value=None)
        pool = AsyncMock()
        pool.acquire = MagicMock(return_value=acq)

        with patch("src.services.retention.get_pool", AsyncMock(return_value=pool)):
            deleted, backlog = await retention._delete_old_rows(
                "logs", "time", datetime.now(tz=timezone.utc), 5000, budget_seconds=0.01
            )

        assert deleted > 0
        assert backlog is True, "a capped sweep must report that work remains"

    @pytest.mark.asyncio
    async def test_drained_table_reports_no_backlog(self):
        from src.services import retention

        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="DELETE 3")
        acq = MagicMock()
        acq.__aenter__ = AsyncMock(return_value=conn)
        acq.__aexit__ = AsyncMock(return_value=None)
        pool = AsyncMock()
        pool.acquire = MagicMock(return_value=acq)

        with patch("src.services.retention.get_pool", AsyncMock(return_value=pool)):
            deleted, backlog = await retention._delete_old_rows(
                "logs", "time", datetime.now(tz=timezone.utc), 5000
            )

        assert deleted == 3
        assert backlog is False

    def test_backlog_metric_exists(self):
        from src.api.metrics import retention_backlog_remaining

        assert retention_backlog_remaining.name.endswith("retention_backlog_remaining")


# ───────────────────────────────────────────────────────────────
# SS-035 — a disconnected chunked body must not be re-injected
# ───────────────────────────────────────────────────────────────


class TestChunkedDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_does_not_install_a_partial_body(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.middleware import RequestValidationMiddleware

        app = FastAPI()
        seen: dict = {}

        @app.post("/api/v1/ingest")
        async def ingest(request):  # pragma: no cover - body path only
            seen["body"] = await request.body()
            return {"ok": True}

        app.add_middleware(RequestValidationMiddleware)

        async def fake_receive():
            return {"type": "http.disconnect"}

        # Drive the middleware directly with a request whose stream disconnects.
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/ingest",
            "headers": [(b"transfer-encoding", b"chunked")],
            "query_string": b"",
            "root_path": "",
            "http_version": "1.1",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 1),
        }
        request = Request(scope, receive=fake_receive)
        middleware = RequestValidationMiddleware(app=None)  # type: ignore[arg-type]
        response = await middleware.dispatch(request, lambda req: _ok(req))
        assert response.status_code == 400, "a truncated body must be refused, not passed on"

        # sanity: the client construction path still works
        assert TestClient(app) is not None


async def _ok(request):
    from starlette.responses import JSONResponse

    return JSONResponse({"body": (await request.body()).decode()})


# ───────────────────────────────────────────────────────────────
# SS-034 / SS-042 — dev/demo trust posture + no password echo
# ───────────────────────────────────────────────────────────────


class TestDevProxyPosture:
    def test_base_compose_trusts_no_forwarded_headers(self):
        base = (_repo / "docker-compose.yml").read_text()
        assert 'UVICORN_FORWARDED_ALLOW_IPS: ""' in base

    def test_prod_overlays_trust_the_compose_network(self):
        for overlay in ("docker-compose.prod.yml", "docker-compose.local-prod.yml"):
            text = (_repo / overlay).read_text()
            assert 'UVICORN_FORWARDED_ALLOW_IPS: "172.16.0.0/12"' in text, overlay

    def test_entrypoint_honours_an_explicit_empty_value(self):
        entry = (_repo / "scripts" / "entrypoint.sh").read_text()
        assert "${UVICORN_FORWARDED_ALLOW_IPS-172.16.0.0/12}" in entry
        # The false claim ("LAN peers are never trusted because 10/8 and
        # 192.168/16 were dropped") must be gone.
        assert "LAN peers must never be trusted proxies" not in entry

    def test_entrypoint_does_not_echo_the_admin_password(self):
        entry = (_repo / "scripts" / "entrypoint.sh").read_text()
        assert 'cat "$PASSWORD_FILE"' not in entry
        assert 'echo "$PASSWORD"' not in entry
        assert "admin_initial_password" in entry  # the 0600 file stays the handoff


# ───────────────────────────────────────────────────────────────
# SS-041 — WS tokens are swept, not only cleaned on mint
# ───────────────────────────────────────────────────────────────


class TestWsTokenSweep:
    def test_expired_tokens_are_removed_by_the_sweeper(self):
        import time

        from src.api import websocket as ws

        ws._ws_tokens.clear()
        ws._ws_tokens["expired"] = {"username": "u", "role": "viewer", "expires": time.time() - 400}
        ws._ws_tokens["live"] = {"username": "u", "role": "viewer", "expires": time.time() + 300}

        ws._sweep_ws_tokens()

        assert "expired" not in ws._ws_tokens
        assert "live" in ws._ws_tokens
        ws._ws_tokens.clear()

    def test_validation_sweeps_lazily(self):
        import time

        from src.api import websocket as ws

        ws._ws_tokens.clear()
        ws._ws_tokens["stale"] = {"username": "u", "role": "viewer", "expires": time.time() - 400}
        assert ws._validate_ws_token("nope") is None
        assert "stale" not in ws._ws_tokens
        ws._ws_tokens.clear()


# ───────────────────────────────────────────────────────────────
# SS-059 — fleet enroll is idempotent under a race
# ───────────────────────────────────────────────────────────────


class TestFleetEnrollRace:
    def test_enroll_uses_one_upsert(self):
        src = (_repo / "src" / "api" / "fleet.py").read_text()
        assert "ON CONFLICT" in src, "check-then-insert still races"
        assert "SELECT 1 FROM fleet_enrollments WHERE host_name" not in src


# ───────────────────────────────────────────────────────────────
# SS-060 — the DNS executor is shut down
# ───────────────────────────────────────────────────────────────


class TestDnsExecutorShutdown:
    def test_shutdown_function_exists_and_is_wired(self):
        from src.enrichment import pipeline

        assert hasattr(pipeline, "shutdown_dns_executor")
        main = (_repo / "src" / "api" / "main.py").read_text()
        assert "shutdown_dns_executor" in main

    def test_shutdown_is_idempotent(self):
        from src.enrichment import pipeline

        pipeline.shutdown_dns_executor()
        pipeline.shutdown_dns_executor()


# ───────────────────────────────────────────────────────────────
# SS-061 — VALID_OBJECTIVES is actually validated
# ───────────────────────────────────────────────────────────────


class TestComplianceObjectives:
    def test_nist_csf_objectives_are_accepted(self):
        from src.compliance.frameworks import parse_frameworks_document

        doc = {
            "compliance_frameworks": {
                "version": 1,
                "frameworks": {
                    "x": {
                        "controls": [
                            {
                                "id": "1",
                                "requirement": "r",
                                "surface": "s",
                                "objective": "GOVERN (GV)",
                            }
                        ]
                    }
                },
            }
        }
        parsed = parse_frameworks_document(doc)
        assert parsed["frameworks"]["x"]["controls"][0]["objective"] == "GOVERN (GV)"

    def test_unknown_objective_is_dropped(self):
        from src.compliance.frameworks import VALID_OBJECTIVES, parse_frameworks_document

        doc = {
            "compliance_frameworks": {
                "version": 1,
                "frameworks": {
                    "x": {
                        "controls": [
                            {"id": "1", "requirement": "r", "surface": "s", "objective": "A"},
                            {"id": "2", "requirement": "r", "surface": "s", "objective": "ZZZ"},
                        ]
                    }
                },
            }
        }
        parsed = parse_frameworks_document(doc)
        controls = parsed["frameworks"]["x"]["controls"]
        assert controls[0]["objective"] == "A"
        assert "objective" not in controls[1]
        assert {"A", "B", "C", "D"} <= set(VALID_OBJECTIVES)


# ───────────────────────────────────────────────────────────────
# SS-063 — naive datetimes are refused, not silently localised
# ───────────────────────────────────────────────────────────────


class TestNaiveDatetimes:
    def test_api_boundary_rejects_naive(self):
        from src.api._datetime import require_aware

        with pytest.raises(ValueError):
            require_aware(datetime(2026, 11, 18, 12, 0, 0), field="since")

    def test_api_boundary_accepts_aware(self):
        from src.api._datetime import require_aware

        aware = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)
        assert require_aware(aware, field="since") == aware

    def test_ingest_event_timestamp_validator_rejects_naive(self):
        from pydantic import ValidationError

        from src.ingestion.schemas import NormalizedEvent

        with pytest.raises(ValidationError):
            NormalizedEvent(
                timestamp=datetime(2026, 11, 18, 12, 0, 0),  # naive
                host_name="h",
                source="test",
                event_category="process",
                event_type="start",
                raw_data={},
            )

    def test_ingest_event_accepts_aware(self):
        from src.ingestion.schemas import NormalizedEvent

        ev = NormalizedEvent(
            timestamp=datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc),
            host_name="h",
            source="test",
            event_category="process",
            event_type="start",
            raw_data={},
        )
        assert ev.timestamp.tzinfo is not None


# ───────────────────────────────────────────────────────────────
# SS-064 — duplicate rule name is a 409, not a 500
# ───────────────────────────────────────────────────────────────


class TestRuleNameConflict:
    @pytest.mark.asyncio
    async def test_duplicate_name_returns_409(self):
        import asyncpg
        from fastapi import HTTPException

        from src.api.rules import RuleCreate, create_rule

        conn = AsyncMock()
        conn.fetchval = AsyncMock(side_effect=asyncpg.UniqueViolationError("duplicate key value"))
        acq = MagicMock()
        acq.__aenter__ = AsyncMock(return_value=conn)
        acq.__aexit__ = AsyncMock(return_value=None)
        pool = AsyncMock()
        pool.acquire = MagicMock(return_value=acq)

        rule = RuleCreate(
            name="Dup",
            sigma_yaml="""
title: Dup
detection:
    selection:
        process_name: evil
    condition: selection
timeframe: 5m
level: high
""",
            severity="high",
        )
        with patch("src.api.rules.get_pool", AsyncMock(return_value=pool)):
            with pytest.raises(HTTPException) as exc:
                await create_rule(rule=rule, user={"sub": "admin1", "role": "admin"})
        assert exc.value.status_code == 409
