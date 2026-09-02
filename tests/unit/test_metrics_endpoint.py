"""
Phase 3.3 — Prometheus /metrics tests.

Covers:
- Registry primitives (counter / gauge / histogram) and text-format rendering
- path_class cardinality normalization (IDs, UUIDs, usernames → bounded labels)
- GET /api/v1/metrics: localhost scrape (no token), analyst JWT, 403 viewer,
  401 remote unauthenticated, scrape-token auth (constant-time), 401 for
  bad bearer even from localhost
- MetricsMiddleware counts requests + latency, counts 500s on handler raise
- Instrumentation: correlation run duration, ingest + retention wiring
- Router registered in main.py
"""
import re
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from pydantic import SecretStr
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, Response

from src.api.auth import create_jwt
from src.api.metrics import (
    METRICS,
    Counter,
    Gauge,
    Histogram,
    MetricsMiddleware,
    Registry,
    path_class,
    prometheus_metrics,
)

http_requests_total = METRICS._metrics["scarletai_http_requests_total"]  # noqa: SLF001
http_request_duration = METRICS._metrics["scarletai_http_request_duration_seconds"]  # noqa: SLF001


def _metrics_request(ip: str = "127.0.0.1", headers: list[tuple[bytes, bytes]] | None = None,
                     method: str = "GET"):
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/api/v1/metrics",
        "raw_path": b"/api/v1/metrics",
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": (ip, 12345),
        "server": ("testserver", 80),
    }
    return StarletteRequest(scope)


def _snapshot(counter) -> dict:
    return dict(counter.values)


def _hist_count(hist) -> int:
    return sum(e["count"] for e in hist.data.values())


class TestRegistryPrimitives:
    def test_counter_render(self):
        r = Registry()
        c = r.counter("test_counter_total", "A test counter.")
        c.inc(3, method="POST")
        c.inc(2, method="POST")
        c.inc(1, method="GET")
        text = "\n".join(c.render())
        assert "# HELP test_counter_total A test counter." in text
        assert "# TYPE test_counter_total counter" in text
        assert 'test_counter_total{method="POST"} 5' in text
        assert 'test_counter_total{method="GET"} 1' in text

    def test_counter_label_escaping(self):
        c = Counter("esc_total", "help text")
        c.inc(1, path='weird"path\\x')
        text = "\n".join(c.render())
        assert 'esc_total{path="weird\\"path\\\\x"} 1' in text

    def test_gauge_render(self):
        g = Gauge("test_gauge", "A gauge.")
        g.set(42)
        assert "test_gauge 42" in "\n".join(g.render())
        g.set(3.5)
        assert "test_gauge 3.5" in "\n".join(g.render())

    def test_histogram_buckets_cumulative(self):
        h = Histogram("test_hist", "A histogram.", buckets=(0.1, 1.0))
        h.observe(0.05)
        h.observe(0.5)
        h.observe(5.0)
        text = "\n".join(h.render())
        assert 'test_hist_bucket{le="0.1"} 1' in text
        assert 'test_hist_bucket{le="1"} 2' in text
        assert 'test_hist_bucket{le="+Inf"} 3' in text
        assert "test_hist_count 3" in text
        assert "test_hist_sum 5.55" in text

    def test_registry_render_sorted_with_help(self):
        r = Registry()
        r.counter("zeta_total", "z")
        r.gauge("alpha_gauge", "g")
        text = r.render()
        assert text.index("zeta_total") > text.index("alpha_gauge")  # sorted
        assert "# HELP alpha_gauge g" in text
        assert text.endswith("\n")


class TestPathClass:
    def test_numeric_segment(self):
        assert path_class("/api/v1/alerts/123") == "/api/v1/alerts/{id}"

    def test_uuid_segment(self):
        assert (
            path_class("/api/v1/correlation/matches/550e8400-e29b-41d4-a716-446655440000")
            == "/api/v1/correlation/matches/{id}"
        )

    def test_user_segment(self):
        assert path_class("/api/v1/ai/ueba/j.doe@corp.com") == "/api/v1/ai/ueba/{user}"

    def test_plain_path_unchanged(self):
        assert path_class("/api/v1/ingest") == "/api/v1/ingest"

    def test_mixed(self):
        assert (
            path_class("/api/v1/users/42/reset-password")
            == "/api/v1/users/{id}/reset-password"
        )


class TestMetricsEndpoint:
    async def _call(self, ip="127.0.0.1", headers=None):
        return await prometheus_metrics(request=_metrics_request(ip, headers))

    @pytest.mark.asyncio
    async def test_localhost_scrape_ok_content_and_gauges(self):
        resp = await self._call()
        assert isinstance(resp, Response)
        assert resp.media_type == "text/plain; version=0.0.4; charset=utf-8"
        body = resp.body.decode()
        # the two metrics the brief's verification names
        assert "# TYPE scarletai_http_requests_total counter" in body
        assert "# TYPE scarletai_writer_buffer_depth gauge" in body
        assert "# TYPE scarletai_http_request_duration_seconds histogram" in body

    @pytest.mark.asyncio
    async def test_remote_unauthenticated_401(self):
        with pytest.raises(HTTPException) as exc:
            await self._call(ip="10.1.2.3")
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_analyst_jwt_from_remote_ok(self):
        token = create_jwt("analyst1", "analyst")
        resp = await self._call(
            ip="10.1.2.3", headers=[(b"authorization", f"Bearer {token}".encode())]
        )
        assert isinstance(resp, Response)
        assert b"scarletai_http_requests_total" in resp.body

    @pytest.mark.asyncio
    async def test_viewer_jwt_403(self):
        token = create_jwt("v", "viewer")
        with pytest.raises(HTTPException) as exc:
            await self._call(
                ip="10.1.2.3", headers=[(b"authorization", f"Bearer {token}".encode())]
            )
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_jwt_401(self):
        with pytest.raises(HTTPException) as exc:
            await self._call(
                ip="127.0.0.1", headers=[(b"authorization", b"Bearer not-a-jwt")]
            )
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_scrape_token_allows_remote(self):
        scrape_token = "metrics-scrape-secret-0123456789abcdef"
        with patch(
            "src.config.settings.settings.metrics_bearer_token", SecretStr(scrape_token)
        ):
            resp = await prometheus_metrics(
                request=_metrics_request(
                    ip="10.1.2.3",
                    headers=[(b"authorization", f"Bearer {scrape_token}".encode())],
                )
            )
        assert isinstance(resp, Response)
        assert b"scarletai_http_requests_total" in resp.body

    @pytest.mark.asyncio
    async def test_wrong_scrape_token_401_even_from_localhost(self):
        with patch(
            "src.config.settings.settings.metrics_bearer_token",
            SecretStr("right-token-123456"),
        ):
            with pytest.raises(HTTPException) as exc:
                await self._call(
                    ip="127.0.0.1", headers=[(b"authorization", b"Bearer wrong-token")]
                )
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_token_configured_requires_creds_even_from_localhost(self):
        with patch(
            "src.config.settings.settings.metrics_bearer_token",
            SecretStr("right-token-123456"),
        ):
            with pytest.raises(HTTPException) as exc:
                await self._call(ip="127.0.0.1", headers=None)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_ingest_counter_visible_in_scrape(self):
        from src.api.metrics import ingest_accepted_total

        ingest_accepted_total.inc(7)
        resp = await self._call()
        body = resp.body.decode()
        m = re.search(r"^scarletai_ingest_accepted_total (\d+)$", body, re.M)
        assert m is not None
        assert int(m.group(1)) >= 7


class TestMetricsMiddleware:
    @pytest.mark.asyncio
    async def test_counts_request_and_latency(self):
        before = _snapshot(http_requests_total)
        hist_before = _hist_count(http_request_duration)
        mw = MetricsMiddleware(app=None)  # type: ignore[arg-type]

        async def call_next(req):
            return JSONResponse({"ok": True}, status_code=201)

        req = _metrics_request(ip="10.0.0.9", method="POST")
        await mw.dispatch(req, call_next)

        after = _snapshot(http_requests_total)
        key = tuple(sorted({"method": "POST", "path_class": "/api/v1/metrics", "status": "201"}.items()))
        assert after.get(key, 0) == before.get(key, 0) + 1
        assert _hist_count(http_request_duration) == hist_before + 1

    @pytest.mark.asyncio
    async def test_handler_exception_still_counted_as_500(self):
        before = _snapshot(http_requests_total)
        mw = MetricsMiddleware(app=None)  # type: ignore[arg-type]

        async def call_next(req):
            raise RuntimeError("boom")

        req = _metrics_request(ip="10.0.0.9", method="DELETE")
        with pytest.raises(RuntimeError):
            await mw.dispatch(req, call_next)

        after = _snapshot(http_requests_total)
        key = tuple(sorted({"method": "DELETE", "path_class": "/api/v1/metrics", "status": "500"}.items()))
        assert after.get(key, 0) == before.get(key, 0) + 1


class TestInstrumentation:
    @pytest.mark.asyncio
    async def test_run_all_correlations_observes_duration(self):
        from src.detection import correlation as corr

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.execute = AsyncMock(return_value=None)
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=mock_conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquirer)

        count_before = _hist_count(http_request_duration)
        corr_before = _hist_count(METRICS._metrics["scarletai_correlation_run_duration_seconds"])  # noqa: SLF001
        with patch("src.detection.correlation.get_pool", return_value=mock_pool):
            await corr.run_all_correlations(
                as_of=datetime(2026, 9, 2, 8, 0, 0, tzinfo=timezone.utc)
            )
        assert _hist_count(http_request_duration) == count_before  # unchanged by corr run
        assert _hist_count(
            METRICS._metrics["scarletai_correlation_run_duration_seconds"]  # noqa: SLF001
        ) == corr_before + 1

    def test_ingest_endpoint_increments_counter(self):
        """The ingest endpoint references the accepted counter (wiring present)."""
        import inspect

        from src.api import ingest

        src = inspect.getsource(ingest.ingest_events)
        assert "ingest_accepted_total.inc" in src

    def test_retention_instrumented(self):
        import inspect

        from src.services import retention

        src = inspect.getsource(retention.run_retention_once)
        assert "retention_rows_deleted.inc" in src
        assert "retention_errors.inc" in src

    def test_router_registered_in_main(self):
        from src.api.main import app

        paths = {r.path for r in app.routes}
        assert "/api/v1/metrics" in paths

    def test_middleware_registered_in_main(self):
        import src.api.main as main_mod

        middleware_classes = [m.cls for m in main_mod.app.user_middleware]
        assert MetricsMiddleware in middleware_classes


class TestWriterProperties:
    def test_fresh_writer_zeroed(self):
        from src.db.writer import LogWriter

        w = LogWriter()
        assert w.buffer_depth == 0
        assert w.backpressure_events == 0

    @pytest.mark.asyncio
    async def test_buffer_depth_grows_and_drains(self):
        from src.db.writer import LogWriter
        from src.ingestion.schemas import NormalizedEvent

        w = LogWriter(batch_size=1000)
        ev = NormalizedEvent(
            timestamp=datetime.now(tz=timezone.utc),
            host_name="h",
            source="test",
            event_category="cat",
            event_type="type",
            raw_data={},
        )
        def _fake_flush_for(w):
            async def _flush():
                w._buffer.clear()  # noqa: SLF001 — mirrors the real drain

            return _flush

        with patch.object(w, "_flush_unlocked", new=_fake_flush_for(w)):
            await w.write(ev)
            assert w.buffer_depth == 1
            await w.write(ev)
            assert w.buffer_depth == 2
            await w.flush()
            assert w.buffer_depth == 0
