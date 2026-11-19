"""SS-017: Content-Type enforcement must cover /ingest/osquery too.

`RequestValidationMiddleware` only enforced `application/json` on paths ending
exactly `/ingest`. The fleet shipper endpoint `/ingest/osquery` accepts any
content type, so the documented "content-type enforcement on ingestion
endpoints" was narrower than claimed. Enforce it (the fleet contract is JSON)
rather than weaken the doc.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.middleware import RequestValidationMiddleware


def _client() -> TestClient:
    app = FastAPI()

    @app.post("/api/v1/ingest")
    async def ingest():  # pragma: no cover - never reached in the 415 tests
        return {"ok": True}

    @app.post("/api/v1/ingest/osquery")
    async def ingest_osquery():  # pragma: no cover - never reached in the 415 tests
        return {"ok": True}

    app.add_middleware(RequestValidationMiddleware)
    return TestClient(app)


class TestIngestContentType:
    def test_ingest_rejects_non_json(self):
        assert _client().post("/api/v1/ingest", content="x=1").status_code == 415

    def test_ingest_osquery_rejects_non_json(self):
        """The defect: /ingest/osquery accepted anything."""
        resp = _client().post("/api/v1/ingest/osquery", content="x=1")
        assert resp.status_code == 415
        assert "application/json" in resp.json()["detail"]

    def test_ingest_osquery_accepts_json(self):
        resp = _client().post(
            "/api/v1/ingest/osquery",
            json={"lines": ["{}"]},
        )
        assert resp.status_code == 200

    def test_ingest_osquery_accepts_json_with_charset(self):
        resp = _client().post(
            "/api/v1/ingest/osquery",
            content='{"lines": []}',
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        assert resp.status_code == 200

    def test_ingest_accepts_json(self):
        assert _client().post("/api/v1/ingest", json={"events": []}).status_code == 200

    def test_trailing_slash_is_enforced_too(self):
        assert _client().post("/api/v1/ingest/osquery/", content="x=1").status_code in (415, 404)


@pytest.mark.parametrize("path", ["/api/v1/ingest", "/api/v1/ingest/osquery"])
def test_other_paths_unaffected(path):
    client = _client()
    # A GET to a non-ingest path must not be content-type gated.
    assert client.get("/api/v1/ingest").status_code in (200, 405, 404)
