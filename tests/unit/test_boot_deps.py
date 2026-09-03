"""
Slim-image boot dependencies (2026-09-03 regression contract).

The Phase C slim Dockerfile removed the build toolchain and took
postgresql-client (psql/pg_isready) and curl with it. The entrypoint applies
the schema via `psql -f src/db/schema.sql` (statement-by-statement with
ON_ERROR_STOP=1 — see the P0-05 note in scripts/entrypoint.sh for why
asyncpg's single implicit-transaction execute is NOT equivalent), so the API
crash-looped on boot with `psql: command not found` while the CI
certification (`docker build` + `import ok`) stayed green. The compose
healthchecks had the same hole via curl.

The REAL gate for this class of bug is the CI `build` job's "Boot the real
entrypoint against a live Postgres" step (boot path, not import path). These
tests pin the cheap surface contracts so an accidental re-introduction is
caught before CI even builds:

- the runtime image must install postgresql-client (psql is a runtime
  requirement, not build tooling),
- no compose healthcheck may shell out to curl.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
COMPOSE = REPO_ROOT / "docker-compose.yml"
ENTRYPOINT = REPO_ROOT / "scripts" / "entrypoint.sh"


class TestRuntimeImageBootDeps:
    def test_dockerfile_installs_postgresql_client(self):
        contents = DOCKERFILE.read_text()
        assert re.search(r"apt-get install -y --no-install-recommends postgresql-client", contents), (
            "slim image must ship postgresql-client: entrypoint.sh applies schema via "
            "`psql -f` (ON_ERROR_STOP, statement-by-statement) and waits via pg_isready"
        )

    def test_entrypoint_schema_apply_uses_psql(self):
        contents = ENTRYPOINT.read_text()
        assert "psql" in contents, "entrypoint schema-apply contract drifted"
        assert "ON_ERROR_STOP=1" in contents


class TestComposeHealthchecksCurlFree:
    def test_no_curl_in_compose_healthchecks(self):
        contents = COMPOSE.read_text()
        # Comments may legitimately mention curl (regression history) — only
        # the executable probe lines matter.
        code_lines = [
            ln for ln in contents.splitlines() if not ln.lstrip().startswith("#")
        ]
        healthcheck_blocks = re.findall(
            r"healthcheck:.*?(?=\n    \w|\Z)", "\n".join(code_lines), flags=re.DOTALL
        )
        assert healthcheck_blocks, "compose has no healthchecks to protect"
        for block in healthcheck_blocks:
            assert "curl" not in block, (
                "compose healthcheck shells out to curl, which is not in the slim "
                "runtime image — use a python -c urllib probe (curl vanished with "
                "the Phase C toolchain and made healthy containers report unhealthy)"
            )

    def test_api_healthcheck_probes_v1_health(self):
        contents = COMPOSE.read_text()
        assert "/api/v1/health" in contents
