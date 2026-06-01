"""
Tests for the Docker entrypoint (Epic 7).

Covers:
- scripts/entrypoint.sh exists and is executable
- bash syntax check passes
- The script references the right paths and Python modules

We don't actually run the entrypoint (that would require a live Postgres,
Redis, and a real training dataset). We just verify the script is well-formed
and contains the expected milestones.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "scripts" / "entrypoint.sh"


class TestEntrypointExists:
    def test_file_exists(self):
        assert ENTRYPOINT.exists(), f"{ENTRYPOINT} not found"

    def test_file_is_executable(self):
        mode = ENTRYPOINT.stat().st_mode
        assert mode & stat.S_IXUSR, "entrypoint.sh must be executable (chmod +x)"

    def test_syntax_valid(self):
        """`bash -n` parses the script without executing it."""
        result = subprocess.run(
            ["bash", "-n", str(ENTRYPOINT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"bash syntax error: {result.stderr}"


class TestEntrypointContents:
    @pytest.fixture(scope="class")
    def contents(self) -> str:
        return ENTRYPOINT.read_text()

    def test_waits_for_postgres(self, contents: str):
        # Either pg_isready or TCP probe must be present
        assert "pg_isready" in contents or "/dev/tcp" in contents

    def test_applies_schema(self, contents: str):
        assert "schema.sql" in contents

    def test_seeds_demo_data_conditionally(self, contents: str):
        assert "alerts" in contents
        assert "seed_demo_data" in contents

    def test_trains_triage_if_missing(self, contents: str):
        assert "triage_model" in contents
        assert "AlertTriageModel" in contents

    def test_trains_ueba_if_missing(self, contents: str):
        assert "ueba_model" in contents
        assert "UEBABaseline" in contents

    def test_creates_admin_if_no_users(self, contents: str):
        assert "siem_users" in contents
        assert "hash_password" in contents
        assert "secrets.token_urlsafe" in contents

    def test_execs_uvicorn_as_final_step(self, contents: str):
        # exec uvicorn must be the last step (so signals work)
        assert re.search(r"^exec uvicorn", contents, re.MULTILINE), (
            "entrypoint must end with `exec uvicorn ...`"
        )
        # And uvicorn must be the very last line (after the comment header)
        last_meaningful_lines = [
            l for l in contents.strip().splitlines() if not l.startswith("#")
        ]
        assert last_meaningful_lines[-1].startswith("exec uvicorn")

    def test_uses_set_e(self, contents: str):
        # Any failed step should halt the container
        assert "set -e" in contents

    def test_passes_unbuffered_env(self):
        # Dockerfile sets PYTHONUNBUFFERED=1, so Python prints appear in docker logs
        # immediately. Verify the Dockerfile actually sets it.
        dockerfile = (REPO_ROOT / "Dockerfile").read_text()
        assert "PYTHONUNBUFFERED" in dockerfile

    def test_dockerfile_uses_entrypoint(self):
        # The Dockerfile must reference the entrypoint as CMD
        dockerfile = (REPO_ROOT / "Dockerfile").read_text()
        assert "scripts/entrypoint.sh" in dockerfile

    def test_compose_wires_entrypoint(self):
        # docker-compose.yml must override CMD with the entrypoint
        compose = (REPO_ROOT / "docker-compose.yml").read_text()
        assert "scripts/entrypoint.sh" in compose


class TestEntrypointIdempotency:
    """Verify that the script handles the 'already-initialized' case correctly.

    The brief mandates that all bootstrap steps are idempotent. We don't
    actually run against a real DB, but we can verify the conditional logic
    by checking that the count checks use shell variables that compare to "0".
    """

    @pytest.fixture(scope="class")
    def contents(self) -> str:
        return ENTRYPOINT.read_text()

    def test_seed_only_if_alerts_empty(self, contents: str):
        # The script should only seed if COUNT = 0
        assert re.search(r"ALERT_COUNT.*=.*0", contents, re.DOTALL)

    def test_train_only_if_model_missing(self, contents: str):
        # Training gated on file existence with `if [ ! -f ... ]`
        assert "[ ! -f models/triage_model.joblib ]" in contents
        assert "[ ! -f models/ueba_model.joblib ]" in contents

    def test_admin_only_if_no_users(self, contents: str):
        assert re.search(r"USER_COUNT.*=.*0", contents, re.DOTALL)
