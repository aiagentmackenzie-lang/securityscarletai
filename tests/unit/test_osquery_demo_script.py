"""AUD-071: run_osquery_demo.sh must not hide schema-apply failures.

The old schema step piped BOTH legs to /dev/null (stdout+stderr 2>&1),
chained a silenced docker-compose fallback, printed "Schema applied."
unconditionally, and ran psql WITHOUT ON_ERROR_STOP=1 (psql exits 0 on
per-statement errors by default) — a failed apply marched the demo into
unexplained downstream failures. These pins keep the gate honest.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_repo = Path(__file__).resolve().parents[2]
_SCRIPT = _repo / "scripts" / "run_osquery_demo.sh"


@pytest.fixture(scope="module")
def contents() -> str:
    return _SCRIPT.read_text()


class TestOsqueryDemoSchemaGate:
    def test_syntax_valid(self):
        result = subprocess.run(  # noqa: S603 — pinned binary, repo-owned path
            ["/bin/bash", "-n", str(_SCRIPT)],  # noqa: S607
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"bash syntax error: {result.stderr}"

    def test_schema_apply_uses_on_error_stop(self, contents: str):
        # Without ON_ERROR_STOP=1, psql exits 0 even when statements fail.
        # Split on the ECHO lines (not the bare phrase — the comment above the
        # block also mentions "Schema applied.").
        schema_section = contents.split('echo "🗄️ Applying', 1)[1].split(
            'echo "   Schema applied."', 1
        )[0]
        assert "-v ON_ERROR_STOP=1" in schema_section

    def test_schema_apply_stderr_is_visible(self, contents: str):
        # The old shape silenced both legs: `>/dev/null 2>&1` on the psql call.
        # psql's error output must reach the operator's terminal.
        schema_section = contents.split('echo "🗄️ Applying', 1)[1].split(
            'echo "   Schema applied."', 1
        )[0]
        # Comment text may mention 2>&1; only the psql invocation lines matter.
        for line in schema_section.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            assert "2>&1" not in stripped, f"silenced psql leg is the AUD-071 bug: {stripped!r}"

    def test_failed_apply_aborts_the_demo(self, contents: str):
        assert "Schema apply FAILED" in contents
        # The abort must exit non-zero: the demo must not march on.
        fail_idx = contents.index("Schema apply FAILED")
        exit_idx = contents.index("exit 1", fail_idx)
        applied_idx = contents.index('echo "   Schema applied."')
        assert exit_idx < applied_idx, (
            "the abort must be reachable BEFORE the 'Schema applied.' echo"
        )

    def test_applied_echo_only_after_success_check(self, contents: str):
        # Structure: the success echo must come after the failure branch of the
        # schema-apply if-block, never as an unconditional statement before it.
        apply_start = contents.index("ON_ERROR_STOP=1")
        applied_idx = contents.index('echo "   Schema applied."')
        assert applied_idx > apply_start
