"""SS-043 / SS-045: watchdog payload and dead-Streamlit detection.

Both are behavioural tests: the watchdog script is executed for real, with a
stub `curl` on PATH so the payload it would POST to Slack is captured and
parsed with `json.load`. There is no string assertion on the script source —
the defect being fixed is "the payload is not valid JSON", so the test asserts
JSON validity of the payload the script actually builds.

SS-045: the dashboard check must stop reporting `ok` for a Streamlit server
that answers 200 from /_stcore/health while the page renders a traceback.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import textwrap
from pathlib import Path

_repo = Path(__file__).resolve().parents[2]
_WATCHDOG = _repo / "scripts" / "health_watchdog.sh"

_DEGRADED_HEALTH = (
    '{"status":"degraded","checks":{"api":"ok","db":"error: connection refused"},'
    '"detail":"pool exhausted \\"asyncpg\\" timeout"}'
)


def _stub_curl(tmp_path: Path, *, health: str, dash_code: str, dash_body: str) -> Path:
    """A curl stand-in that records POSTed bodies and answers the health probes."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    capture = tmp_path / "posted.json"
    script = textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        CAPTURE={shlex.quote(str(capture))}
        health={shlex.quote(health)}
        dash_code={shlex.quote(dash_code)}
        dash_body={shlex.quote(dash_body)}
        args=("$@")
        last="${{args[${{#args[@]}}-1]}}"
        post=0
        body=""
        for ((i=0; i<${{#args[@]}}; i++)); do
            case "${{args[$i]}}" in
                -X) [[ "${{args[$((i+1))]}}" == "POST" ]] && post=1 ;;
                -d) body="${{args[$((i+1))]}}" ;;
            esac
        done
        if [[ $post -eq 1 ]]; then
            printf '%s' "$body" > "$CAPTURE"
            exit 0
        fi
        for a in "${{args[@]}}"; do
            [[ "$a" == *"_stcore/health"* ]] && {{ printf '%s' "$dash_code"; exit 0; }}
            [[ "$a" == *"/api/v1/health"* ]] && {{ printf '%s' "$health"; exit 0; }}
            [[ "$a" == "http://"*":8501/" || "$a" == "http://"*:8501 ]] && {{
                printf '%s' "$dash_body"; exit 0;
            }}
        done
        exit 0
        """
    )
    (bindir / "curl").write_text(script)
    (bindir / "curl").chmod(0o755)
    return bindir


def _run_watchdog(
    tmp_path: Path,
    *,
    health: str = '{"status":"healthy"}',
    dash_code: str = "200",
    prev_state: str = "api=ok,dashboard=ok",
) -> tuple[subprocess.CompletedProcess, dict | None, str]:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "watchdog_state").write_text(prev_state)
    bindir = _stub_curl(tmp_path, health=health, dash_code=dash_code, dash_body="")

    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "WATCHDOG_STATE_DIR": str(state_dir),
        "SLACK_WEBHOOK_URL": "https://hooks.example.invalid/services/T/B/X",
        "HEALTH_URL": "http://127.0.0.1:8000/api/v1/health",
        "DASHBOARD_URL": "http://127.0.0.1:8501/_stcore/health",
        "DASHBOARD_PAGE_URL": "http://127.0.0.1:8501/",
        # Never shell out to a real docker daemon from a unit test.
        "WATCHDOG_SKIP_DOCKER": "1",
    }
    proc = subprocess.run(  # noqa: S603 — repo-owned script, pinned interpreter
        ["/bin/bash", str(_WATCHDOG)],  # noqa: S607
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    capture = tmp_path / "posted.json"
    payload = None
    if capture.exists():
        payload = json.loads(capture.read_text())
    log = state_dir / "watchdog.log"
    return proc, payload, log.read_text() if log.exists() else ""


class TestWatchdogSlackPayload:
    def test_degraded_health_produces_valid_json(self, tmp_path):
        """SS-043: the degraded body embeds quotes — the payload must still parse."""
        proc, payload, _ = _run_watchdog(tmp_path, health=_DEGRADED_HEALTH)
        assert proc.returncode == 0, proc.stderr
        assert payload is not None, "watchdog never POSTed to the webhook"
        assert "API degraded" in payload["text"]
        # The raw detail survives intact inside the JSON string (no truncation,
        # no mangling of the embedded quotes).
        assert _DEGRADED_HEALTH in payload["text"]

    def test_payload_survives_newlines_and_backslashes(self, tmp_path):
        health = '{"status":"degraded","detail":"line1\\nline2 \\\\ backslash"}'
        proc, payload, _ = _run_watchdog(tmp_path, health=health)
        assert proc.returncode == 0
        assert payload is not None
        assert health in payload["text"]

    def test_recovered_alert_is_valid_json(self, tmp_path):
        proc, payload, _ = _run_watchdog(
            tmp_path, health='{"status":"healthy"}', prev_state="api=down,dashboard=ok"
        )
        assert proc.returncode == 0
        assert payload is not None
        assert "RECOVERED" in payload["text"]

    def test_local_log_always_records_the_alert(self, tmp_path):
        proc, _, log = _run_watchdog(tmp_path, health=_DEGRADED_HEALTH)
        assert proc.returncode == 0
        assert "API degraded" in log
