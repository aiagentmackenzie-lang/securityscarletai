"""Purple-loop validation (V0.4 "Trusted Loop"): fire attack scenarios at
the live pipeline, wait for detection, and score the run against the
evidence-driven coverage map.

    python -m scripts.purple_loop --api http://127.0.0.1:8000 \
        --runs-dir runs --wait 240

What it does:
  1. Preflight: /health must answer and its build sha must match git HEAD
     (a stale image silently running old code is not a valid run).
  2. Snapshot detection coverage BEFORE (armed techniques per the
     coverage map -- rule-exists != telemetry-exists).
  3. Fire the V0.3 correlation matrix (one real event sequence per chain
     through its real pipe: osquery shipper, auth shipper, or ingest).
  4. Poll for alerts from the matrix hosts until the count is stable or
     the wait expires (scheduler ticks every 60s; honesty beats haste).
  5. Snapshot coverage AFTER; score the run:
       - chains fired (correlation matches or alerts per chain host)
       - distinct detection rules that fired
       - ATT&CK techniques hit by the run / total armed techniques
  6. Write runs/purple-<UTC>/report.json + report.md (the per-run
     coverage score a client or CI can consume) and print the summary.

Every assertion in the report is evidence-backed (DB rows), never
aspirational. Exit code: 0 when the run completed and scored, 1 on
preflight/pipeline failure, 2 when --fail-below is set and the chain
score is under it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from src.config.logging import get_logger

log = get_logger("scripts.purple_loop")

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = REPO_ROOT / "runs"


# ───────────────────────────────────────────────────────────────
# Pure scoring core (unit-testable without a DB or a stack)
# ───────────────────────────────────────────────────────────────


def compute_run_score(
    *,
    chains: dict[str, bool],
    fired_alerts: list[dict],
    coverage_after: dict,
    run_window_start: datetime,
) -> dict:
    """Pure: score one purple-loop run from its observed artifacts.

    chains: {chain_host_name: expected} -> observed (True = >=1 alert or
    correlation match in the run window).
    fired_alerts: alert rows (host_name, rule_name, mitre_techniques).
    coverage_after: the coverage-map payload.
    """
    chains_total = len(chains)
    chains_fired = sum(1 for ok in chains.values() if ok)

    fired_rules = sorted({a["rule_name"] for a in fired_alerts})
    techniques_hit: set[str] = set()
    for a in fired_alerts:
        techniques_hit.update(a.get("mitre_techniques") or [])

    armed_techniques = {
        t["technique"] for t in coverage_after.get("techniques", []) if t.get("armed_rules", 0) > 0
    }
    techniques_hit_armed = techniques_hit & armed_techniques
    techniques_missed = sorted(armed_techniques - techniques_hit)

    summary = coverage_after.get("summary", {})
    return {
        "chains_total": chains_total,
        "chains_fired": chains_fired,
        "chain_score": round(chains_fired / chains_total, 3) if chains_total else 0.0,
        "alerts_fired": len(fired_alerts),
        "distinct_rules_fired": len(fired_rules),
        "rules_fired": fired_rules,
        "techniques_hit": sorted(techniques_hit),
        "techniques_hit_armed": sorted(techniques_hit_armed),
        "armed_techniques_total": len(armed_techniques),
        "technique_hit_rate_armed": (
            round(len(techniques_hit_armed) / len(armed_techniques), 3) if armed_techniques else 0.0
        ),
        "armed_techniques_not_hit_by_this_run": techniques_missed,
        "coverage_summary": summary,
        "run_window_start": run_window_start.isoformat(),
    }


def render_report_md(score: dict) -> str:
    """Pure: render the markdown report from the score dict."""
    lines = [
        "# Purple-loop run report",
        "",
        f"- Run window start: {score['run_window_start']}",
        f"- Chains fired: **{score['chains_fired']}/{score['chains_total']}** "
        f"(score {score['chain_score']})",
        f"- Alerts fired: **{score['alerts_fired']}** "
        f"({score['distinct_rules_fired']} distinct rules)",
        f"- ATT&CK techniques hit: **{len(score['techniques_hit'])}** "
        f"({len(score['techniques_hit_armed'])} of them armed-technique hits; "
        f"hit rate over armed techniques: {score['technique_hit_rate_armed']})",
        f"- Coverage map: {score['coverage_summary'].get('armed', '?')} armed / "
        f"{score['coverage_summary'].get('total_rules', '?')} total rules "
        f"(lookback {score['coverage_summary'].get('lookback_hours', '?')}h)",
        "",
        "## Chains",
        "",
        "| Chain | Fired |",
        "|:--|:--|",
    ]
    for chain, ok in score["chains_detail"]:
        lines.append(f"| {chain} | {'YES' if ok else 'NO'} |")
    lines += [
        "",
        "## Rules that fired",
        "",
    ]
    lines += [f"- {r}" for r in score["rules_fired"]] or ["- (none)"]
    lines += [
        "",
        "## Armed techniques NOT hit by this run",
        "",
        "These chains/techniques did not participate in this run; they are",
        "not failures -- they are the rest of the coverage map.",
        "",
    ]
    lines += [f"- {t}" for t in score["armed_techniques_not_hit_by_this_run"]] or [
        "- (none: full armed coverage hit)"
    ]
    return "\n".join(lines) + "\n"


# ───────────────────────────────────────────────────────────────
# Live-fire plumbing
# ───────────────────────────────────────────────────────────────

CHAIN_HOSTS = [
    "live-matrix-brute_force_success",
    "live-matrix-persistence_activated",
    "live-matrix-privilege_escalation_chain",
    "live-matrix-credential_theft_exfil",
    "live-matrix-data_exfiltration",
    "live-matrix-payload_callback",
    "live-matrix-defense_evasion_cleanup",
    "live-matrix-ai_verdict_block_sustained",
]


async def _health(api: str) -> dict:
    import urllib.request

    req = urllib.request.Request(f"{api}/api/v1/health")  # noqa: S310
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        return cast("dict", json.loads(resp.read()))


def _head_sha() -> str:
    git = shutil.which("git")
    if not git:
        return "unknown"
    try:
        # S603 accepted: git resolved via which(), fixed argument list
        return subprocess.run(  # noqa: S603
            [git, "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"


async def _fetch_fired_alerts(window_start: datetime) -> list[dict]:
    from src.db.connection import get_pool

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, host_name, rule_name, severity, mitre_techniques, time
            FROM alerts
            WHERE host_name LIKE 'live-matrix-%' AND time >= $1::timestamptz
            ORDER BY time ASC
            """,
            window_start,
        )
    return [dict(r) for r in rows]


def _hosts_with_alerts(alerts: list[dict]) -> dict[str, bool]:
    hosts = {a["host_name"] for a in alerts}
    return {chain: chain in hosts for chain in CHAIN_HOSTS}


def _merge_chain_hosts(alert_hosts: set[str], match_hosts: set[str]) -> dict[str, bool]:
    """Pure: chain fired = an alert OR a persisted correlation match for the
    chain's matrix host inside the run window (see _fetch_chain_matches)."""
    fired = alert_hosts | match_hosts
    return {chain: chain in fired for chain in CHAIN_HOSTS}


async def _fetch_chain_matches(window_start: datetime) -> list[dict]:
    """Correlation matches for the matrix hosts persisted inside the run
    window. The docstring contract is "chains fired (correlation matches or
    alerts per chain host)" -- alert-only scoring breaks on the two
    documented interleave behaviors: the post-ingest correlation batch can
    race the shipper's last batch (match lands one pass later), and the
    alert-dedup window suppresses repeat Sigma alerts on matrix re-runs.
    Persisted matches are the tamper-evident chain-fired evidence; alerts
    remain the per-rule detail. Found live 2026-09-11 (V0.4/5 regression:
    7/8 by alerts, 8/8 by persisted matches -- the race, not a pipeline
    regression)."""
    from src.db.connection import get_pool

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, correlation_rule, severity, created_at,
                   match_data->>'host_name' AS host_name
            FROM correlation_matches
            WHERE created_at >= $1::timestamptz
              AND match_data->>'host_name' LIKE 'live-matrix-%'
            ORDER BY created_at ASC
            """,
            window_start,
        )
    return [dict(r) for r in rows]


def _write_report(runs_dir: Path, score: dict, fired_alerts: list[dict]) -> Path:
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / "report.json").write_text(
        json.dumps({**score, "alerts": fired_alerts}, indent=2, default=str)
    )
    md_path = runs_dir / "report.md"
    md_path.write_text(render_report_md(score))
    return md_path


async def run(mode: str, api: str, wait_seconds: int, fail_below: float, runs_dir: Path) -> int:
    # Preflight: stack up + right build (stale image = invalid run)
    try:
        health = await _health(api)
    except Exception as e:
        print(f"FAIL: stack not reachable at {api}: {e}")
        return 1
    build_sha = str(health.get("build", ""))
    head = _head_sha()
    if head != "unknown" and build_sha and head != build_sha:
        print(f"FAIL: /health build sha '{build_sha}' does not match git HEAD '{head}'")
        return 1
    print(f"Preflight OK: {health.get('status', '?')} build={build_sha}")

    from src.detection.coverage import compute_coverage

    window_start = datetime.now(tz=timezone.utc) - timedelta(minutes=2)

    print("Coverage snapshot BEFORE...")
    coverage_before = await compute_coverage()
    print(
        f"  armed {coverage_before['summary']['armed']}/"
        f"{coverage_before['summary']['total_rules']} rules"
    )

    if mode == "matrix":
        from scripts.generate_osquery_events import _env_api_bearer_token, run_matrix

        token = _env_api_bearer_token()
        if not token:
            print("FAIL: API_BEARER_TOKEN not found in .env (needed for the ingest chain)")
            return 1
        results_path = str(REPO_ROOT / "data" / "osquery" / "osqueryd.results.log")
        auth_path = str(REPO_ROOT / "data" / "osquery" / "auth_events.log")
        print("Firing the 8-chain correlation matrix through the real pipes...")
        rc = run_matrix(results_path, auth_path, api, token)
        if rc != 0:
            print(f"FAIL: matrix generation exited {rc}")
            return 1
    else:
        print(f"FAIL: unknown mode '{mode}' (supported: matrix)")
        return 1

    # Wait for detection (scheduler ticks every 60s) -- poll until stable
    print(f"Waiting for detection (up to {wait_seconds}s, polling every 10s)...")
    fired: list[dict] = []
    stable_polls = 0
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        await asyncio.sleep(10)
        current = await _fetch_fired_alerts(window_start)
        if len(current) == len(fired):
            stable_polls += 1
        else:
            stable_polls = 0
        fired = current
        if stable_polls >= 2 and fired:
            break
        if stable_polls >= 6 and not fired:
            break
    print(f"Observed {len(fired)} alerts on live-matrix-% hosts")

    print("Coverage snapshot AFTER...")
    coverage_after = await compute_coverage()
    print(
        f"  armed {coverage_after['summary']['armed']}/"
        f"{coverage_after['summary']['total_rules']} rules"
    )

    chain_matches = await _fetch_chain_matches(window_start)
    alert_hosts = {a["host_name"] for a in fired}
    match_hosts = {m["host_name"] for m in chain_matches if m.get("host_name")}
    chains = _merge_chain_hosts(alert_hosts, match_hosts)
    score = compute_run_score(
        chains=chains,
        fired_alerts=fired,
        coverage_after=coverage_after,
        run_window_start=window_start,
    )
    score["chains_detail"] = sorted(chains.items())
    score["chain_matches_persisted"] = len(chain_matches)
    score["match_hosts"] = sorted(match_hosts)
    score["mode"] = mode
    score["coverage_before"] = {
        "armed": coverage_before["summary"]["armed"],
        "total_rules": coverage_before["summary"]["total_rules"],
    }

    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = _write_report(runs_dir / f"purple-{stamp}", score, fired)

    print()
    print("PURPLE-LOOP RESULT")
    print(f"  chains fired      : {score['chains_fired']}/{score['chains_total']}")
    print(f"  alerts fired      : {score['alerts_fired']}")
    print(f"  distinct rules    : {score['distinct_rules_fired']}")
    print(
        f"  techniques hit    : {len(score['techniques_hit'])} "
        f"(armed hit rate {score['technique_hit_rate_armed']})"
    )
    print(f"  report            : {md_path}")

    if score["chain_score"] < fail_below:
        print(f"FAIL: chain score {score['chain_score']} below threshold {fail_below}")
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", default="matrix", choices=["matrix"])
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--wait", type=int, default=240, help="max seconds to wait for detection")
    parser.add_argument(
        "--fail-below",
        type=float,
        default=1.0,
        help="exit 2 if the chain score is under this (default: require all chains)",
    )
    args = parser.parse_args()
    return asyncio.run(run(args.mode, args.api.rstrip("/"), args.wait, args.fail_below, RUNS_DIR))


if __name__ == "__main__":
    raise SystemExit(main())
