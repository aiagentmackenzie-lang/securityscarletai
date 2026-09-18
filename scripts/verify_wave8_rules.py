#!/usr/bin/env python3
"""Wave 8 gate: backtest + coverage + scorecard verification for the changed rules.

Run from the repo root with the API's env (reads .env via settings). Read-only:
run_backtest / compute_coverage / compute_rule_scorecard never write.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detection.backtest import run_backtest  # noqa: E402
from src.detection.coverage import compute_coverage
from src.detection.scorecard import compute_rule_scorecard

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "sigma"

CHANGED = [
    ("network/c2_beaconing.yml", "AUD-076"),
    ("authentication/login_unusual_geography.yml", "AUD-077"),
    ("network/data_exfiltration_volume.yml", "AUD-077"),
    ("network/pass_the_hash_smb.yml", "AUD-078"),
    ("network/dns_tunneling.yml", "AUD-081"),
    ("process/suspicious_tmp_process.yml", "AUD-079a"),
    ("process/scp_sftp_rsync_transfer.yml", "AUD-079b"),
]


async def main() -> int:
    failures: list[str] = []
    print("=== BACKTEST (window 168h, real stored logs) ===")
    for rel, finding in CHANGED:
        yaml_text = (RULES_DIR / rel).read_text()
        report = await run_backtest(yaml_text, window_hours=168)
        res = report["results"]
        comp = report["compilation"]
        unmeasured = report.get("unmeasured_reasons")
        print(
            f"{finding:8s} {rel:44s} measured={res['measured']} "
            f"rows={res['total_rows']} est_alerts={res['estimated_alerts']} "
            f"agg={comp['aggregation']} group_by={comp['group_by']} "
            f"warn={comp['warnings'] or '-'}"
        )
        if comp["warnings"]:
            failures.append(f"{rel}: compile warnings {comp['warnings']}")
        if not res["measured"]:
            failures.append(f"{rel}: unmeasured ({unmeasured})")
        if rel == "network/c2_beaconing.yml" and comp["group_by"] != "destination_ip":
            failures.append("c2 backtest compiled group_by != destination_ip")
        if rel == "network/c2_beaconing.yml":
            top = res["top_values"].get("destination_ip") or []
            print(f"           c2 over-threshold destinations: {top[:5]}")

    print("=== compute_coverage (168h) ===")
    cov = await compute_coverage(lookback_hours=168)
    s = cov["summary"]
    print(f"rules={s['total_rules']} armed={s['armed']} dormant={s['dormant']}")
    for entry in cov["rules"]:
        if entry["kind"] != "sigma":
            continue
        name = entry["name"]
        if name in (
            "C2 Beaconing Pattern",
            "Login from Unusual Geography",
            "Data Exfiltration Volume",
            "Pass-the-Hash SMB Authentication",
            "Suspicious Process from /tmp",
            "SCP/SFTP/Rsync File Transfer Execution",
            "DNS Activity Indicator (port 53)",
        ):
            print(f"  {name:44s} armed={entry['armed']} reason={entry['reason'] or '-'}")
    names = {r["name"] for r in cov["rules"]}
    for gone in ("NTLM Relay Attempt", "Suspicious DNS Query"):
        if gone in names:
            failures.append(f"coverage still lists deleted rule: {gone}")

    print("=== compute_rule_scorecard (720h) ===")
    sc = await compute_rule_scorecard(window_hours=720)
    print(
        f"rules={sc['summary']['total_rules']} "
        f"retirement_candidates={sc['summary']['retirement_candidates']}"
    )
    for r in sc["rules"]:
        if r["name"] in (
            "Pass-the-Hash SMB Authentication",
            "C2 Beaconing Pattern",
            "Suspicious Process from /tmp",
            "SCP/SFTP/Rsync File Transfer Execution",
            "DNS Activity Indicator (port 53)",
        ):
            print(
                f"  {r['name']:44s} fires={r['lifetime_fires']} "
                f"matcher={r['matcher_hits_lifetime']} age={r.get('age_days')}"
            )

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(" -", f)
        return 1
    print("\nWave 8 verification gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
