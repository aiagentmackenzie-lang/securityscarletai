"""SigmaHQ import pipeline CLI (W2.1) — classify a local SigmaHQ rules
checkout into the honest import report; optionally stage the importable
subset. The import path NEVER touches the network: clone SigmaHQ yourself
(git clone --depth 1 https://github.com/SigmaHQ/sigma) and point --dir at
its rules directory.

Usage:
    poetry run python scripts/sigmahq_import.py \
        --dir /path/to/sigma/rules/windows \
        --report-dir /tmp/sigmahq_import \
        [--staging-dir /tmp/sigmahq_staging]

Outputs (never inside the repo unless asked):
    report.json  — machine-readable: counts + every candidate with reasons
    report.md    — the review artifact (the promote/arm decision table)
    staging/     — ONLY with --staging-dir: the imported rules, born
                   `enabled: false` + tagged source.sigmahq, OUTSIDE
                   rules/sigma/ so nothing auto-arms at boot.

Promote + arm an imported rule (explicit operator decisions):
    cp <staging>/<category>/<rule>.yml "rules/sigma/<category>/"   # promote
    # next boot: the reconciler inserts it DISABLED (enabled: false
    # frontmatter); arm via the rules API when you are ready — measurement
    # (the scorecard lifecycle) covers it from the moment it is in the DB.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.detection.sigmahq import (
    classify_directory,
    generate_report,
    report_markdown,
    write_staged_rules,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify a SigmaHQ rules checkout into the W2.1 import report."
    )
    parser.add_argument("--dir", required=True, help="SigmaHQ rules directory (cloned locally)")
    parser.add_argument("--report-dir", required=True, help="where report.json + report.md land")
    parser.add_argument(
        "--staging-dir",
        default=None,
        help="optional: also stage the IMPORTED rules here (born disabled, outside rules/sigma/)",
    )
    args = parser.parse_args(argv)

    try:
        verdicts = classify_directory(Path(args.dir))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    report = generate_report(verdicts)
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (report_dir / "report.md").write_text(report_markdown(report), encoding="utf-8")

    counts = report["counts"]
    print(
        f"SigmaHQ import report: {report['total']} candidates — "
        f"imported {counts['imported']} · needs-rewrite {counts['needs_rewrite']} · "
        f"unsupported {counts['unsupported']} (no silent drops)"
    )
    print(f"report: {report_dir / 'report.md'} (+ report.json)")

    if args.staging_dir:
        staged = write_staged_rules(verdicts, Path(args.staging_dir))
        print(f"staged: {staged} imported rule(s) under {args.staging_dir} (born disabled)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
