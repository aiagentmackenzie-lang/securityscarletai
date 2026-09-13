# MODEL_BENCHMARK — V0.6c "Model currency" (2026-09-13)

**Question:** is `mistral:7b` — the default local model since 2026-08-26 —
still the right default in 2026, or does a challenger win on
quality-per-RAM with a clean license?

**Answer: KEEP `mistral:7b`.** It wins the deployable-quality composite
(0.85 vs the best challenger's 0.70) with a 1.00 production-SLA rate and
1.00 contract validity. The challenger with the best quality-per-GB
(phi4-mini, 0.241) fails the production JSON contracts (0.25 validity) —
it matches the incumbent on *which answer* it picks but cannot reliably
*serve the contract*, so it is not deployable for the verdict task without
prompt hardening. No default swap on this evidence.

## Method

- **Tasks = the SIEM's own production AI tasks** (the purple-loop task set):
  1. *Verdict drafts* — the investigator's `VERDICT_SYSTEM_PROMPT`,
     temperature 0.0, max_tokens 700 (the exact production invocation)
     over a 4-case known-answer corpus: reverse shell → `true_positive`,
     brute-force-to-success → `true_positive`, nightly backup job →
     `benign`, health-check loop → `benign`. 2 runs per case.
  2. *Triage explanations* — the versioned alert-explanation prompt
     renderer + system prompt over 2 alert shapes (reverse shell,
     brute force). 2 runs per case.
- **Real path:** `src.ai.ollama_client.query_llm` with
  `settings.ollama_model` swapped per candidate — the same call the API
  and agents make. The only production difference: the `ai_usage`
  persistence step is skipped (a benchmark must not pollute standing
  telemetry).
- **Robustness step** (needed by any model swap): strip `<think>`
  blocks, extract the first balanced JSON object.
- **Scoring:** `verdict_agreement` (parsed verdict == known answer),
  `contract_validity` (JSON parses to the closed verdict contract),
  `explanation_ok` (source=ollama AND grounded — mentions ≥1 concrete
  entity from the alert), `prod_sla_ok` (call completed under the
  production 30 s `ollama_timeout`), latency, model size.
- **Composite (advisory):** quality = 0.6·agreement + 0.2·validity +
  0.2·explanation_ok; quality_per_gb = quality / size_gb.

## Results (2026-09-13, Ollama 0.34.0, runs/model-benchmark-20260913T*)

| model | size_gb | agreement | validity | explain | prod_sla | quality | q_per_gb |
|---|---|---|---|---|---|---|---|
| **mistral:7b (incumbent, default)** | 4.37 | **0.75** | **1.00** | **1.00** | **1.00** | **0.85** | 0.195 |
| phi4-mini | 2.49 | 0.75 | 0.25 | 0.50 | 1.00 | 0.60 | **0.241** |
| qwen3.5:2b (think=false) | 2.74 | 0.25 | 1.00 | 1.00 | 1.00 | 0.55 | 0.201 |
| qwen3.5:9b (think=false) | 6.59 | 0.50 | 1.00 | 1.00 | 0.92 | 0.70 | 0.106 |

## The `thinking`-model finding (live, 2026-09-13)

The Qwen3.5-family models (and any thinking-capable family) return their
reasoning in Ollama's separate `thinking` field; with the default mode the
`response` text stays **empty** until the thinking phase exhausts the token
budget — the SIEM's JSON contracts receive nothing (both qwen3.5 models
scored 0.0 across the board in the default-mode runs,
`model-benchmark-20260913T153537Z`). This is a production-integration
finding, not a benchmark artifact: the same empty-response behavior would
hit every real caller.

Fix shipped with this phase: `query_llm` gains an opt-in `think` parameter
(None = model default; False = disable the thinking phase so the contracts
get the full budget). The configured-candidate runs above use
`think=false`. Unit-tested in `test_ai_ollama_contract.py::TestThinkParameter`.

## Caveats (honest scope)

- **N is small**: 8 verdict calls + 4 explanation calls per candidate. This
  is a *screening* benchmark on a hand-built known-answer corpus (the
  purple-loop shapes) — it disqualifies models that break the contract or
  the SLA; it does not statistically prove superiority. The purple loop
  remains the deeper harness for whatever model is deployed.
- **phi4-mini's failure mode** (contract validity 0.25): its verdict JSON
  is frequently malformed or missing required keys even when the verdict
  value itself is right. Plausible fix: stronger format instruction in a
  candidate-specific prompt — a future re-benchmark item, NOT a reason to
  swap today.
- **qwen3.5:9b's prod_sla 0.92**: one call exceeded the production 30 s
  ceiling even with thinking disabled — the 9B is borderline on this
  machine and 2× the incumbent's size for less agreement.
- Latency figures are warm-model, single-machine (Apple Silicon via
  Ollama); absolute numbers vary by host, relative ordering is the signal.
- Licenses: mistral:7b (Apache-2.0), phi4-mini (MIT), Qwen3.5 (Apache-2.0)
  — all clean per the plan's preference; license was not the deciding
  factor this round.

## Decision + follow-ups

- **Default stays `mistral:7b`** (settings.py + .env.example unchanged) —
  the reviewed decision with the scorecard above attached. No silent swap.
- Re-benchmark triggers: (a) prompt-hardening for phi4-mini's contract
  compliance, (b) new incumbent generations (the model policy is
  "purple-loop-benchmarked", not vendored), (c) any production timeout
  regression on the standing host.
- Benchmark harness: `scripts/model_benchmark.py` (runnable re-runs:
  `python -m scripts.model_benchmark --models ... --runs-per-case 2`).
  Artifacts: `runs/model-benchmark-*/results.json` + `table.md`.