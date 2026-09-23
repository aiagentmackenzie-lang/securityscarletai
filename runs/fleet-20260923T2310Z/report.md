# Fleet Live-Fire Wave F — full parallel test of ALL running apps

- Run window: 2026-09-23 22:25–23:15 UTC (19:25–20:15 GMT-3)
- Operator: Pi session (fresh, Wave F handoff)
- Fleet: 8 containers healthy on colima **4 CPU / 8 GiB** — ScarletAI api/mcp/dashboard/db/redis @ 342bc44 (one sha) + NeuralGuard app/postgres/redis @ 95c827a + NeuralStrike v1.0.0 (venv, host Ollama)
- Host: M4 Pro, 48 GiB RAM, osqueryd root LaunchDaemon feeding the SIEM
- This is a FINDING wave: no code fixed; fixes queued for Raphael's approval.

## T0 — fleet state gate (PASS, independently verified)

| Check | Result |
|---|---|
| Containers | 8/8 healthy (both stacks) |
| colima | 4 CPU / 8 GiB (docker info) |
| Git | ScarletAI 342bc44=origin clean · NG 95c827a=origin (only untracked override) · NS 2664aa2=origin clean |
| Build sha | `/health` build=342bc44 == git HEAD |
| Shipper | checkpoint == file size EXACT (25,680,770 B at start; EXACT again at close on 30,299,020 B) |
| Posture | docs 404 · metrics 401/200 · redis NOAUTH/PONG · audit-grants strict exit 0 · Timescale logs retention 30d |
| ollama | mistral:7b standing 100% GPU; inventory matches (mistral-7b-capped present, purpose = NS victim cap workaround, NOT deleted) |
| Handoff corrections | NG fleet port is **:8010** (handoff said :8100) · NG judge is **phi4-mini** (post-lineup state, override-verified in running container) |

## T1 — integration matrix (the parallel core)

| # | Feed | Status | Receipt |
|---|---|---|---|
| a | osqueryd → ScarletAI (file pipe) | **LIVE** | checkpoint==size EXACT at start AND close; alerts from real telemetry all session |
| a | labeled event via NO-SUDO ingest POST | **LIVE** | 1 labeled line → 202 in 21.7 ms → **3 Sigma alerts in ~45s** on the labeled host (Reverse Shell critical / Download-and-Execute high / Script-Interpreter medium) |
| b | NS in-process vs NG fixture | **LIVE** | **4/8 EXACT** — per-payload verdicts match the 2026-09-20 receipt with zero drift |
| c | NS → fleet NG :8010 | **LIVE** | **6/8 EXACT** vs the prior-session live bench; audit rows on record (tenant demo: 6 block + 2 allow); judge+semantic engaged (exploit payloads that pass the fixture arm are caught live) |
| c | NG tenant attribution | **PARTIAL** | NG records its KEY's tenant (`demo`); run-unique tenants impossible without a registered key (FT-002); NS-side attribution works via run-stamped hosts |
| d | NG → ScarletAI verdict bridge | **MISSING** | NEURALGUARD_SIEM_* absent in .env AND running container; zero `source=neuralguard` rows from today (only stale 2026-09-05 verify rows); wiring proposal ready (HITL) |
| e | `neuralstrike purple-report` | **LIVE** | Loop closes: caught/gap per payload, gap list AC-WEAP-002 + AC-POST-002; `scarlet.firewall_events={}` honestly records the bridge gap |
| f | PARALLEL TEST | **PASS** | 600 osquery events ingested (20–28 ms/150-batch) WHILE NS attacked NG (6/8) WHILE all three queried live — every probe ≤6 ms except one 1.0 s NG health spike during an active judge-scan (single, recovered); resources flat; ScarletAI producer rules fired on the exercise ("NeuralStrike Probe Succeeded Against Deployed Controls", "C2 Beaconing Pattern", "Data Exfiltration Volume") |

**T1c false-start disclosure:** the first fleet run reported "8/8 caught (100%)" — that was **8× auth 403s** (`tenant_mismatch`, raised pre-evaluation by `_check_tenant_binding`), not firewall blocks. The bench maps any 403 to "block" (FT-001). The corrected run (verbatim credential) is the real 6/8 with audit rows.

## T2 — model run-through

Benchmark (`scripts/model_benchmark.py`, 2 runs/case, local only):

| model | agreement | validity | explain | prod_sla | lat_v | lat_e | quality |
|---|---|---|---|---|---|---|---|
| mistral:7b (incumbent) | 0 | 0.75 | 1 | 1 | 8751ms | 5656ms | **0.35** |
| mistral-7b-capped | 0 | 0.75 | 1 | 1 | 9592ms | 6061ms | 0.35 |
| **phi4-mini** | 0.75 | 1 | 0.5 | 1 | **5870ms** | **2817ms** | **0.75** |
| qwen3.5:9b | 0 | 0 | 0 | 0 | — | — | 0.0 (empty) |
| qwen3.5:2b | 0 | 0 | 0 | 0 | — | — | 0.0 (empty) |
| qwen3.5:9b + `--think-false` | **1** | **1** | **1** | **1** | 12518ms | 6596ms | **1.0** |
| qwen3.5:2b + `--think-false` | 0 | 0.75 | 1 | 1 | 6894ms | 2930ms | 0.35 |

- Standing model NOT switched (mistral:7b re-confirmed working; live chat 3.97 s, audited 854/99 tokens).
- **phi4-mini dominates the incumbent on every measured axis** except explain (0.5 vs 1.0): +agreement, +validity, 33% faster, 43% smaller. Swap = Raphael's call.
- qwen3.5 empty-response class = thinking-model budget exhaustion (documented 2026-09-13 finding); with think:false, 9b is PERFECT but slow.
- NG judge (phi4-mini) verified in the running container; verdict latency: allows avg **81 ms** (judge skipped), blocks avg **601 ms** (max 3.6 s with judge engaged) — inside the 20 s timeout.
- NS: judge-model-list ✓ (nemotron 30b reachable); `evaluate` 2-trial on phi4-mini → **ASR 0%, resisted×2, coverage 100%**.
- ai_usage audit: API-path calls recorded (row on record for the live chat); benchmark script logs tokens to logs but writes NO ai_usage rows (FT-007).
- Eviction: benchmark cycling unloaded everything except mistral (keep-alive reset to ~5 min by non-ScarletAI requests — the 4h timer only survives on ScarletAI's own path) (FT-006).

## T3 — buyer walkthrough

**NeuralGuard :8010 (production v0.2.1, all 5 layers green):**
- benign → **allow 31 ms** · pattern injection → **block 403**
- canary: mint (4 session tokens) → output leak via /v1/scan/output → **block 403 T-EXT** (doctrine: canaries trip on LEAK, not input)
- agent guardian: single-turn prose correctly allows; 3-turn accumulation in one request → **block 403 T-PI-D** (garden-path injection)
- fail-closed: malformed prompt → 422; `/v1/auth/token` → honest 404 "JWT auth is not enabled"
- /v1/info (OWASP coverage) 200 · metrics 401/200
**NeuralStrike:** smoke 3 scenarios coverage 100% exit 0 · evaluate receipts · dashboard "NeuralStrike Results Viewer" serving real app
**ScarletAI (spot-verify per plan):** RT-001 evidence-pack 200 · RT-002 rules detail 200 · RT-003 CSV export 200 · dashboard body real, 0 exceptions

## T4 — limits + resource ceiling

| Limit | Configured | Observed |
|---|---|---|
| ScarletAI login | 5/min | **5×401 → 429 at #6** |
| ScarletAI /ingest | 100/min | **98×202 → 429 at #99** |
| ScarletAI MCP | 30/5min | **30×200 → 429 at #31** |
| ScarletAI /ingest batch cap | 1000 | **1000→202, 1001→413 "Maximum 1000 events per batch"** |
| /ingest/osquery lines cap | 2000 | 1001→202 (cap is 2000; 999/1000/1001 all accepted) |
| Body cap | 1 MB | 2 MB single event → **413** |
| Field caps | 4096 cmdline | oversized → **422** |
| NG rate limit | 60 RPM + burst 10 (redis) | **69×200 → 429 at #70** |

**RESOURCE CEILING — policy-bound, not resource-bound:** under the maximum load the stacks ACCEPT (ramp L1→L3: up to 8 ingest workers × 200-event batches + 4 concurrent NG evaluators + continuous API queries), ScarletAI reads stayed **p50 4 ms**, ingest p50 128 ms, NG evaluates 48–121 ms — the rate limiters engaged BEFORE any resource degradation (the honest ceiling). Memory flat across the whole session (api 236→243 MiB; NG app **772.5 MiB / 75.4% of 1 GiB flat through load**), 8/8 healthy, zero restarts, host 59% free, recovery immediate. NG's 1 GiB headroom stays thin at idle (pre-existing finding; Raphael's call).

## T5 — smoke tests

- ScarletAI: /health healthy (build 342bc44, db ok, ollama ok) · docs 404 · metrics 401/200 · redis NOAUTH/PONG · **audit-grants --strict exit 0** (append-only held) · Timescale logs retention 30d
- NeuralGuard: /v1/health production, all 5 layers true
- NeuralStrike: smoke 3 scenarios, coverage 100%, exit 0

## T6 — FLEET FINDINGS LEDGER

| # | Sev | App | What happened | Receipt | Proposed fix | Queue |
|---|---|---|---|---|---|---|
| FT-001 | **P1** | NeuralStrike | `neuralguard-bench` counts auth/tenant-mismatch 403s as firewall blocks → false "8/8 (100%)" receipt. NG raises 403 pre-evaluation for a valid key + mismatched tenant (`_check_tenant_binding`); the bench maps any non-200 to "block" without reading the body | T1c attempt 1: 8×403 in NG logs, ZERO audit rows, no scanner logs; corrected run = real 6/8 | bench must read the 403 body (`error: tenant_mismatch` vs verdict) and count auth failures separately | FIX (NS, branch+pin) |
| FT-002 | P2 | NeuralGuard | Tenant binding makes run-unique NS tenants impossible: any body `tenant_id` ≠ the key's bound tenant → 403 pre-eval. The "tenant_id=neuralstrike-<runid>" contract cannot work via the credential form — tenant is bound at key registration | routes.py:90-101; corrected T1c run under tenant=demo | Register per-run keys (env change = HITL) OR accept fixed-tenant NG attribution + NS-side run attribution (already works) | DECISION |
| FT-003 | **P1-proposal** | NeuralGuard→ScarletAI | The verdict bridge is UNCONFIGURED: NEURALGUARD_SIEM_* absent (file + running container); zero source=neuralguard rows from today; purple-report's `scarlet.firewall_events={}` | grep receipts + /logs queries | Wire: NEURALGUARD_SIEM_ENABLED=true, NEURALGUARD_SIEM_SCARLETAI_URL=http://host.docker.internal:8000/api/v1/ingest, NEURALGUARD_SIEM_SCARLETAI_TOKEN=<INGEST_BEARER_TOKEN> + container recreate — **HITL ask, standing now** | HITL |
| FT-004 | P2 | Fleet models | qwen3.5 (9b+2b) return EMPTY responses without `think:false` on every benchmark case; with it, 9b scores 1.0 (12.5 s verdict) | T2 tables (both runs) | Any path that may select qwen must pass think:false; NG judge.py still lacks the opt-in knob (prior finding, still queued) | QUEUE |
| FT-005 | P3 | NeuralGuard | .env has duplicate NEURALGUARD_RATELIMIT_BACKEND lines (L18 memory, L29 redis — last wins; container runs redis) | .env lines 18/29 | Dedupe the .env line | Hygiene |
| FT-006 | P3 | Ops | Non-ScarletAI Ollama requests reset the standing model's 4h keep-alive to ~5 min (benchmark left mistral at "2 minutes from now") | ollama ps before/after benchmark | Ops note: re-touch ScarletAI chat (or set keep_alive) after model benchmarking | Ops note |
| FT-007 | P3-low | ScarletAI | Benchmark script logs tokens but writes no ai_usage rows (script-path; same class as RT-005) | ai_usage has zero benchmark rows; benchmark log shows token counts | Optional: wire record_usage into the harness | Nit |
| FT-008 | P3-low | NeuralGuard | Single 1.0 s /v1/health spike during a concurrent evaluate+scan (single-worker event loop contention); recovered next probe; not reproduced | T1f probes.log 22:39:45 | None needed (observe only) | Logged |
| FT-009 | P2 (pre-existing) | NeuralGuard | App container at **75.4% of 1 GiB at idle**, flat through L1–L3 load (no growth, no leak evidence at these loads) — but headroom is thin; OOM-first-casualty risk under heavier load stands | docker stats all session | Limit raise (NG compose change) or leak hunt = Raphael's call | HITL |
| FT-010 | — (positive) | Fleet | The ceiling is POLICY-bound: rate limiters engage before resource saturation at operator-scale load; latency flat; recovery immediate | T4 ramp receipts + stats-pre/post | None — guardrails work as designed | Receipt |

**Pre-existing open items carried (unchanged):** action #7 (quarantine probe) approve/reject · 1.03 GB rotated telemetry replay-or-discard · livefire_viewer/analyst deactivation (hygiene) · NG override file commit proposal (verified matching the running containers this session: judge phi4-mini, semantic/guardian/canary env all present in the container) · shipper bounded-read code fix (queued since the OOM incident).

## T7 — closeout

- No code changed on any repo this session. Evidence committed under `runs/fleet-20260923T2310Z/` on a LOCAL branch (no push without Raphael).
- NG docker-compose.override.yml remains untracked; verified matching the running container this session; commit proposal standing (HITL).
- Synthetic test telemetry (labeled hosts: livefire-fleet-*, ft-parallel-*, ft-ceiling-*, ft-limits, neuralstrike-* run hosts) is INTENTIONAL purple-telemetry — left in the DB (bounded, ~2,500 events).
- Rate-limit cooldowns used during testing (login/ingest/MCP/NG) all expired; no lasting state. No destructive actions taken.