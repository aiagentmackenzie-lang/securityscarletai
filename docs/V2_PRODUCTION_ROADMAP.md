# V2 Production Roadmap

> **Status as of 2026-06-02** — post-Epic-10, both agent worktrees active.
> This file was reconstructed from `SESSION_HANDOFF.md` after the
> previous session's `git clean -fd` incident destroyed the original.
> Update in-place as the sprint progresses.

## Sprint goal

Ship the V2 production hardening pass: AI integration with real LLM contract,
event-driven correlation, infra hardening (rate limiting, JWT, audit, secrets,
Docker, dashboard), and enrichment revamp. Both agent worktrees converge into
the `v2-production` branch at the end.

## Branches

| Branch | Worktree | Owner | Purpose |
|--------|----------|-------|---------|
| `agent-a-ai-data` | `/Users/main/Security Apps/SecurityScarletAI` | Agent A | AI integration, event-driven correlation, ML retrain |
| `agent-b-infra` | `/Users/main/Security Apps/SecurityScarletAI-agentb` | Agent B | Infra, security hardening, UI, deployment |
| `v2-production` | (merge target) | Parent Pi | Integration branch, post-merge |
| `main` | — | — | Pre-sprint baseline (`391e7d1`) |

## Epic status (post-Epic-10)

| # | Epic | Status | Branch | Commit | Notes |
|---|------|--------|--------|--------|-------|
| 1 | Real AI Integration (Ollama contract) | ✅ DONE | agent-a-ai-data | `e13bb5c` + `be5782c` | `LLMResult` dataclass, prompts.py, cost tracker, schema appends |
| 2 | Event-driven correlation | ✅ DONE | agent-a-ai-data | `72d88ff` + `78d0a54` | `as_of`, `persist` contract, endpoints, tests |
| 3 | Retrain triage model | 🔴 NOT STARTED | agent-a-ai-data | — | StratifiedKFold + CalibratedClassifierCV; `cv_accuracy > 0.70` |
| 4 | Redis rate limiting | ✅ DONE | agent-b-infra | `4e017ec` | Per-endpoint overrides, slowapi-backed |
| 5 | JWT hardening | ✅ DONE | agent-b-infra | `4c096cb` | jti, logout, refresh, user_revoke markers |
| 6 | Real audit log (DB-backed) | ✅ DONE | agent-b-infra | `cb5c9ee` | `audit_logs` table + middleware + 47 tests (1105 pass on its own) |
| 7 | Docker bootstrap | ✅ DONE | agent-b-infra | `8460dae` | Idempotent entrypoint.sh, schema + seed + train |
| 8 | Secret hygiene | ✅ DONE (rotated only) | agent-b-infra | `4c096cb` + `09184fb` | Local rotation done; `filter-repo` history purge **explicitly SKIPPED** per parent Pi decision 2026-06-02 (Option B). See `scripts/entrypoint.sh` NOTE. |
| 9 | Event enrichment revamp | ✅ DONE | agent-b-infra | `2dda60b` | GeoIP singleton retry fix, async ingest seam, honest threat-intel stats (`ok`/`error`/`no_key`/`never_refreshed`) |
| 10 | Dashboard | ✅ DONE | agent-b-infra | `b0ffb0f` | Streamlit-in-docker, `DASHBOARD_API_TOKEN` for service-to-service auth |

**Agent B epics 4–10: complete.** Only Agent A's Epic 3 (ML triage retrain) remains.

## Test count

| Stage | Pass | Skip | Fail | Notes |
|-------|------|------|------|-------|
| Pre-sprint baseline | 1050 | — | 0 | Commit `391e7d1` |
| Agent B current (post-Epic-10) | **1114** | 5 | **0** | branch `agent-b-infra` HEAD `b0ffb0f` |
| Agent A reported (pre-stop) | 1084 | — | 9 | All 9 failures in `test_auth_revocation.py` (Agent B's zone; resolved since) |

**+64 net tests** added by Agent B (47 audit + 4 GeoIP retry + 5 dashboard
token + 8 across threat-intel/enrichment test updates).

## File ownership zones

| Agent | Files |
|-------|-------|
| **A — AI/Data** | `src/ai/*`, `src/detection/*`, `src/api/{correlation,ai,health}.py`, `scripts/generate_training_data.py`, `src/db/schema.sql` (append-only) |
| **B — Infra/Security/UI** | `src/api/{auth,auth_login,middleware,main,audit,threat_intel,ingest}.py`, `src/config/*`, `src/enrichment/*`, `src/ingestion/*`, `src/intel/*`, `docker-compose.yml`, `Dockerfile`, `scripts/entrypoint.sh`, `dashboard/*`, `src/db/schema.sql` (append-only) |

`src/db/schema.sql` is **append-only** for both. The merge will need to
manually combine both appends (mechanical, since both appends use
different table names — no semantic conflict).

## Ingestion trigger seam (Epic 2 + Epic 9 wiring)

Briefed in Epic 2, wired in Epic 9 by Agent B (who owns `src/api/ingest.py`):

```python
# src/api/ingest.py — fire-and-forget post-batch
asyncio.create_task(_enrich_and_correlate())
```

Inside the task:
- `enrich_event_dict(...)` for each event in the batch (Agent B's enrichment).
- `run_all_correlations(persist_alerts=True)` (Agent A's correlation engine,
  called by name from B's zone — Agent A owns the function, B owns the call).

This was originally noted as an ownership ambiguity in SESSION_HANDOFF.md
"Known issues" #2; resolved cleanly because the **call site is in Agent B's
file** and the **function being called is Agent A's public API**.

## Open work (post-sprint)

- **Agent A — Epic 3**: ML triage retrain with stratified k-fold + calibrated
  classifier. Target `cv_accuracy > 0.70`. After completion, both branches
  merge into `v2-production`.
- **Schema.sql merge**: combine both agents' appends during merge commit.
  Both appends use different table names (`audit_logs` is B's, AI/correlation
  tables are A's) so it's mechanical, not semantic.
- **Smoke test**: run the deployment smoke test from `docs/DEPLOYMENT.md`
  against a fresh `docker compose up` after the merge.

## Reconstructed from

- `SESSION_HANDOFF.md` (epics table, file ownership zones, known issues)
- `docs/DEPLOYMENT.md` (smoke test reference, env var table)
- `git log` on `agent-b-infra` HEAD `b0ffb0f`

*Last updated: 2026-06-02 by Agent B after Epic 10 commit.*
