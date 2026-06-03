# Agent A — Debug Brief (2026-06-03)

**Role:** Lead Security Engineer (data plane, AI, detection, ingestion).
**Workspace:** `workspace:1, surface:12` — labelled `Agent A (M3)`.
**Branch you are on:** `main` (working tree clean).
**Project root:** `/Users/main/Security Apps/SecurityScarletAI`
**Lead engineer (parent):** Main Pi in `pane:1` (left). Coordinate via `cmux notify` when done or blocked.

---

## Your scope — DO NOT touch files outside this list

**YOU OWN** (all read+write):
- `src/ai/**`
- `src/detection/**`
- `src/api/{correlation,ai,health,ingest,query}.py`
- `src/db/writer.py`
- `src/ingestion/**`

**SHARED** (coordinate via parent before editing):
- `src/db/schema.sql` (append-only — do not modify unless you have a migration story)

**NEVER TOUCH** (Agent B's territory):
- `src/api/{auth,auth_login,middleware,main,audit,threat_intel,alerts,logs,websocket,rate_limit,redis_client,rules,cases,hunt}.py`
- `src/response/**`
- `src/enrichment/**`
- `src/config/**`
- `src/services/**`
- `Dockerfile`, `docker-compose.yml`, `scripts/entrypoint.sh`
- `dashboard/**`
- `tests/**` — write your own tests inside your own scope, do NOT edit existing test files owned by B unless absolutely required.

---

## Your task list (work top → bottom, commit per item)

### A1 — CRITICAL: Fix `run_all_correlations` parameter mismatch
**File:** `src/api/ingest.py` (line 128)
**Bug:** `await run_all_correlations(persist_alerts=True)` — but the new function signature is `run_all_correlations(as_of, persist)`. The legacy `run_all_correlations_legacy` takes `persist_alerts`. This would `TypeError` on every ingest.
**Fix:** Change `persist_alerts=True` → `persist=True` in the call inside `_enrich_and_correlate()`.
**Verify:** Grep confirms no other call site uses `persist_alerts=`. Run `.venv/bin/pytest tests/unit/test_correlation_event_driven.py tests/unit/test_correlation_api.py -q --no-cov` — must still pass.

### A2 — HIGH: Remove stale `# FIXME(agent-b)` and update docstring
**File:** `src/detection/correlation.py` (lines ~715-720)
**Bug:** The docstring says "left as a TODO for Agent B" and the comment says "FIXME(agent-b): wire into the batch-insert success path in `src/db/writer.py`". The actual wiring lives in `src/api/ingest.py` (not writer.py), and it's already done — the docstring/comment is stale.
**Fix:** Update the docstring + remove the FIXME to accurately describe: the trigger is in `src/api/ingest.py:_enrich_and_correlate()` after the batch write, and it uses the `persist=True` flag (per the new contract from Epic 2).

### A3 — HIGH: Verify `correlation_id` is emitted per match
**File:** `src/detection/correlation.py` — the `run_all_correlations` and the rule detection functions
**Bug check:** The docstring at line 700-712 promises: "matches: list of match dicts (each with correlation_id)". Verify each `detect_*` function (lines 60-690 range) and the loop that builds `all_matches` actually assigns a unique `correlation_id` (UUID) per match. If missing, add it.
**Verify:** Grep the file for `correlation_id` to see what gets set and where. If not set, add `d["correlation_id"] = str(uuid.uuid4())` inside the rule-builder block.

### A4 — LOW: Run ruff auto-fix in your scope
**Command:** `.venv/bin/ruff check --fix src/ai/ src/detection/ src/db/ src/ingestion/`
**Then:** `.venv/bin/ruff check src/ai/ src/detection/ src/db/ src/ingestion/` and address any remaining issues manually. Goal: zero errors in your territory.

### ~~A5~~ — REASSIGNED to Agent B (test file is B's territory)

> **2026-06-03 orchestrator decision:** A5 was reassigned to B because the file `tests/unit/test_nl2sql.py` is in B's test-ownership scope. A5 → B7 (now in `AGENT_B_DEBUG_2026-06-03.md`).
>
> Agent A now has **4 tasks total** (A1, A2, A3, A4).

---

## Working protocol

1. **Before each commit:** `git status --short` to verify scope.
2. **After each significant change:** `.venv/bin/pytest tests/ -q --no-cov --tb=line` — full suite, not just yours. Must remain ≥ 1237 passing.
3. **Commit style:** `<type>(<scope>): <subject>` — e.g. `fix(ingest): correct run_all_correlations parameter name`
4. **One commit per task** (A1, A2, A3, A4). Four commits total expected.
5. **Notify parent on each:** `cmux notify --title "Agent A" --body "A1 done — run_all_correlations fix committed"`
6. **If blocked:** notify parent and stop. Do NOT guess.

## Completion criteria
- All 4 tasks committed on `main`.
- `git log --oneline -10` shows your commits.
- `.venv/bin/pytest tests/ -q --no-cov` shows 1237+ passing, 0 failing.
- `.venv/bin/ruff check src/ai/ src/detection/ src/db/ src/ingestion/` shows 0 errors.
- Notify parent: `cmux notify --title "Agent A" --body "All tasks done. Awaiting next brief."`

Start with A1 (critical, runtime-breaking). Go.
