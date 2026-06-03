# Agent B — Debug Brief (2026-06-03)

**Role:** Lead Security Engineer (infra, API surface, response, enrichment, deployment).
**Workspace:** `workspace:1, surface:13` — labelled `Agent B (M3)`.
**Branch you are on:** `main` (working tree clean).
**Project root:** `/Users/main/Security Apps/SecurityScarletAI`
**Lead engineer (parent):** Main Pi in `pane:1` (left). Coordinate via `cmux notify` when done or blocked.

---

## Your scope — DO NOT touch files outside this list

**YOU OWN** (all read+write):
- `src/api/{auth,auth_login,middleware,main,audit,threat_intel,alerts,logs,websocket,rate_limit,redis_client,rules,cases,hunt}.py`
- `src/response/**`
- `src/enrichment/**`
- `src/config/**`
- `src/services/**`
- `Dockerfile`, `docker-compose.yml`, `scripts/entrypoint.sh`
- `dashboard/**`

**NEVER TOUCH** (Agent A's territory):
- `src/ai/**`
- `src/detection/**`
- `src/api/{correlation,ai,health,ingest,query}.py`
- `src/db/writer.py`
- `src/ingestion/**`
- `src/db/schema.sql` (A owns this)

**Coordination point:** `src/ai/prompts.py` is in A's territory. If your B4 cleanup finds an unused import there, **skip it** and notify parent — A will handle via A4.

**Inherited from Agent A (A5 was reassigned to you — test files are B's territory):**

### B7 — MEDIUM: Fix un-awaited coroutine RuntimeWarning
**Test:** `tests/unit/test_nl2sql.py::TestEstimateQueryCost::test_explain_failure_returns_zero`
**Symptom:** `RuntimeWarning: coroutine 'AsyncMockMixin._execute_mock_call' was never awaited` originating from `src/ai/nl2sql.py:556`.
**Action:** Read the test. Find the un-awaited coroutine mock. Either:
- Await the coroutine inside the assertion, OR
- Restructure the test so the async mock is consumed properly, OR
- If the test is asserting the un-awaited state is fine, use `pytest.warns` to assert the warning is emitted and the mock is closed.

Add a brief comment explaining the fix. Confirm by running `.venv/bin/pytest tests/unit/test_nl2sql.py::TestEstimateQueryCost -v --no-cov` and checking the warning is gone.

---

## Your task list (work top → bottom, commit per item)

### B1 — CRITICAL: Fix undefined `HTTPException` in `src/response/soar.py`
**File:** `src/response/soar.py` (lines 126, 134, 142)
**Bug:** Three methods raise `HTTPException(...)` but `HTTPException` is never imported. Would `NameError` at runtime.
**Fix:** Add `from fastapi import HTTPException` to the imports (top of file).
**Verify:** `.venv/bin/python -c "from src.response.soar import SOARPlaybook"` — must succeed without import error.

### B2 — CRITICAL: Resolve orphan SOAR module
**File:** `src/response/soar.py` and its relationship to `src/detection/alerts.py`
**Bug:** `src/response/soar.py` is defined and has `get_playbook_for_alert()` but **nothing in `src/` imports it**. The module is dead code.
**Decision tree:**
- **Option (a) — Wire it in** (recommended): In `src/detection/alerts.py`, when an alert is created with a matching rule, call `get_playbook_for_alert(alert)`, log the proposed actions, and queue auto-approved NOTIFY actions via the existing notification path. This is the "light touch" wiring — you do NOT need to make ISOLATE_HOST/DISABLE_USER/KILL_PROCESS work (those are correctly 501'd). Just wire the playbook creation + notification queueing.
- **Option (b) — Delete it** (only if option (a) is too invasive): remove `src/response/soar.py` and `src/response/__init__.py`. Update `BUG_CATALOG.md` to record the decision.

**Default:** Try option (a) first. If the alert code path is too tangled, fall back to (b) and document.

**Verify (option a):** Add a unit test in `tests/unit/test_soar_wiring.py` that mocks an alert, calls the alert creation path, and asserts `get_playbook_for_alert` was called and the notification was queued.

### B3 — HIGH: Run ruff auto-fix in your scope
**Command:** `.venv/bin/ruff check --fix src/api/ src/response/ src/enrichment/ src/config/ src/services/`
**Then:** `.venv/bin/ruff check src/api/ src/response/ src/enrichment/ src/config/ src/services/` — address remaining manually. Goal: zero errors in your territory.

### B4 — HIGH: Remove confirmed unused imports (B's files only)
**Files / lines (do these only):**
- `src/api/hunting_assistant.py:23` — `FALLBACK_MESSAGE` unused → drop from import
- `src/api/nl2sql.py:24` — `FALLBACK_MESSAGE` unused → drop from import
- `src/api/auth_login.py:22` — `require_role` unused → drop from import
- `src/api/auth_login.py:26` — `LIMIT_INGEST` unused → drop from import
- `src/api/rate_limit.py:18` — `logging` unused → drop from import

**SKIP** (A's territory): `src/ai/prompts.py:16` `typing.Any` — notify parent if you see it; A4 will handle.

**Verify:** `.venv/bin/ruff check src/api/ --select F401` after changes — must show 0 hits.

### B5 — MEDIUM: Add logging to bare `except Exception` in your scope
**Files / lines:**
- `src/api/middleware.py:58` — wrap with `log.exception(...)`
- `src/api/websocket.py:161` — wrap with `log.exception(...)`
- `src/enrichment/pipeline.py:102` — wrap with `log.exception(...)`

**Pattern:**
```python
except Exception as e:  # pragma: no cover — defensive
    log.exception("subsystem_failed", error=str(e))
```

### B6 — LOW: Cross-check `HOW_TO_USE.md` against current state
**Files:** `HOW_TO_USE.md` (last modified 2026-05-04), `README.md` (2026-06-02), `docker-compose.yml` (2026-06-02), `scripts/entrypoint.sh`.
**Action:** Read `HOW_TO_USE.md` end-to-end. For each command in it, verify it still works against the current code. If anything is stale, either:
- Edit `HOW_TO_USE.md` to match reality (preferred — single source of truth is `README.md` and the scripts themselves), OR
- If `HOW_TO_USE.md` is the canonical place and `README.md` is missing context, add a note to `README.md` pointing to it.

**Most likely stale items to check:** `pytest` baseline numbers, docker-compose service names, the `DB_PORT=5433` vs `5432` divergence between `.env` and `.env.example`.

**Output:** Either an updated `HOW_TO_USE.md` or a `HOW_TO_USE_REVIEW.md` note with the list of stale items + recommendations. No need to make every change — just surface them.

---

## Working protocol

1. **Before each commit:** `git status --short` to verify scope.
2. **After each significant change:** `.venv/bin/pytest tests/ -q --no-cov --tb=line` — full suite, not just yours. Must remain ≥ 1237 passing.
3. **Commit style:** `<type>(<scope>): <subject>` — e.g. `fix(soar): import HTTPException for 501 stubs`
4. **One commit per task** (B1..B7). Up to 7 commits expected.
5. **Notify parent on each:** `cmux notify --title "Agent B" --body "B1 done — HTTPException import fix committed"`
6. **If blocked:** notify parent and stop. Do NOT guess.

## Completion criteria
- All 7 tasks committed on `main`.
- `git log --oneline -10` shows your commits.
- `.venv/bin/pytest tests/ -q --no-cov` shows 1237+ passing, 0 failing.
- `.venv/bin/ruff check src/api/ src/response/ src/enrichment/ src/config/ src/services/` shows 0 errors.
- Notify parent: `cmux notify --title "Agent B" --body "All tasks done. Awaiting next brief."`

Start with B1 (critical, runtime-breaking). Go.
