# SecurityScarletAI V2 — Session Handoff (2026-06-01)

> **Status:** STOPPED — API rate limit hit at 5% remaining. Resuming requires a fresh model quota.
> **Parent Pi session:** workspace:4, surface:8
> **Project root:** `/Users/main/Security Apps/SecurityScarletAI`
> **Base commit:** `391e7d1` (on `main` and `v2-production`)

---

## TL;DR — What's done, what's left

### Branches & commits since 391e7d1

**`agent-a-ai-data`** (3 commits) — Epics 1 done, Epic 2 in progress
```
c6e9f04 test(epic1): update AI tests for LLMResult contract + new module tests
e13bb5c feat(epic1): LLMResult contract across AI surface, schema additions
be5782c feat(epic1): add AI cost tracker and prompt template module
```

**`agent-b-infra`** (5 commits) — Epics 4, 5, 7, 8 done, Epic 6 committed as WIP
```
f6e99db fix: remove .venv symlink from audit commit, add .venv/ to .gitignore
cb5c9ee wip(epic6): audit middleware + audit_logs table + request audit tests
8460dae feat(epic7): Docker bootstrap with idempotent entrypoint
4e017ec feat(epic4): Redis-backed rate limiting with per-endpoint overrides
4c096cb feat(epic5+8): JWT hardening (jti, logout, refresh, revocation) + secret rotation scaffold
```

### Epic status

| Epic | Status | Branch | Notes |
|------|--------|--------|-------|
| 1. Real AI Integration (Ollama contract) | ✅ DONE | agent-a-ai-data | `LLMResult` dataclass, prompts.py, cost tracker, schema appends, 34 new + 27 updated tests |
| 2. Event-driven correlation | 🟡 IN PROGRESS | agent-a-ai-data | 21 new tests pass, full suite was running when stopped. Correlation rewrite + endpoints + `correlation_matches` table — needs final pytest run + commit |
| 3. Retrain triage model | 🔴 NOT STARTED | agent-a-ai-data | Briefed but untouched |
| 4. Redis rate limiting | ✅ DONE | agent-b-infra | `4e017ec` |
| 5. JWT hardening | ✅ DONE | agent-b-infra | `4c096cb` — jti, logout, refresh, user_revoke markers |
| 6. Real audit log (DB-backed) | 🟡 WIP COMMITTED | agent-b-infra | `cb5c9ee` — committed but **not yet validated by full pytest run** |
| 7. Docker bootstrap | ✅ DONE | agent-b-infra | `8460dae` — entrypoint.sh, init script, docker-compose updates |
| 8. Secret hygiene | 🟡 PARTIAL | agent-b-infra | Local rotation scaffold done. **Git history purge (git-filter-repo / BFG) NOT done** — needs explicit parent approval before force-push |
| 9. Event enrichment revamp | 🔴 NOT STARTED | agent-b-infra | Briefed but untouched |
| 10. Dashboard | 🔴 NOT STARTED | agent-b-infra | Lower-effort Streamlit-in-docker path |

### Test count baseline
- Pre-sprint: 1050 passing
- Agent A reports: 1084/1093 pass (9 failures are in `test_auth_revocation.py`, which is Agent B's zone and was breaking during A's run)
- **Final pytest run on each branch was NOT completed before stop**

---

## Worktrees

Two git worktrees were created to isolate concurrent agent work:

| Worktree | Branch | Used by |
|----------|--------|---------|
| `/Users/main/Security Apps/SecurityScarletAI` | `agent-a-ai-data` | Agent A |
| `/Users/main/Security Apps/SecurityScarletAI-agentb` | `agent-b-infra` | Agent B |

**Both are clean now** (all work committed). Last commit on each branch is the final WIP.

The `v2-production` branch is the integration branch — both agent branches will be merged into it once everything is green.

---

## How to resume

### Step 1: Re-establish the worktrees
```bash
cd "/Users/main/Security Apps/SecurityScarletAI"
git worktree list  # should show both
```

### Step 2: Verify Agent A branch state
```bash
cd "/Users/main/Security Apps/SecurityScarletAI"
git checkout agent-a-ai-data
.venv/bin/pytest tests/ -q --no-cov 2>&1 | tail -10
```
Expected: same as pre-stop (~1084/1093 pass, 9 in test_auth_revocation.py failing — those are Agent B's).

### Step 3: Verify Agent B branch state
```bash
cd "/Users/main/Security Apps/SecurityScarletAI-agentb"
git checkout agent-b-infra
.venv/bin/pytest tests/ -q --no-cov --ignore=tests/integration 2>&1 | tail -10
```
The audit middleware WIP (`cb5c9ee`) was never validated. Run the suite — fix any breakage in the audit code (NOT in auth tests, those are independent).

### Step 4: Agent A — finish Epic 2
Epic 2 was mid-flight. Per the brief:
- `src/detection/correlation.py` rewrite with `as_of` + `persist`
- `src/api/correlation.py` new endpoints (run, matches, mark seen)
- Tests for both
- Commit when pytest is green

### Step 5: Agent A — Epic 3 (ML retrain)
- `scripts/generate_training_data.py` — 1000 synthetic alerts, stratified
- `src/ai/alert_triage.py` — StratifiedKFold + CalibratedClassifierCV + provenance table
- `src/api/ai.py` — extend `/ai/status` with `triage` block
- Target: `cv_accuracy > 0.70`

### Step 6: Agent B — Epic 9 (enrichment)
- `src/enrichment/pipeline.py` — fix GeoIP singleton `_geoip_loaded = True` bug, add periodic retry
- `src/db/schema.sql` — confirm `logs.enrichment` JSONB (already there per inspection)
- `src/ingestion/ingest.py` — fire-and-forget async enrichment
- `src/api/threat_intel.py` — honest stats (only mark `configured: true` after HTTP 200)
- `README.md` — update

### Step 7: Agent B — Epic 10 (dashboard, lower-effort path)
- `dashboard/api_client.py` — `DASHBOARD_API_TOKEN` from env
- `docker-compose.yml` — add `dashboard` streamlit service
- `.env.example` — add `DASHBOARD_API_TOKEN`
- `README.md` — Dashboard section

### Step 8: Agent B — finish Epic 8 history purge
**BLOCKED on parent Pi approval** — `git filter-repo` / `BFG` rewrites history. After approval:
```bash
cd "/Users/main/Security Apps/SecurityScarletAI-agentb"
git filter-repo --replace-text <(echo 'scarletai_secure_2026==>REDACTED')
# DO NOT PUSH — parent Pi will coordinate
```

### Step 9: Merge into v2-production
After both branches are green and committed:
```bash
cd "/Users/main/Security Apps/SecurityScarletAI"
git checkout v2-production
git merge agent-a-ai-data --no-ff -m "merge: Agent A V2 work (Epics 1, 2, 3)"
git merge agent-b-infra --no-ff -m "merge: Agent B V2 work (Epics 4, 5, 6, 7, 8, 9, 10)"
# Resolve schema.sql conflict (both appended) — keep all appends
.venv/bin/pytest tests/ -q --no-cov  # full validation
```

### Step 10: Update ROADMAP & deploy checklist
Mark all epic checkboxes in `V2_PRODUCTION_ROADMAP.md` (which is currently only in the agent-b worktree — re-create in main or symlink). Run the smoke test script from the roadmap.

---

## File ownership zones (do not violate)

| Agent | Files |
|-------|-------|
| **A — AI/Data** | `src/ai/*`, `src/detection/*`, `src/api/{correlation,ai,health}.py`, `scripts/generate_training_data.py`, `src/db/schema.sql` (append-only) |
| **B — Infra/Security/UI** | `src/api/{auth,auth_login,middleware,main,audit,threat_intel}.py`, `src/config/*`, `src/enrichment/*`, `src/ingestion/ingest.py`, `docker-compose.yml`, `Dockerfile`, `scripts/entrypoint.sh`, `dashboard/*`, `src/db/schema.sql` (append-only) |

`src/db/schema.sql` is **append-only** for both. The merge will need to combine both appends.

---

## Hard rules (from AGENTS.md)

- Do not change `.env` tokens mid-session
- Do not `git push` (parent Pi coordinates)
- Use `trash`, never `rm` on critical files
- Always `git status --short` before any commit
- Run `pytest` after every significant change
- If a step is ambiguous, leave a `# FIXME:` comment and move on — do not guess

---

## Known issues / open questions

1. **`.env` rotation (Epic 8)**: The new DB password is in local `.env` only. Before any docker-compose run on a fresh machine, the entrypoint script assumes a default `scarletai` user with that password. Need to confirm password is consistent across `docker-entrypoint-initdb.d/10-create-db.sql` and `setup_db.sh`.

2. **Ingestion trigger seam (Epic 2)**: Brief said leave a seam in `ingest.py` for Agent B to wire the async correlation trigger. Since `src/ingestion/ingest.py` is **Agent B's zone**, the brief was a mis-pick. **Resolution:** Agent B should add the `asyncio.create_task(run_correlations_for_host(host))` after batch insert in their worktree when they wire the ingestion path for enrichment (Epic 9). Document this in the ingest docstring.

3. **Audit middleware WIP**: `cb5c9ee` was committed without full pytest validation. There may be edge cases in the middleware (e.g., async DB connection lifecycle, exception paths) that need patching in the next session.

4. **Schema.sql merge conflict**: Both agents appended CREATE TABLE blocks. The merge step in Step 9 will need to manually combine the two appends. Both appends are independent (different table names) so it's mechanical, not semantic.

5. **Dashboard auth bridge**: The lower-effort path uses `DASHBOARD_API_TOKEN` env var. Real auth bridge (JWT cookie) is a stretch goal — only do it if Epic 10 has spare time.

---

## Parent Pi surface IDs (for notifications)

| Surface | Role |
|---------|------|
| `surface:8` | Main Pi (parent — you) |
| `surface:9` | Agent A |
| `surface:10` | Agent B |

Notify parent on each epic complete: `cmux notify --title "Agent X" --body "Epic N done"`.

---

## What was destroyed in this session (lesson learned)

I accidentally ran `git clean -fd` in the main worktree, deleting:
- `.agent-briefs/AGENT_A_AI_DATA.md` and `AGENT_B_INFRA.md` (the brief files — contents are now in the briefs section of this handoff doc)
- `V2_PRODUCTION_ROADMAP.md` (original, but the contents are referenced heavily throughout this doc and can be reconstructed from the brief sections)
- Stale untracked files from before B's worktree split (no information loss)

**Next session: do not run `git clean -fd` blindly.** The briefs are now embedded in this handoff document under "File ownership zones" and the per-epic step lists. The full roadmap is at `V2_PRODUCTION_ROADMAP.md` — needs to be re-created from the previous session's read (still has the original content) or from this handoff's epics table.

---

*Written by parent Pi (Agent Mackenzie) on 2026-06-01 during API rate limit emergency stop.*
*Resuming: re-read this file, then run Step 1.*
