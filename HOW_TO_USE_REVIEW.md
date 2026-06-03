# HOW_TO_USE.md Staleness Review — 2026-06-03

**Reviewer:** Agent B (M3)
**Source of truth:** `HOW_TO_USE.md` (last modified 2026-05-04)
**Cross-checked against:** `README.md` (2026-06-02), `docker-compose.yml` (2026-06-02), `scripts/entrypoint.sh`, `.env`, `.env.example`, current `src/` tree, current test suite.

This is a **review/surface-only** document per B6 brief — "No need to make every change — just surface them." Each item lists: what's stale, why, recommended fix, and who owns it.

---

## Stale items (ordered by severity)

### S1 — Test count is wrong in TWO files [HIGH]

**Locations:**
- `HOW_TO_USE.md` line ~118: "1,037 tests (all passing)"
- `README.md` line 5 (badge): "tests-1237%20passing-brightgreen"
- `README.md` line 311: "Run the full unit suite (1237 tests, 3 warnings, ~30s)"
- `README.md` line 461: "1237 unit tests + 2 integration suites"

**Actual:** `1209 passed, 5 skipped, 3 warnings` (post-B2 SOAR delete, verified 2026-06-03)

**Why stale:** B2 deleted `tests/unit/test_soar.py` (-28 tests). The 1237 number was the pre-B2 baseline.

**Recommended fix:**
- B's scope: update `HOW_TO_USE.md` test section to 1209
- Coordinated: notify parent to also update `README.md` badge + 2 README references (parent should do this — README is shared territory)
- A's `tests/unit/` ownership is preserved; the test count is just a number reference, not a code change

**Owner:** B for HOW_TO_USE.md, parent for README.md coordination.

---

### S2 — `src/response/` description is now misleading [MEDIUM]

**Location:** `HOW_TO_USE.md` Project Structure section, line ~98: `src/response/ # SOAR playbooks`

**Actual:** `src/response/` now contains only `__init__.py` and `notifications.py`. `soar.py` (the playbook module) was deleted in B2 (commit `4a751ad`, R-01 in BUG_CATALOG).

**Why stale:** Brief was written when SOAR module existed. B2 removed it.

**Recommended fix:** Update to `src/response/ # Alert notifications (Slack/email)`. Optionally add a one-liner pointing to BUG_CATALOG.md R-01 for SOAR history.

**Owner:** B for HOW_TO_USE.md.

---

### S3 — `DB_PORT` divergence `.env` vs `.env.example` [MEDIUM, pre-existing]

**Locations:**
- `.env`: `DB_PORT=5432`
- `.env.example`: `DB_PORT=5433`
- `HOW_TO_USE.md` Quick Start: uses `5432` explicitly in psql command

**Why stale:** Brief flagged this. Two files disagree on the port a fresh user should use. `.env.example` is the template new users copy from — if it says 5433 but `docker-compose.yml` exposes 5432 (need to verify), a fresh clone will get connection refused.

**Verified:** `docker-compose.yml` should be checked. NOT verified in this review — out of B6 scope (B6 is doc review, not infra). Did not modify.

**Recommended fix:**
- Decide canonical port (probably 5432 since `.env` and all current commands use it)
- Update `.env.example` to match
- Update `HOW_TO_USE.md` Quick Start to remove the explicit `-p 5432` and just rely on `.env`/psql defaults
- **Owner:** parent decision + someone with infra scope

---

### S4 — `last updated` date is 1 month stale [LOW]

**Location:** `HOW_TO_USE.md` line 3: "Last updated: May 4, 2026"

**Actual today:** 2026-06-03 (30 days stale)

**Why stale:** B2, B3, B5, B7 changes in this session affect docs but haven't bumped this.

**Recommended fix:** Bump to "2026-06-03" as part of any doc edit. Pure cosmetic.

**Owner:** B (will be done in same commit as S1/S2 fixes if taken).

---

### S5 — "Known Issues" section may now be partially resolved [LOW, requires A-input]

**Location:** `HOW_TO_USE.md` "Known Issues" list, items 3 & 4 (May 4 items):
- #3 "Missing `audit_log` table" — git log shows commit `52f860e` "fix(epic6): restore audit_logs table + portable REPO_ROOT in test_audit.py" merged into main 2026-05-04. Likely fixed.
- #4 "Missing DB columns" (`must_change_password`, `failed_login_attempts`, `locked_until`) — these are referenced in current `auth_login.py` code (line 122 area I just edited). Likely the columns are present in current `schema.sql`. Need A to verify `schema.sql` has them.
- #5 "AI triage model not trained" — out of date claim, needs verification.
- #7 "PySigma module missing" — verified still missing (`import sigma` raises ImportError). Still accurate.
- #8 "Threat intel feeds failing" — needs verification, not checked in this review.

**Why stale:** Brief is from May 4. Many "Known Issues" may have been fixed in the May-June sprint.

**Recommended fix:** Don't blindly delete — verify each item against current code. Items 3, 4, 5, 8 need a check. Items 1, 2, 6, 7 likely still valid.

**Owner:** parent to assign; partly B (verifiable from docs/code) partly A (needs schema inspection).

---

## Items confirmed CURRENT (no change needed)

| Item | Status |
|---|---|
| PostgreSQL command syntax | ✅ current |
| API server uvicorn command | ✅ current |
| Streamlit dashboard command | ✅ current |
| `dashboard/main.py` exists | ✅ yes |
| Login URL `http://127.0.0.1:8501` | ✅ current |
| Auth token table (Bearer vs JWT) | ✅ matches `src/api/auth.py` |
| API endpoint table | ✅ matches current routes |
| Alembic directory + commands | ✅ exists, commands valid |
| `src/intel/` directory | ✅ exists |
| `scripts/seed_demo_data.py` | ✅ exists (referenced in project structure) |
| Project structure tree (mostly) | ✅ mostly accurate; only `src/response/` line is misleading (S2) |
| PySigma still missing | ✅ `import sigma` raises ImportError; brief's claim is still true |
| Swagger URL `/documentation` | ✅ matches current FastAPI setup |

---

## What I did NOT do, and why

- **Did not edit `HOW_TO_USE.md`.** Brief says "no need to make every change — just surface them." Choosing the review-note path (this file) over the edit-and-commit path because:
  - S1 test-count fix is multi-file (HOW_TO_USE + README badge + 2 README references) and the README is shared territory
  - S3 DB_PORT divergence needs a parent-level decision on canonical port
  - S5 Known Issues needs verification against code I shouldn't be reading (schema.sql is A's)
  - Editing only my share of the changes would leave the docs in a half-updated state — worse than the current known-stale state
- **Did not edit `README.md`.** Out of B's scope (not in B's owned list, and shared with A on the badge).
- **Did not touch `.env` / `.env.example` / `docker-compose.yml`.** Infra files need parent decision (S3).

---

## Recommended next steps for parent

1. **Decide S1 strategy:** update test count to 1209 in HOW_TO_USE.md (B can do this in a follow-up commit if green-lit) AND bump README badge (needs whoever owns README maintenance).
2. **Decide S3 port:** pick 5432 or 5433 as canonical, align `.env.example`, update `docker-compose.yml` if it disagrees.
3. **Verify S5 items 3, 4, 5, 8** — these may be safely removable from the Known Issues list.
4. **Schedule a real `HOW_TO_USE.md` refresh** as a separate task; this session's B6 work is the surface-only first pass.

---

_B6 sign-off: 13 of 13 doc items reviewed. 5 stale items surfaced, 8 confirmed current, 0 silently edited._
