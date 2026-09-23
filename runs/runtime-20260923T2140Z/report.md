# Runtime Wave E — live-fire purple test of the production stack

- Run window: 2026-09-23 21:09–21:50 UTC (18:09–18:50 GMT-3)
- Operator: Pi session (fresh, Wave E handoff from the review/boot sessions)
- Stack: 5 containers @ 97550bf, colima/Docker 29.5.2, one sha across api/mcp/dashboard
- Repo at run start: main = origin/main = 97550bf (tag v0.9.0 → 8a4a04f, two commits behind HEAD)
- Full suite at close: **2,598 passed / 0 failed / exit 0 / coverage 88.29%** (CI command re-run, PIPESTATUS 0)

## T0 — state gate (all green, independently verified)

| Check | Result |
|---|---|
| 5 containers healthy | ✅ api / dashboard / mcp / db / redis |
| `/api/v1/health` build | 97550bf == HEAD == all image revision labels |
| `/api/docs` | 404 |
| `/api/v1/metrics` | 401 no-token · 200 with METRICS_BEARER_TOKEN |
| Redis | NOAUTH unauth · PONG with password |
| `check_audit_grants --strict` (app-role scarletai_app) | exit 0 |
| Timescale logs retention | drop_after = 30 days == LOGS_RETENTION_DAYS (re-verified) |
| osqueryd | root LaunchDaemon PID 607, system domain, user agent properly booted out |
| mistral:7b | 100% GPU, 32768 ctx, keep-alive 4h, health ollama ok |
| results log | 4,771,312 B at start, root:staff 644, growing; 1.03 GB rotated file preserved |
| api memory baseline | 146.5 MiB / 1 GiB (14.3%) |

## T1 — auth + session (the pending W5-A test)

**Confirmed: `/auth/refresh` had ZERO rows ever** before this session (first production refresh
happened below). Test users created via the sanctioned admin API (static bearer, P2.6 path):
`livefire_viewer` (viewer) + `livefire_analyst` (analyst) — created 201 → first-login 403
(must-change gate) → force-change 200 → login 200 with rotated-pair shape.

| Test | Result | Receipt |
|---|---|---|
| must-change flow (both live + mine) | ✅ | audit rows 248–260 (Raphael's own 20:59:05 + mine) |
| RBAC viewer: read 200 / write 403 | ✅ | /alerts 200, /cases 200, POST /rules 403, GET /users 403 |
| RBAC analyst → admin-only 403 | ✅ | GET+POST /users 403; POST /response/actions/7/approve 403 |
| static-admin identity 200 | ✅ | GET /users 200 (api-client) |
| Login rate limit | ✅ | 5×401 then 429 `{"error":"rate_limited","retry_after":60}` (rows 267–272) |
| Logout → presented refresh token reuse | ✅ | 401 "Refresh token has been revoked" (W1-D, row 266) |
| Access token jti blocklist after logout | ✅ | 401 |
| **15-min TTL expiry → 401** | ✅ | ta (exp 21:26:29Z) → 401 at 21:27:14Z |
| **/auth/refresh FIRST-EVER 200 in prod** | ✅ | row 291 at 21:19:10Z; rotated pair (jti rotated, type correct) |
| Old refresh token single-use | ✅ | reuse → 401 |
| Session continues after refresh | ✅ | refreshed access → 200 |

- **Session durability (dashboard force-recreate): NOT EXECUTED — HITL.** Raphael was logged in
  during the window (audit row 280, 21:16:29Z via the dashboard container). The event already
  occurred naturally at 21:02:48Z (unified rebuild): his pre-rebuild session died, fresh login at
  21:03:17Z (172.18.0.6). Audit-trail reconstruction is the receipt; the deliberate replay awaits
  his go. Pending design decision (browser-side refresh vs server-side) unchanged — documented, not implemented.
- Browser-side 16-min idle test: remains Raphael's (API-layer equivalent fully proven above).

## T2 — detection live-fire (purple core)

**10/10 chains — the full correlation matrix fires on today's stack.**
Report: `runs/purple-20260923T211901Z/` (repo tooling, stamp 211901Z).

- 47 alerts · 27 distinct rules · 16 ATT&CK techniques · armed hit rate 0.39 · coverage 102/130 armed
- vs 2026-09-18 baseline (10/10, 28 alerts, 25 rules, 16 techniques, 0.381): no regression, more volume
- Method disclosure: OSQUERY-targeted chains POSTed raw lines to `/api/v1/ingest/osquery` (server-side
  `parse_osquery_line` — same ECS truth as the shipper) because the results log is root-owned 644
  since the 07:00 daemon reboot (RT-008). AUTH chains rode the REAL auth-shipper file pipe
  (auth_events.log, user-owned). ai_verdict chain POSTed `/ingest` as designed.
- Run 1 (stamp 211544) crashed mid-fire on a DRIVER bug (wrong JSON envelope for /ingest — my error,
  422; disclosed). Run 2 used a fresh stamp and re-fired everything cleanly.
- 84 alerts in the last 90 min · 1,208 correlation matches in 90 min · no P0 — no chain lost vs baseline.

## T3 — AI feature pass (models warm)

| Call | Result | Latency | ai_usage |
|---|---|---|---|
| POST /ai/chat | 200, context_used=true | **6.68s** (baseline 7.9s) | ✅ tokens_in 860 / out 268 / 6670ms / user attributed |
| POST /ai/explain/1036 | 200, ai_generated=true, mistral:7b | **5.40s** | ✅ 764 / 183 / 5387ms |
| POST /ai/triage/1036 | 200 true_positive @ 0.91 | 46ms (ML) | n/a (ML, not LLM) |
| /query template path | 200, 8–10ms, correct canned SQL | — | n/a |
| /query LLM path | 2/3 failures (RT-004) | 1.8–3.1s | ❌ no rows (RT-005) |
| MCP investigate | 200, full agent run (5,613 chars) | **29.1s** (just under flag threshold) | run recorded |
| model benchmark harness | SKIPPED (optional; standing model re-confirmed by the latency receipts above; no switch) | — | — |

## T4 — feature walkthrough (buyer-facing surface)

- **Alerts**: detail/notes/list ✅ (note author-attributed); labels: no manual label CRUD exists —
  `alert_labels` is written by the ML triage provenance pipeline only; analyst labeling = notes + status.
- **Case lifecycle** (case #3): create+inline-link → W4-B guard **409 "unlink it first"** (live-verified)
  → verdict 200 → gated close (400 without lessons_learned → 200 with) → full timeline vocabulary ✅
- **Evidence pack**: **500 on every call (RT-001, P1)** — the W4-C truncation flags sit behind a dead endpoint.
- **Response actions**: notify_slack → policy allow → immediate execute → honest fail ("unconfigured
  webhook"); quarantine_host probe → policy `approval_required` → status `requested`, nothing executed —
  **HITL gate holds; action #7 left pending for Raphael (approve or reject)**. Analyst approve → 403 (admin-only).
- **Rules CRUD**: list 124 ✅ · **create/GET-detail/PATCH all 500 (RT-002, P1)** · delete 204 (probe cleaned up).
- **/decisions since/until**: unfiltered 200 + windowed 200 (3 items) — W4-D pushdown live-verified.
- **Exports/suppressions bounds**: csv/stix hours=721 → 422, stats hours=8761 → 422, over-limit
  suppression rule_name → 422 — W4-G/H live-verified. CSV export hours=24 → **500 (RT-003, P1)**.
- **Compliance/frameworks 200 · coverage 200 · hunt templates + gaps 200** ✅
- **Scheduled reports + notification channels**: no API surface (YAML-configured internal services);
  runtime fail-closed verified — `channels: []`, `schedules: []` loaded, nothing sends, slack
  fail-loud warnings observed.
- **MCP**: unauth `/healthz` → booleans only (W3-C live) · `/mcp` without token → 401 JSON-RPC error ·
  `tools/list` → 3 tools (investigate, hunt, explain) · `investigate` full agent run OK (29.1s).

## T5 — runtime seam checks

- api memory 146.5 → 149.2 MiB across the whole pass (no OOM-class growth); all containers 1GiB/512MiB/512MiB bounded, no restarts, 5/5 healthy end-to-end.
- Shipper: checkpoint == file size exactly (9,347,212 B at close; 4,771,312 at start) — zero lag, +4.5 MB real telemetry ingested during the pass.
- Dashboard: page body asserts the real app (Streamlit markers, no Exception/ValidationError), 0 exceptions in container logs — dead-app class clear.

## T6 — RUNTIME FINDINGS LEDGER

| # | Sev | Component | What happened | Receipt | Proposed fix | Disposition |
|---|---|---|---|---|---|---|
| RT-001 | **P1** | compliance evidence pack | GET /compliance/incidents/{id}/evidence-pack → 500 on EVERY call: `KeyError: 'notes'` (evidence.py:126 reads alerts.notes; the SELECT never fetched it — jsonb column exists, populated on 539/539 rows; born broken v0.7 ee49e8e 2026-09-14, tests mock the seam) | api traceback + 500 repro'd twice | add `notes` to the SELECT + FAIL-proof pin exercising the real SQL shape | QUEUE (one-line + pin) |
| RT-002 | **P1** | rules CRUD | POST /rules, GET /rules/{id}, PATCH /rules/{id} → 500: `ResponseValidationError` — RuleResponse types run_interval/lookback `str` (d9f447a 2026-08-22 P1-15) but get_rule_by_id serializes only datetimes → raw timedelta reaches the model; INSERT commits before the 500 (my probe rule 4565 was created, then deleted) | api traceback; GET+PATCH repro'd; list works via from_row | serialize intervals in get_rule_by_id (or route detail routes through from_row) | QUEUE |
| RT-003 | **P1** | alerts export | GET /alerts/export/csv → 500 at hours=24: `ValueError: dict contains fields not in fieldnames: 'description','status','id','rule_name'` — CSV writer fieldnames don't match row keys | api traceback + 500 repro | align CSV fieldnames with the exported dict | QUEUE |
| RT-004 | P2 | NL→SQL LLM path | Non-template questions: 2/3 attempts fail (validation "got UNKNOWN"; hallucinated `logs.alert_id`; 3rd returned 0 rows from a guessed `normalized` JSONB shape presented as success). Template path solid. Errors honest/fail-closed. | saved request/response receipts in session log | schema-context improvement OR honest "best-effort beyond templates" doc; do NOT switch standing model on this evidence | QUEUE (decision) |
| RT-005 | P2-low | ai_usage accounting | /query LLM calls never call record_usage (wired in chat.py:241 + alert_explanation.py:72, absent from nl2sql.py) — the "Per-user LLM quota applies" docstring claim has no usage rows behind it | ai_usage has zero nl2sql rows for 6 /query calls today | wire record_usage into the nl2sql LLM path | QUEUE |
| RT-006 | P3 | audit | /auth/refresh audit rows carry no `user` attribution (endpoint has no auth dependency; token IS the credential) | rows 266/291 user NULL | decode+attribute the subject in the audit row | QUEUE (nit) |
| RT-007 | P3 | response actions API shape | POST /response/actions returns params/evidence as JSON *strings* on the approval_required path, objects on the allow path (raw asyncpg str vs parsed) — consumer-hostile double-parse | the two 201 bodies in session log | normalize via load_jsonb in the response model | QUEUE (nit) |
| RT-008 | P3-doc | osquery ownership / docs | Root-daemon era (§1.3) produces root-owned 644 results log: shipper read path fine, user-space append (§1.4 generator) now PermissionError; §1.5 "user-level agent" scope note stale vs §1.3 | ls receipts; generator PermissionError (prior session); handoff confirmed | reconcile §1.4/§1.5 with the root daemon; one sudo chown (or sudo-run generator) restores the labeled-event append path | DOC + Raphael decision (sudo or not) |
| RT-009 | P3 | purple harness | purple_loop preflight build-sha check silently no-ops: `health.get("build")` is empty since build nests under `checks` → falsy → skipped | run 2 preflight printed `healthy build=` | read checks.build; fail loudly when absent | QUEUE (harness) |
| RT-010 | P4 | cases | Closed case shows `resolved_at: null` (only status="resolved" sets it) | case #3 body | set resolved_at on close too (or document) | QUEUE (nit) |
| RT-011 | P4 | ai/status | Untrained UEBA exposes trained_window_days=1 (train() sets window before the insufficient-samples bail at ueba.py:583) | /ai/status body | leave window untouched when train() bails | QUEUE (nit) |
| RT-012 | — | process | Handoff discrepancies corrected by verification: v0.9.0 tag → 8a4a04f (not 97550bf) · rules on disk = 130 total / 124 via API (handoff said 120) · the "container-bounce incident" is absent from the 2026-09-23 memory file (handoff is the only record; audit trail reconstructed it: rebuild 21:02:48Z → forced re-login 21:03:17Z) · osqueryd-as-root IS documented (§1.3) — the handoff overstated that discrepancy | git + coverage + audit rows | memory-protocol: log incidents the same day they happen | LOGGED |

**Withheld by design (HITL / data-safety):** quarantine action #7 approval/execution (real containment
on this Mac = Raphael's explicit call) · dashboard force-recreate test · browser-side 16-min idle test ·
the 1.03 GB rotated telemetry replay-or-discard · no code fixes made (finding wave; fixes queued).

## Closeout gates

- L2: `pytest tests/unit/ -q --cov=src --cov-fail-under=80` → **2,598 passed, 0 failed, exit 0, 88.29%** (52.8s)
- Secret scan: no code diffs this session (evidence-only changes: runs/ + memory logs); tokens handled via .env reads into process vars, never printed or committed
- No push, no merge — this report is committed to a local branch for Raphael's review
## ADDENDUM — P1 dispositions (fix session, same day, Raphael's go: "lets make those fixes")

| RT | Disposition | Commit |
|---|---|---|
| RT-001 | SHIPPED on branch — SELECT gains notes + real-SQL FAIL-proof pin | 95f95cd |
| RT-002 | SHIPPED on branch — get_rule_by_id serializes intervals; helper + TestClient pins FAIL-proven | 3f0a002 |
| RT-003 | SHIPPED on branch — fieldnames materialized (root cause: asyncpg 0.31 Record.keys() is a one-shot iterator; writeheader's internal dict(zip(it, it)) consumes+pairs it); FakeAsyncpgRecord pin FAIL-proven | 50c7f7b |

L2 at branch tip fix/runtime-wave-e-p1s (3 fix commits over 97550bf): **2,603 passed / 0 failed / exit 0 / coverage 88.32%** · ruff · format --check (256 files) · mypy (103 files) · secret scan of diff: clean. Live endpoint verification pending the merge + unified rebuild (containers still run 97550bf).
