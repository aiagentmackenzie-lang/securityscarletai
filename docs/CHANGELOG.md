# CHANGELOG

## V0.6b 2026 behavioral detection pack (2026-09-14, feat/v0.6b-detection-pack)

**Detections aimed at the techniques that actually topped 2026 incident
telemetry -- built CI-verified, live-fire deferred to the final stage of
the V0.6/V0.7 stack.**

- 8 new Sigma rules (104 -> 112), all through the rule-quality gate
  (vocabulary-gated, single-modifier, pure-OR conditions) and all
  compiling to parameterized SQL:
  - ClickFix / paste-and-run cross-platform (T1204.004, 2026's #1
    initial-access delivery): macOS (applescript:// deep links, osascript
    curl+exec, curl-piped-to-shell, quarantine-attribute removal) and
    Windows (mshta/rundll32 with remote payloads, hidden+encoded
    PowerShell, cmd-piped fetches). Honest scope: FileFix TypedPaths
    registry shapes are NOT Sigma-expressible (registry rows carry no
    selectable column) -- documented in the spec.
  - Windows LOLBin abuse (certutil/bitsadmin/regsvr32/msbuild), shadow
    copy deletion (vssadmin/wbadmin/diskshadow -- T1490 ransomware
    recovery-inhibition chokepoint, critical), RMM tool execution
    (ScreenConnect/AnyDesk/NetSupport/SimpleHelp/TeamViewer/RustDesk/VNC
    variants -- T1219), cloudflared tunnel (T1572), AI CLI credential/
    shell abuse (OWASP ASI02 process-level shape, QUIETVAULT pattern).
- 2 new correlation chains (8 -> 10), both with coverage requirements +
  matrix scenarios (the deferred live-fire drives them through the real
  pipe in one pass): `clickfix_dropper_execution` (payload dropped in
  user-writable paths -> interpreter execution, incl. the double-clicked
  .command shape) and `ai_process_egress` (AI CLI start -> external
  egress; ASI02).
- NEW ingest token: windows_events 4720 -> `account_created` (the
  reviewed per-token widening the V0.6a comment promised) + the T1136
  rule `windows_local_account_created` selecting it.
- BUG FOUND BY CODE READ, FIXED: `es_process_events` rows carry NO `name`
  column (same shape as process_etw_events) and the parser's
  basename(path) fallback covered ETW but NOT ES -- every ES exec row
  (the majority of macOS process telemetry) had process_name NULL, so
  process-name-keyed rules and the coverage process-name probe could
  never fire on the ES path. Fix: the same basename(path) fallback for
  es_process_events (both path separators).
- TEST FLAKINESS CLASS FIXED (LRN-20260911-004 variant): 4 tests in
  test_api_endpoints.py patched `get_pool` with `return_value=...` --
  when the module's get_pool binding was a MagicMock (import-order
  dependent), patch() never auto-created an AsyncMock and `await
  get_pool()` exploded in isolated runs (passed full-suite runs by
  import-order luck). Fix: explicit `new=AsyncMock(...)` on all 4 patch
  sites.
- Parser-limitation lessons documented in RULES.md (single modifier per
  key; conditions split on OR first -- mixed and/or silently degrades;
  missing selection names fail safe to FALSE). Two rule-authoring
  mistakes were caught by verification before merge.
- Matrix generator: scenarios for both new chains (live-matrix- hosts,
  auto-covered by the deferred live-fire cleanup scope) + fixture-level
  validation tests (scenario shapes parse to the chain vocabulary).
- Tests: 2,007 -> 2,028 unit (net +21).

## V0.6c model currency — benchmarked, default retained (2026-09-13, feat/v0.6c-model-benchmark)

**The local LLM is now selected by a measured, reproducible benchmark on
the SIEM's own validation loop — and the incumbent wins it.**

- Harness: scripts/model_benchmark.py — the purple-loop task set (verdict
  drafts via the investigator's exact VERDICT_SYSTEM_PROMPT + triage
  explanations via the versioned prompt renderer) across candidate local
  SLMs through the REAL client path (query_llm with settings.ollama_model
  swapped; ai_usage persistence skipped so the standing volume stays
  clean). Scoring: verdict agreement vs a known-answer corpus, closed-
  contract validity, explanation grounding, production-SLA compliance
  (30s ollama_timeout), latency, size; artifacts committed under runs/.
- Result (4 candidates, 2 runs/case, docs/MODEL_BENCHMARK.md): mistral:7b
  wins the deployable-quality composite (0.85; agreement 0.75, contract
  validity 1.00, explanation grounding 1.00, prod-SLA 1.00). phi4-mini
  ties on agreement but breaks the JSON contract (0.25) — not deployable
  for the verdict task without prompt hardening. qwen3.5:2b/9b (with
  think=false) reach 0.55/0.70. DEFAULT RETAINED: mistral:7b (no silent
  swap; the reviewed decision carries the scorecard).
- LIVE FINDING (production-integration, not benchmark-only):
  thinking-capable models (Qwen3.5-family) return their reasoning in
  Ollama's separate `thinking` field and leave `response` EMPTY until the
  thinking budget is exhausted — every SIEM JSON contract receives
  nothing. Fix: query_llm gains an opt-in think parameter (None = model
  default; False = disable the thinking phase so contracts get the full
  budget); unit-tested (TestThinkParameter).
- Honest scope: screening benchmark (N=8 verdict + 4 explanation calls per
  candidate), hand-built known-answer corpus (the purple-loop shapes);
  disqualifies contract/SLA breakers, does not statistically prove
  superiority. Re-benchmark triggers documented (phi4-mini prompt
  hardening, incumbent generations, timeout regressions).

## V0.6a cross-platform fleet + auth sources (2026-09-14, feat/v0.6a-cross-platform)

**The SIEM stops being a macOS product. The brute-force chain now has a
real auth telemetry source on every platform.**

- Windows auth (closes the G1 Windows half): osquery `windows_events`
  (Security channel, eventid 4624/4625) is parsed server-side into the
  closed auth vocabulary (`auth_success` / `auth_failed`) -- arming the
  ENTIRE existing brute-force chain (Sigma threshold +
  brute_force_to_success correlation) on Windows with zero rule changes.
  user/IP are extracted best-effort from the `data` payload (JSON hunt
  first, XML-text regex fallback, 16 KB scan bound, fail-closed: nothing
  found -> NULL, raw always preserved). Other eventids (4720 user created,
  4724 reset, ...) stay UNMAPPED -- adding tokens is a reviewed per-token
  decision for V0.6b, not a silent widening.
- Windows telemetry surfaces mapped (closes the G2 parser half):
  `process_etw_events` (ProcessStart/ProcessStop -> process vocabulary;
  event_type flips to end on stop; NO `name` column so process_name comes
  from basename(path) on both separators), `powershell_events`
  (script_text -> command_observed + process_cmdline, script_path ->
  process_path), `ntfs_journal_events` (USN actions -> the file-token
  vocabulary), `scheduled_tasks` / `services` / `registry` ->
  config_observed. Every table/column/flag verified against osquery source
  2026-09-14 before mapping -- including the catch that the Windows
  services table is named `services`, NOT `windows_services` (a name the
  planning research got wrong; corrected everywhere).
- Per-platform agent configs: `config/osquery.linux.conf` +
  `config/osquery.windows.conf` schedule ONLY tables verified for that
  platform (kills the empty-table waste of the single generic config;
  Linux drops the 3 macOS-only tables, Windows gains 12 entries incl. the
  evented Security/ETW/PowerShell/USN streams with their exact required
  flags). Kit templates derived 1:1 (`osqueryd.conf.darwin/linux/windows.example`);
  the bash bootstrap installs the platform-exact template.
- Fleet platform inventory: `fleet_enrollments.platform`
  (darwin|linux|windows|unknown, closed vocabulary, fail-closed 422 on
  garbage; legacy rows = unknown). Enroll request/response + /fleet/hosts
  + audit rows carry it. The server does NOT push configs -- the field is
  the kit's selection input.
- Windows agent kit: `deploy/fleet/bootstrap_fleet_host.ps1` (fail-closed
  mirrors the bash installer: https-only default, health gate, ZERO-WRITE
  token probe before touching the disk, config JSON validated after
  install, distinct exit codes; osqueryd via the official MSI, shipper as
  a SYSTEM scheduled task with restart-on-failure, no execution-time
  limit, token in an ACL-locked file). `scripts/fleet_shipper.py` gains
  `--token-file` (Task Scheduler has no env-file mechanism and argv is
  visible to other local users -- the file is the credential path).
- Linux auth shipper: `scripts/auth_log_shipper.py` gains `--backend
  darwin|linux` (auto-detected). sshd message formats are identical
  across platforms so the pattern corpus is shared verbatim; only the
  transport differs (journalctl JSON primary, /var/log/auth.log fallback
  for non-journald hosts). systemd unit + timer examples in the kit.
  Windows needs NO auth shipper -- windows_events IS the source.
- Honest scope: 27 new unit tests (2,007 total, from 1,980). The Windows
  kit + config ship behind tests; the FIRST WINDOWS LIVE-FIRE needs a real
  Windows host/VM (explicit pending item). Linux live-fire (container
  test host) executable locally.

## Correlation sweep (2026-09-12, feat/es-process-events)

**Closes a real detection gap found by the productized purple-loop
feedback on its very first run.**

- Gap: correlations triggered ONLY per ingest batch. A batch that raced an
  in-flight run was coalesced away -- and if ingest then went quiet, the
  late-landing pair was never correlated (no alert, no persisted match,
  forever). Verified live: the payload_callback pair sat in the DB, found
  by the detector SQL run manually, yet the detector logged matches=0 at
  its last pass.
- Fix: the coalescing state moves to src.detection.correlation
  (trigger_correlation_coalesced) as the single shared entrypoint; the
  scheduler gains a periodic correlation_sweep job (default 60s,
  settings-driven) under the SAME inflight guard; the 15-min INSERT dedup
  makes sweeps cheap and idempotent.
- Proven live: re-run scored 8/8 chains (the feedback artifact empty),
  with the progression table now carrying the full real history: 8 runs,
  6 from Sep 11, 2 from Sep 12, the 7/8 gap and the fix both visible in
  the series.

## es_process_events parser mapping (2026-09-12, feat/es-process-events)

**macOS EndpointSecurity native process events are now first-class SIEM
telemetry.**

- On macOS 10.15+ the plain `process_events` table is OpenBSM-backed and
  EMPTY -- the FIM session removed it from the schedule as a dead query and
  left the `es_process_events` parser mapping as a backlog item. This
  closes that backlog.
- Parser: `es_process_events` maps into the closed vocabulary (exec ->
  process_start, exit -> process_end) with the event_type flipped to end
  for exit rows; fork rows stay UNMAPPED on purpose (a fork row carries
  the parent's pid -- attributing a process_start to it would
  misattribute; the raw row survives in raw_data). Snapshot shapes stay
  neutral.
- Value: event-precise process telemetry (vs the 60s `processes`
  differential) -- processes that live and die inside one schedule window
  were invisible and are now caught. Codesigning evidence (signing_id,
  team_id, platform_binary, cwd) rides in raw_data for investigations and
  future signed-binary-abuse rules.
- Honest note: no dormant rule waits on this vocabulary (all 112 rules
  evaluate on existing tokens), so the armed count is unchanged (86/112);
  this is detection DEPTH + future-rule enablement, not an armed-count
  bump.
- Schedule entries: config/osquery.conf (macOS deployment, live) +
  deploy/fleet/osqueryd.conf.example (commented macOS-only for Linux fleet
  hosts). 4 new unit tests (exec/exit/fail-closed fork/snapshot), 1967
  total, all green.

## V0.5d "Small-Fleet Deployment" (2026-09-12, feat/v0.5c-timescale)

**The agent side of the fleet: a fail-closed bootstrap kit that turns one
machine into an agent host, and the runbook that ties it to the SIEM node.**

- deploy/fleet/bootstrap_fleet_host.sh: idempotent one-host installer
  (Linux systemd / macOS launchd). Fail-closed everywhere: SIEM unhealthy ->
  nothing installed; token rejected (401/403) -> nothing installed;
  osqueryd missing -> exact install commands, exit 2. The token is verified
  with a ZERO-WRITE probe (a malformed line the server refuses to parse,
  rejected_parse) so proving auth never persists telemetry. Token hygiene:
  never echoed, never on argv, never in logs (env file 0600 on Linux, 0600
  plist on macOS -- launchd has no env-file mechanism; documented).
- deploy/fleet/osqueryd.conf.example: agent-host osquery config derived 1:1
  from config/osquery.conf (same query names -> the same server-side parser
  mapping), platform-specific queries documented for per-OS pruning.
- deploy/fleet/fleet-shipper.service.example + launchd plist example:
  service templates with least-privilege notes (dedicated system user,
  ProtectSystem=strict, ReadWritePaths for the checkpoint only).
- deploy/fleet/README.md + DEPLOYMENT.md "Small-fleet deployment": the
  flow (enroll -> bootstrap -> verify via last_seen), ops runbook (rotation
  = re-enroll + re-bootstrap, revocation immediate, sizing vs the 100/min
  per-IP ingest limit behind Caddy with F-07 real-IP forwarding, audit
  events), TLS posture (https default; the internet overlay fronts the
  SIEM node), and honest scope notes (osqueryd binary install left to the
  operator; remote auth-failure telemetry is a future item, stated as such).
- No new compose file by design: the fleet SIEM node = the existing
  internet prod overlay; V0.5d is the agent kit + the runbook connecting
  the shipped V0.5a/b enrollment + raw-line ingest to it. Group C
  complete.

## V0.5c "TimescaleDB" (2026-09-12, feat/v0.5c-timescale)

**Logs become a TimescaleDB hypertable: chunk pruning, compression, and
chunk-granular retention replace the BRIN index and the logs sweep.**

- docker-compose: postgres:17-alpine -> timescale/timescaledb:2.30.0-pg17
  (pinned) with shared_preload_libraries=timescaledb. Same PG 17 major, so
  the standing volume boots unchanged under the new engine.
- src/db/schema.sql gains an idempotent, guarded upgrade block ($tsdb$): a
  NO-OP on vanilla PostgreSQL (CI's plain postgres service and dev volumes
  untouched; verified 27/27 integration on a vanilla throwaway), and on the
  Timescale engine it (1) creates the extension, (2) restructures the logs
  PK (id) -> (time, id) -- hypertable unique constraints must contain the
  partition key; the identity column and every writer are unchanged,
  (3) converts logs to a 1-day-chunk hypertable (migrate_data => true),
  (4) drops the BRIN index (superseded by chunk exclusion), (5) softens the
  correlation_matches -> logs FK into a plain index (regular tables cannot
  reference a hypertable), (6) enables compression (segmentby host_name,
  orderby time DESC) with a 7-day compress-after policy and a 30-day
  drop_chunks retention policy.
- TimescaleDB 2.30 API note: add_compression_policy no longer accepts
  segmentby/orderby -- compression config lives on the table reloptions,
  the policy only schedules it (live-boot finding; the first apply rolled
  back loudly at that point, as designed).
- Standing-volume migration executed 2026-09-12 (HITL): verified backup gate
  first (37 MB dump, 18 tables, restore-listable), schema re-applied as the
  owner on a db-only boot, 433,819 logs preserved EXACTLY (zero data loss,
  verified pre/post), 9 chunks created, the oldest chunk compressed by the
  policy on its own schedule. Full posture re-verified after the swap
  (build sha, loopback-only, docs 404, Redis NOAUTH, audit two-role strict
  pass) and real telemetry flowed through the same writer into the
  hypertable. Rollback path: the verified backup + vanilla postgres:17
  (docs/PRODUCTION.md section 7).

## V0.5a+b "Fleet Enrollment + Fleet Shipper" (2026-09-11, feat/v0.5a-fleet-enrollment; live-fire verified 2026-09-12)

## V0.4/5 "Agentic SOC" (2026-09-11, feat/v0.4.5-*)

**The governed agentic SOC — read-only agents inside the guardrails, the
SIEM as an MCP server, AI usage as a detection domain.**

- Read-only agentic investigation (src/agents/investigator.py): the loop
  plan-generate -> query -> correlate -> verdict DRAFT, wrapped around the
  existing NL->SQL core. The agent has NO write tools; every step rides
  the append-only audit chain; fail-closed everywhere (LLM fallbacks and
  unparseable plans/verdicts refuse honestly; unknown verdict tokens map
  to needs_review; confidence clamped; HITL required on every draft).
- agent_investigations: durable run record (status enum, plan, steps,
  verdict DRAFT, HITL state) + API (POST /agent/investigate,
  GET /agent/runs[/{id}], POST /agent/runs/{id}/hitl human-only
  confirm/reject with mandatory note, 409 on already-decided drafts,
  AGENT_ENABLED kill switch 423). Decision records: new closed type
  agent_investigation (actor_kind=ai).
- SIEM MCP server (src/mcp_server/): JSON-RPC 2.0 over streamable-HTTP
  POST (SSE refused, fail-closed), exactly three read-only tools
  (investigate / hunt / explain). Scoped read-only DB role
  (scripts/provision_readonly.sql, owner-applied, password via stdin;
  SELECT-only on SIEM data + append-only audit writes), scope verified at
  boot against information_schema -- tools refused on drift. MCP auth is
  MCP_BEARER_TOKEN only, constant-time; every call audited with
  mcp:<session> attribution. Live-verified 2026-09-11: UPDATE logs AS
  scarletai_readonly -> permission denied.
- AI-usage detection domain (src/ingestion/ai_usage.py +
  rules/sigma/ai/): closed tokens ai_agent_run / mcp_tool_call /
  mcp_tool_denied / ai_prompt_injection via POST /ingest (the
  NeuralGuard-verdict producer convention); 4 Sigma rules with OWASP
  Agentic ASI mappings (docs/AI_USAGE_DETECTIONS.md, ASI01-10 coverage
  table); producers: the API agent path (writer), the MCP server (scoped
  ingest token), scripts/generate_ai_usage_events.py (true/false matrix
  pairs through the real pipe). Live-fire 2026-09-11: all 4 firing
  scenarios detected, both quiet scenarios silent, MCP calls dogfooded
  into the domain, coverage 90/112 armed.
- Purple-loop harness: chain scoring now uses persisted correlation
  matches IN ADDITION to alerts (the docstring always said so); fixes the
  documented shipper-race + alert-dedup interleave that made re-runs
  under-score. 8/8 verified on the standing stack.
- Unit test suite: 1851 -> 1929 (all mocked-DB; a new conftest guard makes
  a real DB pool connection in ANY unit test raise immediately).
- Fleet/TimescaleDB: deliberately NOT started (queued behind the agentic
  layer's live-fire verification).

## V0.4 "Trusted Loop" (2026-09-11, feat/v0.4-response-authority)

**Governance + verification — outcome verification is the market's dividing line.**

- Durable case object: `case_events` append-only timeline (closed event
  vocabulary, CHECK-enforced enum); verdicts as first-class events with
  mandatory rationale; timeline + summary endpoints; governance gates
  (resolve/close rejected without an adjudicated verdict).
- Bounded response authority: `response_actions` table + closed action
  and status vocabularies; `config/response_policy.yaml` (versioned,
  fail-closed) with allow / approval_required / never per action,
  blast-radius max_per_day, requires_case, rollback notes; pure policy
  engine (src/response/policy.py).
- HITL approval with four-eyes: requester cannot self-approve (enforced
  live, 403); approval, execution, and verification ride the audit
  chain; rejection requires a reason (a decision record too).
- Verified outcomes: 6 executors (src/response/executors.py) with
  plan/execute/verify. Live-verified: disable_siem_user (re-query +
  login-refusal proof), quarantine_host (re-query + ingest enforcement),
  notify_slack (delivery receipt). Capability-gated fail-closed:
  pf_block_ip, disable_macos_user, isolate_host_fleet — honest refusals,
  never simulated, unverifiable never reported verified.
- Quarantine enforcement: the ingest endpoint refuses events from hosts
  on the quarantine list (rejected_quarantine in the response).
- Governed decision records: GET /decisions (read-only) assembles ai_triage,
  correlation, verdict, response_action, and policy_refusal decisions.
- Purple-loop validation: scripts/purple_loop.py (preflight /health sha
  gate, coverage before/after, per-chain fired table, ATT&CK technique
  hit rate over armed techniques). Live run 2026-09-11: 8/8 chains,
  20 alerts, 18 distinct rules, 13 techniques (hit rate 0.371 over
  armed techniques); report committed under runs/.
- Live-boot findings fixed (the posture guard and /health had never
  actually booted): posture-check false positive (unawaited probe +
  nonexistent table), /health permanently degraded (build sha counted
  as a failed check), and two JSONB-as-string crashes (response-action
  execution, decisions view).
- Tests: 1768 -> 1851 unit (+83); integration 27; coverage 86% (6712
  stmts, L3 measured).

## V0.3 "Trusted Engine" (2026-09-11, feat/v0.3-trusted-engine)

**Detection truth — the phase's rule: detections that fire on reality.**

- P1.2b correlation vocabulary pass: closed, ECS-aligned event_action
  vocabulary at the parser (fail-closed — raw action preserved in
  raw_data); 5 of 6 blocked correlation chains fixed in SQL (priv-esc,
  credential-theft, defense-evasion, data-exfil, brute-force).
- ALL 8 correlation chains live-fire verified on the standing stack
  (2026-09-11): fire + persist + ATT&CK-mapped alerts.
- Identity/auth telemetry: closed auth-event contract + macOS unified-log
  sshd shipper (watermark dedup, atomic state) + second FileShipper
  instance (normalized format). The parser never fakes auth failures.
- Evidence-driven coverage map: GET /detection/coverage — per-rule
  armed/dormant with reasons; MITRE heatmap counts ARMED techniques only;
  correlation chains join the rollup. 86/108 rules armed on real telemetry.
- Rule-quality CI: sigma structural gate (UUID/fields/levels/condition),
  vocabulary gate (closed tokens, |contains semantics), waiver registry
  (18 documented future-source rules, bidirectional with coverage), and
  the per-chain true/false matrix in Postgres-backed integration tests
  (16 sigma rules fixed to the vocabulary; 17 dead event_type filters
  caught by the gate).
- Scheduler pool-deadlock fix (live-fire finding): run_rule no longer
  holds connections across alert creation/LLM enrichment; enrichment is
  bounded fire-and-forget; rule queries bounded by a 60s fail-closed
  timeout.
- Decorative sequences module + /correlation/sequences endpoint removed
  (zero engine consumers).
- osquery-fim.conf overlay prepared (file_events + process_events), gated
  on EndpointSecurity/FDA live validation — not silently enabled.
- Generator gains --matrix mode: one event sequence per chain in real
  pipeline shapes (the reusable live-fire harness).
- Counts: 1750 unit tests / 27 integration tests / 87% coverage.


Fixes shipped on SecurityScarletAI, newest last. This is the **public** record
of what was fixed — it lists resolved issues, not open ones. The full
finding-by-finding catalog (the audit that produced these fixes) is kept
locally, out of the public repo.

Severity key: **P0** = exploitable / ship-blocker · **P1** = control-bypass or
data-integrity gap · **P2** = quality / slop / doc drift.

## 2026-09-02 — Phase 2 (hard boundaries)

Merged to `main`. Each fix shipped on its own branch via `--no-ff` merge;
tests went 1473 → 1525 passed (unit, `--no-cov`).

- **P2.1** `fix/redis-degradation` (`98189b4`) — the documented "fails back
  to in-memory" rate-limit fallback never existed (Redis storage connects
  lazily, so the construction-time try/except was dead code; a dead Redis
  500'd every rate-limited request). Now `in_memory_fallback_enabled=True`:
  storage failures are caught at REQUEST time, checks serve from a
  memory-backed strategy, and the backend is re-probed with exponential
  backoff to recover without a restart. Redis client converted to
  `redis.asyncio` (P2-32): revocation checks, blocklist, and lockout ops no
  longer block the event loop (F-08 bounded-retry + cooldown preserved,
  awaited backoff). Fail-open semantics unchanged.
- **P2.2** `fix/stream-cap-request-body` (`8cf54ca`) — chunked request
  bodies were buffered ENTIRELY in RAM before the 1 MB check (memory-DoS:
  any chunked uploader pinned unbounded RAM per request). The stream is now
  consumed in chunks and aborted with 413 the moment the cap is exceeded.
  Hardening bonus: garbage/negative/conflicting Content-Length headers
  return 400 instead of raising ValueError → 500 (also kills a request-
  smuggling primitive).
- **P2.3** `fix/pagination-bounds` (`36e974f`) — `/alerts` (≤1000), `/cases`
  (≤500), and `/correlation/matches` (≤1000) now bound their pagination via
  Annotated Query constraints (`?limit=10000000` used to pull the whole
  table into memory; logs/audit were already bounded, these weren't).
- **P2.4** `fix/ws-backpressure` (`9d3397f`) — WebSocket broadcast moved off
  the ingest hot path into the per-batch background task (one slow
  dashboard socket used to stall event ingestion), and every send is
  capped with a 1 s `asyncio.wait_for` — slow clients get EVICTED, not
  waited on. F-16 filter semantics unchanged.
- **P2.5** `fix/ti-negative-cache` (`bcbb9ce`) — every IOC-cache miss fired
  a LIVE AbuseIPDB check (attacker-sprayed fresh IPs burned the daily
  quota, leaving enrichment blind). Clean results are now negative-cached
  in Redis for 1 h, live calls are capped by an hourly budget (default
  500, env `ABUSEIPDB_HOURLY_BUDGET`), API errors are never cached as
  clean, and Redis-down = documented fail-open.
- **P2.6** `fix/scoped-ingest-token` (`122483b`) — a leaked static bearer
  was FULL ADMIN everywhere. New optional `INGEST_BEARER_TOKEN` is
  viewer-class and honored ONLY on the ingest router: `get_current_user`
  rejects it on every other endpoint, `get_ingest_client` (new, wired to
  `/ingest`) accepts admin bearer + dashboard JWTs + the scoped token.
  Unset → byte-for-byte pre-P2.6 behavior.
- **P2.7** `fix/ml-off-event-loop` (`51497d6`) — `/ai/train` (and the
  hourly auto-train) froze the whole API for the fit duration: RF fit,
  CV score, the v2 per-fold CalibratedClassifierCV loop, the final
  calibration fit, and UEBA's IsolationForest all ran synchronously inside
  async methods. All CPU-bound blocks now run via `asyncio.to_thread`;
  thread-identity tests pin the behavior.
- **P2.8** `fix/sigma-limits-rules-validation` (`8145c5d`) — simple
  detection queries carry a parameterized LIMIT (`MAX_DETECTION_ROWS`
  = 1000); rules API bounds create + patch: `run_interval` ≥30 s, lookback
  ≤24 h, threshold ≥1, severity restricted to the known enum (off-enum
  values 500'd on the DB enum — now a clean 422).

## 2026-09-01 — Phase 1 (trust & truth)

Merged to `main`. Each fix shipped on its own branch via `--no-ff` merge;
tests went 1450 → 1473 passed (unit, `--no-cov`).

- **P1.1** `fix/dashboard-esc-huntview` (`7af9554`) — alerts-view stored XSS
  fixed at the `_note_card_html` / `_expander_title` choke points (esc()
  everywhere, MITRE tags escaped; esc-sweep tests extended) and three dead
  API-shape paths in hunt_view repaired (`_summarize_gaps`, `_group_templates`,
  `_hunts_for_alert`). New `tests/unit/test_hunt_view_shapes.py`.
- **P1.2** `fix/demo-seed-gate` (`9c61293`) — demo seeding (synthetic alerts
  AND the publicly documented `demo_analyst` credential) previously ran
  unconditionally from the Docker entrypoint on any first boot. Now opt-in via
  `DEMO_SEED_ENABLED=true` — gated in `settings`, `seed_demo_data.py`, the
  entrypoint, and compose passthrough; docs + troubleshooting updated.
- **P1.3** `fix/llm-fence-risk-score` (`b3f41c1`) — the two unfenced LLM
  paths re-fenced (LLM01 regression): `build_prompt` fences ingest-fed
  `host_name` + evidence; `_suggest_hunts_for_alert` fences `host_name`.
  LLM risk_score validated before returning — non-numeric/bool → 50,
  out-of-range clamped to [0, 100] (a string verdict previously crashed
  `enrich_alert` and aborted the rule's alert loop).
- **P1.4** `fix/hunt-from-alert-quota` (`2196144`) — `/hunt/from-alert` now
  carries the 30-per-5-min LLM limit keyed by `user_or_ip_key` (the quota
  hole let a user bypass the LLM budget); dashboard client passes the
  60 s AI timeout on that path.
- **P1.5** `fix/secret-placeholder-gate` (`e2c19d6`) — fail-closed: startup
  rejects `CHANGE_ME` placeholders on `API_SECRET_KEY` and `API_BEARER_TOKEN`
  (joining `DB_PASSWORD`), with the `openssl rand` command in the error.
- **P1.6** `fix/f10-dedup-payload` (`49bf287`) — correlation dedup now
  actually dedups: the dupe comparison excludes the per-match uuid4
  `correlation_id` (the full payload never matched, so rows piled up
  unboundedly).
- **P1.7** `fix/truth-pass-docs-csv` (`cb14869`) — truth pass:
  `docs/RULES.md` regenerated from the real 100 rule files (was "45");
  CSV export guards formula injection (`=`, `+`, `-`, `@` cells quoted,
  hostile-host test); `docs/AI.md` training-label description matches the
  code (`resolved`/`closed` = 1, `false_positive` = 0); README Status line
  states the real test count and date; dead internal link removed.

## 2026-08-26 — Phase 1 + Phase 2 (production-hardening)

Merged to `main` (final `793186a`). Each fix shipped on its own branch via
`--no-ff` merge; tests went 1218 → 1258 passed.

- **P0-A** `fix/nl2sql-table-allowlist` (`a20e79f`) — NL→SQL now enforces a
  `{logs, alerts}` table allowlist (sqlparse FROM/JOIN extraction, recursive
  for subqueries/CTEs) in `validate_sql_structure` before execution. A crafted
  question targeting `siem_users.password_hash` is rejected, never executed.
  README's "parameterized SQL" claim corrected (the AI path is regex-filtered
  raw execution, not parameterized; the Sigma path IS parameterized). +9 tests.
- **P1-A** `fix/jwt-type-claim-enforcement` (`be4d249`) — `verify_jwt` /
  `get_current_user` reject `type != "access"`. A refresh token (7d) no longer
  works as an access token on every endpoint. Drive-by: switched `auth.py` to
  structlog `get_logger` (the stdlib `logging` call was a latent `TypeError`). +6 tests.
- **P1-B / P2-12** `fix/force-password-change-token-scope` (`c8e41fa`) — new
  `verify_force_change_token` dependency (the ONLY path accepting a force
  token). `verify_jwt`/`get_current_user` reject `force_password_change: True`,
  so the must_change_password control is no longer bypassable for the 15-min
  TTL. `/force-change-password` sets a `user_revoke_marker` so the force token
  dies on success. +6 tests.
- **P0-B** `fix/prod-dashboard-jwt-only` (`b5e69fe`) — `DASHBOARD_API_TOKEN` =
  admin; the dashboard skips login when set. Added a loud startup warning
  (warnings.warn + stderr), a commented Caddy `basicauth` block + note, a
  DEPLOYMENT "Dashboard exposure" section, and a README correction. Prod
  overlay already defaults the token to empty (JWT-only); now explicit.
- **P1-D** `fix/retention-and-brin-index` (`64a82d0`) — new
  `src/services/retention.py`: APScheduler job (hourly) deletes rows older
  than env-configurable windows (LOGS=30d, ALERTS=180d, AUDIT=365d,
  CORRELATION=90d, AI_USAGE=90d) in batched parameterized DELETEs
  (CTE + LIMIT + FOR UPDATE SKIP LOCKED; capped loops). 0 = keep forever.
  BRIN index on `logs(time)` + TimescaleDB upgrade note. +7 tests.
- **P1-E** `fix/writer-backpressure-and-dead-letter-replay` (`c2c808f`) —
  `LogWriter` buffer capped at `MAX_BUFFER` (10× batch); when full, `write()`
  flushes first (backpressure, not OOM). New `scripts/replay_dead_letter.py`
  reads `data/dead_letter/*.jsonl`, re-ingests via the writer, moves replayed
  files to `processed/`. Entrypoint runs it on boot (best-effort, non-fatal). +5 tests.
- **P1-C** `fix/audit-append-only-hardening` (`793186a`) — README's "append-only
  with REVOKE hardening" was false (the REVOKE was a schema COMMENT, never
  applied, and can't bind in the default single-role deploy — the app role owns
  the tables; owners bypass REVOKE). New `scripts/harden_audit.sql` (superuser,
  two-role deploy), `scripts/check_audit_grants.py` (reports real grant state;
  `--strict` for gates). Entrypoint applies it when `DATABASE_SUPERUSER_URL`
  is set, else prints a convention-only notice. README/DEPLOYMENT corrected. +7 tests.

## 2026-08-22 → 2026-08-25 — production-readiness fix pass

The fix pass that closed the original 59-finding audit. One line per fix;
commits are the `sha` prefixes. Grouped by the pass that shipped them.

### Pass 1 — schema / boot / Sigma path (`0edaa14`)
- **P0-02** — `logs.id` BIGINT PK; `correlation_matches.trigger_event_id` INT→BIGINT.
- **P0-03** — `logs.severity` TEXT column + writer inserts it.
- **P0-05** — entrypoint applies schema via `psql -v ON_ERROR_STOP=1` (statement-by-statement, no all-or-nothing rollback).
- **P0-06** — Dockerfile: deleted stale `COPY alembic/ alembic.ini`.
- CREATE TYPE idempotency (`DO $$ EXCEPTION duplicate_object`).

### Pass 2 — Sigma parser / execution (`359a339`)
- **P0-01** — `sigma_to_sql` routes through the legacy `SigmaParser` only; all 45 rules execute against real Postgres.
- **P0-04** — deleted the dead pySigma parse path (`_parse_with_pysigma`).
- **P2-42** — `SigmaParser._parse_condition` plain `and` support (webshell_creation).
- **P1-04** — `reverse_shell.yml` + `ssh_success_after_failures.yml` duplicate-key YAML fixed.
- **P2-10** — `to_sql` parses the condition once (was double-parse leaving untyped unreferenced placeholders).
- INET LIKE `host(col)::text` + Sigma `'*'` → `IS NOT NULL` (unflagged INET runtime bugs surfaced by the execution test).

### Pass 3 — ingest / correlation enrichment (`8d357de`, `7890108`)
- **P0-03** (completion) — `severity` verified in the `detect_defense_evasion_cleanup` query.
- **P1-07** — ingest writes enrichment back to `logs.enrichment` JSONB; `LogWriter.flush()` added.
- **P1-16** — `IngestEvent` adds `process_cmdline`/`process_path`/`host_ip`; seed sets `process_cmdline`.
- **P1-06** — `run_all_correlations(persist=True)` calls `create_alert(rule_id=None)` per match; dedup by `rule_name+host_name`.
- **P1-13** — ingest loop broadcasts each event to `/ws/logs` via `broadcast_event` (best-effort).
- **P2-28** (partial) — deleted the dead `run_all_correlations_legacy` wrapper.

### Pass 4 — provenance / risk / auto-train (`6338cf0`)
- **P1-08** — `_write_provenance` uses `json.dumps` for JSONB; provides `model_hash`/`training_samples`/`cv_accuracy` (NOT NULL).
- **P1-09** — `calculate_asset_risk` exposure query moved inside the async-with block.
- **P1-10** — `get_top_risk_assets` rewritten (joined outbound-conns subquery).
- **P2-25** — `schedule_rules` schedules `auto_train_check` hourly.

### Pass 5 — auth hardening (`52ed123`)
- **P1-11** — `get_current_user` enforces jti blocklist + user_revoke via shared `_check_revocation`.
- **P1-12** — rule mutations require admin role; viewer gets 403.
- **P1-14 / P2-41** — `seed-admin` localhost-only + `must_change_password=TRUE`; dashboard button + admin/admin text removed.
- **P2-23** — `log_audit_action` no longer raises (logs + returns None); audit added to rule/alert mutations.
- **P2-24** — `alerts.py` uses `user.get("sub")` not `str(user)` for author/created_by/updated_by/assigned_to.
- **P2-40** — dashboard logout POSTs `/auth/logout` (server-side blocklist) before clearing the session.

### Pass 6 — dashboard field-shape fixes (`d9f447a`)
- **P1-15** — `RuleResponse` exposes `mitre_tactics`/`techniques`/`sigma_yaml`/`run_interval`/`lookback`/`threshold`; `from_row` serializes intervals.
- **P2-43** — `PATCH /rules/{id}` partial update; dashboard `update_rule` uses PATCH; dashboard field-shape fixes (prediction string, matching_hunts+llm_suggestions, is_trained/training_samples/training_accuracy/ollama_available, templates description+id).
- **P2-39** — sidebar AI Triage uses `is_trained`.
- **P2-20** — `PUT update_rule` re-parses `sigma_yaml` + refreshes MITRE.
- interval params use `timedelta` (asyncpg str→interval bug); `scheduler.start()` idempotent.

### Pass 7 — prod proxy / threat intel / osquery / health (`3a4897a`)
- **P1-17** — Caddyfile `handle_path` → `handle /api/*` (preserve the `/api` prefix the FastAPI app requires).
- **P2-17** — threat-intel initial refresh runs as a background task (non-blocking startup).
- **P2-37** — `osquery.conf` `logger_path` aligned; unmapped tables documented as intentional.
- **P2-31** — docker-compose `OLLAMA_MODEL` default aligned. *(Note: later re-corrected to `mistral:7b` — the verified running model — in the 2026-08-26 docs-honesty pass.)*
- **P2-34** — `/health` caches the Ollama probe (60s TTL).
- **P2-16** — startup `validate_ollama_model` warns on result (was discarded).
- **P2-35** — cases link/unlink/note + alerts `link_to_case` use atomic SQL (`array_append`/`remove`, `notes || jsonb`).

### Pass 8 — dead code / cleanup (`53cedb0`)
- **P2-07** — `FileShipper` docstring corrected (polling, not watchfiles).
- **P2-13 / P2-28** — dead code deleted (`get_sequence`, `suggest_hunting_queries`, `get_hunt_history`, `summarize_multiple_alerts`, `suggest_investigation_steps`, `calculate_severity_boost`, `send_email_notification`, `send_daily_summary`).
- **P2-14** — unused `JWT_EXPIRY_HOURS` removed.
- **P2-15** — `AuditLogMiddleware` best-effort decodes JWT to attribute actors/role.
- **P2-18** — MITRE STIX master-vs-v14 drift documented (accept).
- **P2-19** — nl2sql `add_safety_limits` whitespace-tolerant `)\s+SELECT`; comment-check + EXPLAIN-failure limits documented.
- **P2-27** — `GET /hunt/history` removed from the hunt.py docstring (function already deleted).
- **P2-29** — stale/broken `scripts/demo.sh` deleted (port conflict, unreferenced).
- **P2-30** — `make migrate` uses `psql -v ON_ERROR_STOP=1`.
- **P2-32** — sync redis in async auth paths documented as follow-up (socket_timeout bounds; switch to redis.asyncio at scale).
- **P2-33** — correlation `_unwrap`/`_parse_as_of` left as-is (acceptable test-coupling).
- **P2-36** — `execute_hunt` forwards actor; `save_hunt_history` records the analyst, not `hunting_assistant`.
- **P2-44** — `generate_attack_data` brute-force fixture adds `local_address` so the parser extracts `source_ip`.
- **P2-11** — moot (pySigma parse path deleted in P0-04).
- **P2-21** — `send_email_notification`/`send_daily_summary` deleted as dead code (send_alert_notification is the only wired path).

### Pass 9 — rules reconcile / writer / correlation docs / geoip (`fa9c6fd`)
- **P1-05** — `load_sigma_rules` reconciles every boot (upsert by name, preserve operator state, log db-only orphans).
- **P2-08** — dead-letter writes one event per line (true JSON-Lines).
- **P2-09** — correlation `as_of` docstrings corrected to `datetime.now(timezone.utc)`.
- **P2-12** — lifespan calls `close_geoip_reader()` on shutdown.
- **P2-22** — `FileShipper` checkpoint path per-instance (defaults to legacy global).

### Pass 10 — chat / CI (`39155e9`, `4e1b210`)
- **P2-26** — chat forwards the authenticated user to cost tracking; `session_id` threaded as correlation key (multi-turn memory documented as not implemented).
- **P2-38** — CI builds the Docker image + applies schema (`ON_ERROR_STOP=1`) + runs integration tests (were skipping); fixed two wrong integration test contracts (`get_alert_stats` int, dedup returns -1).
## 2026-08-28 — Post-audit remediation (8 branches, dashboard + AI + auth + deploy + resilience + hygiene)

Phase 1–6 of the 08-28 double-sweep remediation plan (findings F-01…F-26).
Each phase shipped on its own branch, gated (ruff src+dashboard · mypy src ·
pytest) and merged `--no-ff`. Tests 1343 → 1438.

- **`fix/dashboard-esc-sweep`** — every data-derived value rendered inside
  `unsafe_allow_html=True` is escaped (case titles/notes/assignments, metric
  labels incl. ingestion-fed host names, badge labels, sidebar username);
  logout() now posts to the client's own base_url (F-01/F-02/F-19).
- **`fix/llm-content-fencing`** — NEW `src/ai/untrusted.py`: untrusted log
  data enters prompts only inside explicit data fences with
  neutralized escape sequences (OWASP LLM01:2026); `ai_generated` labeling
  end-to-end (F-06).
- **`fix/llm-rate-quota`** — per-user LLM quota (30/5min default,
  `LLM_RATE_LIMIT`) on /ai/chat, /ai/explain, /query, /hunt execute, keyed
  by authenticated sub (OWASP LLM10) (F-14).
- **`fix/lockout-and-revocation-robustness`** — composite login lockout
  (per-(user,ip) counters, exponential 15m→1h→6h, distributed-noise no-lock)
  replaces the flat renewing lockout DoS; Redis client bounded-retry +
  cooldown; user_revoke fixed-key (O(1) read); /auth/refresh honors
  must_change_password; disabled/locked login branches burn bcrypt
  (F-05/F-08/F-09/F-11/F-15).
- **`fix/prod-deploy-hardening`** — prod overlay revokes DB/redis host
  ports (only Caddy publishes 80/443), redis requirepass enforced, uvicorn
  trusts XFF from private ranges, static-bearer audit rows attributed,
  platform pins removed, containers capped (F-04/F-07/F-21/F-26).
- **`fix/ingest-pipeline-backpressure`** — reverse-DNS off the event loop
  (bounded pool); correlation capped/coalesced/deduped; WS filters honored
  + registry capped; fire-and-forget tasks GC-referenced; enrichment
  write-back IP-keyed; sigma missing selection parses FALSE (F-03/F-10/
  F-16/F-17/F-18/F-20).
- **`fix/hygiene-deps-ci`** — dead deps dropped (passlib, sqlalchemy, black);
  redis pinned >=6,<9; CI gains a scripts/+tests/ lint gate (was a 195-error
  blind spot); README gains an honest Limitations section; PyJWT migration
  filed as backlog (F-25).

## 2026-09-02 — Phase 3 (product & proof) + v0.2.0

Merged to `main`; tagged `v0.2.0` (Phase 1–3 remediation complete). Each item
shipped on its own branch via `--no-ff` merge; tests went 1525 → 1640 passed
(unit, `--no-cov`), coverage 86% → 87% (CI-enforced ≥80%).

- **P3.1** `feat/user-management-api` (`e0794ca`) — admin-only user
  management API: `GET /users` (never exposes password_hash — excluded from
  the response model AND the SQL), `POST /users` (hashed password, role
  enum, `must_change_password=true`, duplicate → 409), `PATCH /users/{id}`
  (role change + is_active toggle; deactivation AND role change set the
  Redis user_revoke marker — the JWT carries the role claim, so pre-change
  tokens must not survive a demotion; self-guard prevents an admin from
  deactivating themselves or changing their own role), and
  `POST /users/{id}/reset-password` (one-time `secrets.token_urlsafe(16)`
  password returned once in the response, never logged, never in the audit
  entry; lockout state cleared; older tokens revoked). Every mutation
  audit-logged with actor + IP. DEPLOYMENT.md's raw-SQL password reset
  replaced with the API path.
- **P3.2** `fix/wire-request-body-hash` (`d962e79`) —
  `audit_logs.request_body_hash` was plumbed end-to-end but never written
  (always NULL). Now: RequestValidationMiddleware sha256-hashes size-bounded
  POST/PUT/PATCH bodies ≤ 64KB onto `request.state` (Starlette caches +
  replays the body downstream — bytes reach the endpoint intact,
  regression-tested at app level); AuditLogMiddleware passes the hash to
  the audit row. Bodies > 64KB stay NULL by policy ("not hashed", distinct
  from an empty body). 8 tests incl. chunked bodies and a full
  middleware-chain passthrough.
- **P3.3** `feat/prometheus-metrics` (`9d98426`) — `GET /api/v1/metrics` in
  Prometheus text format via a tiny in-process registry (zero new
  dependencies): HTTP request count + latency histogram by method +
  path-class (IDs/UUIDs/usernames normalized — cardinality control), ingest
  accepted, writer buffer depth + backpressure, DB pool in-use/size,
  correlation run duration, retention rows-deleted/errors. Access
  fail-closed: optional `METRICS_BEARER_TOKEN` or analyst JWT; token unset
  → localhost-only unauthenticated scrape; an invalid bearer is always 401
  even from localhost; malformed JWTs caught (no 500). Verified live:
  199 samples, path-class normalization and live gauges rendering.
- **P3.4** `chore/ops-honesty-sweep` (`001882e`) — Slack alert links use
  `DASHBOARD_PUBLIC_URL` (new setting) instead of a hardcoded localhost:8501;
  `/ai/status` uses the CACHED Ollama probe (the /health P2-34 cache) instead
  of a fresh 5s probe per call; `scripts/migrate_passwords.py` derives its
  DSN from settings (+asyncpg stripped) instead of the stale-DATABASE_URL
  footgun; PersistFlags-era `/correlation/run-legacy` removed after a
  verified zero-caller check (dashboard client, docs, tests).
- **P3.5** `chore/ci-dependency-image-scanning` (`3a0efaa`) — CI gains
  `pip-audit` (over the same locked dependency set the test job installs)
  and a Trivy HIGH/CRITICAL image scan. Both NON-BLOCKING for two weeks
  (continue-on-error, policy in the YAML); `.trivyignore` ships with zero
  CVE accepts — entries require CVE/GHSA ID + rationale + date, enforced by
  a unit test. Build/test jobs stay hard-failing.
- **P3.6** `test/llm-redteam-matrix` (`4d1b5be`) — OWASP LLM Top 10 (2025)
  matrix as a permanent 41-probe regression suite at the prompt boundary
  (no live Ollama): LLM01 direct+indirect injection against FOUR prompt
  surfaces (build_prompt, hunt suggestions, NL→SQL conversation context,
  chat security context) with fence-balance + outside-fence assertions;
  LLM02 synthetic-SQL validator bypasses (siem_users.password_hash via
  direct/UNION/JOIN, dblink, pg_read_file, pg_catalog, stacking, pt-BR
  comment obfuscation) — all rejected; LLM09 fallback labeling (no silent
  fabrication); LLM10 quota marking on all five LLM-costing endpoints.
  Findings: none new — Phase 1 fencing + M-07 redaction hold.
- **P3.7** full-stack local verification (colima vz VM) + two shipped
  findings: `fix/cors-env-parsing` (`954cf05`) — a P0 boot-blocker where
  docker-compose's bare-string `API_CORS_ORIGINS` default crashed every
  container boot at settings load (pydantic-settings demands JSON for list
  fields at the source level, before validators run); now NoDecode +
  tolerant validator (bare string, comma list, JSON — malformed JSON still
  fails loudly). And `fix/ai-status-test-seam` (`f55ceaa`) — a test left
  patching the pre-P3.4 probe seam passed only while another test primed
  the shared cache; now deterministic. DEMO.md §4 page-by-page verified
  against the live stack (see README Status): stats 35/12c/12h/9m/2l,
  35 alert rows, 20 logs, 3 cases, 15 TI, 100 rules, suppressions 200 `[]`
  (route-shadowing fix holding). Phase 1 XSS fix verified in rendered
  reality: a live-stored `<img src=x onerror=alert(1)>` note renders as
  escaped inert text in the dashboard's note card. Findings logged: host
  Ollama on this machine lacks `mistral:7b` (demo run used the documented
  `OLLAMA_MODEL` override); a fresh demo volume seeds only `demo_analyst`
  (DEMO.md §5's "admin exists" claim is stale — entrypoint bootstrap wrote
  no admin on this volume).

## 2026-09-03 → 2026-09-04 — Local production (real telemetry, hard boundaries, ops)

Raphael's mandate: "not a demo, not an online stack — a local program, safe,
in-house, AI connected." Executed as phased branches, each merged `--no-ff`
with CI green; tests went 1640 → 1683 passed, coverage holds 87%.

- **fix/slim-image-boot-deps + fix/test-redis-hermetic + fix/ci-provenance-db-seam
  + fix/trivy-action-pin (Sep 3)** — demo spin-up surfaced three real bugs
  (missing runtime deps in the slim image, test-isolation leak into the live
  Redis, CI postgres-dependent test, never-running trivy action).
- **vuln triage + fast-wins + Project A + Project C (Sep 3)** — 126 pip-audit
  findings triaged reachability-first → 9 → 2 risk-accepts; KEV
  CVE-2026-48710 killed via fastapi/starlette upgrade; trivy image scan at
  ZERO HIGH/CRITICAL; runtime image 1.83GB → 1.11GB (poetry evicted,
  multi-stage).
- **feat/local-telemetry-pipe (Sep 4)** — REAL host telemetry: zero-sudo
  osqueryd LaunchAgent (inside-.app-bundle execution, root-only path redirects,
  CLI-only flags), config/osquery.conf rewritten against live 5.23.1 schema
  checks (shell_history uid, sip_config columns, browser_plugins dropped), a
  read-only bind mount into the API, shipper enabled. Verified end-to-end:
  reverse-shell-pattern event → critical alert within one scheduler tick.
  Fixed live: shipper checkpoint at Path.home() (nonexistent in-container →
  duplicate re-ingest) → persistent data/ checkpoint; pydantic extra=forbid
  vs undeclared .env deployment keys; metrics tests pinning ambient env.
- **feat/local-prod-overlay (Sep 4)** — production cutover: loopback-only
  publishing (redis unpublished, closes the LAN-exposed unauthenticated Redis),
  requirepass enforced, DOCS_ENABLED=false, PASSWORD_PEPPER enforced
  (fail-fast), no-new-privileges + cap_drop, memory limits, dashboard
  live-reload mount removed, JWT-login default. Fresh volume; demo archived to
  data/backups/.
- **feat/local-prod-ops (Sep 4)** — DB-ENFORCED audit immutability: two-role
  deploy (owner applies schema via DATABASE_SUPERUSER_URL; restricted
  scarletai_app runs the API with INSERT/SELECT-only audit privileges;
  harden_audit.sql re-applied every boot; tamper UPDATE/DELETE/TRUNCATE all
  denied). scripts/backup_local.sh (verify-gated dumps, rotation, owner audit
  prune, RESTORE TEST against a throwaway postgres) + launchd nightly;
  scripts/health_watchdog.sh edge-triggered watchdog + launchd; enforcing-flip
  plan documented for Sep 16.
- **docs/readme-honesty-audit (Sep 4)** — full README/docs honesty pass:
  killed the vapor "syslog" ingest claim, fixed stale rule-category counts
  (9/8/7/6/10/5 → 14/34/17/17/12/6 = 100), test counts (1473/1656 → 1683),
  CI branch triggers, structure block (17 routers, missing modules), stale
  PHASE_PLAN.md deleted; PRODUCTION.md added to the docs set.

## 2026-09-05 — 8th correlation rule + NeuralGuard log source

- **feat(neuralguard) (Sep 5, `0e4fd41`)** — NeuralGuard (the sibling AI
  firewall) audit verdicts now land in this SIEM: NeuralGuard's sink
  (`src/neuralguard/siem.py::map_to_scarletai`, in the NeuralGuard repo)
  maps every verdict to an ECS IngestEvent and POSTs it to `/ingest` with
  the SHA-256 chain hash + Ed25519 signature riding in
  `raw_data.neuralguard`. New 8th correlation rule
  `ai_verdict_block_sustained` alerts on sustained BLOCK verdicts per
  (host, source, tenant). Fixed correlation-match persistence (F-10).
  Unit suite 1683 → 1689; 8 integration tests pass live against Postgres
  (ingest → detection → correlation on real DB).

## 2026-09-06 — README run-modes overhaul

- **docs (Sep 6, `35eac22`)** — the single Quick Start conflated three
  different things; the README now opens with **Running SecurityScarletAI**,
  one section per run mode:
  - **Demo** — full spin-up: generate real secrets (the app fail-fasts on the
    CHANGE_ME placeholders — validators in `src/config/settings.py`),
    `DEMO_SEED_ENABLED=true` BEFORE first boot, `make up`, health gate on
    `/api/v1/health` (no root `/health`), `make demo-refresh` before every
    demo (the #1 failure mode), `demo_analyst` credentials, the
    no-admin-on-a-demo-volume gotcha, and the `make demo` live-telemetry demo
    (port 8001, stops the compose api, re-run `make up` after).
  - **Local production** — the standing real-SIEM posture end-to-end: the
    fail-fast overlay (`REDIS_PASSWORD` + `PASSWORD_PEPPER` with the
    no-fallback warning), two-role audit hardening, real osqueryd telemetry
    install gotchas + end-to-end pipe verification, backups/watchdog/retention
    ops, user-scope honesty.
  - **Dev** — poetry outside Docker, derived DSN (no `DATABASE_URL`).
  - Mode-comparison table, one-mode-per-volume rule, per-mode authoritative
    guides (DEMO.md / PRODUCTION.md / DEPLOYMENT.md); Deployment section
    slimmed to the guide table; Screenshots placeholder tied to the demo flow.
  - All commands verified against the Makefile, scripts/, compose files,
    `src/config/settings.py`, and the two authoritative docs before writing.
  - Same pass fixed the status header (Trivy job is step-enforced but
    job-level non-blocking until the Sep 16 flip), the stale "default
    deployment seeds synthetic data" claim, 1683→1689 test counts,
    5→8 integration tests, the NeuralGuard mapper cross-repo path, and
    appended the missing Sep 5 CHANGELOG entry.

## 2026-09-07 — Production go-live findings

- **fix(ingest) (`f5e6696` merge, 9 commits)** — go-live live-fire found the
  osquery `listening_ports` rows with EMPTY `source_ip`/`host_ip` poisoning
  whole 100-event `executemany` batches (asyncpg INET parse error on
  `''`): 1,550 events / 2.27 MB stranded in dead-letter from only 128 bad
  rows. Fix: `_safe_ip` parser + field validators ('' → NULL) on
  `host_ip`/`source_ip`/`destination_ip` in BOTH `NormalizedEvent` and
  `IngestEvent` — the API schema is the choke point for every ingest path
  (osquery parse, HTTP ingest, dead-letter replay). All 1,551 stranded
  events replayed and recovered.
- **fix(auth)** — admin bootstrap never set `must_change_password` (schema
  default false, INSERT omitted the column): the documented forced
  first-login change never engaged. Bootstrap now sets it true; the live
  admin was remediated owner-side. First real admin login then exposed a
  dashboard bug: the forced-change 403 was rendered as raw JSON
  (`ceaa034`) — now handled with the set-new-password form + 2 regression
  tests.
- **docs(ops)** — `check_audit_grants` documents/uses `--app-role "$DB_USER"`
  at every site (the bare documented command audited the OWNER role via the
  process-env default and false-alarmed).
- **ops remediations (same session)** — a `DEMO_SEED_ENABLED=true` flag on
  the production `.env` was flipped to false (mode-guard violation; the
  double gate prevented damage); the `demo_analyst` account seeded during
  that window was deactivated owner-side; the missed-backup gap was closed
  with a verified `backup_local.sh` run + restore test.
- **P1 verification board executed with evidence**: correlation live-fire
  (persistence_activated fires → persists → ATT&CK-mapped alert
  end-to-end), live red-team 3/3 held against real Ollama (recorded in
  `docs/AI.md`), restart drill (durability semantics measured: shipper
  at-least-once, HTTP at-most-once), retention live-fire. Suite 1689 →
  1702.

## 2026-09-10 — Sigma param-type trap (rules 91/100)

- **fix(sigma) (`4683e41`)** — rules 91 (`setuid_binary_set`) and 100
  (`wmi_remote_execution`) failed EVERY scheduler run since they shipped
  with asyncpg "expected str, got int" / "expected str, got dict": unquoted
  YAML ints (`4755`/`4754`) bound as Python ints against the TEXT column
  `process_cmdline`, and `- /node:` parsed as a YAML MAPPING
  (`{'/node': None}`). Compiler-side fix at the choke point: `_coerce_param`
  coerces every selection value per schema column type (TEXT=str,
  INTEGER=int, INET=validated IP, pattern context=str; INTEGER columns cast
  to ::text for LIKE-family), and anything unrepresentable fails the
  selection SAFE to FALSE (F-20 pattern) — an empty selection `{}` also
  fails safe now (was silently TRUE). Rule YAML hygiene: quoted values
  (preserving the trailing space in `wmic `). Corpus guard test: no shipped
  rule may produce an unbindable param. Suite 1702 → 1710.

## 2026-09-10 — Format gate + enforcing flip (P3.5 closed)

- **chore (bulk format)** — `ruff format` applied repo-wide (139 files
  reformatted) after the check-only era left 141 files drifted; full suite
  1710/0 + mypy clean on the mechanical commit (zero behavior change).
  CI now ENFORCES `ruff format --check` (lesson from the NeuralGuard
  hotfix: `ruff check` cannot see format drift).
- **chore (enforcing flip, executed 6 days early)** — the Sep 16 flip
  condition held early: pip-audit residual = the two documented
  risk-accepts only (now reported as PYSEC-2026-2447/1325, aliased to
  CVE-2025-69872/CVE-2024-23342; all four IDs ignored with rationale),
  trivy zero findings. Both advisory jobs dropped `continue-on-error` —
  dependency-audit and trivy-image-scan now gate CI. P3.5 two-week window
  closed.
