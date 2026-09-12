# SecurityScarletAI — Evolution Roadmap (2026-09-10)

Where the product stands, what businesses actually demand in the 2026 threat
landscape, and the prioritized path to "cutting edge." Grounded in: the SANS
2026 SOC Survey, Gartner Hype Cycle for Security Operations 2026, the 2026
AI-SOC market research (SACR Trusted SOC model), and the repo's own verified
state (1,711 tests / 88% / enforcing CI / go-live evidence Sep 7-10).

---

## 1. Where the market is (the demand side)

**The numbers that shape buyer behavior:**
- Security automation: $9.7B (2025) → $26B+ (2033). AI SOC agents went from
  Innovation Trigger to **Peak of Inflated Expectations in one year** (Gartner
  2026) — 1–5% penetration, embryonic, mainstream in 2–5 years.
- Alert reality: ~11,000 alerts/day per enterprise SOC, **70% never
  investigated**, 60–80% false-positive rates, 4,8M unfilled security seats.
  Manual triage cannot scale — that is the product wedge.
- **The adoption–integration gap** (SANS 2026, first time measured at scale):
  79% of SOCs use AI/ML tools, but only **36%** have them in a defined,
  governed workflow. The rest are unsanctioned individual use. Governance is
  the gap, not capability.
- Identity is the blind spot: "the visibility gap executives name is, in
  large measure, an identity gap" (SANS 2026 expert corner). OT/IoT: only 45%
  monitor nontraditional assets.
- SIEM is **splitting in two**: low-cost security data lakes vs integrated
  SOC systems. Standalone XDR is "being rendered obsolete."

**What separates leaders from demos in the AI-SOC market** (the SACR Trusted
SOC lifecycle — the evaluation frame the whole industry now uses):

| Lifecycle stage | State in market |
|---|---|
| Evidence assembly | Table stakes |
| Investigation / summarization / enrichment | **Commodity** — everyone has it |
| Decisioning (verdicts with rationale) | Differentiator |
| Bounded authority (policy, approvals, blast radius) | Differentiator |
| Response execution | Rare |
| **Outcome verification** (re-query the source system, prove the state changed) | **The clearest dividing line in the market — almost nobody has it** |
| Continuous improvement (detection feedback loop) | The emerging moat (self-improving SOC, CTEM) |

**Regulatory tailwind:** EU AI Act Art. 14 (human oversight + audit trails for
high-risk AI), NIST CSF 2.0 GOVERN, CIRCIA 72h reporting, SEC disclosure — all
push toward decision records, signed evidence, and governed autonomy. That is
governance-as-product, and it lands directly on SIEM evidence trails.

**The mid-market squeeze:** enterprise AI-SOC platforms quote $200–600K/yr;
open-source DIY stacks cost $150–250K/yr in FTEs; SaaS SIEMs price by ingest.
Same threats, 10–20% of the budget. Nobody owns "governed AI SOC at
mid-market price with data sovereignty."

---

## Where SecurityScarletAI already IS cutting edge (verified, not aspirational)

1. **Local-first / air-gapped AI SIEM.** The market is SaaS-first; sovereignty
   (EU AI Act, GDPR, DORA, UK GDPR) is a buying trigger and our posture is
   already documented and drilled (loopback-only, two-role DB, air-gapped runbook).
2. **AI-native from the core, not bolted on:** NL→SQL with 7-layer injection
   defense, ML triage + UEBA, honest LLMResult contract. Most "AI SOCs" are
   copilots on a legacy store — Gartner now formally separates the two.
3. **Stronger AI guardrails than most vendors demo:** fail-closed fencing,
   table allowlist, 41-probe OWASP LLM red-team suite, quota + budget gates.
4. **Tamper-evident evidence chain:** hash-chained + Ed25519-signed audit
   events, DB-enforced append-only (two-role deploy) — exactly what
   "governed autonomy" buyers must prove and most platforms cannot show.
5. **The portfolio closed loop exists in pieces nobody else has wired:**
   NeuralStrike (AI offense) → generates real attack traffic →
   SecurityScarletAI (detection/correlation) → NeuralGuard (AI firewall,
   verdicts → SIEM ingest). The "self-improving SOC" loop the analysts
   describe (pentest → hunt → detect → detection engineering) is
   *assemblable today from repos we already own*.

---

## What is missing (honest, prioritized)

### A. Detection truth — the engine must fire on reality
1. **P1.2b correlation vocabulary pass** (6/8 chains structurally unable to
   fire on real shapes; per-chain dependencies documented in
   TESTING-ROADMAP.md). Nothing else matters if detections don't fire.
2. **Second telemetry source: identity/auth.** osquery has no auth-failure
   table; the brute-force chain is dead without it. Identity is the #1
   visibility gap (SANS) — macOS `log stream`/auditd + sshd logs, or a
   Linux-beat source. Also unlocks brute_force_success.
3. **FIM via EndpointSecurity** (entitlement present, needs FDA pass) —
   unlocks data_exfiltration + credential_theft chains and ransomware-class
   detections.
4. **Detectability/coverage mapping:** ATT&CK heatmap that distinguishes
   *rule exists* from *telemetry exists to fire it* (the "detectability"
   framing is where detection engineering is heading). Our MITRE heatmap is
   title-driven today — make it evidence-driven.
5. **Rule-quality CI:** every rule carries synthetic true/false event pairs
   (we have the generator + live-fire harness); FP-rate gates in CI; Sigma
   community-rule sync as a versioned feed.

### B. The case object + outcome verification (the market's dividing line)
6. **Durable case management:** case = the operating unit (evidence, verdicts,
   actions, approvals, closure) with continuity — today cases are thin.
7. **Bounded response authority + verified outcomes:** SOAR-lite actions
   (Slack/email/pf) exist but nothing verifies state change. Add: action
   policy engine (allow / approval-required / never), HITL approval with the
   full evidence package, post-action re-query proving the intended state,
   rollback notes. Even 3 verified action types (isolate via osquery, disable
   local user, firewall block) beats 90% of the market on verification.
8. **Decision records as first-class evidence:** every autonomous decision
   (triage verdict, correlation match, AI explanation, action) already rides
   the audit chain — surface it as a *governed decision record* view.

### C. Scale + fleet (from one host to a deployment)
9. **Multi-host collection:** osquery fleet endpoint / distributed shippers
   with TLS ingest + per-host checkpointing; TimescaleDB hypertables for
   scale; tiered retention.
10. **Ingest batching** for verdict rates >100/min (NeuralGuard feed ceiling).
11. **Deployment story:** hardened single-node (done) → small-fleet overlay +
    ops runbook → the product a business could actually run.

### D. The agentic frontier (where the market is going, where we have a moat)
12. **Agentic investigation, read-only first:** plan-generate → query →
    correlate → verdict-with-evidence agents, all inside the existing
    guardrails (allowlist, fencing, red-team suite) with HITL gates. We have
    the NL→SQL core; the agent wrapper is the step.
13. **SIEM MCP server** (read-only analyst role): agents everywhere are
    becoming the interface; NeuralGuard already speaks MCP — the SIEM
    exposing `investigate`, `hunt`, `explain` over MCP with a scoped
    read-only DB role is a natural, defensible frontier. (Prompt-injection
    surface → the untrusted-fencing + allowlist stack is already the answer.)
14. **AI-security observability as a detection domain:** monitor AI agent /
    MCP / LLM-usage events as first-class log sources (NeuralGuard verdicts
    already are). "The SIEM that watches your AI agents" is a genuinely
    underserved, 2026-native wedge — OWASP Agentic Top 10 mapping already
    exists in the portfolio.
15. **Purple-loop productization:** `generate_attack_data` (exists) →
    NeuralStrike scenarios → live-fire → detection-coverage score per run →
    rule-feedback. The compounding-coverage demo (33%→56%→83% pattern) is the
    single most compelling thing we can show a client.

### E. Compliance/reporting (budget-justifying surface)
16. Scheduled reports: ATT&CK coverage, MTTR/alerts, UEBA outliers;
    evidence exports mapped to SOC 2 / ISO 27001 / NIST CSF 2.0 controls.
    The audit trail already exists — packaging it is the differentiator.

---

## Recommended sequencing (three tracks, one rule: detections that fire first)

> **STATUS 2026-09-11: V0.3 "Trusted Engine" DELIVERED** — merged to main
> (cf49bd0), CI green (run 34605038751), ALL 8 correlation chains
> live-fire verified on the standing stack. See the phase table below
> for per-item outcomes.

| Phase | Theme | Items | Status |
|---|---|---|---|
| **V0.3 "Trusted Engine"** | Detection truth | P1.2b pass → identity log source → FIM → detectability map → rule-quality CI | ✅ **DELIVERED 2026-09-11** (merged `cf49bd0`, CI green, all 8 chains live-fire verified). Item notes: P1.2b closed (all chains fire+persist) · identity/auth shipper shipped · evidence-driven coverage map shipped · rule-quality CI shipped · **FIM config prepared, validation pending TCC live pass** (cmdline paths of the exfil/credential chains already live; file paths arm on FIM) · benign-corpus FP gates → moved to a later phase |
| **V0.4 "Trusted Loop"** | Governance + verification | Case object → bounded actions w/ verified outcomes → decision records → purple-loop validation | ✅ **DELIVERED 2026-09-11** (branch feat/v0.4, live-fire verified on the standing stack). Item notes: durable case object shipped (append-only case_events timeline, closed vocabulary, verdict gates) · bounded response authority shipped (policy engine allow/approval-required/never, fail-closed; HITL four-eyes enforced; 6 action types — 3 live-verified: disable_siem_user w/ login-refusal proof, quarantine_host w/ ingest-enforcement proof, notify_slack; 3 capability-gated fail-closed: pf_block_ip, disable_macos_user, isolate_host_fleet) · governed decision records shipped (GET /decisions, read-only) · purple-loop validation shipped (scripts/purple_loop.py; 2026-09-11 live run: 8/8 chains, 20 alerts, 18 rules, 13 ATT&CK techniques, report committed under runs/) · bonus live-boot findings fixed: posture-check false positive, /health permanent-degraded, 2x JSONB-as-string crashes |
| **V0.4/5 "Agentic SOC"** | Frontier | Investigation agents (read-only, HITL) → SIEM MCP server → AI-domain detections → fleet/Timescale | ✅ **DELIVERED 2026-09-11** (branch feat/v0.4.5-*, live-fire verified on the standing stack). Item notes: read-only investigation agent shipped (no write tools, every step audited, HITL-gated verdict DRAFTs, MCP-initiated runs recorded) · SIEM MCP server shipped (JSON-RPC 2.0 POST-only, 3 read-only tools, scoped read-only DB role verified at boot, live-verified: UPDATE denied at DB level as the MCP role) · AI-usage detection domain shipped (4 Sigma rules, closed vocabulary, dogfooded -- the SIEM's own agent + MCP calls land in the domain; ASI01-10 mapping table in docs/AI_USAGE_DETECTIONS.md) · purple-loop harness fix (chains score from alerts OR persisted matches) · fleet/Timescale deliberately not started |
| **V0.5 "Fleet & Scale"** | Group C: fleet identity + raw-line fleet ingest + TimescaleDB + deployment story | fleet enrollments -> fleet shipper -> Timescale hypertables -> small-fleet overlay | 🟡 **V0.5a + V0.5b + V0.5c DELIVERED (a+b: 2026-09-11, branch feat/v0.5a-fleet-enrollment; c: 2026-09-12, branch feat/v0.5c-timescale)**. V0.5a per-host enrollment (sha256-at-rest tokens, host-bound at ingest, revocation immediate) · V0.5b POST /ingest/osquery (server-side parsing = one ECS truth, same writer + coalesced correlation) + standalone stdlib fleet_shipper.py (checkpoint/rotation/partial-line discipline, at-least-once delivery, 401/403 fatal) · **V0.5a/b LIVE-FIRE VERIFIED 2026-09-12**: enroll -> token -> ship -> parse -> detect (3 alerts incl. critical) -> spoof refused 403 whole-batch + audited -> revocation immediate, retry 401 FATAL; no live fleet token remains. Bonus build fix: data/ excluded from the Docker build context (the root osqueryd pidfile is 0600 root:wheel and broke the context check). **V0.5c TimescaleDB shipped 2026-09-12 (HITL)**: image swap (pinned timescale/timescaledb:2.30.0-pg17) + schema's guarded idempotent block (PK (id)->(time,id), hypertable 1-day chunks migrate_data, BRIN dropped, corr FK softened to an index, compression 7d + retention 30d policies); standing volume migrated behind a verified backup gate, 433,819 logs preserved exactly, zero data loss; 2.30 compression API finding fixed (reloptions carry segmentby/orderby); 27/27 integration on vanilla PG (block no-ops there). **V0.5d small-fleet deployment kit SHIPPED 2026-09-12**: deploy/fleet/ (bootstrap_fleet_host.sh fail-closed installer with zero-write auth probe + per-host osquery config template derived 1:1 from config/osquery.conf + systemd unit + launchd plist + kit README) + the fleet runbook in DEPLOYMENT.md (enroll -> bootstrap -> verify via last_seen, rotation/revocation ops, TLS posture: https default, internet overlay for the SIEM node). Group C COMPLETE. |

Bonus delivered with V0.3 (live-fire finding, 2026-09-11): scheduler
pool-deadlock fix — run_rule no longer holds connections across alert
creation/LLM enrichment; rule queries bounded (60s, fail-closed);
enrichment is bounded fire-and-forget.

Each phase ships behind the existing gates (branch → L2 → --no-ff → push
approval) and each phase ends portfolio-rescored.

## Honest business frame (THE RULE)

Evolution of an existing asset — no new-project gate. Value paths: (a) the
Security Services portfolio story (client demos, SOC credibility), (b)
NeuralGuard↔ScarletAI↔NeuralStrike as a *demonstrable* AI-security stack,
(c) a potential future product/MDR-lite for sovereignty-sensitive
organizations — only pursued with a validated revenue path per the Apr 1
rule. The mid-market gap (governed AI SOC, local, affordable) is the only
plausible product wedge; everything above strengthens it.