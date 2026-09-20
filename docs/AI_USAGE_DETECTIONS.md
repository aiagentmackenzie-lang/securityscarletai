# AI-Usage Detection Domain (V0.4/5 "Agentic SOC", item 3)

The SIEM watches AI agents: agent runs, MCP tool calls, MCP denials, and
prompt-injection detections are a FIRST-CLASS log source with the same
discipline as identity telemetry (V0.3): one shape contract, closed
vocabulary, matrix-verified Sigma rules.

- Shape contract: `src/ingestion/ai_usage.py` (single definition shared by
  producers, generators, and tests -- the same pattern as
  `src/ingestion/auth_source.py`)
- Event convention: `event_category=ai`, `event_action` in the closed set
  below, `source=ai_usage`, transported via POST /ingest (the same
  producer convention as NeuralGuard verdicts)
- Field mapping: `user_name` = the acting identity (human requester or
  `mcp:<session>`); `process_name` = the MCP tool name (the tool acts on
  the SIEM the way a process acts on a host -- documented, deliberate)

## The closed vocabulary (ingest-convention tokens)

| Token | Producer | Meaning |
|---|---|---|
| `ai_agent_run` | API agent path (src/api/agents.py) | An agentic investigation lifecycle event (event_type start/end) |
| `mcp_tool_call` | SIEM MCP server | An allowed MCP tool call (tool name in process_name) |
| `mcp_tool_denied` | SIEM MCP server | A denied or failed MCP call (unknown tool, invalid params, tool error) |
| `ai_prompt_injection` | Any producer mapping in an injection verdict | A detected injection attempt against an AI surface |

Producers map INTO these tokens; anything else is rejected by
`build_ai_usage_event` (fail-closed: an unknown kind is never guessed into
a token). NeuralGuard verdicts continue to ride ingest as `verdict_block`;
a NeuralGuard prompt-injection verdict maps into `ai_prompt_injection` at
its producer (shipped 2026-09-19, NeuralGuard `map_to_scarletai_batch`:
user_name = the audit event's tenant_id — the actor slot; companions ride
the SAME ingest POST as their parent verdict, so they inherit its routing,
including the allow-filter).

## NeuralGuard verdict family (fleet producer contract, 2026-09-19)

The firewall's full event_action vocabulary is now declared in
`src/ingestion/schemas.py`: `verdict_allow` / `verdict_block` /
`verdict_sanitize` / `verdict_escalate` / `verdict_quarantine` /
`verdict_rate_limit` + `block_rate_spike` (edge-triggered block storm,
critical). Two rules consume it directly (`rules/sigma/neuralguard/`):

| Rule | Detects | ASI mapping (primary) | ATT&CK tag (approximate) |
|---|---|---|---|
| `block_rate_spike` | The firewall's edge-triggered block-storm alert (one critical event per episode) | sustained ASI01/ASI02/ASI10 pressure at volume | T1499 (denial of service) |
| `confirmed_ai_attack_block` | A single confirmed attack: `verdict_block` or `verdict_quarantine` at critical severity (>=0.9-confidence blocks, quarantines, canary-leak blocks) — no 10-in-5min threshold needed | ASI01 agent goal hijack, ASI02 tool misuse (confirmed certainty) | T1190 |

Both rules key on `source: neuralguard` + `event_category:
intrusion_detection` (the flat-column compiler path) and report DORMANT in
the coverage map until real NeuralGuard verdicts flow via the fleet
compose — armed the moment they do.

## NeuralStrike red-team exercise family (fleet producer contract, 2026-09-20)

The offensive third of the local stack (NeuralStrike drives the attacks,
NeuralGuard defends, this SIEM detects and measures) reports PLANNED,
AUTHORIZED red-team exercises through POST /ingest (source=`neuralstrike`,
category=`ai`). The vocabulary is a reviewed per-token decision in
`src/ingestion/schemas.py`: `exercise_start` / `exercise_end` /
`probe_succeeded` / `probe_resisted` / `probe_inconclusive`. The probe_*
tokens are NeuralStrike's own deterministic-oracle verdicts (canary /
predicate / schema oracles — the advisory Judge never flips them); canary
token VALUES never leave the producer (events carry a hashed id only).
Two rules consume the family (`rules/sigma/neuralstrike/`):

| Rule | Detects | Level | ASI mapping (primary) | ATT&CK tag (approximate) |
|---|---|---|---|---|
| `neuralstrike_probe_succeeded` | A probe SUCCEEDED against the target under test — with the firewall in path this is defense-gap evidence (the attack beat the deployed controls) | high | per-scenario ASI/LLM tags ride raw_data; lens: ASI01/ASI02 | T1190 (same nearest-neighbor as `prompt_injection_attempt`) |
| `neuralstrike_exercise_lifecycle` | The exercise bookends (one start + one end per exercise) — the window the purple-report join walks; also the operator's receipt that planned testing ran | low | n/a (bookend, not an incident) | T1190 (documented approximation) |

Attribution: the exercise drives the SAME payloads through a live
NeuralGuard with a run-scoped tenant (`neuralstrike-<runid>`), so the
firewall's verdict events carry that tenant in `user_name` — the join key
with these exercise events is (user_name, exercise window). The producer
is NeuralStrike itself; probe_succeeded severity high is the honest
signal: a red-team success against deployed controls is what the purple
loop exists to surface, and the lifecycle rule keeps the receipt without
noise. DORMANT until a fleet exercise emits — armed the moment one does.

## Sigma rules (rules/sigma/ai/)

| Rule | Detects | Threshold / window | ASI mapping (primary) | ATT&CK tag (documented approximation) |
|---|---|---|---|---|
| `prompt_injection_attempt` | Any AI prompt-injection detection | any | ASI01 agent goal hijack, ASI09 human-agent trust exploitation | T1190 (the AI surface is an application being probed) |
| `mcp_tool_denial_burst` | >= 10 MCP denials from one acting identity in 15m | count by user_name > 10, 15m | ASI02 tool misuse and exploitation, ASI10 rogue agents | T1110 (probing an access control) |
| `mcp_tool_call_volume` | >= 50 allowed MCP calls from one acting identity in 15m | count by user_name > 50, 15m | ASI02 tool misuse, ASI10 rogue agents | T1213 (the SIEM IS an information repository; scraping it via MCP is direct) |
| `agent_run_burst` | >= 20 agent runs from one acting identity in 15m | count by user_name > 20, 15m | ASI10 rogue agents, ASI09 human-agent trust exploitation | T1059 (automated execution loop) |

ATT&CK tags are the nearest-neighbor mapping for coverage-map
compatibility; the PRIMARY mapping is OWASP Agentic. Where the mapping is
approximate, the rule description says so -- no forced or fake mappings.

## OWASP Agentic Top 10 (2026) coverage by this domain

Portfolio-canonical list (security-engineer frameworks reference):

| ASI | Threat | Covered here by |
|---|---|---|
| ASI01 | Agent Goal Hijack (prompt injection) | `prompt_injection_attempt` rule + the agent path (injection attempts in objectives are sanitized and noted in draft rationales) |
| ASI02 | Tool Misuse and Exploitation | `mcp_tool_denial_burst` + `mcp_tool_call_volume` rules; the closed 3-tool surface itself (no mutation tool exists) |
| ASI03 | Identity and Privilege Abuse | The scoped read-only DB role (SELECT-only on data, DB-verified at boot); INGEST_BEARER_TOKEN is viewer-class |
| ASI04 | Supply Chain | Not covered by dedicated rules (honest: covered corpus-wide by the portfolio's other tooling, e.g. dependency-audit CI) |
| ASI05 | Unexpected Code Execution | Structural: the agent never executes generated SQL directly -- every query rides the NL->SQL validation stack (allowlist, cost gate, timeout) |
| ASI06 | Memory and Context Poisoning | The untrusted-content stack: fenced evidence in every LLM prompt, neutralization warnings logged and auditable |
| ASI07 | Insecure Inter-Agent Communication | The MCP transport: single endpoint, bearer auth, SSE refused; session attribution in the audit chain |
| ASI08 | Cascading Failures | Bounded agent runs (step cap, wall-clock budget, concurrency cap of 2); LLM failures fail the run honestly, never cascade |
| ASI09 | Human-Agent Trust Exploitation | The HITL gate: every AI verdict is a draft requiring a human decision with a mandatory note; four-eyes on response actions (V0.4) |
| ASI10 | Rogue Agents | `agent_run_burst` + `mcp_tool_call_volume` + `mcp_tool_denial_burst` rules; the audit chain records every agent step with actor attribution |

## Detection-matrix generator

`scripts/generate_ai_usage_events.py` emits true/false event pairs through
the REAL ingest pipe (same discipline as the V0.3 matrix): four scenarios
that must fire, two quiet scenarios that must stay silent. All synthetic
rows carry `host_name LIKE 'ai-matrix-%'` for scoped cleanup.

## Governance notes

- The MCP server emits its own tool events via POST /ingest with the
  scoped INGEST_BEARER_TOKEN -- the read-only DB role must not write logs
  directly. The append-only audit chain (INSERT on the scoped role) is the
  source of truth for MCP calls; the ai_usage feed is the detection-domain
  projection. A failed emission is logged, never silent.
- AI-usage events are bounded (`logs` retention windows apply as for any
  other log source).