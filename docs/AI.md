# AI Features Documentation

SecurityScarletAI integrates AI/ML throughout the detection-to-response pipeline. All AI features degrade gracefully when Ollama is unavailable — template-based fallbacks and rule-based responses ensure the system never blocks on LLM availability. Every LLM call returns a structured `LLMResult` dataclass that records source, token usage, latency, and whether a fallback was used.

The AI subsystem provides: a unified `LLMResult` contract across all LLM callsites, versioned Jinja2 prompt templates (`src/ai/prompts.py`), per-call cost tracking (`src/ai/cost_tracker.py`), a calibrated triage model (`CalibratedClassifierCV` wrapper), and the chat endpoint.

---

## LLM Infrastructure

### The `LLMResult` contract

Every Ollama call returns an `LLMResult` dataclass (`src/ai/ollama_client.py`) instead of a raw string. This contract is uniform across `query_llm`, `chat`, alert explanation, and hunting suggestions:

```python
@dataclass
class LLMResult:
    ok: bool                       # True iff `text` is safe to use
    text: str                      # The model output (or template fallback)
    source: SourceType             # "ollama" | "template" | "error"
    model_used: Optional[str]      # The Ollama model that answered
    tokens_in: int                 # Prompt tokens (0 for templates)
    tokens_out: int                # Completion tokens (0 for templates)
    latency_ms: int                # Wall-clock latency
    fallback_used: bool            # True if Ollama was unreachable
    warning: Optional[str]         # User-facing message when fallback fires
    error: Optional[str]           # Internal error if source == "error"
    prompt_version: Optional[str]  # e.g. "v1.0.0" from prompts.py
    extra: dict                    # Call-specific extras
```

Callers check `result.ok` and `result.fallback_used` rather than catching exceptions for "expected" unavailability.

### Versioned prompt templates (`src/ai/prompts.py`)

All LLM prompts live in one place as Jinja2 templates with explicit version constants. Bumping a version produces a new `version_hash` so callers can record which prompt produced which result:

| Constant | Version | Used by |
|----------|---------|---------|
| `ALERT_EXPLANATION_PROMPT_VERSION` | `v1.0.0` | `src/ai/alert_explanation.py` |
| `ALERT_SUMMARY_PROMPT_VERSION` | `v1.0.0` | `src/ai/alert_triage.py` (summaries) |
| `INVESTIGATION_STEPS_PROMPT_VERSION` | `v1.0.0` | `src/ai/alert_explanation.py` (steps) |
| `CHAT_SYSTEM_PROMPT_VERSION` | `v1.0.0` | `src/api/chat.py` |

Render helpers (`render_alert_explanation`, `render_alert_summary`, etc.) return both the rendered text and a content hash. Bumping the version constant is the only edit needed to roll a prompt forward.

### Per-call cost tracking (`src/ai/cost_tracker.py`)

`record_usage()` writes one row to the `ai_usage` table per LLM call with `tokens_in`, `tokens_out`, the calling user, endpoint, and model. This powers the cost rollups surfaced in `/ai/status`.

### Graceful degradation

If Ollama is unreachable, `LLMResult.source == "template"` and `fallback_used == True`. Each AI feature has a deterministic template fallback so behavior is reproducible without an LLM.

---

## Natural Language → SQL (NL→SQL)

### How It Works

The NL→SQL engine (`src/ai/nl2sql.py`) converts plain English security questions into safe, parameterized SQL queries:

1. **Input sanitization** — Strips prompt injection patterns before sending to the LLM
2. **LLM translation** — Sends the question to Ollama with a strict system prompt requiring SELECT-only output
3. **Structural validation** — `sqlparse` rejects any non-SELECT statement
4. **Pattern rejection** — Regex check forbids DDL, DML, and system table access
5. **Cost estimation** — `EXPLAIN` estimates scan rows; rejects queries exceeding 10,000 rows
6. **Result limiting** — Maximum 1,000 rows returned per query
7. **Execution timeout** — 5-second hard limit per query

### Example Queries

| Natural Language | Generated SQL Pattern |
|------------------|---------------------|
| "How many failed logins in the last hour?" | `SELECT COUNT(*) FROM logs WHERE event_action LIKE '%failed%' AND time > NOW() - INTERVAL '1 hour'` |
| "Which hosts are exfiltrating the most data?" | `SELECT host_name, SUM(COALESCE((enrichment->>'bytes_sent')::bigint, 0)) AS total FROM logs WHERE event_category = 'network' GROUP BY host_name ORDER BY total DESC` |
| "Show me all root logins this week" | `SELECT * FROM logs WHERE user_name = 'root' AND event_action LIKE '%login%' AND time > NOW() - INTERVAL '7 days'` |

### 7-Layer Injection Defense

| Layer | Protection |
|-------|-----------|
| 1. Input sanitization | Strips common prompt injection patterns (`ignore instructions`, `you are now`, etc.) |
| 2. LLM system prompt | Instructs the model to generate only SELECT queries |
| 3. `sqlparse` validation | Rejects any non-SELECT statement at the AST level |
| 4. `FORBIDDEN_PATTERNS` regex | Blocks `DROP`, `ALTER`, `CREATE`, `TRUNCATE`, `INSERT`, `UPDATE`, `DELETE`, `GRANT`, `REVOKE`, `COPY`, system tables |
| 5. `EXPLAIN` cost check | Rejects queries estimated to scan > 10,000 rows |
| 6. Result size limit | Caps output at 1,000 rows |
| 7. Execution timeout | 5-second hard limit per query |

### API Endpoint

```
POST /api/v1/query
Body: {"question": "your natural language question"}
Response: {"question": "...", "sql": "...", "results": [...], "row_count": N}
```

---

## Alert Triage (ML)

### Architecture

The alert triage system (`src/ai/alert_triage.py`) uses a **Random Forest classifier** wrapped in **`CalibratedClassifierCV`** (isotonic, cv=3) to predict whether alerts are true positives or false positives, and to prioritize them for analyst review.

**Why calibration matters:** Earlier iterations emitted raw RF probabilities that were poorly calibrated — a 0.7 output did not mean 70% of such alerts were true positives in practice. Wrapping in `CalibratedClassifierCV` gives trustworthy probability estimates suitable for threshold-based routing ("auto-close anything with confidence < 0.2", etc.).

### Feature Set (11 input features)

The `AlertTriageModel.FEATURES` list defines the input feature vector:

| Feature | Type | Description |
|---------|------|-------------|
| `severity_score` | Float (0-1) | Severity mapped to numeric (critical=1.0, high=0.75, medium=0.5, low=0.25, info=0.0) |
| `hour_of_day` | Float (0-1) | Normalized hour of the alert (circadian pattern) |
| `rule_hit_count` | Int | How often this rule has fired historically |
| `host_alert_count` | Int | Number of historical alerts on this host |
| `asset_risk_score` | Float (0-1) | Host risk score from the asset inventory |
| `mitre_count` | Int | Number of distinct MITRE techniques in the alert |
| `time_since_last_hours` | Float | Hours since the most recent similar alert |
| `has_threat_intel` | Float (0-1) | Whether any IOC matches a threat intel feed |
| `command_entropy` | Float | Shannon entropy of recent process names |
| `session_duration_hours` | Float | Duration of the associated user session |
| `login_hour_deviation` | Float (0-1) | How far the alert hour is from the user's normal login hour |

### Training Pipeline

1. Alerts with status `resolved` or `false_positive` are pulled from the DB as training data (positive = `true_positive`, negative = `false_positive`).
2. For development without real labels, `scripts/generate_training_data.py` produces 1,000 stratified synthetic alerts (seed=42, deterministic).
3. Features are extracted from each alert's context.
4. `RandomForestClassifier(n_estimators=100, class_weight="balanced")` is wrapped in `CalibratedClassifierCV(cv=3, method="isotonic")`.
5. 5-fold StratifiedKFold cross-validation computes precision, recall, and F1 on the aggregated CV predictions (not per-fold averaged — this was a V2 bugfix).
6. The trained model is saved to `models/triage_model.joblib` with a SHA-256 integrity hash to `models/triage_model.sha256`.
7. A provenance row is written to `triage_model_provenance` recording the model path, hyperparameters, dataset size, CV metrics, and run metadata.
8. Persistence is threshold-gated: the model is only saved if `min_cv_accuracy >= 0.70` (configurable).

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ai/train` | POST | Trigger model training |
| `/api/v1/ai/status` | GET | Training status, model info, provenance, cost rollup |
| `/api/v1/ai/triage/{alert_id}` | POST | Get triage prediction for a specific alert |
| `/api/v1/ai/ueba/{user_name}` | GET | UEBA anomaly score for a user |
| `/api/v1/ai/explain/{alert_id}` | POST | LLM-generated alert explanation |

### Model Integrity

- Models are saved using `joblib` with SHA-256 hash verification
- Hash is stored in `models/triage_model.sha256`
- On load, the hash is verified before the model is used
- This prevents tampering with the trained model file

---

## UEBA (User and Entity Behavior Analytics)

### How It Works

The UEBA module (`src/ai/ueba.py`) builds behavioral baselines for each user using an **Isolation Forest** anomaly detection model:

1. **Feature extraction** — For each user per day, extract 8 behavioral features from the `logs` table
2. **Baseline training** — Isolation Forest learns "normal" behavior patterns
3. **Anomaly scoring** — New events are scored against the baseline (0-1 scale)
4. **Flagging** — Users with anomaly scores above the contamination threshold are flagged

### Behavioral Features (8)

| Feature | Calculation | Anomaly Signal |
|---------|-------------|----------------|
| `login_hour_of_day` | Mode of user's login hour distribution | Off-hours access |
| `unique_processes_count` | Count of distinct processes run by the user | Unusual tool usage |
| `command_diversity` | Shannon entropy of process names | Abnormal process variety |
| `network_connections_count` | Outbound connection count | Excessive networking |
| `unique_destination_ips` | Distinct IPs contacted | Broad network reach |
| `file_access_count` | File operations count | Excessive file access |
| `sudo_usage_count` | Privilege escalation count | Unusual sudo patterns |
| `session_duration_minutes` | Time between first and last event of the day | Abnormally long sessions |

### Scoring

- **Anomaly score**: 0.0 (normal) to 1.0 (highly anomalous)
- Default contamination rate: 0.05 (top 5% of behavior flagged)
- Scores feed into the Risk Scoring engine as the `anomaly_score` factor

---

## Alert Explanation (LLM)

### How It Works

When an alert is created, the system generates a human-readable explanation via `src/ai/alert_explanation.py`:

1. **Context assembly** — Rule name, severity, affected host, MITRE techniques, and evidence are gathered
2. **Jinja2 prompt render** — `render_alert_explanation()` produces the user prompt from `ALERT_EXPLANATION_PROMPT_VERSION = "v1.0.0"`; `render_investigation_steps()` produces the recommended next-steps block from `INVESTIGATION_STEPS_PROMPT_VERSION = "v1.0.0"`
3. **LLM query** — Ollama is asked to explain the alert in 2-4 sentences covering:
   - **What happened**: Brief description of detected activity
   - **Why it matters**: Risk and context assessment
   - **Next steps**: Specific investigation recommendations
4. **Fallback** — If Ollama is unavailable, a template-based explanation is selected by `(event_category, severity)`. The fallback is recorded in the `LLMResult` (`source="template"`, `fallback_used=True`).

### Template Fallbacks (6)

| Template | Trigger Condition |
|----------|------------------|
| Authentication template | `event_category = 'authentication'` |
| Process template | `event_category = 'process'` |
| Network template | `event_category = 'network'` |
| File template | `event_category = 'file'` |
| Critical severity template | `severity = 'critical'` |
| Generic template | Default fallback |

### Example Explanation

For an SSH Brute Force alert:

> **What happened**: Multiple failed SSH login attempts (8 within 5 minutes) were detected from source IP 203.0.113.50 targeting host web-server-01.
>
> **Why it matters**: This pattern is consistent with credential brute-force attacks (MITRE T1110). Successful compromise could lead to unauthorized access.
>
> **Next steps**: 1) Check if any successful logins followed from this IP. 2) Block the source IP via firewall. 3) Review user accounts on the target host for weak passwords.

---

## Hunting Assistant

### Pre-Built Hunt Templates (7)

| ID | Name | Category | MITRE |
|----|------|----------|-------|
| `lateral_movement_service_accounts` | Lateral Movement — New Service Accounts | Persistence | T1078, T1021 |
| `data_staging_temp_files` | Data Staging in Temp Directories | Exfiltration | T1074 |
| `c2_beaconing_connections` | C2 Beaconing Connection Patterns | Command & Control | T1071 |
| `privilege_escalation_sudo` | Sudo-Based Privilege Escalation | Privilege Escalation | T1548 |
| `credential_dumping` | Credential Dumping Tool Execution | Credential Access | T1003 |
| `unusual_network_activity` | Unusual Outbound Network Activity | Command & Control | T1071 |
| `persistence_launch_agents` | LaunchAgent Persistence Creation | Persistence | T1547 |

Each template includes a ready-to-execute parameterized SQL query.

### MITRE Gap Analysis

The hunting assistant analyzes your current rule coverage against MITRE ATT&CK and identifies:
- **Covered tactics**: Tactics where you have detection rules
- **Uncovered tactics**: Tactics with no detection rules (gaps)
- **Weak techniques**: Techniques with only 1-2 rules covering them
- **Suggested hunts**: Recommended hunting queries for weak coverage areas

### Hunt from Alert

Given an alert, the hunting assistant:
1. Extracts key indicators (IPs, users, hosts, processes)
2. Generates targeted hunting queries pivoting on those indicators
3. Suggests broader investigation paths based on the MITRE technique

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/hunt/suggestions` | GET | Get hunting suggestions |
| `/api/v1/hunt/execute` | POST | Execute a hunt query |
| `/api/v1/hunt/from-alert/{alert_id}` | GET | Generate hunts from an alert |
| `/api/v1/hunt/mitre-gaps` | GET | MITRE ATT&CK coverage gaps |
| `/api/v1/hunt/history` | GET | Hunt execution history |

---

## Risk Scoring

### Factor Weights

The risk scoring engine (`src/ai/risk_scoring.py`) combines multiple signals into a single 0-100 risk score:

| Factor | Weight | Description |
|--------|--------|-------------|
| Alert Severity | 30% | Critical=50, High=40, Medium=25, Low=10, Info=0 |
| Alert Count | 20% | Normalized count of recent alerts on the entity |
| UEBA Anomaly | 25% | Behavioral anomaly score (0-1 from Isolation Forest) |
| Threat Intel Match | 15% | +15 if source IP appears in threat intel feeds |
| Exposure | 10% | Internet-facing assets score higher |

### Alert Risk Score

Individual alert risk = `base_severity_score + asset_criticality_adj + threat_intel_adj + anomaly_adj`

- Base severity: Critical=50, High=40, Medium=25, Low=10, Info=0
- Asset criticality: Up to +20 (based on host vulnerability/exposure)
- Threat intel match: +15 if source IP is in any feed
- User anomaly: Up to +15 (from UEBA baseline deviation)

All scores are capped at 100.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ai/risk/alert/{alert_id}` | GET | Risk score for a specific alert |
| `/api/v1/ai/risk/asset/{hostname}` | GET | Risk score for a host/asset |
| `/api/v1/ai/risk/user/{username}` | GET | Risk score for a user |

---

## Chat Endpoint

The `/api/v1/chat` endpoint exposes a conversational interface backed by the same Ollama client. The system prompt is rendered from `CHAT_SYSTEM_PROMPT_VERSION = "v1.0.0"`. The endpoint:

1. Loads the recent alert context for the user
2. Renders the chat system prompt with that context
3. Calls Ollama with the user's message + history
4. Returns the `LLMResult` (text, model, token counts, latency)

The chat endpoint is **read-only** — it has no access to mutation routes. All responses cite the alert IDs they referenced for audit.
