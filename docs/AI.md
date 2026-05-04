# AI Features Documentation

SecurityScarletAI integrates AI/ML throughout the detection-to-response pipeline. All AI features degrade gracefully when Ollama is unavailable — template and rule-based fallbacks ensure the system never blocks on LLM availability.

---

## Natural Language → SQL (NL→SQL)

### How It Works

The NL→SQL engine converts plain English security questions into safe, parameterized SQL queries:

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

### Injection Defense

The 7-layer defense prevents SQL injection from natural language input:

| Layer | Protection |
|-------|-----------|
| 1. Input sanitization | Strips common prompt injection patterns (`ignore instructions`, `you are now`, etc.) |
| 2. LLM system prompt | Instructs the model to generate only SELECT queries |
| 3. sqlparse validation | Rejects any non-SELECT statement at the AST level |
| 4. FORBIDDEN_PATTERNS regex | Blocks `DROP`, `ALTER`, `CREATE`, `TRUNCATE`, `INSERT`, `UPDATE`, `DELETE`, `GRANT`, `REVOKE`, `COPY`, system tables |
| 5. EXPLAIN cost check | Rejects queries estimated to scan > 10,000 rows |
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

The alert triage system uses a **Random Forest classifier** (scikit-learn) to predict whether alerts are true positives or false positives, and to prioritize them for analyst review.

### Feature Engineering (11 Features)

| Feature | Type | Description |
|---------|------|-------------|
| `severity_score` | Float | Severity mapped to numeric (critical=4, high=3, medium=2, low=1, info=0) |
| `source_ip_entropy` | Float | Shannon entropy of source IPs across alerts (diversity = suspicious) |
| `process_name_entropy` | Float | Shannon entropy of process names (diversity indicates anomaly) |
| `host_count` | Int | Number of distinct hosts affected |
| `event_count` | Int | Number of related events |
| `has_threat_intel_match` | Bool | Whether source IP appears in threat intel feeds |
| `has_geo_anomaly` | Bool | Whether source IP is from an unusual geographic location |
| `is_off_hours` | Bool | Whether alert occurred outside business hours |
| `hour_of_day` | Float | Sin/cos-encoded hour of alert (circadian pattern) |
| `day_of_week` | Float | Sin/cos-encoded day of week |
| `login_hour_deviation` | Float | How much the alert hour deviates from that user's typical pattern |

### Auto-Training

The model auto-trains when 100+ resolved alerts exist:
1. Alerts with status `resolved` or `false_positive` become training data
2. Features are extracted from each alert's context
3. Random Forest (100 estimators) is trained with class weight balancing
4. Model is saved with SHA-256 integrity hash to `models/triage_model.joblib`
5. Model metadata is saved to `models/triage_meta.joblib`

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ai/triage/train` | POST | Trigger model training |
| `/api/v1/ai/triage/status` | GET | Get training status and model info |
| `/api/v1/ai/triage/predict` | POST | Get triage prediction for an alert |
| `/api/v1/ai/triage/explain` | POST | Get feature importance explanation |

### Model Integrity

- Models are saved using `joblib` with SHA-256 hash verification
- Hash is stored in `models/triage_model.sha256`
- On load, the hash is verified before the model is used
- This prevents tampering with the trained model file

---

## UEBA (User and Entity Behavior Analytics)

### How It Works

The UEBA module builds behavioral baselines for each user using an **Isolation Forest** anomaly detection model:

1. **Feature extraction** — For each user per day, extract 7 behavioral features
2. **Baseline training** — Isolation Forest learns "normal" behavior patterns
3. **Anomaly scoring** — New events are scored against the baseline (0-1 scale)
4. **Flagging** — Users with anomaly scores above the contamination threshold are flagged

### Behavioral Features (7)

| Feature | Calculation | Anomaly Signal |
|---------|-------------|----------------|
| `login_hour_of_day` | Mode hour of user's logins | Off-hours access |
| `unique_processes_count` | Count of distinct processes | Unusual tool usage |
| `command_diversity` | Shannon entropy of process names | Abnormal process variety |
| `network_connections_count` | Outbound connection count | Excessive networking |
| `unique_destination_ips` | Distinct IPs contacted | Broad network reach |
| `file_access_count` | File operations count | Excessive file access |
| `sudo_usage_count` | Privilege escalation count | Unusual sudo patterns |
| `session_duration_minutes` | Time between first/last event | Abnormally long sessions |

### Scoring

- **Anomaly score**: 0.0 (normal) to 1.0 (highly anomalous)
- Default contamination rate: 0.05 (top 5% of behavior flagged)
- Scores feed into the Risk Scoring engine as the `anomaly_score` factor

---

## Alert Explanation (LLM)

### How It Works

When an alert is created, the system generates a human-readable explanation:

1. **Context assembly** — Rule name, severity, affected host, MITRE techniques, and evidence are gathered
2. **LLM query** — Ollama is asked to explain the alert in 2-4 sentences covering:
   - **What happened**: Brief description of detected activity
   - **Why it matters**: Risk and context assessment
   - **Next steps**: Specific investigation recommendations
3. **Fallback** — If Ollama is unavailable, one of 6 template-based explanations is used

### Template Fallbacks

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
| `impossible_travel_check` | Impossible Travel — Geographic Anomaly | Initial Access | T1078 |
| `new_process_from_tmp` | Suspicious /tmp Process Execution | Execution | T1059 |
| `dns_tunneling_hunt` | DNS Tunneling Indicators | Command & Control | T1071 |
| `credential_access_patterns` | Credential Access Attempts | Credential Access | T1003 |
| `data_staging_exfil` | Data Staging and Exfiltration | Exfiltration | T1048 |
| `c2_beaconing_hunt` | C2 Beaconing Detection | Command & Control | T1071 |

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

The risk scoring engine combines multiple signals into a single 0-100 risk score:

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
| `/api/v1/ai/risk/user/{username}` | GET | Risk score for a user |_