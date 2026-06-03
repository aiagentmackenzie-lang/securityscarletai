# Detection Rules Reference

SecurityScarletAI ships with **45 Sigma rules** and **7 event-driven correlation rules**, covering authentication, process, network, file, macOS, and cloud attack patterns. All rules are MITRE ATT&CK mapped and written in the Sigma YAML specification, compiled to safe parameterized SQL via our custom pySigma PostgreSQL backend.

---

## Sigma Rule Catalog (45 total)

45 rules distributed across 6 categories. Each rule is a YAML file under `rules/sigma/<category>/`.

### Authentication (9 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | SSH Brute Force Detected | High | Credential Access (TA0006) | T1110 | Multiple failed SSH login attempts from the same source IP |
| 2 | Failed Login Spike | High | Credential Access (TA0006) | T1110 | Spike of failed logins across multiple accounts from one source |
| 3 | Login from Unusual Geography | Medium | Initial Access (TA0001) | T1078 | Successful auth from IP with unexpected geographic origin |
| 4 | Multiple Account Lockouts | High | Credential Access (TA0006) | T1110 | Multiple account lockouts from the same source IP |
| 5 | Privilege Escalation via Sudo | Medium | Privilege Escalation (TA0004) | T1548 | Sudo execution for privilege escalation |
| 6 | Root Login from Non-Console | High | Privilege Escalation (TA0004) | T1078 | Root user login from remote or non-console session |
| 7 | Credential Dumping Attempt | Critical | Credential Access (TA0006) | T1003 | Mimikatz, procdump, LaZagne, or keychain dump processes |
| 8 | SSH Successful Login After Failures | Critical | Credential Access (TA0006) | T1110 | Successful SSH login following multiple failed attempts |
| 9 | Service Account Anomaly | Low | Initial Access (TA0001) | T1078 | Service account authentication outside normal patterns |

### Process (8 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Reverse Shell Pattern Detected | Critical | Execution (TA0002) | T1059 | Common reverse shell patterns (`bash -i`, `socat`, `nc -e`, etc.) |
| 2 | Suspicious Process from /tmp | Medium | Execution (TA0002) | T1059 | Process execution from temporary directories |
| 3 | Living-off-the-Land Binary Execution | Medium | Defense Evasion (TA0005) | T1218 | LOLBin abuse (`curl`, `wget`, `base64`, `xattr`, `launchctl`, `defaults`) |
| 4 | Encoded Command Execution | High | Defense Evasion (TA0005) | T1027 | Base64-encoded or obfuscated command execution |
| 5 | Suspicious Parent-Child Process Chain | Medium | Execution (TA0002) | T1059 | Unusual parent-child process relationships |
| 6 | Download and Execute Pattern | High | Execution (TA0002) | T1059 | Download-then-execute patterns from malware droppers |
| 7 | Script Interpreter from Unexpected Location | Medium | Execution (TA0002) | T1059 | Python, Perl, Ruby, Node running from /tmp or unusual paths |
| 8 | Process Injection Indicator | High | Privilege Escalation (TA0004) | T1055 | `ptrace`, `lldb`, `dtrace`, or `LD_PRELOAD` injection |

### Network (7 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Suspicious DNS Query | Low | Command and Control (TA0011) | T1071 | DNS queries to suspicious or known-malicious domains |
| 2 | DNS Tunneling Indicators | Medium | Command and Control (TA0011) | T1071 | DNS query patterns indicating tunneling for data exfiltration |
| 3 | C2 Beaconing Pattern | Medium | Command and Control (TA0011) | T1071 | Regular-interval outbound connections suggesting C2 |
| 4 | Data Exfiltration Volume | High | Exfiltration (TA0010) | T1048 | Large outbound data transfers indicating exfiltration |
| 5 | Tor Exit Node Connection | Medium | Command and Control (TA0011) | T1090 | Connections to known Tor exit node ports |
| 6 | Internal Lateral Movement | Medium | Lateral Movement (TA0008) | T1021 | Internal connections on SSH, RDP, SMB, or VNC ports |
| 7 | Outbound Connection to Rare/C2 Port | High | Command and Control (TA0011) | T1071 | Outbound connections to ports 4444, 31337, 6667, etc. |

### File (6 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Sensitive File Access | High | Credential Access (TA0006) | T1003 | Access to `/etc/shadow`, `.ssh/id_rsa`, `authorized_keys` |
| 2 | Ransomware File Encryption Pattern | Critical | Impact (TA0040) | T1486 | Rapid file encryption patterns (`openssl enc`, `gpg symmetric`) |
| 3 | Cron Job Modification | Medium | Persistence (TA0003) | T1053 | Modification of cron jobs for persistence |
| 4 | Webshell Creation | Critical | Persistence (TA0003) | T1505 | PHP files created in web-served directories |
| 5 | Log File Deletion | Critical | Defense Evasion (TA0005) | T1070 | `rm`/`shred`/`srm` targeting `/var/log` files |
| 6 | Binary Replacement or Hijacking | High | Persistence (TA0003) | T1574 | Modification of system binaries or libraries |

### macOS (10 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | LaunchAgent Persistence Created | High | Persistence (TA0003) | T1547 | Creation of macOS LaunchAgent plist files |
| 2 | LaunchDaemon Persistence Created | Critical | Persistence (TA0003) | T1547 | Creation of macOS LaunchDaemon plist files |
| 3 | TCC Database Modification | Critical | Defense Evasion (TA0005) | T1562 | Modification of macOS TCC (permissions) database |
| 4 | Gatekeeper Bypass Attempt | High | Defense Evasion (TA0005) | T1553 | `spctl`, `xattr` quarantine removal, or `codesign` tampering |
| 5 | XProtect Removal or Modification | Critical | Defense Evasion (TA0005) | T1562 | Modification or deletion of macOS XProtect files |
| 6 | Safari Extension Installation | Medium | Persistence (TA0003) | T1176 | Installation of browser extensions in Safari |
| 7 | Keychain Access by Unusual Process | High | Credential Access (TA0006) | T1555 | Access to macOS Keychain via `security find-generic-password` |
| 8 | SIP Modification | Critical | Defense Evasion (TA0005) | T1562 | Attempts to disable System Integrity Protection |
| 9 | Authorization Database Modification | High | Privilege Escalation (TA0004) | T1548 | Modification of macOS authorization database |
| 10 | Hidden File Creation in User Directories | Low | Defense Evasion (TA0005) | T1564 | Hidden (dot-prefix) file creation in user home |

### Cloud (5 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Impossible Travel — Distant Logins | Critical | Initial Access (TA0001) | T1078 | Auth from two distant locations within impossible time window |
| 2 | API Key Usage from New IP | Medium | Initial Access (TA0001) | T1078 | API key authentication from previously unseen IP |
| 3 | Bulk Data Download | Medium | Exfiltration (TA0010) | T1567 | Unusually large data downloads from cloud services |
| 4 | SaaS Permission Escalation | High | Privilege Escalation (TA0004) | T1078 | Permission/role changes in SaaS applications |
| 5 | New Admin Account Creation | High | Persistence (TA0003) | T1136 | Creation of new accounts with admin privileges |

---

## Correlation Rules (7 event-driven)

The correlation engine (`src/detection/correlation.py`) defines 7 multi-step attack chain detectors. Each rule is **event-driven** (queries the `logs` table with an explicit `as_of` timestamp for point-in-time safety — no `NOW()` baked into SQL) and returns matches with a unique `correlation_id`. When `run_all_correlations(persist=True)` is called, matches are written to the `correlation_matches` table and surfaced as alerts via `create_alert()`.

| # | Rule ID | Title | Severity | Confidence (base) | MITRE Tactics | MITRE Techniques | Description |
|---|---------|-------|----------|-------------------|---------------|------------------|-------------|
| 1 | `brute_force_success` | Brute Force → Successful Login | Critical | 80% | Credential Access (TA0006) | T1110 | N failed logins followed by success from same source IP |
| 2 | `payload_callback` | Dropped Payload → C2 Callback | Critical | 75% | Execution (TA0002), C2 (TA0011) | T1059, T1071 | Process from `/tmp` followed by outbound network connection |
| 3 | `persistence_activated` | Persistence Created → Activated | High | 70% | Persistence (TA0003) | T1547 | LaunchAgent creation followed by `launchctl load` |
| 4 | `data_exfiltration` | Large Read → Large Network Transfer | High | 65% | Exfiltration (TA0010) | T1048 | Large file reads followed by significant outbound transfers |
| 5 | `privilege_escalation_chain` | Privilege Escalation → Root Process | Critical | 70% | Privilege Escalation (TA0004) | T1548 | Sudo followed by new root-level process execution |
| 6 | `credential_theft_exfil` | Credential Access → External Connection | Critical | 80% | Credential Access (TA0006), Exfiltration (TA0010) | T1555, T1048 | Access to sensitive credential files followed by outbound network connection |
| 7 | `defense_evasion_cleanup` | Suspicious Activity → Log Deletion | High | 70% | Defense Evasion (TA0005) | T1070 | High-severity process followed by log file deletion |

### Programmatic invocation

```python
from src.detection.correlation import run_all_correlations

# Manual retro-hunt (no DB writes)
result = await run_all_correlations(as_of=datetime.now(timezone.utc), persist=False)

# Persist matches to correlation_matches + create alerts
result = await run_all_correlations(as_of=..., persist=True)
# Returns: {"matches": [...], "total_matches": N, "persisted": N,
#          "as_of": ..., "per_rule": {...}}
```

The ingestion endpoint (`POST /api/v1/ingest`) fires `run_all_correlations(persist=True)` as a fire-and-forget background task after each batch insert.

---

## Writing Custom Sigma Rules

Create a YAML file in the appropriate subdirectory under `rules/sigma/`:

```yaml
title: Your Custom Rule Name
id: scarlet-custom-001
status: experimental
description: Detects a specific suspicious activity pattern
author: Your Name
date: 2026/01/01
logsource:
    category: process          # One of: authentication, process, network, file
detection:
    selection:
        event_type: start
        process_name: suspicious_binary
        process_cmdline|contains: suspicious_flag
    condition: selection
level: high                    # One of: info, low, medium, high, critical
tags:
    - attack.execution          # MITRE tactic (attack.<tactic_name>)
    - attack.ta0002             # MITRE tactic ID
    - attack.t1059              # MITRE technique ID
```

### Supported Detection Fields

| Field | Description | Example |
|-------|-------------|---------|
| `event_type` | Event type | `start`, `end`, `connection`, `creation` |
| `event_action` | Specific action | `failed`, `success`, `login`, `modification` |
| `event_category` | ECS category | `process`, `network`, `file`, `authentication` |
| `host_name` | Hostname | `web-server-01` |
| `source_ip` | Source IP | `10.0.0.5` |
| `destination_ip` | Destination IP | `203.0.113.50` |
| `destination_port` | Destination port | `4444` |
| `process_name` | Process binary name | `curl`, `bash`, `nc` |
| `process_cmdline` | Full command line | `bash -i >& /dev/tcp/...` |
| `process_path` | Binary path | `/usr/bin/curl` |
| `user_name` | Username | `root`, `admin` |
| `file_path` | File path | `/etc/shadow` |

### Supported Detection Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `|contains` | Substring match | `process_cmdline|contains: curl` |
| `|endswith` | Suffix match | `file_path|endswith: .php` |
| `|startswith` | Prefix match | `file_path|startswith: /tmp` |
| List values | OR condition | `process_name: [curl, wget, nc]` |

### Aggregation Conditions

Rules support count-based aggregation:

```yaml
condition: selection | count(source_ip) by host_name > 5
```

This triggers when more than 5 events from the same source IP occur per host within the specified timeframe.

### Timeframes

```yaml
timeframe: 5m    # 5 minutes
timeframe: 1h    # 1 hour
timeframe: 24h   # 24 hours
```

The timeframe sets the rolling window for the detection query.

---

## Testing Rules

Use the Sigma compiler directly to verify a rule compiles to safe SQL:

```python
from src.detection.sigma import compile_sigma_rule

with open("rules/sigma/process/my_new_rule.yml") as f:
    rule_yaml = f.read()

sql, params = compile_sigma_rule(rule_yaml)
print(sql)       # Parameterized SQL (no string interpolation)
print(params)    # Bound parameters
```

Unit tests under `tests/unit/test_sigma.py` exercise the compiler across all 45 bundled rules.

---

## Rule Lifecycle

- **Loading**: `src/detection/sigma.py` loads all `.yml` files under `rules/sigma/` at API startup.
- **Evaluation**: The detection scheduler ticks periodically and runs each rule against recent `logs` rows.
- **Alert creation**: Matching rows are inserted into the `alerts` table via `create_alert()`.
- **Suppression**: Per-rule suppression rules in the `alert_suppressions` table allow tuning false-positive rates without modifying rule YAML.
- **Tuning**: When a rule generates too many false positives, either (a) add a suppression rule, (b) tighten the detection condition, or (c) retrain the triage model (see [docs/AI.md](AI.md)) to better rank its output.
