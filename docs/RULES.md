# Detection Rules Reference

SecurityScarletAI ships with **45 Sigma rules** and **12 correlation rules** (5 SQL + 7 sequence-based), covering authentication, process, network, file, macOS, and cloud attack patterns.

All rules are MITRE ATT&CK mapped and use the Sigma YAML specification, compiled to safe parameterized SQL via our custom pySigma PostgreSQL backend.

---

## Authentication Rules (9)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | SSH Brute Force Detected | High | Credential Access | T1110 | Multiple failed SSH login attempts from the same source IP |
| 2 | Failed Login Spike | High | Credential Access | T1110 | Spike of failed logins across multiple accounts from one source |
| 3 | Login from Unusual Geography | Medium | Initial Access | T1078 | Successful auth from IP with unexpected geographic origin |
| 4 | Multiple Account Lockouts | High | Credential Access | T1110 | Multiple account lockouts from the same source IP |
| 5 | Privilege Escalation via Sudo | Medium | Privilege Escalation | T1548 | Sudo execution for privilege escalation |
| 6 | Root Login from Non-Console | High | Privilege Escalation | T1078 | Root user login from remote or non-console session |
| 7 | Credential Dumping Attempt | Critical | Credential Access | T1003 | Mimikatz, procdump, LaZagne, or keychain dump processes |
| 8 | SSH Successful Login After Failures | Critical | Credential Access | T1110 | Successful SSH login following multiple failed attempts |
| 9 | Service Account Anomaly | Low | Initial Access | T1078 | Service account authentication outside normal patterns |

## Process Rules (8)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Reverse Shell Pattern Detected | Critical | Execution | T1059 | Common reverse shell patterns (bash -i, socat, nc -e, etc.) |
| 2 | Suspicious Process from /tmp | Medium | Execution | T1059 | Process execution from temporary directories |
| 3 | Living-off-the-Land Binary Execution | Medium | Defense Evasion | T1218 | LOLBin abuse (curl, wget, base64, xattr, launchctl, defaults) |
| 4 | Encoded Command Execution | High | Defense Evasion | T1027 | Base64-encoded or obfuscated command execution |
| 5 | Suspicious Parent-Child Process Chain | Medium | Execution | T1059 | Unusual parent-child process relationships |
| 6 | Download and Execute Pattern | High | Execution | T1059 | Download-then-execute patterns from malware droppers |
| 7 | Script Interpreter from Unexpected Location | Medium | Execution | T1059 | Python, Perl, Ruby, Node running from /tmp or unusual paths |
| 8 | Process Injection Indicator | High | Privilege Escalation | T1055 | ptrace, lldb, dtrace, or LD_PRELOAD injection |

## Network Rules (7)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Suspicious DNS Query | Low | Command and Control | T1071 | DNS queries to suspicious or known-malicious domains |
| 2 | DNS Tunneling Indicators | Medium | Command and Control | T1071 | DNS query patterns indicating tunneling for data exfiltration |
| 3 | C2 Beaconing Pattern | Medium | Command and Control | T1071 | Regular-interval outbound connections suggesting C2 |
| 4 | Data Exfiltration Volume | High | Exfiltration | T1048 | Large outbound data transfers indicating exfiltration |
| 5 | Tor Exit Node Connection | Medium | Command and Control | T1090 | Connections to known Tor exit node ports |
| 6 | Internal Lateral Movement | Medium | Lateral Movement | T1021 | Internal connections on SSH, RDP, SMB, or VNC ports |
| 7 | Outbound Connection to Rare/C2 Port | High | Command and Control | T1071 | Outbound connections to ports 4444, 31337, 6667, etc. |

## File Rules (6)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Sensitive File Access | High | Credential Access | T1003 | Access to /etc/shadow, .ssh/id_rsa, authorized_keys |
| 2 | Ransomware File Encryption Pattern | Critical | Impact | T1486 | Rapid file encryption patterns (openssl enc, gpg symmetric) |
| 3 | Cron Job Modification | Medium | Persistence | T1053 | Modification of cron jobs for persistence |
| 4 | Webshell Creation | Critical | Persistence | T1505 | PHP files created in web-served directories |
| 5 | Log File Deletion | Critical | Defense Evasion | T1070 | rm/shred/srm targeting /var/log files |
| 6 | Binary Replacement or Hijacking | High | Persistence | T1574 | Modification of system binaries or libraries |

## macOS-Specific Rules (10)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | LaunchAgent Persistence Created | High | Persistence | T1547 | Creation of macOS LaunchAgent plist files |
| 2 | LaunchDaemon Persistence Created | Critical | Persistence | T1547 | Creation of macOS LaunchDaemon plist files |
| 3 | TCC Database Modification | Critical | Defense Evasion | T1562 | Modification of macOS TCC (permissions) database |
| 4 | Gatekeeper Bypass Attempt | High | Defense Evasion | T1553 | spctl, xattr quarantine removal, or codesign tampering |
| 5 | XProtect Removal or Modification | Critical | Defense Evasion | T1562 | Modification or deletion of macOS XProtect files |
| 6 | Safari Extension Installation | Medium | Persistence | T1176 | Installation of browser extensions in Safari |
| 7 | Keychain Access by Unusual Process | High | Credential Access | T1555 | Access to macOS Keychain via security find-generic-password |
| 8 | SIP Modification | Critical | Defense Evasion | T1562 | Attempts to disable System Integrity Protection |
| 9 | Authorization Database Modification | High | Privilege Escalation | T1548 | Modification of macOS authorization database |
| 10 | Hidden File Creation in User Directories | Low | Defense Evasion | T1564 | Hidden (dot-prefix) file creation in user home |

## Cloud Rules (5)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Impossible Travel — Distant Logins | Critical | Initial Access | T1078 | Auth from two distant locations within impossible time window |
| 2 | API Key Usage from New IP | Medium | Initial Access | T1078 | API key authentication from previously unseen IP |
| 3 | Bulk Data Download | Medium | Exfiltration | T1567 | Unusually large data downloads from cloud services |
| 4 | SaaS Permission Escalation | High | Privilege Escalation | T1078 | Permission/role changes in SaaS applications |
| 5 | New Admin Account Creation | High | Persistence | T1136 | Creation of new accounts with admin privileges |

---

## Correlation Rules (5 SQL-Based)

These rules detect multi-step attack chains by correlating events across time windows.

| # | Rule Name | Severity | MITRE Tactics | MITRE Techniques | Description |
|---|-----------|----------|---------------|------------------|-------------|
| 1 | Brute Force → Successful Login | Critical | Credential Access | T1110 | N failed logins followed by success from same source IP |
| 2 | Dropped Payload → C2 Callback | Critical | Execution, C2 | T1059, T1071 | Process from /tmp followed by outbound network connection |
| 3 | Persistence Created → Activated | High | Persistence | T1547 | LaunchAgent creation followed by launchctl load |
| 4 | Large Read → Large Network Transfer | High | Exfiltration | T1048 | Large file reads followed by significant outbound transfers |
| 5 | Privilege Escalation → Root Process | Critical | Privilege Escalation | T1548 | Sudo followed by new root-level process execution |

---

## Sequence Rules (7 Event-Based)

These define event sequence patterns (A → B within N minutes) for multi-event detection.

| # | Rule Name | Severity | Time Window | MITRE Tactics | Description |
|---|-----------|----------|-------------|---------------|-------------|
| 1 | Brute Force → Successful Login | Critical | 5 min | TA0006 | Failed auth followed by success |
| 2 | Dropped Payload → C2 Callback | Critical | 10 min | TA0002, TA0011 | /tmp process → outbound connection |
| 3 | Persistence Created → Activated | High | 30 min | TA0003 | LaunchAgent → launchctl load |
| 4 | Large File Read → Network Transfer | High | 60 min | TA0010 | Data read → outbound transfer |
| 5 | Privilege Escalation → Root Process | Critical | 10 min | TA0004 | Sudo → root process |
| 6 | Credential Access → External Connection | Critical | 15 min | TA0006, TA0010 | .ssh access → outbound |
| 7 | Suspicious Activity → Log Deletion | High | 30 min | TA0005 | High-severity process → log cleanup |

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

---

## Rule Testing Workflow

1. **Write the rule** as a YAML file in `rules/sigma/<category>/`
2. **Verify YAML syntax**:
   ```bash
   python -c "import yaml; yaml.safe_load(open('rules/sigma/category/rule.yml'))"
   ```
3. **Restart the API** — Rules are loaded from disk at startup:
   ```bash
   poetry run uvicorn src.api.main:app --reload
   ```
4. **Trigger the rule** by ingesting matching events:
   ```bash
   curl -X POST http://localhost:8000/api/v1/ingest \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '[{"host_name":"test-host","source":"test","event_category":"process",
           "event_type":"start","process_name":"suspicious_binary"}]'
   ```
5. **Check alerts**:
   ```bash
   curl http://localhost:8000/api/v1/alerts | jq
   ```
6. **Verify via unit tests** — Add test cases to `tests/unit/test_sigma.py`

---

## Correlation Rule Testing

Correlation rules run on a scheduler and query the database directly. Test by:

1. **Ingest the trigger events** (e.g., failed logins followed by a success)
2. **Run correlations manually**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/correlation/run
   ```
3. **Check correlation results**:
   ```bash
   curl http://localhost:8000/api/v1/correlation/results | jq
   ```

Each correlation rule applies confidence scoring — base confidence + bonus for additional signals.