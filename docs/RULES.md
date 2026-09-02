# Detection Rules Reference

SecurityScarletAI ships with **100 Sigma rules** and **7 event-driven correlation rules**, covering authentication, process, network, file, macOS, and cloud attack patterns. All rules are MITRE ATT&CK mapped and written in the Sigma YAML specification, compiled to safe parameterized SQL by the legacy `SigmaParser` + custom PostgreSQL backend in `src/detection/sigma.py`. (A pySigma-backed `PostgreSQLBackend` is retained as a unit-tested module but is off the production detection path — see P0-01/P0-04.)

---

## Sigma Rule Catalog (100 total)

100 rules distributed across 6 categories. Each rule is a YAML file under `rules/sigma/<category>/`. Generated from the rule frontmatter — regenerate rather than hand-editing.

### Authentication (14 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Anomalous Kerberos Ticket Request | Medium | Lateral Movement (TA0008) | T1558 | Detects a Kerberos TGS-REQ for a sensitive service principal (kerberoasting) |
| 2 | Credential Dumping Attempt | Medium | Credential Access (TA0006) | T1003 | Detects processes associated with credential dumping activity |
| 3 | Failed Login Spike | Medium | Credential Access (TA0006) | T1110 | Detects a spike of failed login attempts across multiple accounts from the same source |
| 4 | Kerberoasting Service Ticket Request | Medium | Credential Access (TA0006) | T1558 | Detects an unusual volume of TGS requests for SPNs (kerberoasting indicator) |
| 5 | Login from Unusual Geography | Medium | Initial Access (TA0001) | T1078 | Detects successful authentication from an IP address that does not match expected geographic patterns |
| 6 | Multiple Account Lockouts | Medium | Credential Access (TA0006) | T1110 | Detects multiple account lockouts from the same source IP, indicating systematic password guessing |
| 7 | New Account Created | Medium | Persistence (TA0003) | T1136 | Detects creation of a new user account (possible persistence backdoor) |
| 8 | Password Spray Pattern | Medium | Credential Access (TA0006) | T1110 | Detects many usernames failing auth from one source in a short window |
| 9 | Privilege Escalation via Sudo | Medium | Privilege Escalation (TA0004) | T1548 | Detects privilege escalation attempts using sudo |
| 10 | RDP Login From Anomalous Source | Medium | Lateral Movement (TA0008) | T1021 | Detects an RDP authentication worth investigating for lateral movement |
| 11 | Root Login from Non-Console | Medium | Privilege Escalation (TA0004) | T1078 | Detects root user login from a remote or non-console session, which is unusual and potentially malicious |
| 12 | Service Account Anomaly | Medium | Initial Access (TA0001) | T1078 | Detects authentication events from service accounts outside of normal patterns |
| 13 | SSH Brute Force Detected | Medium | Credential Access (TA0006) | T1110 | Detects multiple failed SSH login attempts from the same source IP, indicating a brute force attack |
| 14 | SSH Successful Login After Multiple Failures | Medium | Credential Access (TA0006) | T1110 | Detects repeated failed SSH logins from a single source — a brute-force indicator. NOTE (P1-04): the origin... |

### Process (34 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | ADFS Token Signing Key Modification | Medium | Credential Access (TA0006) | T1606 | Detects modification of federation token-signing key material (token forgery) |
| 2 | Alternative Authentication Package Loaded | Medium | Lateral Movement (TA0008) | T1550 | Detects loading of a non-standard auth package (token theft / lateral movement) |
| 3 | Archive Created Before Transfer | Medium | Exfiltration (TA0010) | T1560 | Detects creation of a compressed archive (staging for exfiltration) |
| 4 | Command History Cleared | Medium | Defense Evasion (TA0005) | T1070 | Detects truncation/deletion of shell history (defense evasion) |
| 5 | Credentials Passed on Command Line | Medium | Credential Access (TA0006) | T1552 | Detects password-like strings passed on a process command line |
| 6 | Cron Job Creation | Medium | Persistence (TA0003) | T1053 | Detects creation or modification of cron jobs (persistence) |
| 7 | Data Exfil to Cloud Storage | Medium | Exfiltration (TA0010) | T1567 | Detects cloud-storage CLI upload commands (exfiltration via cloud object stores) |
| 8 | DNS-over-HTTPS Tunneling Indicator | Medium | Defense Evasion (TA0005) | T1071 | Detects a process configured to use a DoH resolver (potential covert channel) |
| 9 | Download and Execute Pattern | Medium | Execution (TA0002) | T1059 | Detects download-then-execute patterns commonly used by malware droppers |
| 10 | Encoded Command Execution | Medium | Defense Evasion (TA0005) | T1027 | Detects execution of base64-encoded commands, commonly used by attackers to obfuscate malicious payloads |
| 11 | Encoded PowerShell Download Cradle | Medium | Defense Evasion (TA0005) | T1027 | Detects base64-encoded PowerShell download cradels (obfuscated execution) |
| 12 | Event Log Cleared | Medium | Defense Evasion (TA0005) | T1070 | Detects clearing of system event logs (defense evasion) |
| 13 | File Timestomping via touch -r | Medium | Defense Evasion (TA0005) | T1070 | Detects use of touch -r to clone file timestamps (timestomping) |
| 14 | LD_PRELOAD Process Injection | Medium | Defense Evasion (TA0005) | T1055 | Detects LD_PRELOAD used to inject a shared object into a process (injection) |
| 15 | Living-off-the-Land Binary Execution | Medium | Defense Evasion (TA0005) | T1218 | Detects execution of LOLBins (living-off-the-land binaries) commonly abused by attackers for fileless malware |
| 16 | Logging Disabled | Medium | Defense Evasion (TA0005) | T1562 | Detects commands disabling audit/syslog logging (defense evasion) |
| 17 | LSASS Memory Dump Attempt | Medium | Credential Access (TA0006) | T1003 | Detects process command lines attempting to dump LSASS memory (credential theft) |
| 18 | Process Injection Indicator | Medium | Privilege Escalation (TA0004) | T1055 | Detects potential process injection indicators through unusual debugging or tracing activity |
| 19 | PsExec Service Creation | Medium | Lateral Movement (TA0008) | T1021 | Detects PsExec-style remote service creation (lateral movement) |
| 20 | Renamed System Binary (Masquerading) | Medium | Defense Evasion (TA0005) | T1036 | Detects renamed copies of system utilities executing from non-standard paths |
| 21 | Reverse Shell Pattern Detected | Medium | Execution (TA0002) | T1059 | Detects common reverse shell patterns in command lines indicating a compromised host calling back to attacker |
| 22 | Scheduled Task Creation | Medium | Persistence (TA0003) | T1053 | Detects creation of a scheduled task (persistence) |
| 23 | SCP Transfer to External Host | Medium | Exfiltration (TA0010) | T1048 | Detects scp/sftp transferring data to an external host (exfiltration) |
| 24 | Script Interpreter from Unexpected Location | Medium | Execution (TA0002) | T1059 | Detects script interpreters (python, perl, ruby, node) running from unexpected directories like /tmp or /va... |
| 25 | Secure File Deletion (shred) | Medium | Defense Evasion (TA0005) | T1070 | Detects use of shred to securely delete files (artifact destruction) |
| 26 | Security Tool Disabled | Medium | Defense Evasion (TA0005) | T1562 | Detects commands disabling security tooling (defense evasion) |
| 27 | Setuid Bit Set on Binary | Medium | Persistence (TA0003) | T1548 | Detects chmod setuid on a binary (persistence/privilege path) |
| 28 | Suspicious Parent-Child Process Chain | Medium | Execution (TA0002) | T1059 | Detects unusual parent-child process relationships often seen in attack chains |
| 29 | Suspicious Process from /tmp | Medium | Execution (TA0002) | T1059 | Detects process execution from temporary directories, common for malware staging |
| 30 | Systemd Service Creation | Medium | Persistence (TA0003) | T1543 | Detects creation of a systemd service unit (persistence) |
| 31 | Systemd Timer Creation | Medium | Persistence (TA0003) | T1543 | Detects creation of a systemd timer unit (persistence) |
| 32 | Tamper Protection Disabled | Medium | Defense Evasion (TA0005) | T1562 | Detects attempts to disable tamper protection on EDR/AV agents |
| 33 | Upload to File-Sharing Service | Medium | Exfiltration (TA0010) | T1567 | Detects uploads to consumer file-sharing services via CLI (exfiltration channel) |
| 34 | WMI Remote Execution | Medium | Lateral Movement (TA0008) | T1047 | Detects WMI-based remote process execution (lateral movement) |

### Network (17 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | ADMIN$ / IPC$ Share Access | Medium | Lateral Movement (TA0008) | T1021 | Detects access to administrative SMB shares (lateral movement indicator) |
| 2 | Bulk Transfer to External IP | Medium | Exfiltration (TA0010) | T1041 | Detects an elevated count of outbound connections to a single external IP (exfil) |
| 3 | C2 Beaconing Pattern | Medium | Command and Control (TA0011) | T1071 | Detects potential C2 beaconing through regular interval outbound connections to the same IP |
| 4 | Data Exfiltration Volume | Medium | Exfiltration (TA0010) | T1048 | Detects large outbound data transfers that may indicate data exfiltration |
| 5 | DNS Tunneling Indicators | Medium | Command and Control (TA0011) | T1071 | Detects DNS queries with suspicious patterns that may indicate DNS tunneling for data exfiltration |
| 6 | High-Volume DNS (Exfil Indicator) | Medium | Exfiltration (TA0010) | T1048 | Detects a host issuing an elevated volume of DNS queries (possible DNS exfil channel) |
| 7 | Internal Lateral Movement | Medium | Lateral Movement (TA0008) | T1021 | Detects internal host-to-host connections on management ports that may indicate lateral movement |
| 8 | Large Outbound HTTPS Transfer | Medium | Exfiltration (TA0010) | T1048 | Detects a large outbound HTTPS data transfer (possible exfiltration) |
| 9 | NTLM Relay Attempt | Medium | Credential Access (TA0006) | T1557 | Detects SMB/NTLM authentication to an unexpected internal destination (relay indicator) |
| 10 | Outbound Connection to Rare/C2 Port | Medium | Command and Control (TA0011) | T1071 | Detects outbound connections to non-standard ports commonly associated with C2 and malware |
| 11 | Outbound RDP to Unknown Host | Medium | Lateral Movement (TA0008) | T1021 | Detects outbound RDP sessions (lateral movement / exfil indicator) |
| 12 | Outbound SSH (Lateral Movement Indicator) | Medium | Lateral Movement (TA0008) | T1021 | Detects outbound SSH connections worth investigating for lateral movement |
| 13 | Pass-the-Hash SMB Authentication | Medium | Lateral Movement (TA0008) | T1550 | Detects SMB authentication with an NTLM hash (pass-the-hash indicator) |
| 14 | SMTP Exfiltration | Medium | Exfiltration (TA0010) | T1048 | Detects outbound SMTP sessions (email-based exfiltration channel) |
| 15 | Suspicious DNS Query | Medium | Command and Control (TA0011) | T1071 | Detects DNS queries to suspicious or known-malicious domains |
| 16 | Tor Exit Node Connection | Medium | Command and Control (TA0011) | T1090 | Detects connections to known Tor exit node ports indicating potential Tor usage or C2 via Tor |
| 17 | WinRM Remote Execution | Medium | Lateral Movement (TA0008) | T1021 | Detects WinRM-based remote command execution (lateral movement) |

### File (17 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | authorized_keys Modification | Medium | Persistence (TA0003) | T1098 | Detects modification of SSH authorized_keys (persistence via key backdoor) |
| 2 | Binary Replacement or Hijacking | Medium | Persistence (TA0003) | T1574 | Detects modification of system binaries or libraries, indicating potential DLL side-loading or binary repla... |
| 3 | Browser Credential Store Access | Medium | Credential Access (TA0006) | T1555 | Detects access to browser-stored credential databases |
| 4 | Cron Job Modification | Medium | Persistence (TA0003) | T1053 | Detects modification of cron jobs, a common persistence mechanism |
| 5 | Data Staged in Temporary Directory | Medium | Exfiltration (TA0010) | T1074 | Detects bulk data staged under /tmp or /var/tmp (exfil staging) |
| 6 | Executable in Startup Folder | Medium | Persistence (TA0003) | T1547 | Detects an executable dropped in a startup folder (persistence) |
| 7 | Hidden Directory Created | Medium | Defense Evasion (TA0005) | T1564 | Detects creation of dot-prefixed directories in unexpected locations (stealth) |
| 8 | Hidden File Creation in Sensitive Path | Medium | Persistence (TA0003) | T1564 | Detects creation of dotfile/hidden files in sensitive directories (stealth persistence) |
| 9 | Log File Deletion | Medium | Defense Evasion (TA0005) | T1070 | Detects deletion of log files, which may indicate an attacker trying to cover their tracks |
| 10 | PAM Module Modification | Medium | Persistence (TA0003) | T1547 | Detects modification of PAM config (auth backdoor persistence) |
| 11 | Ransomware File Encryption Pattern | Medium | Impact (TA0040) | T1486 | Detects rapid file encryption patterns consistent with ransomware activity |
| 12 | Sensitive File Access | Medium | Credential Access (TA0006) | T1003 | Detects access to sensitive system files like /etc/shadow, .ssh directories, and private keys |
| 13 | Shadow Password File Read | Medium | Credential Access (TA0006) | T1003 | Detects reads of /etc/shadow by a non-root process (credential access) |
| 14 | Shell Profile Modification | Medium | Persistence (TA0003) | T1546 | Detects modification of bash/shell profile files (persistence via login hook) |
| 15 | SSH Private Key File Access | Medium | Credential Access (TA0006) | T1552 | Detects reads of SSH private key files from a non-owner process |
| 16 | Webshell Creation | Medium | Persistence (TA0003) | T1505 | Detects creation of files with webshell signatures in web-served directories |
| 17 | Webshell Deployed | Medium | Persistence (TA0003) | T1505 | Detects a script file written under a web root (webshell persistence) |

### macOS (12 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | Authorization Database Modification | Medium | Privilege Escalation (TA0004) | T1548 | Detects modification of the macOS authorization database, which controls privilege escalation policies |
| 2 | Gatekeeper Bypass Attempt | Medium | Defense Evasion (TA0005) | T1553 | Detects attempts to bypass macOS Gatekeeper by removing quarantine attributes or using spctl to disable ass... |
| 3 | Hidden File Creation in User Directories | Medium | Defense Evasion (TA0005) | T1564 | Detects creation of hidden files (dot-prefix) in user home directories, commonly used for stealth |
| 4 | Keychain Access by Unusual Process | Medium | Credential Access (TA0006) | T1555 | Detects access to macOS Keychain by unusual processes, which may indicate credential theft |
| 5 | LaunchAgent Persistence Created | Medium | Persistence (TA0003) | T1547 | Detects creation of macOS LaunchAgent plist files for persistence |
| 6 | LaunchDaemon Persistence Created | Medium | Persistence (TA0003) | T1547 | Detects creation of macOS LaunchDaemon plist files, often used for privilege persistence |
| 7 | LaunchDaemon Plist Modification | Medium | Persistence (TA0003) | T1543 | Detects modification of macOS LaunchDaemon/LaunchAgent plists (persistence) |
| 8 | macOS Keychain Dump | Medium | Credential Access (TA0006) | T1555 | Detects attempts to dump the macOS keychain (credential theft) |
| 9 | Safari Extension Installation | Medium | Persistence (TA0003) | T1176 | Detects installation of browser extensions in Safari, which can be used for persistence and data theft |
| 10 | System Integrity Protection Modification | Medium | Defense Evasion (TA0005) | T1562 | Detects attempts to disable macOS System Integrity Protection (SIP), which protects system integrity |
| 11 | TCC Database Modification | Medium | Defense Evasion (TA0005) | T1562 | Detects modification of the macOS TCC (Transparency, Consent, and Control) database, which controls app per... |
| 12 | XProtect Removal or Modification | Medium | Defense Evasion (TA0005) | T1562 | Detects modification or deletion of macOS XProtect malware scanning files |

### Cloud (6 rules)

| # | Rule Name | Severity | MITRE Tactic | MITRE Technique | Description |
|---|-----------|----------|--------------|-----------------|-------------|
| 1 | API Key Usage from New IP | Medium | Initial Access (TA0001) | T1078 | Detects API key authentication from a previously unseen IP address |
| 2 | Bulk Data Download | Medium | Exfiltration (TA0010) | T1567 | Detects unusually large data downloads that may indicate data exfiltration from cloud services |
| 3 | Cloud Access Key Leaked in Logs | Medium | Credential Access (TA0006) | T1552 | Detects AWS access key patterns appearing in process command lines (leaked credentials) |
| 4 | Impossible Travel - Distant Logins | Medium | Initial Access (TA0001) | T1078 | Detects authentication from two geographically distant locations within an impossible time window (correlat... |
| 5 | New Admin Account Creation | Medium | Persistence (TA0003) | T1136 | Detects creation of new accounts with administrative privileges |
| 6 | SaaS Permission Escalation | Medium | Privilege Escalation (TA0004) | T1078 | Detects permission or role changes in SaaS applications indicating privilege escalation |

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
from src.detection.sigma import sigma_to_sql

with open("rules/sigma/process/my_new_rule.yml") as f:
    rule_yaml = f.read()

sql, params = sigma_to_sql(rule_yaml)
print(sql)       # Parameterized SQL (no string interpolation)
print(params)    # Bound parameters
```

Unit tests under `tests/unit/test_sigma.py` exercise the compiler across all 100 bundled rules.

---

## Rule Lifecycle

- **Loading**: `src/api/main.py::load_sigma_rules` reconciles all `.yml` files under `rules/sigma/` into the `rules` table on **every boot** (upsert by name; operator-set state like `enabled`/`last_run` is preserved). New/edited Sigma YAML is no longer silently ignored after first boot (P1-05).
- **Evaluation**: The detection scheduler ticks periodically and runs each rule against recent `logs` rows.
- **Alert creation**: Matching rows are inserted into the `alerts` table via `create_alert()`.
- **Suppression**: Per-rule suppression rules in the `alert_suppressions` table allow tuning false-positive rates without modifying rule YAML.
- **Tuning**: When a rule generates too many false positives, either (a) add a suppression rule, (b) tighten the detection condition, or (c) retrain the triage model (see [docs/AI.md](AI.md)) to better rank its output.
