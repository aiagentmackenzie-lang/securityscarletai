"""
Dashboard main entry point using Streamlit.

SecurityScarletAI web dashboard for analysts and administrators.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import httpx
import asyncio
from datetime import datetime, timedelta

API_BASE = "http://localhost:8000/api/v1"
TOKEN = "bedd3171c0cf5a095e5ab6acc28c202257688340a7ff5874e0bf97d61cc624d1"

def api_get(path: str, params: dict = None) -> dict | list | None:
    """Synchronous API GET helper."""
    try:
        r = httpx.get(f"{API_BASE}{path}", headers={"Authorization": f"Bearer {TOKEN}"}, params=params, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def api_patch(path: str, json_data: dict = None) -> dict | None:
    """Synchronous API PATCH helper."""
    try:
        r = httpx.patch(f"{API_BASE}{path}", headers={"Authorization": f"Bearer {TOKEN}"}, json=json_data, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# Page config
st.set_page_config(
    page_title="SecurityScarletAI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ SecurityScarletAI")
st.subheader("AI-Native SIEM Dashboard")

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Overview", "Live Logs", "Alerts", "Rules"])

# Health check
health = api_get("/health")
if health and health.get("status") == "healthy":
    st.sidebar.success("✅ System Healthy")
else:
    st.sidebar.error("❌ System Down")

# Auto-refresh
auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
if auto_refresh:
    st.sidebar.info("⏱️ Page refreshes every 30s")
    import time
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.time()
    if time.time() - st.session_state.last_refresh > 30:
        st.session_state.last_refresh = time.time()
        st.rerun()

# ─── OVERVIEW ────────────────────────────────────────────────
if page == "Overview":
    st.header("📊 Overview")

    # Fetch stats directly from DB via API
    alerts_data = api_get("/alerts", {"limit": 1000}) or []
    rules_data = api_get("/rules") or []

    total_alerts = len(alerts_data) if isinstance(alerts_data, list) else 0
    active_rules = len([r for r in rules_data if r.get("enabled", False)]) if isinstance(rules_data, list) else 6
    critical = len([a for a in (alerts_data if isinstance(alerts_data, list) else []) if a.get("severity") == "critical"])
    high = len([a for a in (alerts_data if isinstance(alerts_data, list) else []) if a.get("severity") == "high"])
    new_alerts = len([a for a in (alerts_data if isinstance(alerts_data, list) else []) if a.get("status") == "new"])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🚨 Total Alerts", total_alerts, f"+{new_alerts} new")
    col2.metric("📋 Active Rules", active_rules)
    col3.metric("🔴 Critical", critical)
    col4.metric("🟠 High Severity", high)

    st.divider()

    # Alert severity breakdown
    if total_alerts > 0:
        st.subheader("Alert Severity Distribution")
        severities = {}
        for a in (alerts_data if isinstance(alerts_data, list) else []):
            s = a.get("severity", "info")
            severities[s] = severities.get(s, 0) + 1

        cols = st.columns(len(severities))
        colors = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for i, (sev, count) in enumerate(sorted(severities.items())):
            cols[i].metric(f"{colors.get(sev, '⚪')} {sev.title()}", count)

        st.divider()

        # Recent alerts table
        st.subheader("Recent Alerts")
        if isinstance(alerts_data, list) and alerts_data:
            table_data = []
            for a in alerts_data[:20]:
                table_data.append({
                    "Time": a.get("time", "")[:19] if a.get("time") else "",
                    "Rule": a.get("rule_name", ""),
                    "Severity": a.get("severity", ""),
                    "Status": a.get("status", ""),
                    "Host": a.get("host_name", ""),
                })
            st.dataframe(table_data, use_container_width=True, hide_index=True)
        else:
            st.info("No alerts yet. Detection rules are running every 60 seconds.")
    else:
        st.info("""
        **Getting Started:**
        1. 📡 Ingest logs via `POST /api/v1/ingest`
        2. 📋 Detection rules run automatically every 60s
        3. 🚨 Alerts appear here when rules match
        
        Use `scripts/seed_realistic_data.py` to generate test data.
        """)

# ─── LIVE LOGS ────────────────────────────────────────────────
elif page == "Live Logs":
    st.header("📡 Live Log Stream")

    col1, col2 = st.columns([3, 1])
    with col2:
        category_filter = st.selectbox("Category", ["All", "authentication", "network", "process", "file", "security"])
        limit = st.number_input("Rows", min_value=10, max_value=500, value=50)

    # Query DB via psql
    try:
        import subprocess
        psql = "/opt/homebrew/Cellar/postgresql@17/17.9/bin/psql"
        if category_filter != "All":
            cmd = [psql, "-h", "localhost", "-U", "main", "-d", "scarletai", "-t", "-A", "-F", "|",
                    "-c", f"SELECT time, host_name, event_category, event_type, event_action, source_ip, destination_ip, destination_port, user_name, process_name, file_path, severity FROM logs WHERE event_category = '{category_filter}' ORDER BY time DESC LIMIT {limit}"]
        else:
            cmd = [psql, "-h", "localhost", "-U", "main", "-d", "scarletai", "-t", "-A", "-F", "|",
                    "-c", f"SELECT time, host_name, event_category, event_type, event_action, source_ip, destination_ip, destination_port, user_name, process_name, file_path, severity FROM logs ORDER BY time DESC LIMIT {limit}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        cols = ["Time", "Host", "Category", "Type", "Action", "Source IP", "Dest IP", "Port", "User", "Process", "File", "Severity"]
        logs = []
        for line in result.stdout.strip().split("\n"):
            if line:
                vals = line.split("|")
                if len(vals) == len(cols):
                    logs.append(dict(zip(cols, vals)))
        if logs:
            st.dataframe(logs, use_container_width=True, hide_index=True)
            st.caption(f"Showing {len(logs)} of most recent logs")
        else:
            st.info("No logs found. Ingest events via the API.")
    except Exception as e:
        st.error(f"Could not connect to database: {e}")

# ─── ALERTS ──────────────────────────────────────────────────
elif page == "Alerts":
    st.header("🚨 Security Alerts")

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox("Status", ["All", "new", "investigating", "resolved", "false_positive"])
    with col2:
        severity_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with col3:
        limit = st.number_input("Max alerts", min_value=10, max_value=500, value=100)

    st.divider()

    # Fetch alerts from API
    alerts = api_get("/alerts", {"limit": limit}) or []

    if isinstance(alerts, list):
        # Apply filters
        filtered = alerts
        if status_filter != "All":
            filtered = [a for a in filtered if a.get("status") == status_filter]
        if severity_filter != "All":
            filtered = [a for a in filtered if a.get("severity") == severity_filter]

        if filtered:
            for a in filtered:
                sev = a.get("severity", "info")
                colors = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
                icon = colors.get(sev, "⚪")

                with st.expander(
                    f"{icon} [{sev.upper()}] {a.get('rule_name', 'Unknown')} — {a.get('host_name', '')}",
                    expanded=False,
                ):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Description:** {a.get('description', '')}")
                        st.write(f"**AI Summary:** {a.get('ai_summary', '⏳ Pending...')}")
                        st.write(f"**Time:** {a.get('time', '')}")
                        risk = a.get('risk_score')
                        if risk:
                            st.progress(min(risk / 100, 1.0), text=f"Risk Score: {risk}/100")
                        st.write(f"**Status:** {a.get('status', 'new')}")
                        if a.get("mitre_tactics"):
                            st.write(f"**MITRE Tactics:** {', '.join(a['mitre_tactics'])}")
                        if a.get("mitre_techniques"):
                            st.write(f"**MITRE Techniques:** {', '.join(a['mitre_techniques'])}")
                        if a.get("evidence"):
                            st.json(a["evidence"])

                    with col2:
                        new_status = st.selectbox(
                            "Update status",
                            ["new", "investigating", "resolved", "false_positive", "closed"],
                            index=["new", "investigating", "resolved", "false_positive", "closed"].index(a.get("status", "new")),
                            key=f"status_{a.get('id', 0)}"
                        )
                        if st.button("Update", key=f"btn_{a.get('id', 0)}"):
                            result = api_patch(f"/alerts/{a['id']}", {"status": new_status})
                            if result:
                                st.success(f"Alert #{a['id']} updated to {new_status}")
                                st.rerun()
                            else:
                                st.error("Failed to update alert")
        else:
            st.info(f"No alerts matching filters (showing {len(alerts)} total)")
    else:
        st.info("No alerts yet. Rules are running — alerts will appear here when detections fire.")

# ─── RULES ───────────────────────────────────────────────────
elif page == "Rules":
    st.header("📋 Detection Rules")

    rules = api_get("/rules") or []

    if isinstance(rules, list) and rules:
        table_data = []
        for r in rules:
            table_data.append({
                "ID": r.get("id", ""),
                "Name": r.get("name", ""),
                "Severity": r.get("severity", ""),
                "Enabled": "✅" if r.get("enabled") else "❌",
                "Last Run": str(r.get("last_run", ""))[:19] if r.get("last_run") else "Never",
                "Matches": r.get("match_count", 0),
            })
        st.dataframe(table_data, use_container_width=True, hide_index=True)

        # Rule details
        st.divider()
        st.subheader("Rule Details")
        for r in rules:
            with st.expander(f"📌 {r.get('name', '')} — {r.get('severity', '')}"):
                st.write(f"**Description:** {r.get('description', 'N/A')}")
                st.write(f"**Interval:** {r.get('run_interval', '')}")
                st.write(f"**Lookback:** {r.get('lookback', '')}")
                st.write(f"**Threshold:** {r.get('threshold', 1)}")
                st.write(f"**Match Count:** {r.get('match_count', 0)}")
                if r.get("mitre_tactics"):
                    st.write(f"**MITRE Tactics:** {', '.join(r['mitre_tactics'])}")
                if r.get("mitre_techniques"):
                    st.write(f"**MITRE Techniques:** {', '.join(r['mitre_techniques'])}")
    else:
        st.info("No rules loaded. Rules are auto-loaded from rules/sigma/ on API startup.")

# Footer
st.divider()
st.caption("SecurityScarletAI v0.1.0 — AI-Native SIEM")