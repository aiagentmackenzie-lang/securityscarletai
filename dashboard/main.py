"""
Dashboard main entry point using Streamlit.

SecurityScarletAI web dashboard for analysts and administrators.
"""
import sys
from pathlib import Path
# Add project root to path for src imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import httpx
import asyncio
from datetime import datetime, timedelta

from src.config.settings import settings
from src.config.logging import get_logger

log = get_logger("dashboard")

# Page config
st.set_page_config(
    page_title="SecurityScarletAI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Title and description
st.title("🛡️ SecurityScarletAI")
st.subheader("AI-Native SIEM Dashboard")

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Overview", "Live Logs", "Alerts", "Rules", "Threat Hunting", "Cases", "Settings"]
)

# Check API health
async def check_health():
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"http://{settings.api_host}:{settings.api_port}/api/v1/health")
            return resp.json()
    except Exception as e:
        return {"status": "down", "error": str(e)}

# Cache health check
@st.cache_data(ttl=30)
def get_health():
    return asyncio.run(check_health())

health = get_health()

# Display health indicator
if health.get("status") == "healthy":
    st.sidebar.success("✅ System Healthy")
else:
    st.sidebar.error("❌ System Degraded")
    st.sidebar.json(health)

# Overview page
if page == "Overview":
    st.header("📊 Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # TODO: Fetch real stats from API
    col1.metric("Total Alerts", "0", "+0")
    col2.metric("Active Rules", "6", "+6")
    col3.metric("Logs Ingested", "0", "+0/s")
    col4.metric("Threats Blocked", "0", "0")
    
    st.divider()
    
    st.info("""
    Welcome to SecurityScarletAI!
    
    **Quick Start:**
    - 📡 **Live Logs**: Monitor real-time log ingestion
    - 🚨 **Alerts**: Review and manage security alerts
    - 📋 **Rules**: Configure detection rules
    - 🔍 **Threat Hunting**: Investigate suspicious activity
    """)

elif page == "Live Logs":
    st.header("📡 Live Log Stream")
    st.info("Real-time log streaming via WebSocket")
    
    # Placeholder for WebSocket connection
    st.code("""
    WebSocket connection would be established here
    ws://localhost:8000/api/v1/ws/logs?token=YOUR_TOKEN
    """)
    
    # Log table placeholder
    st.dataframe(
        {"Time": [], "Host": [], "Category": [], "Action": []},
        use_container_width=True,
    )

elif page == "Alerts":
    st.header("🚨 Security Alerts")
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox("Status", ["All", "New", "Investigating", "Resolved", "False Positive"])
    with col2:
        severity_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Info"])
    with col3:
        time_range = st.selectbox("Time Range", ["Last 1 hour", "Last 24 hours", "Last 7 days", "All time"])
    
    st.divider()
    
    # Alerts table placeholder
    st.dataframe(
        {"ID": [], "Time": [], "Rule": [], "Severity": [], "Status": [], "Host": []},
        use_container_width=True,
    )

elif page == "Rules":
    st.header("📋 Detection Rules")
    
    if st.button("+ Create New Rule"):
        st.session_state.show_rule_form = True
    
    st.divider()
    
    # Rules table placeholder
    st.dataframe(
        {"ID": [], "Name": [], "Severity": [], "Status": [], "Last Run": [], "Matches": []},
        use_container_width=True,
    )

elif page == "Threat Hunting":
    st.header("🔍 Threat Hunting")
    
    st.info("Query logs using natural language or predefined queries")
    
    # NL query input
    nl_query = st.text_input("Ask in plain English:", placeholder="Show me failed logins from the last hour")
    
    if st.button("Generate SQL"):
        st.code("SELECT * FROM logs WHERE ...", language="sql")
    
    # Predefined queries
    st.subheader("Quick Queries")
    
    queries = {
        "Processes from /tmp": "SELECT * FROM logs WHERE process_path LIKE '/tmp/%' AND time > NOW() - INTERVAL '1 hour'",
        "Outbound to rare ports": "SELECT * FROM logs WHERE destination_port IS NOT NULL AND destination_port NOT IN (80, 443, 53, 22)",
        "Failed authentications": "SELECT * FROM logs WHERE event_category = 'authentication' AND event_action LIKE '%failed%'",
    }
    
    for name, sql in queries.items():
        if st.button(f"▶️ {name}"):
            st.code(sql, language="sql")

elif page == "Cases":
    st.header("📁 Investigation Cases")
    st.info("Group related alerts into cases for investigation")
    
    # Cases placeholder
    st.dataframe(
        {"ID": [], "Title": [], "Status": [], "Severity": [], "Alerts": [], "Assigned To": []},
        use_container_width=True,
    )

elif page == "Settings":
    st.header("⚙️ Dashboard Settings")
    
    st.subheader("API Connection")
    st.text_input("API Host", value=settings.api_host, disabled=True)
    st.number_input("API Port", value=settings.api_port, disabled=True)
    
    st.subheader("Display")
    st.toggle("Dark Mode", value=False)
    st.slider("Log Refresh Rate (seconds)", min_value=5, max_value=60, value=10)
    
    if st.button("Save Settings"):
        st.success("Settings saved!")

# Footer
st.divider()
st.caption("SecurityScarletAI v0.1.0 — Built with ❤️ and ☕")
