"""
SecurityScarletAI Dashboard — Main Entry Point

A professional, dark-themed SIEM dashboard powered by Streamlit.

SECURITY: This module uses ONLY the API client for data access.
No direct database connections. No subprocess calls. No SQL in frontend.
All auth tokens are handled through session state.

Pages:
  - Overview: Alert metrics, severity distribution, trends
  - Live Logs: Real-time log viewing with filters
  - Alerts: Alert list with investigation, AI triage, bulk ops
  - Rules: Detection rule management
  - Cases: Investigation case management
  - AI Chat: Context-aware security assistant
  - Hunting: Threat hunting templates & MITRE gaps
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from dashboard.api_client import ApiError
from dashboard.auth import (
    get_api_client,
    is_admin,
    render_login_page,
    render_sidebar_user_info,
)

# ───────────────────────────────────────────────────────────
# Auto-refresh — graceful fallback if component not installed
# ───────────────────────────────────────────────────────────

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False

# ───────────────────────────────────────────────────────────
# Dark Theme Configuration
# ───────────────────────────────────────────────────────────

DARK_THEME_CSS = """
<style>
    /* Global dark theme */
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #1a1d23;
    }

    /* Cards and containers */
    .stContainer, .stForm, .stExpander {
        background-color: #1a1d23;
        border-color: #2d2d3d;
    }

    /* Input fields */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > select {
        background-color: #262730;
        color: #fafafa;
    }

    /* Dataframe */
    .stDataFrame {
        background-color: #1a1d23;
    }

    /* Metrics — animate value changes */
    [data-testid="stMetricValue"] {
        color: #fafafa;
        animation: fadeInValue 0.4s ease-out;
    }

    /* Buttons */
    .stButton > button {
        background-color: #262730;
        color: #fafafa;
        border-color: #3d3d5c;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        background-color: #3d3d5c;
        border-color: #5a5a8c;
        transform: translateY(-1px);
    }
    .stButton > button:active {
        transform: translateY(0);
    }

    /* Chat messages */
    .stChatMessage {
        background-color: #1a1d23;
    }

    /* Progress bars */
    .stProgress > div > div > div {
        background-color: #ff6b6b;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    .stTabs [data-baseweb="tab-panel"] {
        background-color: #1a1d23;
    }

    /* Severity colors */
    .severity-critical { color: #ff4444; font-weight: bold; }
    .severity-high { color: #ff8c00; font-weight: bold; }
    .severity-medium { color: #ffd700; }
    .severity-low { color: #4488ff; }
    .severity-info { color: #888888; }

    /* Keyboard shortcuts hint */
    .shortcut-hint {
        position: fixed;
        bottom: 10px;
        right: 10px;
        background: #262730;
        color: #888;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        z-index: 1000;
    }

    /* Content fade-in animation */
    .stMain .block-container {
        animation: fadeInContent 0.3s ease-out;
    }

    /* Toast notification styling */
    .stToast {
        animation: slideInRight 0.3s ease-out;
    }

    /* Spinner text color */
    .stSpinner > div > div {
        color: #a0a0a0;
    }

    /* Keyframes */
    @keyframes fadeInContent {
        from { opacity: 0.7; }
        to { opacity: 1.0; }
    }
    @keyframes fadeInValue {
        from { opacity: 0; transform: translateY(-4px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes slideInRight {
        from { opacity: 0; transform: translateX(100px); }
        to { opacity: 1; transform: translateX(0); }
    }

    /* Inline status message styling */
    .stAlert {
        animation: fadeInContent 0.3s ease-out;
    }
</style>
"""

# ───────────────────────────────────────────────────────────
# Page Configuration
# ───────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SecurityScarletAI — SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Apply dark theme
st.markdown(DARK_THEME_CSS, unsafe_allow_html=True)


# ───────────────────────────────────────────────────────────
# Authentication Gate
# ───────────────────────────────────────────────────────────

def check_auth():
    """Check authentication state. Returns True if authenticated."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        render_login_page()
        return False
    return True


# ───────────────────────────────────────────────────────────
# Navigation
# ───────────────────────────────────────────────────────────

PAGES = {
    "📊 Overview": "overview",
    "📡 Live Logs": "logs",
    "🚨 Alerts": "alerts",
    "📋 Rules": "rules",
    "📁 Cases": "cases",
    "🤖 AI Chat": "ai_chat",
    "🎯 Hunting": "hunting",
}

ADMIN_PAGES = {
    "🔐 Audit Log": "audit",
}

# Default refresh intervals (ms) per page type
PAGE_REFRESH_MS = {
    "overview": 30000,
    "logs": 15000,
    "alerts": 30000,
    "rules": 120000,
    "cases": 60000,
    "ai_chat": 0,       # Never auto-refresh (chat context matters)
    "hunting": 120000,
    "audit": 60000,
}


def render_sidebar():
    """Render the sidebar with navigation and status info."""
    st.sidebar.title("🛡️ SecurityScarletAI")
    st.sidebar.caption("AI-Native SIEM")

    # Page navigation
    st.sidebar.subheader("Navigation")

    # Regular pages
    page_labels = list(PAGES.keys())
    # Add admin pages if user is admin
    if is_admin():
        page_labels.extend(list(ADMIN_PAGES.keys()))

    selected = st.sidebar.radio("Go to", page_labels, label_visibility="collapsed")

    # Determine which page
    page_key = PAGES.get(selected) or ADMIN_PAGES.get(selected) or "overview"

    # Store selected page in session state for refresh logic
    st.session_state.current_page = page_key

    # Health check
    st.sidebar.divider()
    st.sidebar.subheader("System Status")
    try:
        api = get_api_client()
        health = api.health()
        if health and health.get("status") in ("healthy", "degraded"):
            checks = health.get("checks", {})
            db_status = checks.get("database", "unknown")
            ollama_status = checks.get("ollama", "unknown")

            db_icon = "🟢" if db_status == "ok" else "🔴"
            ollama_icon = "🟢" if ollama_status == "ok" else "🟡"

            st.sidebar.markdown(f"{db_icon} Database: {db_status}")
            st.sidebar.markdown(f"{ollama_icon} Ollama: {ollama_status}")

            if health.get("status") == "healthy":
                st.sidebar.success("✅ System Healthy")
            else:
                st.sidebar.warning("⚠️ System Degraded")
        else:
            st.sidebar.error("❌ System Down")
    except Exception:
        st.sidebar.error("❌ API Unreachable")

    # Auto-refresh toggle with interval selector
    st.sidebar.divider()
    auto_refresh = st.sidebar.toggle("🔄 Auto-refresh", value=False, key="auto_refresh_toggle")

    if auto_refresh:
        if HAS_AUTOREFRESH:
            # Configurable refresh interval
            default_secs = PAGE_REFRESH_MS.get(page_key, 30000) // 1000
            refresh_interval = st.sidebar.select_slider(
                "Refresh interval",
                options=[10, 15, 30, 60, 120],
                value=min(default_secs, 120),
                format_func=lambda x: f"{x}s",
                key="refresh_interval",
            )
            # Use st_autorefresh component to trigger rerun
            st_autorefresh(
                interval=refresh_interval * 1000,
                limit=None,
                key=f"autorefresh_{page_key}",
            )
            st.sidebar.caption(f"🔄 Auto-refreshing every {refresh_interval}s")
        else:
            st.sidebar.warning("⚠️ Install `streamlit-autorefresh` for auto-refresh.")
            if st.sidebar.button("🔄 Refresh Now"):
                st.rerun()

    # AI Status
    st.sidebar.divider()
    st.sidebar.subheader("AI Status")
    try:
        status = api.ai_status()
        triage = status.get("triage", {})
        model_status = triage.get("status", "unknown")
        if model_status == "trained":
            st.sidebar.markdown("🟢 AI Triage: Trained")
        elif model_status == "no_data":
            st.sidebar.markdown("🟡 AI Triage: No training data")
        else:
            st.sidebar.markdown(f"⚪ AI Triage: {model_status}")
    except Exception:
        st.sidebar.markdown("⚪ AI Status: Unavailable")

    # User info and logout
    render_sidebar_user_info()

    # Keyboard shortcuts hint
    st.sidebar.divider()
    st.sidebar.caption("⌨️ Press 1-7 for quick navigation")

    return page_key


# ───────────────────────────────────────────────────────────
# Page Renderers
# ───────────────────────────────────────────────────────────

def render_overview():
    """Dashboard overview page with metrics, charts, and recent alerts."""
    from dashboard.charts import (
        render_alert_trend,
        render_dashboard_metrics,
        render_host_risk_scores,
        render_mitre_heatmap,
        render_severity_distribution,
        render_severity_sparklines,
    )

    st.header("📊 Security Overview")

    # Top-level metrics with loading state
    alerts = render_dashboard_metrics()

    st.divider()

    # Severity sparklines
    render_severity_sparklines()

    st.divider()

    # Charts in columns
    col1, col2 = st.columns(2)

    with col1:
        render_severity_distribution()

    with col2:
        render_alert_trend()

    # Host risk scores
    render_host_risk_scores()

    st.divider()

    # MITRE coverage with loading state
    with st.spinner("Loading MITRE ATT&CK coverage...", show_time=True):
        try:
            rules = get_api_client().get_rules()
            render_mitre_heatmap(rules)
        except ApiError:
            st.info(
                "Rule information unavailable "
                "— MITRE coverage will show when rules are loaded."
            )

    # Recent alerts table
    st.divider()
    st.subheader("🚨 Recent Alerts")
    if alerts:
        table_data = []
        for a in alerts[:20]:
            table_data.append({
                "Time": a.get("time", "")[:19] if a.get("time") else "",
                "Rule": a.get("rule_name", ""),
                "Severity": a.get("severity", ""),
                "Status": a.get("status", ""),
                "Host": a.get("host_name", ""),
            })
        st.dataframe(table_data, use_container_width=True, hide_index=True)
    else:
        st.info("No alerts yet. Detection rules run automatically every 60 seconds.")


def render_audit():
    """Audit log page — admin only."""
    from dashboard.alerts_view import render_alert_list  # noqa: F401 — not used, just ensuring import

    api = get_api_client()

    st.header("🔐 Audit Log")

    if not is_admin():
        st.error("You need admin permissions to view the audit log.")
        return

    limit = st.number_input("Entries", min_value=10, max_value=500, value=100)

    with st.spinner("Loading audit log...", show_time=True):
        try:
            entries = api.get_audit_log(limit=limit)
            if entries:
                table_data = []
                for e in entries:
                    table_data.append({
                        "Time": e.get("created_at", "")[:19] if e.get("created_at") else "",
                        "Actor": e.get("actor", ""),
                        "Action": e.get("action", ""),
                        "Target": f"{e.get('target_type', '')} #{e.get('target_id', '')}",
                        "Details": (
                        str(e.get("new_values", ""))[:100]
                        if e.get("new_values") else ""
                    ),
                    })
                st.dataframe(table_data, use_container_width=True, hide_index=True)
            else:
                st.info("No audit log entries found.")
        except ApiError as e:
            st.error(f"Failed to load audit log: {e.detail}")


# ───────────────────────────────────────────────────────────
# Main Application
# ───────────────────────────────────────────────────────────

def main():
    """Main application entry point."""

    # Check authentication
    if not check_auth():
        return

    # Render sidebar and get selected page
    page_key = render_sidebar()

    # Route to page
    if page_key == "overview":
        render_overview()
    elif page_key == "logs":
        from dashboard.logs_view import render_log_viewer
        render_log_viewer()
    elif page_key == "alerts":
        from dashboard.alerts_view import render_alert_list
        render_alert_list()
    elif page_key == "rules":
        from dashboard.rules_view import render_rules_view
        render_rules_view()
    elif page_key == "cases":
        from dashboard.cases_view import render_cases_view
        render_cases_view()
    elif page_key == "ai_chat":
        from dashboard.ai_chat_view import render_ai_chat
        render_ai_chat()
    elif page_key == "hunting":
        from dashboard.hunt_view import render_hunt_view
        render_hunt_view()
    elif page_key == "audit":
        render_audit()
    else:
        render_overview()

    # Footer
    st.divider()
    st.caption(
        "SecurityScarletAI v0.4.1 — AI-Native SIEM | "
        "🛡️ All data via authenticated API — No direct DB access"
    )


# ───────────────────────────────────────────────────────────
# JavaScript for keyboard shortcuts
# ───────────────────────────────────────────────────────────

KEYBOARD_SHORTCUTS_JS = """
<script>
document.addEventListener('keydown', function(e) {
    // Don't trigger shortcuts when typing in inputs
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

    const pages = ['📊 Overview', '📡 Live Logs', '🚨 Alerts', '📋 Rules',
                   '📁 Cases', '🤖 AI Chat', '🎯 Hunting'];

    const num = parseInt(e.key);
    if (num >= 1 && num <= 7) {
        // Click the corresponding radio button
        const radios = document.querySelectorAll('label[data-baseweb="radio"]');
        if (radios[num - 1]) {
            radios[num - 1].click();
        }
    }
});
</script>
"""


if __name__ == "__main__":
    # Inject keyboard shortcuts
    st.components.v1.html(KEYBOARD_SHORTCUTS_JS, height=0)
    main()
