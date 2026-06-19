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
# Design Tokens
# ───────────────────────────────────────────────────────────

# Elevation layers (darker = deeper in the stack)
BG_APP = "#090c14"          # Deepest background
BG_SURFACE = "#0f1420"      # Cards, forms, expanders
BG_ELEVATED = "#161d2e"     # Hover states, active items
BG_INPUT = "#1a2236"        # Inputs, textareas

# Accent
ACCENT = "#00bcd4"          # Cyan primary
ACCENT_HOVER = "#00acc1"
ACCENT_GLOW = "rgba(0,188,212,0.18)"

# Text
TEXT_PRIMARY = "#e8ecf1"
TEXT_SECONDARY = "#8b95a5"
TEXT_MUTED = "#5a6578"

# Borders
BORDER_SUBTLE = "#1e2636"
BORDER_FOCUS = "#00bcd4"

# Severity (harmonized for dark UI)
SEV_CRITICAL = "#ff3860"
SEV_HIGH = "#ff8f00"
SEV_MEDIUM = "#ffc107"
SEV_LOW = "#2979ff"
SEV_INFO = "#78909c"

# Status
STATUS_NEW = "#ff3860"
STATUS_INVESTIGATING = "#ff8f00"
STATUS_RESOLVED = "#00e676"
STATUS_FALSE_POSITIVE = "#78909c"
STATUS_CLOSED = "#5a6578"

# ───────────────────────────────────────────────────────────
# Dark Theme Configuration
# ───────────────────────────────────────────────────────────

DARK_THEME_CSS = f"""
<style>
    /* ─── Global ─── */
    .stApp {{
        background-color: {BG_APP};
        color: {TEXT_PRIMARY};
    }}
    .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }}

    /* ─── Sidebar ─── */
    section[data-testid="stSidebar"] {{
        background-color: {BG_SURFACE};
        border-right: 1px solid {BORDER_SUBTLE};
    }}
    section[data-testid="stSidebar"] .stRadio > div {{
        gap: 0.25rem;
    }}
    section[data-testid="stSidebar"] .stRadio label {{
        padding: 0.5rem 0.75rem;
        border-radius: 0.5rem;
        color: {TEXT_SECONDARY};
        font-weight: 500;
        cursor: pointer;
        transition: all 0.15s ease;
    }}
    section[data-testid="stSidebar"] .stRadio label:hover {{
        background-color: {BG_ELEVATED};
        color: {TEXT_PRIMARY};
    }}
    section[data-testid="stSidebar"] .stRadio input:checked + div {{
        background-color: {BG_ELEVATED};
        color: {ACCENT};
        box-shadow: inset 2px 0 0 {ACCENT};
        font-weight: 600;
    }}

    /* ─── Cards / Containers ─── */
    .stContainer, .stForm {{
        background-color: {BG_SURFACE};
        border: 1px solid {BORDER_SUBTLE};
        border-radius: 0.75rem;
        padding: 1rem;
    }}
    .stExpander {{
        background-color: {BG_SURFACE};
        border: 1px solid {BORDER_SUBTLE};
        border-radius: 0.5rem;
    }}

    /* ─── Input fields ─── */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > select {{
        background-color: {BG_INPUT};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_SUBTLE};
        border-radius: 0.5rem;
        padding: 0.5rem 0.75rem;
    }}
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus,
    .stSelectbox > div > div > select:focus {{
        border-color: {BORDER_FOCUS};
        box-shadow: 0 0 0 2px {ACCENT_GLOW};
        outline: none;
    }}
    .stNumberInput input {{
        background-color: {BG_INPUT};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_SUBTLE};
    }}

    /* ─── Buttons ─── */
    .stButton > button {{
        background-color: {BG_ELEVATED};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_SUBTLE};
        border-radius: 0.5rem;
        font-weight: 500;
        transition: all 0.15s ease;
    }}
    .stButton > button:hover {{
        background-color: {BG_INPUT};
        border-color: {ACCENT};
        transform: translateY(-1px);
    }}
    .stButton > button:active {{
        transform: translateY(0);
    }}
    /* Primary accent variant (use st.markdown to inject class later) */
    button[kind="primary"] {{
        background-color: {ACCENT} !important;
        color: #000 !important;
        border-color: {ACCENT} !important;
        font-weight: 600;
    }}
    button[kind="primary"]:hover {{
        background-color: {ACCENT_HOVER} !important;
    }}
    button[kind="secondary"] {{
        background-color: transparent !important;
        color: {ACCENT} !important;
        border: 1px solid {ACCENT} !important;
    }}

    /* ─── DataFrames ─── */
    .stDataFrame {{
        background-color: {BG_SURFACE};
        border: 1px solid {BORDER_SUBTLE};
        border-radius: 0.5rem;
    }}
    .stDataFrame thead th {{
        background-color: {BG_ELEVATED};
        color: {TEXT_PRIMARY};
        font-weight: 600;
        border-bottom: 1px solid {BORDER_SUBTLE};
    }}
    .stDataFrame tbody td {{
        color: {TEXT_SECONDARY};
        border-bottom: 1px solid {BORDER_SUBTLE};
    }}
    .stDataFrame tbody tr:hover td {{
        background-color: {BG_ELEVATED};
        color: {TEXT_PRIMARY};
    }}

    /* ─── Metrics ─── */
    [data-testid="stMetricValue"] {{
        color: {TEXT_PRIMARY};
        font-weight: 700;
        font-size: 1.75rem;
    }}
    [data-testid="stMetricLabel"] {{
        color: {TEXT_SECONDARY};
        font-weight: 500;
        font-size: 0.85rem;
    }}
    [data-testid="stMetricDelta"] svg {{
        color: #00e676;
    }}
    [data-testid="stMetricDelta"] {{
        color: #00e676;
    }}

    /* ─── Chat messages ─── */
    .stChatMessage {{
        background-color: {BG_SURFACE};
        border: 1px solid {BORDER_SUBTLE};
        border-radius: 0.75rem;
    }}

    /* ─── Progress bars ─── */
    .stProgress > div > div > div {{
        background-color: {ACCENT};
    }}

    /* ─── Tabs ─── */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 0;
        border-bottom: 1px solid {BORDER_SUBTLE};
    }}
    .stTabs [data-baseweb="tab"] {{
        color: {TEXT_SECONDARY};
        font-weight: 500;
        padding: 0.5rem 1rem;
        border-bottom: 2px solid transparent;
    }}
    .stTabs [data-baseweb="tab"][aria-selected="true"] {{
        color: {ACCENT};
        border-bottom-color: {ACCENT};
        font-weight: 600;
    }}
    .stTabs [data-baseweb="tab-panel"] {{
        background-color: transparent;
        padding-top: 1rem;
    }}

    /* ─── Severity / status badge helpers (injected via html) ─── */
    .badge {{
        display: inline-block;
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        padding: 0.15rem 0.5rem;
        border-radius: 0.25rem;
        line-height: 1.2;
    }}
    .badge-critical  {{ background: {SEV_CRITICAL}22; color: {SEV_CRITICAL};
        border: 1px solid {SEV_CRITICAL}44; }}
    .badge-high      {{ background: {SEV_HIGH}22; color: {SEV_HIGH};
        border: 1px solid {SEV_HIGH}44; }}
    .badge-medium    {{ background: {SEV_MEDIUM}22; color: {SEV_MEDIUM};
        border: 1px solid {SEV_MEDIUM}44; }}
    .badge-low       {{ background: {SEV_LOW}22; color: {SEV_LOW}; border: 1px solid {SEV_LOW}44; }}
    .badge-info      {{ background: {SEV_INFO}22; color: {SEV_INFO};
        border: 1px solid {SEV_INFO}44; }}
    .badge-new       {{ background: {STATUS_NEW}22; color: {STATUS_NEW};
        border: 1px solid {STATUS_NEW}44; }}
    .badge-investigating {{ background: {STATUS_INVESTIGATING}22; color: {STATUS_INVESTIGATING};
        border: 1px solid {STATUS_INVESTIGATING}44; }}
    .badge-resolved  {{ background: {STATUS_RESOLVED}22; color: {STATUS_RESOLVED};
        border: 1px solid {STATUS_RESOLVED}44; }}
    .badge-false_positive {{ background: {STATUS_FALSE_POSITIVE}22; color: {STATUS_FALSE_POSITIVE};
        border: 1px solid {STATUS_FALSE_POSITIVE}44; }}
    .badge-closed    {{ background: {STATUS_CLOSED}22; color: {STATUS_CLOSED};
        border: 1px solid {STATUS_CLOSED}44; }}

    /* ─── Spinner / status ─── */
    .stSpinner > div > div {{
        color: {ACCENT};
    }}

    /* ─── Horizontal rule ─── */
    hr {{
        border-color: {BORDER_SUBTLE};
        margin: 1rem 0;
    }}

    /* ─── Headers ─── */
    h1, h2, h3 {{
        color: {TEXT_PRIMARY};
        font-weight: 700;
    }}
    h1 {{ font-size: 1.6rem; letter-spacing: -0.02em; }}
    h2 {{ font-size: 1.3rem; letter-spacing: -0.01em; }}
    h3 {{ font-size: 1.05rem; }}
    p, li {{ color: {TEXT_SECONDARY}; }}

    /* ─── Animations ─── */
    .stMain .block-container {{
        animation: fadeInContent 0.35s ease-out;
    }}
    @keyframes fadeInContent {{
        from {{ opacity: 0; transform: translateY(6px); }}
        to   {{ opacity: 1; transform: translateY(0); }}
    }}
</style>
"""

# ───────────────────────────────────────────────────────────
# Severity / Status → badge helper
# ───────────────────────────────────────────────────────────

SEV_CSS_MAP = {
    "critical": "badge-critical",
    "high": "badge-high",
    "medium": "badge-medium",
    "low": "badge-low",
    "info": "badge-info",
}

STATUS_CSS_MAP = {
    "new": "badge-new",
    "investigating": "badge-investigating",
    "resolved": "badge-resolved",
    "false_positive": "badge-false_positive",
    "closed": "badge-closed",
}


def badge(label: str, css_class: str) -> str:
    """Return HTML for a styled badge."""
    return f'<span class="badge {css_class}">{label}</span>'


def sev_badge(severity: str) -> str:
    css = SEV_CSS_MAP.get(severity.lower(), "badge-info")
    return badge(severity.upper(), css)


def status_badge(status: str) -> str:
    css = STATUS_CSS_MAP.get(status.lower().replace(" ", "_"), "badge-closed")
    return badge(status.replace("_", " ").upper(), css)

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

    # L-11 fix: Call require_auth() to re-verify token periodically
    from dashboard.auth import require_auth
    if not require_auth():
        st.session_state.authenticated = False
        st.rerun()
        return False

    return True


# ───────────────────────────────────────────────────────────
# Navigation
# ───────────────────────────────────────────────────────────

PAGES = {
    "Overview": "overview",
    "Live Logs": "logs",
    "Alerts": "alerts",
    "Rules": "rules",
    "Cases": "cases",
    "AI Chat": "ai_chat",
    "Hunting": "hunting",
}

ADMIN_PAGES = {
    "Audit Log": "audit",
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


_SIDEBAR_LABEL_CSS = (
    "color:#8b95a5;font-size:0.75rem;font-weight:600;"
    "text-transform:uppercase;letter-spacing:0.06em;"
)
_SIDEBAR_HR = "<hr style='margin:0.5rem 0;border-color:#1e2636;'/>"


def _sidebar_label(text: str) -> str:
    """Sidebar section label (uppercase styled <p>)."""
    return f"<p style='{_SIDEBAR_LABEL_CSS}'>{text}</p>"


def _sidebar_dot(color: str) -> str:
    """Sidebar status dot span."""
    return f"<span style='color:{color}'>&#9679;</span>"


def _sidebar_p(color: str, icon: str, text: str, bold: bool = False) -> str:
    """Sidebar status line as a styled <p>."""
    weight = "font-weight:500;" if bold else ""
    return f"<p style='color:{color};font-size:0.85rem;{weight}'>{icon} {text}</p>"


def render_sidebar():
    """Render the sidebar with navigation and status info."""
    st.sidebar.title("SecurityScarletAI")
    st.sidebar.caption("AI-Native SIEM")
    st.sidebar.markdown(_SIDEBAR_HR, unsafe_allow_html=True)

    # Page navigation
    st.sidebar.markdown(_sidebar_label("Navigation"), unsafe_allow_html=True)

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
    st.sidebar.markdown(_SIDEBAR_HR, unsafe_allow_html=True)
    st.sidebar.markdown(_sidebar_label("System Status"), unsafe_allow_html=True)
    try:
        api = get_api_client()
        health = api.health()
        if health and health.get("status") in ("healthy", "degraded"):
            checks = health.get("checks", {})
            db_status = checks.get("database", "unknown")
            ollama_status = checks.get("ollama", "unknown")

            db_icon = _sidebar_dot("#00e676") if db_status == "ok" else _sidebar_dot("#ff3860")
            ollama_icon = (
                _sidebar_dot("#00e676") if ollama_status == "ok" else _sidebar_dot("#ffc107")
            )

            st.sidebar.markdown(
                f"{db_icon}&nbsp;&nbsp;Database: "
                f"<span style='color:#e8ecf1'>{db_status}</span>",
                unsafe_allow_html=True,
            )
            st.sidebar.markdown(
                f"{ollama_icon}&nbsp;&nbsp;Ollama: "
                f"<span style='color:#e8ecf1'>{ollama_status}</span>",
                unsafe_allow_html=True,
            )

            if health.get("status") == "healthy":
                st.sidebar.markdown(
                    _sidebar_p("#00e676", "&#10003;", "System Healthy", bold=True),
                    unsafe_allow_html=True,
                )
            else:
                st.sidebar.markdown(
                    _sidebar_p("#ffc107", "&#9888;", "System Degraded", bold=True),
                    unsafe_allow_html=True,
                )
        else:
            st.sidebar.markdown(
                _sidebar_p("#ff3860", "&#10007;", "System Down", bold=True),
                unsafe_allow_html=True,
            )
    except Exception:
        st.sidebar.markdown(
            _sidebar_p("#ff3860", "&#10007;", "API Unreachable", bold=True),
            unsafe_allow_html=True,
        )

    # Auto-refresh toggle with interval selector
    st.sidebar.markdown(_SIDEBAR_HR, unsafe_allow_html=True)
    auto_refresh = st.sidebar.toggle("Auto-refresh", value=False, key="auto_refresh_toggle")

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
            st.sidebar.caption(f"Auto-refreshing every {refresh_interval}s")
        else:
            st.sidebar.warning("Install `streamlit-autorefresh` for auto-refresh.")
            if st.sidebar.button("Refresh Now"):
                st.rerun()

    # AI Status
    st.sidebar.markdown(_SIDEBAR_HR, unsafe_allow_html=True)
    st.sidebar.markdown(_sidebar_label("AI Status"), unsafe_allow_html=True)
    try:
        status = api.ai_status()
        triage = status.get("triage", {})
        model_status = triage.get("status", "unknown")
        if model_status == "trained":
            st.sidebar.markdown(
                _sidebar_p("#00e676", "&#9679;", "AI Triage: Trained"),
                unsafe_allow_html=True,
            )
        elif model_status == "no_data":
            st.sidebar.markdown(
                _sidebar_p("#ffc107", "&#9679;", "AI Triage: No data"),
                unsafe_allow_html=True,
            )
        else:
            st.sidebar.markdown(
                _sidebar_p("#78909c", "&#9679;", f"AI Triage: {model_status}"),
                unsafe_allow_html=True,
            )
    except Exception:
        st.sidebar.markdown(
            _sidebar_p("#78909c", "&#9679;", "AI Status: Unavailable"),
            unsafe_allow_html=True,
        )

    # User info and logout
    render_sidebar_user_info()

    # Keyboard shortcuts hint
    st.sidebar.markdown(_SIDEBAR_HR, unsafe_allow_html=True)
    st.sidebar.caption("Press 1-7 for quick nav")

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

    st.header("Security Overview")

    # Fetch alerts once — all chart functions reuse this single fetch
    from dashboard.charts import cached_alerts
    alerts = cached_alerts()

    # Top-level metrics with loading state
    render_dashboard_metrics(alerts)

    st.divider()

    # Severity sparklines
    render_severity_sparklines(alerts)

    st.divider()

    # Charts in columns
    col1, col2 = st.columns(2)

    with col1:
        render_severity_distribution(alerts)

    with col2:
        render_alert_trend(alerts)

    # Host risk scores
    render_host_risk_scores(alerts)

    st.divider()

    # MITRE coverage with loading state
    with st.spinner("Loading MITRE ATT&CK coverage...", show_time=True):
        try:
            rules = get_api_client().get_rules()
            render_mitre_heatmap(rules)
        except ApiError:
            st.info(
                "Rule information unavailable — MITRE coverage will show when rules are loaded."
            )

    # Recent alerts table
    st.divider()
    st.subheader("Recent Alerts")
    if alerts:
        table_data = []
        for a in alerts[:20]:
            table_data.append({
                "Time": a.get("time", "")[:19] if a.get("time") else "",
                "Rule": a.get("rule_name", ""),
                "Severity": a.get("severity", "").upper(),
                "Status": a.get("status", "").replace("_", " ").upper(),
                "Host": a.get("host_name", ""),
            })
        st.dataframe(table_data, use_container_width=True, hide_index=True)
    else:
        st.info("No alerts yet. Detection rules run automatically every 60 seconds.")


def render_audit():
    """Audit log page — admin only."""
    api = get_api_client()

    st.header("Audit Log")

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
        "All data via authenticated API — No direct DB access"
    )


# ───────────────────────────────────────────────────────────
# Keyboard shortcuts
# ───────────────────────────────────────────────────────────

KEYBOARD_SHORTCUTS_JS = """
<script>
document.addEventListener('keydown', function(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    const pages = ['Overview', 'Live Logs', 'Alerts', 'Rules',
                   'Cases', 'AI Chat', 'Hunting'];
    const num = parseInt(e.key);
    if (num >= 1 && num <= 7) {
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
