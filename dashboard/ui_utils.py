"""
UI utilities for the SecurityScarletAI dashboard.

Shared design tokens, badge helpers, and styled component renderers.
Used across all view modules.  No business logic — pure presentational helpers.

The CSS classes (badge-*) are defined in dashboard.main.DARK_THEME_CSS and
injected once at app startup.
"""

import html as html_module

# ─── Design Tokens ────────────────────────────────────────────

BG_APP = "#090c14"
BG_SURFACE = "#0f1420"
BG_ELEVATED = "#161d2e"
BG_INPUT = "#1a2236"
ACCENT = "#00bcd4"
ACCENT_GLOW = "rgba(0,188,212,0.18)"
TEXT_PRIMARY = "#e8ecf1"
TEXT_SECONDARY = "#8b95a5"
TEXT_MUTED = "#5a6578"
BORDER_SUBTLE = "#1e2636"
BORDER_FOCUS = "#00bcd4"

SEVERITY_COLORS = {
    "critical": "#ff3860",
    "high": "#ff8f00",
    "medium": "#ffc107",
    "low": "#2979ff",
    "info": "#78909c",
}

STATUS_COLORS = {
    "new": "#ff3860",
    "investigating": "#ff8f00",
    "resolved": "#00e676",
    "false_positive": "#78909c",
    "closed": "#5a6578",
}

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


# ─── Helpers ──────────────────────────────────────────────────

def badge(label: str, css_class: str) -> str:
    """HTML badge span.  The CSS class must exist in injected global styles."""
    return f'<span class="badge {css_class}">{label}</span>'


def sev_badge(severity: str) -> str:
    css = SEV_CSS_MAP.get(severity.lower(), "badge-info")
    return badge(severity.upper(), css)


def status_badge(status: str) -> str:
    css = STATUS_CSS_MAP.get(status.lower().replace(" ", "_"), "badge-closed")
    return badge(status.replace("_", " ").upper(), css)


def esc(text: str) -> str:
    """Escape HTML special characters to prevent stored XSS."""
    if text is None:
        return ""
    return html_module.escape(str(text))


def colored_metric(label: str, value, color: str | None = None):
    """Render a metric card with an optional colored value.

    Must be called inside a Streamlit column or container.
    """
    import streamlit as st

    val_style = f"color:{color};" if color else f"color:{TEXT_PRIMARY};"
    html = f"""
    <div style="
        background:{BG_SURFACE};
        border:1px solid {BORDER_SUBTLE};
        border-radius:0.5rem;
        padding:0.75rem 1rem;
        margin-bottom:0.5rem;
    ">
        <p style="
            color:{TEXT_SECONDARY};
            font-size:0.72rem;
            font-weight:600;
            text-transform:uppercase;
            letter-spacing:0.05em;
            margin:0 0 0.35rem 0;
        ">{label}</p>
        <p style="
            font-size:1.5rem;
            font-weight:700;
            margin:0;
            {val_style}
        ">{value}</p>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)
