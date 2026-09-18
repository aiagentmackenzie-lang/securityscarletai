"""
UI utilities for the SecurityScarletAI dashboard.

Shared design tokens, badge helpers, and styled component renderers.
Used across all view modules.  No business logic — pure presentational helpers.

The CSS classes (badge-*) are defined in dashboard.main.DARK_THEME_CSS and
injected once at app startup.
"""

import html as html_module
import string

# ─── Design Tokens ────────────────────────────────────────────

BG_APP = "#090c14"
BG_SURFACE = "#0f1420"
BG_ELEVATED = "#161d2e"
BG_INPUT = "#1a2236"
ACCENT = "#00bcd4"
ACCENT_GLOW = "rgba(0,188,212,0.18)"

# Brand scarlet (the shield mark) — used for the auth front door: wordmark
# and the Sign In button. The app-wide functional accent stays cyan.
BRAND_SCARLET = "#e11d48"  # rose-600 — shield mid, button base
BRAND_SCARLET_BRIGHT = "#f43f5e"  # rose-400 — shield top, wordmark
BRAND_SCARLET_DEEP = "#be123c"  # rose-700 — button gradient end/hover
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

SEV_CSS_MAP = {
    "critical": "badge-critical",
    "high": "badge-high",
    "medium": "badge-medium",
    "low": "badge-low",
    "info": "badge-info",
}

STATUS_CSS_MAP = {
    # Alert statuses
    "new": "badge-new",
    "investigating": "badge-investigating",
    "resolved": "badge-resolved",
    "false_positive": "badge-false_positive",
    "closed": "badge-closed",
    # Case statuses (cases_view STATUS_FLOW: open → in_progress → resolved
    # → closed). open/in_progress previously fell through to badge-closed —
    # an OPEN case rendered in closed-case gray styling (AUD-065).
    "open": "badge-new",
    "in_progress": "badge-investigating",
}


# ─── Helpers ──────────────────────────────────────────────────


def badge(label: str, css_class: str) -> str:
    """HTML badge span.  The CSS class must exist in injected global styles.

    The label is escaped HERE — severity/status strings often come straight
    from API payloads (ingest-fed), so the single choke point treats them as
    untrusted (dashboard esc sweep, findings F-01/F-02).
    """
    return f'<span class="badge {css_class}">{esc(label)}</span>'


def sev_badge(severity: str) -> str:
    css = SEV_CSS_MAP.get(severity.lower(), "badge-info")
    return badge(severity.upper(), css)


def status_badge(status: str) -> str:
    css = STATUS_CSS_MAP.get(status.lower().replace(" ", "_"), "badge-closed")
    return badge(status.replace("_", " ").upper(), css)


def logo_svg(size: int = 64, id_prefix: str = "ss") -> str:
    """SecurityScarletAI mark: scarlet-gradient shield + cyan EKG pulse.

    Inline SVG (no binary assets, crisp at any size). id_prefix keeps
    gradient ids unique when the mark is rendered more than once per page
    (login card + sidebar).
    """
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 64 64" '
        'fill="none" xmlns="http://www.w3.org/2000/svg">'
        "<defs>"
        f'<linearGradient id="{id_prefix}-shield" x1="10" y1="4" x2="54" y2="60" '
        'gradientUnits="userSpaceOnUse">'
        '<stop offset="0" stop-color="#f43f5e"/>'
        '<stop offset="0.55" stop-color="#e11d48"/>'
        '<stop offset="1" stop-color="#9f1239"/>'
        "</linearGradient>"
        "</defs>"
        '<path d="M32 3 L55 11 V29 C55 44.5 45.5 55.5 32 61 '
        'C18.5 55.5 9 44.5 9 29 V11 Z" '
        f'fill="url(#{id_prefix}-shield)"/>'
        '<path d="M32 3 L55 11 V29 C55 44.5 45.5 55.5 32 61 '
        'C18.5 55.5 9 44.5 9 29 V11 Z" '
        'stroke="rgba(255,255,255,0.22)" stroke-width="1" fill="none"/>'
        '<path d="M17 33 h9 l3.5-7.5 5.5 13 3.5-5.5 H49" stroke="#00e5ff" '
        'stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" '
        'fill="none"/>'
        '<circle cx="49" cy="33" r="1.6" fill="#00e5ff"/>'
        "</svg>"
    )


def brand_header_html(id_prefix: str = "login") -> str:
    """Centered logo + wordmark block for the top of the auth card."""
    return f"""
    <div style="text-align:center;margin:0.5rem 0 1.4rem 0;">
        <div style="display:flex;justify-content:center;margin-bottom:0.9rem;">
            {logo_svg(64, id_prefix)}
        </div>
        <h1 style="margin:0;font-size:1.45rem;letter-spacing:-0.02em;
            color:{TEXT_PRIMARY};">
            Security<span style="color:{BRAND_SCARLET_BRIGHT};">ScarletAI</span>
        </h1>
        <p style="margin:0.4rem 0 0 0;color:{TEXT_PRIMARY};font-size:0.78rem;
            text-transform:uppercase;letter-spacing:0.14em;">
            AI-Native SIEM
        </p>
    </div>
    """


def esc(text: str) -> str:
    """Escape HTML special characters to prevent stored XSS."""
    if text is None:
        return ""
    return html_module.escape(str(text))


# Every ASCII punctuation char is backslash-escapable in CommonMark, and an
# escaped punctuation char renders as the literal character — so escaping ALL
# of them displays the original text faithfully while making every markdown
# construct inert. Single-pass translate table; the backslash entry maps to a
# double backslash so a literal backslash in the input is preserved literally.
_MD_ESCAPE_TABLE = {ord(c): "\\" + c for c in string.punctuation}


def esc_md(text: str) -> str:
    """Escape markdown-significant punctuation for plain st.markdown() text.

    HTML stays inert without unsafe_allow_html, but markdown LINK syntax is
    still rendered: [text](http://evil) inside hunt suggestions, triage
    reasoning, AI chat output, or ingest-fed names produces a clickable link
    inside the SIEM (phishing-from-inside), and headings/rules/emphasis
    restructure the page. AUD-061 choke point: every untrusted string going
    into a plain st.markdown/st.write/st.caption/st.expander-label passes
    through HERE, the way HTML-bound strings pass through esc().
    """
    if text is None:
        return ""
    return str(text).translate(_MD_ESCAPE_TABLE)
