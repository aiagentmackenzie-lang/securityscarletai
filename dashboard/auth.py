"""
Dashboard authentication — JWT-based against the SecurityScarletAI API.

Three roles:
- admin: Full access — can manage rules, users, and cases
- analyst: Standard access — can view logs, manage alerts and cases
- viewer: Read-only access — can view dashboards and logs

This module uses the API client for authentication — NO direct DB access.
"""
import os
import time

import streamlit as st

from dashboard.api_client import ApiClient, ApiError, PasswordChangeRequiredError
from dashboard.ui_utils import (
    BG_APP,
    BG_SURFACE,
    BORDER_SUBTLE,
    BRAND_SCARLET,
    BRAND_SCARLET_BRIGHT,
    BRAND_SCARLET_DEEP,
    TEXT_PRIMARY,
    brand_header_html,
)

ROLE_REVERIFY_INTERVAL = 300

ROLES = {
    "admin": {
        "description": "Full access — manage rules, users, and cases",
        "permissions": ["read", "write", "delete", "manage_users", "manage_rules"],
    },
    "analyst": {
        "description": "Standard access — view logs, manage alerts and cases",
        "permissions": ["read", "write", "manage_alerts", "manage_cases"],
    },
    "viewer": {
        "description": "Read-only access — view dashboards and logs",
        "permissions": ["read"],
    },
}


def _setup_help_enabled() -> bool:
    """Operator setup notes on the login screen only when explicitly enabled.

    Off by default: login is the front door — operator bootstrap instructions
    (docker logs, seed-admin) don't belong there unless the operator asks
    (DASHBOARD_SHOW_SETUP_HELP=1).
    """
    return os.environ.get("DASHBOARD_SHOW_SETUP_HELP", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


LOGIN_CARD_CSS = f"""
<style>
    /* Subtle brand glow on the app background (auth screens only) */
    [data-testid="stAppViewContainer"] {{
        background:
            radial-gradient(1100px 480px at 50% -8%, rgba(225,29,72,0.07), transparent 62%),
            radial-gradient(900px 420px at 85% 110%, rgba(0,188,212,0.05), transparent 60%),
            {BG_APP};
    }}
    /* The auth card: one bordered surface holding brand + form + button.
       Header HTML is rendered INSIDE the form so the card is a single
       visual unit (inputs and title can never drift apart). */
    [data-testid="stForm"] {{
        width: 100%;
        max-width: 430px;
        margin-left: auto !important;
        margin-right: auto !important;
        margin-top: 7vh;
        background: {BG_SURFACE};
        border: 1px solid {BORDER_SUBTLE};
        border-radius: 16px;
        padding: 2.4rem 2.25rem 1.6rem !important;
        box-shadow: 0 12px 40px rgba(0,0,0,0.35);
    }}
    [data-testid="stForm"] label {{
        color: #ffffff !important;
        font-size: 0.78rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.3rem;
    }}
    /* Symmetric inputs: Streamlit puts the password eye-toggle INSIDE the
       input wrapper, shrinking the password <input> ~50px vs the username
       input (both wrappers are equal width). Overlay the toggle instead:
       full-width input, eye button absolutely positioned over its right
       edge, padding keeps typed text clear of the icon. */
    [data-testid="stForm"] [data-testid="stTextInputRootElement"] {{
        position: relative;
        padding-right: 0 !important;  /* Streamlit reserves 14px for the eye */
    }}
    [data-testid="stForm"] [data-testid="stTextInputRootElement"] input {{
        width: 100% !important;
        padding-right: 2.75rem !important;
    }}
    [data-testid="stForm"] [data-testid="stTextInputRootElement"] button {{
        position: absolute !important;
        right: 0.375rem;
        top: 50%;
        transform: translateY(-50%);
        margin: 0 !important;
        padding: 0.35rem !important;
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
    }}
    [data-testid="stFormSubmitButton"] {{
        margin-top: 1.1rem;
    }}
    /* Brand scarlet Sign In — white-on-scarlet (AA contrast), scoped to the
       auth card so app-wide primary buttons keep the cyan accent.
       Streamlit 1.40 renders the form submit with kind="primaryFormSubmit"
       inside [data-testid=stFormSubmitButton] — verified in the live DOM
       via CDP 2026-08-27. Legacy kind variants kept for robustness. */
    [data-testid="stFormSubmitButton"] button,
    [data-testid="stForm"] button[kind="primaryFormSubmit"],
    [data-testid="stForm"] button[kind="primary"],
    [data-testid="stForm"] button[kind="primaryForm"] {{
        background: linear-gradient(135deg, {BRAND_SCARLET} 0%,
            {BRAND_SCARLET_DEEP} 100%) !important;
        background-color: {BRAND_SCARLET} !important;
        color: #ffffff !important;
        border: 1px solid {BRAND_SCARLET_DEEP} !important;
        font-weight: 700;
        font-size: 1rem;
        letter-spacing: 0.02em;
        box-shadow: 0 4px 16px rgba(225,29,72,0.35);
    }}
    /* Pin white on every text layer — Streamlit renders the label inside
       div > span, so the button-level color alone is not enough if a
       future Streamlit version sets an explicit color on the span. */
    [data-testid="stFormSubmitButton"] button div,
    [data-testid="stFormSubmitButton"] button span,
    [data-testid="stForm"] button[kind="primaryFormSubmit"] div,
    [data-testid="stForm"] button[kind="primaryFormSubmit"] span {{
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
        text-shadow: none !important;
    }}
    [data-testid="stFormSubmitButton"] button:hover,
    [data-testid="stForm"] button[kind="primaryFormSubmit"]:hover {{
        background: linear-gradient(135deg, {BRAND_SCARLET_BRIGHT} 0%,
            {BRAND_SCARLET} 100%) !important;
        background-color: {BRAND_SCARLET_BRIGHT} !important;
        border-color: {BRAND_SCARLET} !important;
        box-shadow: 0 6px 20px rgba(225,29,72,0.45);
    }}
    .auth-card-footer {{
        text-align: center;
        color: {TEXT_PRIMARY};
        font-size: 0.72rem;
        letter-spacing: 0.05em;
        margin: 1.2rem 0 0 0;
    }}
</style>
"""


def get_api_client() -> ApiClient:
    """Get the shared API client instance."""
    if "api_client" not in st.session_state:
        st.session_state.api_client = ApiClient()
    return st.session_state.api_client


def has_permission(permission: str) -> bool:
    """Check if the current user has a specific permission."""
    role = st.session_state.get("role", "")
    return permission in ROLES.get(role, {}).get("permissions", [])


def can_manage_rules() -> bool:
    """Check if the current user can manage rules."""
    return has_permission("manage_rules")


def can_write() -> bool:
    """Check if the current user can write (analyst+)."""
    return has_permission("write")


def is_admin() -> bool:
    """Check if the current user is an admin."""
    return st.session_state.get("role") == "admin"


def render_force_password_change_form():
    """Render the set-new-password form for a must_change_password account.

    Shown when a login returned PASSWORD_CHANGE_REQUIRED. Uses the
    force_change_token (a one-off JWT) to call /auth/force-change-password,
    then logs in with the new password.
    """
    fpc = st.session_state["force_pw_change"]
    username = fpc["username"]
    force_change_token = fpc["force_change_token"]

    # Card treatment: same auth card CSS applies (injected by
    # render_login_page). Brand header + notice + fields inside ONE form.
    with st.form("force_pw_form"):
        st.markdown(brand_header_html("forcepw"), unsafe_allow_html=True)
        st.info(
            f"Welcome, **{username}**. Your account requires a new password "
            f"before first login."
        )
        new_password = st.text_input(
            "New password", type="password", placeholder="At least 8 characters"
        )
        confirm = st.text_input("Confirm new password", type="password")
        submitted = st.form_submit_button(
            "Set new password & sign in", use_container_width=True, type="primary"
        )
        if submitted:
            if not new_password.strip() or len(new_password) < 8:
                st.error("Password must be at least 8 characters.")
            elif new_password != confirm:
                st.error("Passwords do not match.")
            else:
                with st.spinner("Updating password...", show_time=True):
                    api = get_api_client()
                    try:
                        api.force_change_password(force_change_token, new_password)
                        # Password changed and must_change_password cleared —
                        # log in normally with the new password.
                        result = api.login(username, new_password)
                        st.session_state.authenticated = True
                        st.session_state.username = result["username"]
                        st.session_state.role = result["role"]
                        st.session_state.access_token = result["access_token"]
                        st.session_state.pop("force_pw_change", None)
                        st.toast("Password updated — welcome!")
                        st.rerun()
                    except PasswordChangeRequiredError:
                        # Shouldn't happen after a successful change, but
                        # surface it clearly if it does.
                        st.error(
                            "Password changed but the reset flag is still set. "
                            "Contact an admin."
                        )
                    except ApiError as e:
                        st.error(f"Could not change password: {e.detail}")
                    except Exception as e:
                        st.error(f"Unexpected error: {e}")

    if st.button("Back to login"):
        st.session_state.pop("force_pw_change", None)
        st.rerun()


def render_login_page():
    """Render the login form as a single centered auth card."""
    st.markdown(LOGIN_CARD_CSS, unsafe_allow_html=True)

    # If a prior login returned PASSWORD_CHANGE_REQUIRED, show the
    # change-password form instead of the login form.
    if st.session_state.get("force_pw_change"):
        render_force_password_change_form()
        return False

    with st.form("login_form"):
        st.markdown(brand_header_html("login"), unsafe_allow_html=True)
        username = st.text_input("Username", placeholder="admin")
        password = st.text_input("Password", type="password", placeholder="Enter password")
        submitted = st.form_submit_button(
            "Sign In", use_container_width=True, type="primary"
        )
        st.markdown(
            '<p class="auth-card-footer">'
            "JWT authentication &middot; Role-based access control"
            "</p>",
            unsafe_allow_html=True,
        )

        if submitted and username and password:
            with st.spinner("Authenticating...", show_time=True):
                api = get_api_client()
                try:
                    result = api.login(username, password)
                    st.session_state.authenticated = True
                    st.session_state.username = result["username"]
                    st.session_state.role = result["role"]
                    st.session_state.access_token = result["access_token"]
                    st.toast(f"Welcome, {result['username']}!")
                    st.rerun()
                except PasswordChangeRequiredError as e:
                    # Account must change password — capture the force_change_token
                    # + username and rerun into the change-password form.
                    st.session_state.force_pw_change = {
                        "force_change_token": e.force_change_token,
                        "username": e.username,
                    }
                    st.rerun()
                except ApiError as e:
                    if e.status_code == 401:
                        st.error("Invalid username or password")
                    else:
                        st.error(f"Login failed: {e.detail}")
                except Exception as e:
                    st.error(f"Connection error: {e}")

    if _setup_help_enabled():
        st.divider()
        with st.expander("Initial setup (operators)"):
            st.markdown(
                "Fresh installs: the Docker entrypoint creates an admin "
                "automatically — the one-time password is written to "
                "`data/admin_initial_password` (mode 600) and echoed once to "
                "`docker logs scarletai-api`.\n\n"
                "Optional bootstrap: run the API with `SEED_ADMIN_ENABLED=true`, "
                "then from the API host **only** (localhost-restricted):\n"
                "```bash\n"
                "curl -X POST http://localhost:8000/api/v1/auth/seed-admin\n"
                "```\n"
                "A password reset is forced on first login. Do **not** use a "
                "default password in production."
            )

    return False


def render_sidebar_user_info():
    """Display current user info and logout button in sidebar."""
    if not st.session_state.get("authenticated"):
        return

    username = st.session_state.get("username", "Unknown")
    role = st.session_state.get("role", "viewer")

    role_label = role.upper()

    st.sidebar.markdown(
        "<hr style='margin:0.5rem 0;border-color:#1e2636;'/>", unsafe_allow_html=True
    )
    st.sidebar.markdown(
        f"""
        <div style="
            background:{BG_SURFACE};
            border:1px solid {BORDER_SUBTLE};
            border-radius:0.5rem;
            padding:0.75rem;
            margin-bottom:0.5rem;
        ">
            <p style="margin:0;color:#e8ecf1;font-weight:600;font-size:0.9rem;">{username}</p>
            <p style="margin:0.15rem 0 0 0;color:#8b95a5;font-size:0.7rem;
                text-transform:uppercase;letter-spacing:0.06em;">{role_label}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.sidebar.button("Logout", use_container_width=True):
        ApiClient.logout()
        st.session_state.authenticated = False
        st.rerun()


def require_auth():
    """Check if user is authenticated. Re-verify token periodically."""
    if st.session_state.get("authenticated") and st.session_state.get("access_token"):
        api = get_api_client()
        last_verified = st.session_state.get("last_role_verify", 0)
        now = time.time()

        if now - last_verified > ROLE_REVERIFY_INTERVAL:
            try:
                me = api.get_me()
                st.session_state.last_role_verify = now
                st.session_state.role = me.get("role", st.session_state.role)
                st.session_state.username = me.get("username", st.session_state.username)
            except ApiError:
                ApiClient.logout()
                st.session_state.authenticated = False
                return False
        return True
    return False
