"""
Dashboard authentication — JWT-based against the SecurityScarletAI API.

Three roles:
- admin: Full access — can manage rules, users, and cases
- analyst: Standard access — can view logs, manage alerts and cases
- viewer: Read-only access — can view dashboards and logs

This module uses the API client for authentication — NO direct DB access.
"""
import time

import streamlit as st

from dashboard.api_client import ApiClient, ApiError, PasswordChangeRequiredError
from dashboard.ui_utils import BG_SURFACE, BORDER_SUBTLE

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

    st.info(
        f"Welcome, **{username}**. Your account requires a new password "
        f"before first login."
    )
    with st.form("force_pw_form"):
        new_password = st.text_input(
            "New password", type="password", placeholder="At least 8 characters"
        )
        confirm = st.text_input("Confirm new password", type="password")
        submitted = st.form_submit_button(
            "Set new password & sign in", use_container_width=True
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
    """Render the login form."""
    st.markdown(f"""
    <div style="display:flex;justify-content:center;padding-top:12vh;">
        <div style="
            max-width:400px;
            width:100%;
            background:{BG_SURFACE};
            border:1px solid {BORDER_SUBTLE};
            border-radius:0.75rem;
            padding:2rem;
        ">
            <h1 style="text-align:center;color:#e8ecf1;margin:0 0 0.25rem 0;">
                SecurityScarletAI
            </h1>
            <p style="text-align:center;color:#8b95a5;margin:0 0 1.5rem 0;font-size:0.9rem;">
                AI-Native SIEM Dashboard
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # If a prior login returned PASSWORD_CHANGE_REQUIRED, show the
    # change-password form instead of the login form.
    if st.session_state.get("force_pw_change"):
        render_force_password_change_form()
        return False

    with st.form("login_form"):
        username = st.text_input("Username", placeholder="admin")
        password = st.text_input("Password", type="password", placeholder="Enter password")
        submitted = st.form_submit_button("Sign In", use_container_width=True)

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
                    st.success(f"Welcome, {result['username']}!")
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

    st.divider()
    with st.expander("Initial Setup"):
        st.markdown("""
        If this is a fresh install, an admin user is created automatically by
        the Docker entrypoint — the one-time password is printed to
        `docker logs scarletai-api` (look for the `ADMIN USER CREATED` block).

        Alternatively, bootstrap from the API host **only** (localhost-restricted):
        ```bash
        curl -X POST http://localhost:8000/api/v1/auth/seed-admin
        ```
        A password reset is forced on first login. Do **not** use a default
        password in production.
        """)

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
