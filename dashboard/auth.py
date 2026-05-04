"""
Dashboard authentication — JWT-based against the SecurityScarletAI API.

Three roles:
- admin: Full access — can manage rules, users, and cases
- analyst: Standard access — can view logs, manage alerts and cases
- viewer: Read-only access — can view dashboards and logs

This module uses the API client for authentication — NO direct DB access.
"""
import streamlit as st

from dashboard.api_client import ApiClient, ApiError

# Role definitions
ROLES = {
    "admin": {
        "description": "Full access — can manage rules, users, and cases",
        "permissions": ["read", "write", "delete", "manage_users", "manage_rules"],
    },
    "analyst": {
        "description": "Standard access — can view logs, manage alerts and cases",
        "permissions": ["read", "write", "manage_alerts", "manage_cases"],
    },
    "viewer": {
        "description": "Read-only access — can view dashboards and logs",
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


def render_login_page():
    """Render the login form. Returns True if user just logged in."""
    st.markdown("""
    <div style="display: flex; justify-content: center; padding-top: 10vh;">
        <div style="max-width: 400px; width: 100%;">
            <h1 style="text-align: center;">🛡️ SecurityScarletAI</h1>
            <p style="text-align: center; color: #888;">AI-Native SIEM Dashboard</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    with st.form("login_form"):
        username = st.text_input("👤 Username", placeholder="admin")
        password = st.text_input("🔑 Password", type="password", placeholder="Enter password")
        submitted = st.form_submit_button("🚀 Sign In", use_container_width=True)

        if submitted and username and password:
            with st.spinner("Authenticating...", show_time=True):
                api = get_api_client()
                try:
                    result = api.login(username, password)
                    st.session_state.authenticated = True
                    st.session_state.username = result["username"]
                    st.session_state.role = result["role"]
                    st.session_state.access_token = result["access_token"]
                    st.toast(f"✅ Welcome, {result['username']}!", icon="✅")
                    st.success(f"Welcome, {result['username']}!")
                    st.rerun()
                except ApiError as e:
                    if e.status_code == 401:
                        st.error("❌ Invalid username or password")
                    else:
                        st.error(f"❌ Login failed: {e.detail}")
                except Exception as e:
                    st.error(f"❌ Connection error: {e}")

    # Option to seed admin if no users exist
    st.divider()
    with st.expander("🔧 Initial Setup"):
        st.markdown("""
        If this is a fresh install, you need to create an admin user first.

        **Option 1:** Use the API:
        ```bash
        curl -X POST http://localhost:8000/api/v1/auth/seed-admin
        ```

        **Option 2:** Default credentials after seeding:
        - Username: `admin`
        - Password: `admin`

        ⚠️ **Change the password immediately after first login!**
        """)
        if st.button("Seed Admin User", type="secondary"):
            with st.spinner("Creating admin user...", show_time=True):
                api = get_api_client()
                try:
                    result = api._post("/auth/seed-admin")
                    st.toast("✅ Admin user created", icon="✅")
                    st.success(f"✅ {result.get('message', 'Admin user created!')}")
                except ApiError as e:
                    st.error(f"❌ {e.detail}")

    return False


def render_sidebar_user_info():
    """Display current user info and logout button in sidebar."""
    if not st.session_state.get("authenticated"):
        return

    username = st.session_state.get("username", "Unknown")
    role = st.session_state.get("role", "viewer")

    role_icons = {"admin": "👑", "analyst": "🔍", "viewer": "👁️"}

    st.sidebar.divider()
    st.sidebar.markdown(f"**{role_icons.get(role, '👤')} {username}**")
    st.sidebar.caption(f"Role: {role}")

    if st.sidebar.button("🚪 Logout"):
        ApiClient.logout()
        st.session_state.authenticated = False
        st.rerun()


def require_auth():
    """Check if user is authenticated. Returns True if authenticated, shows login if not."""
    if st.session_state.get("authenticated") and st.session_state.get("access_token"):
        # Verify token is still valid by calling /auth/me
        api = get_api_client()
        try:
            # Only verify once per session
            if "user_verified" not in st.session_state:
                me = api.get_me()
                st.session_state.user_verified = True
                st.session_state.role = me.get("role", st.session_state.role)
                st.session_state.username = me.get("username", st.session_state.username)
            return True
        except ApiError:
            # Token expired or invalid
            ApiClient.logout()
            st.session_state.authenticated = False
            return False
    return False
