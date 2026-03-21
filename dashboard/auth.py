"""
Dashboard authentication with RBAC.

Three roles:
- admin: Can manage rules, users, and cases
- analyst: Can view logs, manage alerts and cases  
- viewer: Read-only access
"""
import streamlit as st
import httpx
import asyncio
from datetime import datetime, timedelta

from src.config.settings import settings
from src.config.logging import get_logger

log = get_logger("dashboard.auth")


# Role definitions
ROLES = {
    "admin": {
        "description": "Full access - can manage rules, users, and cases",
        "permissions": ["read", "write", "delete", "manage_users", "manage_rules"],
    },
    "analyst": {
        "description": "Standard access - can view logs, manage alerts and cases",
        "permissions": ["read", "write", "manage_alerts", "manage_cases"],
    },
    "viewer": {
        "description": "Read-only access - can view dashboards and logs",
        "permissions": ["read"],
    },
}


class DashboardUser:
    """Dashboard user session."""
    
    def __init__(self, username: str, role: str, token: str):
        self.username = username
        self.role = role
        self.token = token
        self.login_time = datetime.now()
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in ROLES.get(self.role, {}).get("permissions", [])
    
    def can_manage_rules(self) -> bool:
        return self.has_permission("manage_rules")
    
    def can_manage_users(self) -> bool:
        return self.has_permission("manage_users")
    
    def can_write(self) -> bool:
        return self.has_permission("write")


def login_form():
    """Display login form and return user if authenticated."""
    st.header("🔐 Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            # TODO: Implement actual authentication against API
            # For now, demo mode
            if username and password:
                st.session_state.user = DashboardUser(
                    username=username,
                    role="analyst",  # Default role
                    token="demo_token",
                )
                st.success(f"Welcome, {username}!")
                st.rerun()
            else:
                st.error("Please enter username and password")
    
    return None


def require_auth(func):
    """Decorator to require authentication for a page."""
    def wrapper(*args, **kwargs):
        if "user" not in st.session_state:
            login_form()
            return
        return func(*args, **kwargs)
    return wrapper


def logout_button():
    """Display logout button in sidebar."""
    if st.sidebar.button("🚪 Logout"):
        del st.session_state.user
        st.rerun()


def show_user_info():
    """Display current user info in sidebar."""
    if "user" in st.session_state:
        user = st.session_state.user
        st.sidebar.divider()
        st.sidebar.write(f"👤 **{user.username}**")
        st.sidebar.caption(f"Role: {user.role}")
        logout_button()
