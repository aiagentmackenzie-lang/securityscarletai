"""
Alert list view for Streamlit dashboard.

Displays paginated alerts with filtering and bulk actions.
"""
import streamlit as st
import httpx
import asyncio
from datetime import datetime
from typing import Optional

from src.config.settings import settings
from src.config.logging import get_logger
from dashboard.auth import DashboardUser

log = get_logger("dashboard.alerts")


async def fetch_alerts(
    token: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """Fetch alerts from API."""
    params = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"http://{settings.api_host}:{settings.api_port}/api/v1/alerts",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()


async def update_alert_status(
    token: str,
    alert_id: int,
    status: str,
    assigned_to: Optional[str] = None,
) -> dict:
    """Update alert status via API."""
    async with httpx.AsyncClient() as client:
        resp = await client.put(
            f"http://{settings.api_host}:{settings.api_port}/api/v1/alerts/{alert_id}",
            json={"status": status, "assigned_to": assigned_to},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()


def severity_badge(severity: str) -> str:
    """Return emoji badge for severity."""
    badges = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }
    return badges.get(severity.lower(), "⚪")


def status_badge(status: str) -> str:
    """Return emoji badge for status."""
    badges = {
        "new": "🆕",
        "investigating": "🔍",
        "resolved": "✅",
        "false_positive": "🚫",
        "closed": "📁",
    }
    return badges.get(status.lower(), "❓")


def render_alert_list(user: DashboardUser):
    """Render the alert list view."""
    st.header("🚨 Security Alerts")
    
    # Filters
    col1, col2, col3 = st.columns([2, 2, 2])
    
    with col1:
        status_filter = st.selectbox(
            "Status",
            ["All", "New", "Investigating", "Resolved", "False Positive", "Closed"],
            key="alert_status_filter",
        )
    
    with col2:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "Critical", "High", "Medium", "Low", "Info"],
            key="alert_severity_filter",
        )
    
    with col3:
        st.write("")
        st.write("")
        if st.button("🔄 Refresh"):
            st.cache_data.clear()
            st.rerun()
    
    # Pagination
    page = st.session_state.get("alert_page", 0)
    page_size = 25
    
    # Fetch alerts
    try:
        status_param = None if status_filter == "All" else status_filter.lower()
        severity_param = None if severity_filter == "All" else severity_filter.lower()
        
        alerts = asyncio.run(fetch_alerts(
            token=user.token,
            status=status_param,
            severity=severity_param,
            limit=page_size,
            offset=page * page_size,
        ))
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        alerts = []
    
    if not alerts:
        st.info("No alerts found matching your criteria.")
        return
    
    # Alert count
    st.caption(f"Showing {len(alerts)} alerts")
    
    # Alert table
    for alert in alerts:
        with st.expander(
            f"{severity_badge(alert['severity'])} [{alert['severity'].upper()}] "
            f"{alert['rule_name']} on {alert['host_name']} "
            f"{status_badge(alert['status'])}",
        ):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.write(f"**ID:** {alert['id']}")
                st.write(f"**Time:** {alert['time']}")
                st.write(f"**Description:** {alert['description']}")
                
                if alert.get('mitre_techniques'):
                    st.write(f"**MITRE:** {', '.join(alert['mitre_techniques'])}")
            
            with col2:
                if user.can_write():
                    new_status = st.selectbox(
                        "Update Status",
                        ["new", "investigating", "resolved", "false_positive", "closed"],
                        index=["new", "investigating", "resolved", "false_positive", "closed"].index(alert['status']),
                        key=f"status_{alert['id']}",
                    )
                    
                    if st.button("Update", key=f"update_{alert['id']}"):
                        try:
                            asyncio.run(update_alert_status(
                                token=user.token,
                                alert_id=alert['id'],
                                status=new_status,
                                assigned_to=user.username,
                            ))
                            st.success("Updated!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Update failed: {e}")
    
    # Pagination controls
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        if page > 0:
            if st.button("⬅️ Previous"):
                st.session_state.alert_page = page - 1
                st.rerun()
    
    with col2:
        st.write(f"Page {page + 1}")
    
    with col3:
        if len(alerts) == page_size:
            if st.button("Next ➡️"):
                st.session_state.alert_page = page + 1
                st.rerun()


def render_alert_detail(alert_id: int, user: DashboardUser):
    """Render detailed view of a single alert."""
    st.header(f"Alert #{alert_id}")
    st.info("Alert detail view would show full evidence, timeline, and remediation guidance here.")
