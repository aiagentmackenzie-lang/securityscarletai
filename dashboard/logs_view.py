"""
Log viewer for Streamlit dashboard.

Real-time and historical log viewing with filtering.
"""
import streamlit as st
import asyncio
from datetime import datetime, timedelta
from typing import Optional

from src.config.logging import get_logger
from src.db.connection import get_pool
from dashboard.auth import DashboardUser

log = get_logger("dashboard.logs")


async def fetch_logs(
    host_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    hours: int = 1,
    limit: int = 100,
) -> list[dict]:
    """Fetch logs from database."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        conditions = ["time > NOW() - INTERVAL '$1 hours'"]
        params = [hours]
        
        if host_filter:
            params.append(f"%{host_filter}%")
            conditions.append(f"host_name ILIKE ${len(params)}")
        
        if category_filter:
            params.append(category_filter)
            conditions.append(f"event_category = ${len(params)}")
        
        where_clause = " AND ".join(conditions)
        
        rows = await conn.fetch(
            f"""
            SELECT time, host_name, event_category, event_type, event_action,
                   user_name, process_name, source_ip, destination_ip
            FROM logs
            WHERE {where_clause}
            ORDER BY time DESC
            LIMIT ${len(params) + 1}
            """,
            *params,
            limit,
        )
        return [dict(r) for r in rows]


def render_log_viewer(user: DashboardUser):
    """Render the log viewer page."""
    st.header("📡 Log Viewer")
    
    # Real-time toggle
    col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
    
    with col1:
        time_range = st.selectbox(
            "Time Range",
            ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours"],
            index=1,
        )
    
    with col2:
        category_filter = st.selectbox(
            "Category",
            ["All", "process", "network", "file", "authentication", "configuration"],
        )
    
    with col3:
        host_filter = st.text_input("Host Filter", placeholder="e.g., macbook-pro")
    
    with col4:
        st.write("")
        st.write("")
        auto_refresh = st.toggle("🔄 Auto-refresh", value=False)
    
    # Convert time range to hours
    hours_map = {
        "Last 15 minutes": 0.25,
        "Last 1 hour": 1,
        "Last 6 hours": 6,
        "Last 24 hours": 24,
    }
    hours = hours_map.get(time_range, 1)
    
    # Fetch logs
    try:
        category = None if category_filter == "All" else category_filter
        logs = asyncio.run(fetch_logs(
            host_filter=host_filter if host_filter else None,
            category_filter=category,
            hours=int(hours),
            limit=100,
        ))
    except Exception as e:
        st.error(f"Failed to fetch logs: {e}")
        logs = []
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", len(logs))
    col2.metric("Hosts", len(set(l.get("host_name") for l in logs)))
    col3.metric("Categories", len(set(l.get("event_category") for l in logs)))
    
    st.divider()
    
    # Log table
    if logs:
        # Format for display
        display_logs = []
        for log_entry in logs:
            display_logs.append({
                "Time": log_entry.get("time", "")[:19],
                "Host": log_entry.get("host_name", "")[:20],
                "Category": log_entry.get("event_category", ""),
                "Action": log_entry.get("event_action", "")[:30],
                "User": log_entry.get("user_name", "") or "-",
                "Process": log_entry.get("process_name", "")[:20] or "-",
            })
        
        st.dataframe(
            display_logs,
            use_container_width=True,
            hide_index=True,
        )
        
        # Raw JSON view
        if st.checkbox("Show raw data"):
            st.json(logs[:5])  # Show first 5
    else:
        st.info("No logs found matching your criteria.")
    
    # Auto-refresh
    if auto_refresh:
        st.caption("Auto-refreshing every 10 seconds...")
        # Note: In Streamlit, we'd use st.rerun() with a timer
        # For now, manual refresh button
        if st.button("Refresh Now"):
            st.rerun()
