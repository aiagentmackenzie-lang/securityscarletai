"""
Chart components for Streamlit dashboard.

Real-time metrics and visualizations.
"""
import streamlit as st
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List, Dict

import pandas as pd
from src.config.logging import get_logger
from src.db.connection import get_pool

log = get_logger("dashboard.charts")


async def fetch_time_series_data(
    hours: int = 24,
    interval: str = "1 hour",
) -> List[Dict]:
    """Fetch event counts over time."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT 
                date_trunc('hour', time) as hour,
                event_category,
                COUNT(*) as count
            FROM logs
            WHERE time > NOW() - INTERVAL '$1 hours'
            GROUP BY hour, event_category
            ORDER BY hour ASC
            """,
            hours,
        )
        return [dict(r) for r in rows]


async def fetch_severity_distribution() -> Dict[str, int]:
    """Fetch alert severity distribution."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE time > NOW() - INTERVAL '24 hours'
            GROUP BY severity
            """
        )
        return {r["severity"]: r["count"] for r in rows}


async def fetch_top_hosts(limit: int = 10) -> List[Dict]:
    """Fetch top hosts by event count."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT host_name, COUNT(*) as count
            FROM logs
            WHERE time > NOW() - INTERVAL '24 hours'
            GROUP BY host_name
            ORDER BY count DESC
            LIMIT $1
            """,
            limit,
        )
        return [dict(r) for r in rows]


def render_event_timeline():
    """Render event timeline chart."""
    st.subheader("📈 Event Timeline (24h)")
    
    try:
        data = asyncio.run(fetch_time_series_data(hours=24))
        
        if data:
            df = pd.DataFrame(data)
            
            # Pivot for stacked area chart
            pivot = df.pivot(index="hour", columns="event_category", values="count").fillna(0)
            
            st.area_chart(pivot, use_container_width=True)
        else:
            st.info("No data available for timeline")
    except Exception as e:
        st.error(f"Failed to load timeline: {e}")


def render_severity_chart():
    """Render alert severity distribution."""
    st.subheader("🎯 Alert Severity Distribution")
    
    try:
        data = asyncio.run(fetch_severity_distribution())
        
        if data:
            df = pd.DataFrame([
                {"Severity": k, "Count": v} 
                for k, v in data.items()
            ])
            
            st.bar_chart(df.set_index("Severity"), use_container_width=True)
        else:
            st.info("No alerts in last 24 hours")
    except Exception as e:
        st.error(f"Failed to load severity chart: {e}")


def render_top_hosts():
    """Render top hosts chart."""
    st.subheader("🖥️ Top Hosts by Activity")
    
    try:
        data = asyncio.run(fetch_top_hosts(limit=10))
        
        if data:
            df = pd.DataFrame(data)
            st.bar_chart(df.set_index("host_name"), use_container_width=True)
        else:
            st.info("No host data available")
    except Exception as e:
        st.error(f"Failed to load hosts chart: {e}")


def render_dashboard_charts():
    """Render all dashboard charts."""
    col1, col2 = st.columns(2)
    
    with col1:
        render_event_timeline()
    
    with col2:
        render_severity_chart()
    
    render_top_hosts()
