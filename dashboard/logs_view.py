"""
Log viewer for SecurityScarletAI dashboard.

Real-time and historical log viewing with filtering.
ALL data fetched through ApiClient — NO direct database access.
Loading states: st.spinner() on data fetches, auto-refresh friendly.
"""
import streamlit as st
import pandas as pd

from dashboard.api_client import ApiError
from dashboard.auth import get_api_client
from dashboard.ui_utils import SEVERITY_COLORS, TEXT_SECONDARY, BG_SURFACE, BORDER_SUBTLE, TEXT_PRIMARY


def render_log_viewer():
    """Render the log viewer page."""
    api = get_api_client()

    st.header("Log Viewer")

    # ─── Filters ───
    with st.expander("Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            time_range = st.selectbox(
                "Time Range",
                ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours"],
                index=1,
                key="log_time_range",
            )

        with col2:
            category_filter = st.selectbox(
                "Category",
                ["All", "process", "network", "file", "authentication", "configuration", "security"],
                key="log_category_filter",
            )

        with col3:
            host_filter = st.text_input(
                "Host Filter",
                placeholder="e.g., macbook-pro",
                key="log_host_filter",
            )

        with col4:
            limit = st.number_input(
                "Rows", min_value=10, max_value=500, value=100, key="log_limit"
            )

    # ─── Fetch Logs ───
    category = None if category_filter == "All" else category_filter
    host = host_filter if host_filter else None

    time_map = {
        "Last 15 minutes": 15,
        "Last 1 hour": 60,
        "Last 6 hours": 360,
        "Last 24 hours": 1440,
    }
    time_minutes = time_map.get(time_range, 60)

    with st.spinner("Loading log entries...", show_time=True):
        try:
            logs = api.get_logs(limit=limit, category=category, host=host, time_minutes=time_minutes)
        except ApiError as e:
            if e.status_code == 401:
                st.error("Session expired. Please log in again.")
            else:
                st.error(f"Failed to fetch logs: {e.detail}")
            return
        except Exception as e:
            st.error(f"Unexpected error: {e}")
            return

    if not logs:
        st.info("No logs found matching your criteria. Ingest events via the API.")
        return

    # ─── Metrics ───
    df = pd.DataFrame(logs)
    col1, col2, col3, col4 = st.columns(4)

    total_count = len(logs)
    col1.metric("Total Events", total_count)

    host_n = df["host_name"].nunique() if "host_name" in df.columns else 0
    col2.metric("Hosts", host_n)

    cat_n = df["event_category"].nunique() if "event_category" in df.columns else 0
    col3.metric("Categories", cat_n)

    col4.metric("Recent", total_count)

    # ─── Display Table ───
    display_cols = [
        "time", "host_name", "event_category", "event_type", "event_action",
        "source_ip", "destination_ip", "destination_port", "user_name",
        "process_name", "process_cmdline",
    ]

    available_cols = [c for c in display_cols if c in df.columns]
    display_df = df[available_cols].copy()
    if "time" in display_df.columns:
        display_df["time"] = display_df["time"].astype(str).str[:19]

    for col in ["process_cmdline", "event_action"]:
        if col in display_df.columns:
            display_df[col] = display_df[col].astype(str).str[:60]

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        height=500,
    )

    st.caption(f"Showing {len(logs)} most recent log entries")

    # ─── Raw JSON view ───
    with st.expander("Raw JSON (first 5 entries)"):
        st.json(logs[:5])
