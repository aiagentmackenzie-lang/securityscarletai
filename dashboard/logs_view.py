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


def render_log_viewer():
    """Render the log viewer page."""
    api = get_api_client()

    st.header("📡 Log Viewer")

    # ─── Filters ───
    with st.expander("🔍 Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            time_range = st.selectbox(  # noqa: F841
                "Time Range",
                ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours"],
                index=1,
                key="log_time_range",
            )

        with col2:
            category_filter = st.selectbox(
                "Category",
                ["All", "process", "network", "file", "authentication", "configuration", "security"],  # noqa: E501
                key="log_category_filter",
            )

        with col3:
            host_filter = st.text_input("Host Filter", placeholder="e.g., macbook-pro", key="log_host_filter")  # noqa: E501

        with col4:
            limit = st.number_input("Rows", min_value=10, max_value=500, value=100, key="log_limit")

    # ─── Fetch Logs ───
    category = None if category_filter == "All" else category_filter
    host = host_filter if host_filter else None

    with st.spinner("Loading log entries...", show_time=True):
        try:
            logs = api.get_logs(limit=limit, category=category, host=host)
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
    col1.metric("📊 Total Events", total_count)

    if "host_name" in df.columns:
        col2.metric("🖥️ Hosts", df["host_name"].nunique())
    else:
        col2.metric("🖥️ Hosts", "N/A")

    if "event_category" in df.columns:
        col3.metric("📁 Categories", df["event_category"].nunique())
    else:
        col3.metric("📁 Categories", "N/A")

    if "severity" in df.columns:
        critical = sum(1 for r in logs if r.get("severity") == "critical")
        col4.metric("🔴 Critical", critical)
    else:
        col4.metric("🔴 Critical", "N/A")

    st.divider()

    # ─── Severity Distribution (inline mini-bar) ───
    if "severity" in df.columns:
        sev_counts = df["severity"].value_counts()
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        bar_parts = []
        for sev, count in sev_counts.items():
            icon = severity_icons.get(sev, "⚪")
            bar_parts.append(f"{icon}{sev}: {count}")
        st.caption("  |  ".join(bar_parts))

    # ─── Display Table ───
    display_cols = [
        "time", "host_name", "event_category", "event_type", "event_action",
        "source_ip", "destination_ip", "destination_port", "user_name",
        "process_name", "process_cmdline", "severity",
    ]

    # Filter to available columns
    available_cols = [c for c in display_cols if c in df.columns]

    display_df = df[available_cols].copy()
    # Format time
    if "time" in display_df.columns:
        display_df["time"] = display_df["time"].astype(str).str[:19]

    # Truncate long fields for display
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
    with st.expander("🔍 Raw JSON (first 5 entries)"):
        st.json(logs[:5])
