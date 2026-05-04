"""
Chart components for SecurityScarletAI dashboard.

ALL data is fetched through the API client — NO direct database access.
Uses Altair for rich visualizations and Streamlit native charts for simplicity.

Loading states: Every data fetch is wrapped in st.spinner() for UX polish.
"""
import streamlit as st
import pandas as pd
import altair as alt

from dashboard.api_client import ApiError
from dashboard.auth import get_api_client

# ───────────────────────────────────────────────────────────────
# Dark theme configuration for Altair charts
# ───────────────────────────────────────────────────────────────

DARK_THEME = {
    "background": "#0e1117",
    "title": {"color": "#fafafa", "fontSize": 14},
    "axis": {
        "labelColor": "#a0a0a0",
        "titleColor": "#fafafa",
        "gridColor": "#262730",
        "domainColor": "#505050",
    },
    "legend": {
        "labelColor": "#a0a0a0",
        "titleColor": "#fafafa",
    },
    "view": {"stroke": "transparent"},
}

SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high": "#ff8c00",
    "medium": "#ffd700",
    "low": "#4488ff",
    "info": "#888888",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _altair_theme():
    """Register a dark theme for Altair charts."""
    return {
        "config": {
            "background": "#0e1117",
            "title": {"color": "#fafafa", "fontSize": 14, "fontWeight": "bold"},
            "axis": {
                "labelColor": "#a0a0a0",
                "titleColor": "#fafafa",
                "gridColor": "#262730",
                "domainColor": "#505050",
            },
            "legend": {
                "labelColor": "#a0a0a0",
                "titleColor": "#fafafa",
            },
            "view": {"stroke": "transparent"},
        }
    }


def render_severity_distribution():
    """Render alert severity distribution as a donut chart."""
    api = get_api_client()

    with st.spinner("Loading severity distribution...", show_time=True):
        try:
            alerts = api.get_alerts(limit=1000)
            if not alerts:
                st.info("No alerts to display")
                return

            # Count by severity
            severity_counts = {}
            for a in alerts:
                sev = a.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            if not severity_counts:
                st.info("No alert data available")
                return

            # Build dataframe
            df = pd.DataFrame([
                {"Severity": k, "Count": v, "Color": SEVERITY_COLORS.get(k, "#888888")}
                for k, v in severity_counts.items()
            ])

            # Sort by severity order
            severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
            df["Order"] = df["Severity"].map(severity_rank).fillna(99)
            df = df.sort_values("Order")

            # Create chart
            chart = (
                alt.Chart(df)
                .encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color("Severity:N", scale=alt.Scale(
                        domain=list(df["Severity"]),
                        range=list(df["Color"]),
                    )),
                    tooltip=["Severity", "Count"],
                )
            )

            pie = chart.mark_arc(innerRadius=50, outerRadius=100, stroke="#0e1117", strokeWidth=2)
            text = chart.mark_text(radius=75, size=12, fill="#fafafa").encode(text="Count:Q")

            st.altair_chart((pie + text).properties(
                title="Alert Severity Distribution",
                width=300,
                height=300,
            ), use_container_width=True)

        except ApiError as e:
            st.error(f"Failed to load severity data: {e.detail}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")


def render_alert_trend():
    """Render alert volume trend over time as a line chart."""
    api = get_api_client()

    with st.spinner("Loading alert trend...", show_time=True):
        try:
            alerts = api.get_alerts(limit=1000)
            if not alerts:
                st.info("No alerts to display")
                return

            # Group by date
            df = pd.DataFrame(alerts)
            if "time" not in df.columns:
                st.info("No time data in alerts")
                return

            df["time"] = pd.to_datetime(df["time"], utc=True)
            df["date"] = df["time"].dt.date

            # Count by date and severity
            trend = df.groupby(["date", "severity"]).size().reset_index(name="count")

            # Sort severities
            severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
            trend["order"] = trend["severity"].map(severity_rank).fillna(99)
            trend = trend.sort_values(["date", "order"])

            chart = (
                alt.Chart(trend)
                .mark_line(point=True)
                .encode(
                    x=alt.X("date:T", title="Date"),
                    y=alt.Y("count:Q", title="Alerts"),
                    color=alt.Color("severity:N", scale=alt.Scale(
                        domain=SEVERITY_ORDER,
                        range=[SEVERITY_COLORS.get(s, "#888") for s in SEVERITY_ORDER],
                    ), title="Severity"),
                    tooltip=["date", "severity", "count"],
                )
                .properties(title="Alert Trend (Last 1000)", width=600, height=300)
            )

            st.altair_chart(chart, use_container_width=True)

        except ApiError as e:
            st.error(f"Failed to load alert trend: {e.detail}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")


def render_top_hosts():
    """Render top hosts by alert count."""
    api = get_api_client()

    with st.spinner("Loading host data...", show_time=True):
        try:
            alerts = api.get_alerts(limit=1000)
            if not alerts:
                st.info("No alerts to display")
                return

            # Count by host
            host_counts = {}
            for a in alerts:
                host = a.get("host_name", "unknown")
                host_counts[host] = host_counts.get(host, 0) + 1

            df = pd.DataFrame(
                [{"Host": k, "Alerts": v} for k, v in
                 sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
            )

            if df.empty:
                st.info("No host data available")
                return

            chart = (
                alt.Chart(df)
                .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
                .encode(
                    y=alt.Y("Host:N", sort="-x", title="Host"),
                    x=alt.X("Alerts:Q", title="Number of Alerts"),
                    color=alt.value("#ff6b6b"),
                    tooltip=["Host", "Alerts"],
                )
                .properties(title="🖥️ Top Hosts by Alert Count", height=300)
            )

            st.altair_chart(chart, use_container_width=True)

        except ApiError as e:
            st.error(f"Failed to load host data: {e.detail}")


def render_mitre_heatmap(rules: list[dict]):
    """Render MITRE ATT&CK technique coverage heatmap."""
    if not rules:
        st.info("No rules loaded — MITRE coverage will show once rules are loaded.")
        return

    # Collect all technique → tactic mappings from rules
    technique_data = []
    for rule in rules:
        techniques = rule.get("mitre_techniques", []) or []
        tactics = rule.get("mitre_tactics", []) or []
        sev = rule.get("severity", "medium")
        enabled = rule.get("enabled", True)

        for tech in techniques:
            technique_data.append({
                "Technique": tech,
                "Tactics": ", ".join(tactics) if tactics else "Unknown",
                "Severity": sev,
                "Enabled": enabled,
                "Rule": rule.get("name", ""),
            })

    if not technique_data:
        st.info("No MITRE ATT&CK mappings found in rules.")
        return

    df = pd.DataFrame(technique_data)

    # Count rules per technique
    df.groupby("Technique").agg(
        Rule_Count=("Rule", "count"),
        Tactic=("Tactics", "first"),
    ).reset_index()

    # Display as a table with heatmap colors
    st.subheader("🎯 MITRE ATT&CK Coverage")

    # Simplified tactic categories
    TACTIC_TITLES = {
        "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
        "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
        "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
        "TA0009": "Collection", "TA0011": "Command and Control",
        "TA0010": "Exfiltration", "TA0040": "Impact",
    }

    # Build per-tactic columns
    tactic_data = {}
    for tactic_id, tactic_name in TACTIC_TITLES.items():
        rules_in_tactic = df[df["Tactics"].str.contains(tactic_id, na=False)]
        if not rules_in_tactic.empty:
            technique_list = rules_in_tactic.groupby("Technique")["Rule"].apply(
                lambda x: "<br>".join(x)
            ).to_dict()
            tactic_data[tactic_name] = technique_list

    # Count per tactic
    tactic_counts = {}
    for tactic_id, tactic_name in TACTIC_TITLES.items():
        count = len(df[df["Tactics"].str.contains(tactic_id, na=False)]["Technique"].unique())
        if count > 0:
            tactic_counts[tactic_name] = count

    if tactic_counts:
        cols = st.columns(min(len(tactic_counts), 4))
        for i, (tactic, count) in enumerate(
            sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
        ):
            with cols[i % 4]:
                # Color based on coverage
                if count >= 3:
                    color = "🟢"
                elif count >= 2:
                    color = "🟡"
                else:
                    color = "🔴"
                st.metric(f"{color} {tactic}", f"{count} techniques")

    # Full technique table
    with st.expander("📋 Detailed Technique Coverage"):
        st.dataframe(
            df[["Technique", "Tactics", "Severity", "Rule"]],
            use_container_width=True,
            hide_index=True,
        )


def render_dashboard_metrics():
    """Render top-level dashboard metrics cards."""
    api = get_api_client()

    with st.spinner("Loading dashboard metrics...", show_time=True):
        try:
            alerts = api.get_alerts(limit=1000) or []

            # Compute metrics from the data
            total = len(alerts)
            critical = sum(1 for a in alerts if a.get("severity") == "critical")
            high = sum(1 for a in alerts if a.get("severity") == "high")
            new = sum(1 for a in alerts if a.get("status") == "new")
            investigating = sum(1 for a in alerts if a.get("status") == "investigating")

            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("🚨 Total Alerts", total)
            col2.metric("🔴 Critical", critical)
            col3.metric("🟠 High", high)
            col4.metric("🆕 New", new)
            col5.metric("🔍 Investigating", investigating)

            return alerts

        except ApiError as e:
            st.error(f"Failed to load metrics: {e.detail}")
            return []
        except Exception:
            st.error("Unexpected error loading metrics")
            return []


def render_severity_sparklines():
    """Render mini sparkline charts for alert severity over time."""
    api = get_api_client()

    with st.spinner("Loading severity trends...", show_time=True):
        try:
            alerts = api.get_alerts(limit=500) or []
            if not alerts:
                return

            df = pd.DataFrame(alerts)
            if "time" not in df.columns:
                return

            df["time"] = pd.to_datetime(df["time"], utc=True)
            df["date"] = df["time"].dt.date

            cols = st.columns(len(SEVERITY_ORDER))
            for i, sev in enumerate(SEVERITY_ORDER):
                sev_df = df[df["severity"] == sev]
                daily = sev_df.groupby("date").size().reset_index(name="count")

                if len(daily) > 1:
                    chart = (
                        alt.Chart(daily)
                        .mark_line(color=SEVERITY_COLORS.get(sev, "#888"))
                        .encode(
                            x=alt.X("date:T", axis=alt.Axis(labels=False, ticks=False)),
                            y=alt.Y("count:Q", axis=alt.Axis(labels=False, ticks=False)),
                        )
                        .properties(height=60, title=f"{sev.upper()}: {len(sev_df)}")
                    )
                    cols[i].altair_chart(chart, use_container_width=True)
                else:
                    cols[i].metric(sev.upper(), len(sev_df))

        except Exception:  # noqa: S110
            pass  # Non-critical sparkline, fail silently


def render_host_risk_scores():
    """Render risk score gauges for top hosts."""
    api = get_api_client()

    with st.spinner("Loading host risk scores...", show_time=True):
        try:
            alerts = api.get_alerts(limit=1000) or []
            if not alerts:
                return

            # Calculate per-host risk from alert severity
            host_risk = {}
            severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

            for a in alerts:
                host = a.get("host_name", "unknown")
                sev = a.get("severity", "info")
                weight = severity_weights.get(sev, 1)
                host_risk[host] = host_risk.get(host, 0) + weight

            # Cap at 100 and take top 5
            top_hosts = sorted(host_risk.items(), key=lambda x: x[1], reverse=True)[:5]

            if top_hosts:
                cols = st.columns(min(len(top_hosts), 5))
                for i, (host, score) in enumerate(top_hosts):
                    score = min(score, 100)
                    # Color based on risk
                    if score >= 70:
                        color = "🔴"
                    elif score >= 40:
                        color = "🟠"
                    else:
                        color = "🟢"
                    cols[i].metric(f"{color} {host}", f"{score}/100")

        except Exception:  # noqa: S110
            pass  # Non-critical gauge, fail silently
