"""
Chart components for SecurityScarletAI dashboard.

ALL data is fetched through the API client — NO direct database access.
Uses Altair for rich visualizations and Streamlit native charts for simplicity.

Loading states: Every data fetch is wrapped in st.spinner() for UX polish.
Performance: All alert data is fetched once via cached_alerts() then passed
  to chart functions — eliminates N+1 redundant API calls per page load.
"""
import altair as alt
import pandas as pd
import streamlit as st

from dashboard.api_client import ApiError
from dashboard.auth import get_api_client

# ───────────────────────────────────────────────────────────────
# Design Tokens (mirror from main.py)
# ───────────────────────────────────────────────────────────────

BG_APP = "#090c14"
BG_SURFACE = "#0f1420"
BG_ELEVATED = "#161d2e"
ACCENT = "#00bcd4"
TEXT_PRIMARY = "#e8ecf1"
TEXT_SECONDARY = "#8b95a5"
TEXT_MUTED = "#5a6578"
BORDER_SUBTLE = "#1e2636"
BORDER_FOCUS = "#00bcd4"

SEVERITY_COLORS = {
    "critical": "#ff3860",
    "high": "#ff8f00",
    "medium": "#ffc107",
    "low": "#2979ff",
    "info": "#78909c",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _chart_container(chart, title: str, height: int | None = None):
    """Wrap an Altair chart in a styled card container."""
    with st.container():
        # Title only in the container header — chart must NOT have its own title
        st.markdown(
            f"""
            <div style="
                background:{BG_SURFACE};
                border:1px solid {BORDER_SUBTLE};
                border-radius:0.5rem;
                padding:0.75rem 1rem;
                margin-bottom:1rem;
            ">
                <p style="
                    color:{TEXT_PRIMARY};
                    font-weight:600;
                    font-size:0.9rem;
                    margin:0 0 0.5rem 0;
                ">{title}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        props = {}
        if height:
            props["height"] = height
        st.altair_chart(chart, use_container_width=True)


def _altair_theme():
    """Return a dark theme dict for Altair."""
    return {
        "config": {
            "background": BG_SURFACE,
            "title": {
                "color": TEXT_PRIMARY,
                "fontSize": 13,
                "fontWeight": "bold",
                "anchor": "start",
            },
            "axis": {
                "labelColor": TEXT_SECONDARY,
                "titleColor": TEXT_PRIMARY,
                "gridColor": BORDER_SUBTLE,
                "domainColor": BORDER_SUBTLE,
                "tickColor": BORDER_SUBTLE,
            },
            "legend": {
                "labelColor": TEXT_SECONDARY,
                "titleColor": TEXT_PRIMARY,
            },
            "view": {"stroke": BORDER_SUBTLE},
        }
    }


# Register theme — use the modern Altair 6 API
try:
    @alt.theme.register("scarlet_dark", enable=True)
    def _altair_theme():
        return alt.theme.ThemeConfig(
            {
                "background": BG_SURFACE,
                "title": {
                    "color": TEXT_PRIMARY,
                    "fontSize": 13,
                    "fontWeight": "bold",
                    "anchor": "start",
                },
                "axis": {
                    "labelColor": TEXT_SECONDARY,
                    "titleColor": TEXT_PRIMARY,
                    "gridColor": BORDER_SUBTLE,
                    "domainColor": BORDER_SUBTLE,
                    "tickColor": BORDER_SUBTLE,
                },
                "legend": {
                    "labelColor": TEXT_SECONDARY,
                    "titleColor": TEXT_PRIMARY,
                },
                "view": {"stroke": BORDER_SUBTLE},
            }
        )
except Exception:
    # Fallback for older altair versions
    try:
        alt.themes.register("scarlet_dark", _altair_theme)
        alt.themes.enable("scarlet_dark")
    except Exception:  # noqa: S110 — theme registration optional; charts fall back to default
        pass


# ───────────────────────────────────────────────────────────────
# Cached alerts fetch — single API call shared by all chart functions
# ───────────────────────────────────────────────────────────────

@st.cache_data(ttl=60)
def cached_alerts(limit: int = 500) -> list:
    """Fetch alerts once per page load, cached for 60 seconds.

    All chart functions accept an optional `alerts` parameter —
    if provided, they skip their own API call and reuse this data.
    This eliminates 6 redundant API calls per dashboard page load.
    """
    api = get_api_client()
    try:
        return api.get_alerts(limit=limit) or []
    except Exception:
        return []


# ───────────────────────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────────────────────

def _colored_metric(label: str, value, delta=None, color=None):
    """Render a metric where the value is optionally colored."""
    style = ""
    if color:
        style = f' style="color:{color}"'
    label_html = (
        f'<p style="color:{TEXT_SECONDARY};font-size:0.75rem;font-weight:600;'
        f'text-transform:uppercase;letter-spacing:0.04em;margin:0;{style}">{label}</p>'
    )
    value_html = (
        f'<p style="color:{TEXT_PRIMARY};font-size:1.6rem;font-weight:700;'
        f'margin:0;{style}">{value}</p>'
    )
    if delta:
        value_html += (
            f'<p style="color:#00e676;font-size:0.75rem;'
            f'margin:0.25rem 0 0 0;{style}">{delta}</p>'
        )
    st.markdown(
        f'<div style="background:{BG_SURFACE};border:1px solid {BORDER_SUBTLE};'
        f'border-radius:0.5rem;padding:0.75rem 1rem;margin-bottom:0.5rem;">'
        f'{label_html}{value_html}'
        f'</div>',
        unsafe_allow_html=True,
    )


# ───────────────────────────────────────────────────────────────
# Charts
# ───────────────────────────────────────────────────────────────

def render_severity_distribution(alerts: list | None = None):
    """Render alert severity distribution as a donut chart inside a card."""
    api = get_api_client()

    with st.spinner("Loading severity distribution...", show_time=True):
        try:
            if alerts is None:
                alerts = api.get_alerts(limit=500)
            if not alerts:
                st.info("No alerts to display")
                return

            severity_counts = {}
            for a in alerts:
                sev = a.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            if not severity_counts:
                st.info("No alert data available")
                return

            df = pd.DataFrame([
                {"Severity": k, "Count": v, "Color": SEVERITY_COLORS.get(k, "#78909c")}
                for k, v in severity_counts.items()
            ])

            severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
            df["Order"] = df["Severity"].map(severity_rank).fillna(99)
            df = df.sort_values("Order")

            chart = (
                alt.Chart(df)
                .encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color(
                        "Severity:N",
                        scale=alt.Scale(
                            domain=list(df["Severity"]),
                            range=list(df["Color"]),
                        ),
                        legend=alt.Legend(
                            orient="bottom",
                            title=None,
                            labelColor=TEXT_SECONDARY,
                        ),
                    ),
                    tooltip=["Severity", "Count"],
                )
            )

            pie = chart.mark_arc(
                innerRadius=55,
                outerRadius=100,
                stroke=BG_SURFACE,
                strokeWidth=3,
            )
            text = chart.mark_text(
                radius=78,
                size=12,
                fill=TEXT_PRIMARY,
                fontWeight="bold",
            ).encode(text="Count:Q")

            full_chart = (
                (pie + text)
                .properties(width=300, height=300)
                .configure_legend(labelFontSize=12)
            )
            _chart_container(full_chart, "Alert Severity Distribution")

        except ApiError as e:
            st.error(f"Failed to load severity data: {e.detail}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")


def render_alert_trend(alerts: list | None = None):
    """Render alert volume trend over time as a line chart inside a card."""
    api = get_api_client()

    with st.spinner("Loading alert trend...", show_time=True):
        try:
            if alerts is None:
                alerts = api.get_alerts(limit=500)
            if not alerts:
                st.info("No alerts to display")
                return

            df = pd.DataFrame(alerts)
            if "time" not in df.columns:
                st.info("No time data in alerts")
                return

            df["time"] = pd.to_datetime(df["time"], utc=True)
            df["date"] = df["time"].dt.date

            trend = df.groupby(["date", "severity"]).size().reset_index(name="count")

            severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
            trend["order"] = trend["severity"].map(severity_rank).fillna(99)
            trend = trend.sort_values(["date", "order"])

            chart = (
                alt.Chart(trend)
                .mark_line(point=True, strokeWidth=2)
                .encode(
                    x=alt.X(
                        "date:T",
                        title="Date",
                        axis=alt.Axis(grid=True, tickCount=6),
                    ),
                    y=alt.Y(
                        "count:Q",
                        title="Alerts",
                        axis=alt.Axis(grid=True),
                    ),
                    color=alt.Color(
                        "severity:N",
                        scale=alt.Scale(
                            domain=SEVERITY_ORDER,
                            range=[
                                SEVERITY_COLORS.get(s, "#78909c")
                                for s in SEVERITY_ORDER
                            ],
                        ),
                        legend=alt.Legend(
                            orient="bottom",
                            title=None,
                            labelColor=TEXT_SECONDARY,
                        ),
                    ),
                    tooltip=["date", "severity", "count"],
                )
                .properties(
                    width=600,
                    height=300,
                )
                .configure_legend(labelFontSize=12)
            )
            _chart_container(chart, "Alert Volume Trend")

        except ApiError as e:
            st.error(f"Failed to load alert trend: {e.detail}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")


def render_top_hosts(alerts: list | None = None):
    """Render top hosts by alert count inside a card."""
    api = get_api_client()

    with st.spinner("Loading host data...", show_time=True):
        try:
            if alerts is None:
                alerts = api.get_alerts(limit=500)
            if not alerts:
                st.info("No alerts to display")
                return

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
                .mark_bar(
                    cornerRadiusTopLeft=3,
                    cornerRadiusTopRight=3,
                    color=ACCENT,
                )
                .encode(
                    y=alt.Y(
                        "Host:N",
                        sort="-x",
                        title=None,
                        axis=alt.Axis(labelColor=TEXT_SECONDARY),
                    ),
                    x=alt.X(
                        "Alerts:Q",
                        title="Alerts",
                        axis=alt.Axis(grid=True, tickMinStep=1),
                    ),
                    tooltip=["Host", "Alerts"],
                )
                .properties(title="Top Hosts by Alert Count", height=300)
            )
            _chart_container(chart, "Top Hosts")

        except ApiError as e:
            st.error(f"Failed to load host data: {e.detail}")


def render_mitre_heatmap(rules: list[dict]):
    """Render MITRE ATT&CK technique coverage as metric cards + detail table."""
    if not rules:
        st.info("No rules loaded — MITRE coverage will show once rules are loaded.")
        return

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

    TACTIC_TITLES = {
        "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
        "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
        "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
        "TA0009": "Collection", "TA0011": "Command and Control",
        "TA0010": "Exfiltration", "TA0040": "Impact",
    }

    tactic_counts = {}
    for tactic_id, tactic_name in TACTIC_TITLES.items():
        count = len(df[df["Tactics"].str.contains(tactic_id, na=False)]["Technique"].unique())
        if count > 0:
            tactic_counts[tactic_name] = count

    st.markdown(
        f'<p style="color:{TEXT_PRIMARY};font-weight:700;font-size:1.05rem;margin:0 0 0.75rem 0;">'
        f'MITRE ATT&CK Coverage'
        f'</p>',
        unsafe_allow_html=True,
    )

    if tactic_counts:
        cols = st.columns(min(len(tactic_counts), 4))
        for i, (tactic, count) in enumerate(
            sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
        ):
            with cols[i % 4]:
                if count >= 3:
                    color = "#00e676"
                    label = "Strong"
                elif count >= 2:
                    color = "#ffc107"
                    label = "Moderate"
                else:
                    color = "#ff3860"
                    label = "Weak"
                _colored_metric(tactic, f"{count} · {label}", color=color)

    with st.expander("Detailed Technique Coverage"):
        st.dataframe(
            df[["Technique", "Tactics", "Severity", "Rule"]],
            use_container_width=True,
            hide_index=True,
        )


def render_dashboard_metrics(alerts: list | None = None):
    """Render top-level dashboard metrics cards without emoji.

    Uses the /alerts/stats API for accurate counts (no time filter).
    Accepts optional pre-fetched alerts to avoid redundant API call.
    """
    api = get_api_client()

    with st.spinner("Loading dashboard metrics...", show_time=True):
        try:
            # Use the stats API for accurate counts (all time)
            stats = api.get_alert_stats() or {}

            total = stats.get("total_count", 0)
            critical = stats.get("critical_count", 0)
            high = stats.get("high_count", 0)
            new = stats.get("new_count", 0)
            investigating = stats.get("investigating_count", 0)

            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                _colored_metric("Total Alerts", total)
            with col2:
                _colored_metric("Critical", critical, color=SEVERITY_COLORS["critical"])
            with col3:
                _colored_metric("High", high, color=SEVERITY_COLORS["high"])
            with col4:
                _colored_metric("New", new, color="#00e676")
            with col5:
                _colored_metric("Investigating", investigating, color=SEVERITY_COLORS["high"])

            # Reuse pre-fetched alerts or fetch fresh
            if alerts is None:
                alerts = api.get_alerts(limit=500) or []
            return alerts

        except ApiError as e:
            st.error(f"Failed to load metrics: {e.detail}")
            return []
        except Exception:
            st.error("Unexpected error loading metrics")
            return []


@st.cache_data(ttl=60)
def _cached_rules() -> list:
    """Cached fetch for rules."""
    api = get_api_client()
    try:
        return api.get_rules() or []
    except Exception:
        return []


def render_severity_sparklines(alerts: list | None = None):
    """Render mini sparkline charts for alert severity over time."""
    api = get_api_client()

    with st.spinner("Loading severity trends...", show_time=True):
        try:
            if alerts is None:
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

                color = SEVERITY_COLORS.get(sev, "#78909c")
                label = sev.upper()
                count = len(sev_df)

                if len(daily) > 1:
                    chart = (
                        alt.Chart(daily, title=f"{label}")
                        .mark_line(color=color, strokeWidth=2)
                        .encode(
                            x=alt.X(
                                "date:T",
                                axis=alt.Axis(labels=False, ticks=False, title=None),
                            ),
                            y=alt.Y(
                                "count:Q",
                                axis=alt.Axis(labels=False, ticks=False, title=None),
                            ),
                        )
                        .properties(height=60)
                    )
                    with cols[i]:
                        st.markdown(
                            f"""
                            <div style="text-align:center;margin-bottom:0.25rem;">
                                <p style="margin:0;color:{TEXT_SECONDARY};font-size:0.7rem;
                                    font-weight:600;text-transform:uppercase;">
                                    {label}
                                </p>
                                <p style="margin:0;color:{TEXT_PRIMARY};font-size:1.1rem;
                                    font-weight:700;">
                                    {count}
                                </p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        st.altair_chart(chart, use_container_width=True)
                else:
                    # Single or no data point — just show the metric card
                    with cols[i]:
                        _colored_metric(label, count, color=color)

        except Exception:  # noqa: S110 — graceful chart render fallback
            pass


def render_host_risk_scores(alerts: list | None = None):
    """Render risk score cards for top hosts without emoji."""
    api = get_api_client()

    with st.spinner("Loading host risk scores...", show_time=True):
        try:
            if alerts is None:
                alerts = api.get_alerts(limit=500) or []
            if not alerts:
                return

            host_risk = {}
            severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

            for a in alerts:
                host = a.get("host_name", "unknown")
                sev = a.get("severity", "info")
                weight = severity_weights.get(sev, 1)
                host_risk[host] = host_risk.get(host, 0) + weight

            top_hosts = sorted(host_risk.items(), key=lambda x: x[1], reverse=True)[:5]

            if top_hosts:
                # Normalize scores to 0-100 scale based on highest-scoring host
                max_score = top_hosts[0][1] if top_hosts[0][1] > 0 else 1

                st.markdown(
                    f'<p style="color:{TEXT_PRIMARY};font-weight:700;'
                    f'font-size:1.05rem;margin:0.75rem 0;">'
                    f'Host Risk Scores'
                    f'</p>',
                    unsafe_allow_html=True,
                )
                cols = st.columns(min(len(top_hosts), 5))
                for i, (host, raw_score) in enumerate(top_hosts):
                    # Scale to 0-100 proportionally
                    score = round(raw_score / max_score * 100) if max_score > 0 else 0
                    if score >= 70:
                        color = "#ff3860"
                        label = "Critical"
                    elif score >= 40:
                        color = "#ff8f00"
                        label = "High"
                    else:
                        color = "#00e676"
                        label = "Normal"
                    with cols[i]:
                        _colored_metric(host, f"{score} · {label}", color=color)

        except Exception:  # noqa: S110 — graceful chart render fallback
            pass
