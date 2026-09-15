"""
Rule management view for SecurityScarletAI dashboard.

CRUD interface for Sigma detection rules.
ALL data fetched through ApiClient — NO direct database access.
Loading states: st.spinner() on fetches, st.toast() on actions.
"""

import streamlit as st

from dashboard.api_client import ApiError
from dashboard.auth import can_manage_rules, can_write, get_api_client
from dashboard.ui_utils import sev_badge


def _render_backtest_report(report: dict) -> None:
    """Render a W1.1 backtest report (honesty gates first, then numbers)."""
    results = report.get("results", {})
    proj = report.get("projected_fp_ratio", {})

    if report.get("unmeasured_reasons"):
        st.warning("**Unmeasured:** " + " | ".join(report["unmeasured_reasons"]))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Matching rows", results.get("total_rows", 0))
    c2.metric("Est. alerts", results.get("estimated_alerts", 0))
    c3.metric("Hosts affected", results.get("hosts_affected", 0))
    if proj.get("measured"):
        c4.metric("Projected FP ratio", f"{proj['ratio']:.0%}")
    else:
        c4.metric("Projected FP ratio", "unmeasured")

    warnings = report.get("compilation", {}).get("warnings", [])
    if warnings:
        st.warning("Compile warnings: " + " | ".join(warnings))

    if proj.get("measured"):
        st.caption(
            f"FP ratio basis: {proj.get('basis', '')} ({proj.get('dispositions', 0)} dispositions)"
        )
    elif proj.get("note") and not report.get("unmeasured_reasons"):
        st.caption(proj["note"])

    per_day = results.get("per_day") or []
    if per_day:
        st.bar_chart(data={d["day"]: d["rows"] for d in per_day})
    st.caption(results.get("estimate_method", ""))

    top = results.get("top_values") or {}
    for column, values in top.items():
        if values:
            with st.expander(f"Top {column} values", expanded=False):
                st.dataframe(
                    [{"value": v["value"], "count": v["count"]} for v in values],
                    hide_index=True,
                    use_container_width=True,
                )

    if results.get("trigger_buckets_truncated"):
        st.caption("Trigger buckets capped at 500 -- estimate is a lower bound.")
    st.caption(
        f"Window {report['window']['start']} -> {report['window']['end']} UTC "
        "-- read-only backtest, never auto-arms"
    )


# Sample rule templates
RULE_TEMPLATES = {
    "Process Execution": """title: {name}
description: Detects process execution
detection:
    selection:
        event_category: "process"
        process_name: "{process_name}"
    condition: selection
timeframe: 1h
level: medium
tags:
    - attack.execution
""",
    "Network Connection": """title: {name}
description: Detects network connections
detection:
    selection:
        event_category: "network"
        destination_port: {port}
    condition: selection
timeframe: 1h
level: medium
tags:
    - attack.command_and_control
""",
    "File Modification": """title: {name}
description: Detects file changes
detection:
    selection:
        event_category: "file"
        file_path|startswith: "{path}"
    condition: selection
timeframe: 1h
level: low
tags:
    - attack.collection
""",
    "Blank": """title: {name}
description: {description}
detection:
    selection:
        # Add your detection logic here
    condition: selection
timeframe: 1h
level: {severity}
tags:
    - attack.execution
""",
}


def render_rules_view():
    """Render the rules management page."""
    api = get_api_client()

    st.header("Detection Rules")

    tab1, tab2 = st.tabs(["Rule Library", "Create Rule"])

    # ─── Rule Library ───
    with tab1:
        with st.spinner("Loading rules...", show_time=True):
            try:
                rules = api.get_rules()
            except ApiError as e:
                if e.status_code == 401:
                    st.error("Session expired. Please log in again.")
                else:
                    st.error(f"Failed to load rules: {e.detail}")
                return
            except Exception as e:
                st.error(f"Unexpected error: {e}")
                return

        if not rules:
            st.info("No rules found. Rules are loaded from rules/sigma/ on API startup.")
            return

        # Metrics
        enabled = sum(1 for r in rules if r.get("enabled", False))
        total_matches = sum(r.get("match_count", 0) for r in rules)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Rules", len(rules))
        col2.metric("Enabled", enabled)
        col3.metric("Total Matches", total_matches)

        # Filter
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "critical", "high", "medium", "low", "info"],
                key="rule_severity_filter",
            )
        with col_f2:
            enabled_filter = st.selectbox(
                "Filter by Status",
                ["All", "Enabled", "Disabled"],
                key="rule_enabled_filter",
            )

        filtered_rules = rules
        if severity_filter != "All":
            filtered_rules = [r for r in filtered_rules if r.get("severity") == severity_filter]
        if enabled_filter == "Enabled":
            filtered_rules = [r for r in filtered_rules if r.get("enabled", False)]
        elif enabled_filter == "Disabled":
            filtered_rules = [r for r in filtered_rules if not r.get("enabled", False)]

        st.caption(f"Showing {len(filtered_rules)} of {len(rules)} rules")

        # Rule table
        table_data = []
        for r in filtered_rules:
            table_data.append(
                {
                    "ID": r.get("id", ""),
                    "Name": r.get("name", ""),
                    "Severity": r.get("severity", "").upper(),
                    "Enabled": "Enabled" if r.get("enabled") else "Disabled",
                    "Last Run": str(r.get("last_run", ""))[:19] if r.get("last_run") else "Never",
                    "Matches": r.get("match_count", 0),
                }
            )

        if table_data:
            st.dataframe(table_data, use_container_width=True, hide_index=True)

        # Rule details
        for r in filtered_rules[:20]:
            sev = r.get("severity", "info")
            sev_html = sev_badge(sev)
            with st.expander(
                f"{r.get('name', 'Unknown')} — {sev_html}",
                expanded=False,
            ):
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.write(f"**Description:** {r.get('description', 'N/A')}")
                    st.write(f"**Interval:** {r.get('run_interval', 'N/A')}")
                    st.write(f"**Lookback:** {r.get('lookback', 'N/A')}")
                    st.write(f"**Threshold:** {r.get('threshold', 1)}")
                    st.write(f"**Match Count:** {r.get('match_count', 0)}")

                    tactics = r.get("mitre_tactics", []) or []
                    techniques = r.get("mitre_techniques", []) or []
                    if tactics:
                        st.write(f"**MITRE Tactics:** {', '.join(tactics)}")
                    if techniques:
                        st.write(f"**MITRE Techniques:** {', '.join(techniques)}")

                    sigma = r.get("sigma_yaml", "")
                    if sigma:
                        with st.expander("Sigma YAML"):
                            st.code(sigma, language="yaml")

                with col2:
                    if can_manage_rules():
                        is_enabled = r.get("enabled", False)
                        if st.button(
                            "Disable" if is_enabled else "Enable",
                            key=f"toggle_{r.get('id', 0)}",
                        ):
                            with st.spinner(f"{'Disabling' if is_enabled else 'Enabling'} rule..."):
                                try:
                                    api.update_rule(r["id"], {"enabled": not is_enabled})
                                    action = "enabled" if not is_enabled else "disabled"
                                    st.toast(f"Rule {action}")
                                    st.success(f"Rule {action}")
                                    st.rerun()
                                except ApiError as e:
                                    st.error(f"Update failed: {e.detail}")

                        if st.button("Delete", key=f"del_{r.get('id', 0)}"):
                            with st.spinner("Deleting rule..."):
                                try:
                                    api.delete_rule(r["id"])
                                    st.toast("Rule deleted")
                                    st.success("Rule deleted")
                                    st.rerun()
                                except ApiError as e:
                                    st.error(f"Delete failed: {e.detail}")

                    # W1.1 backtest: analyst+ (matches the API gate).
                    if can_write() and st.button("Backtest 7d", key=f"backtest_{r.get('id', 0)}"):
                        with st.spinner("Backtesting against stored logs..."):
                            try:
                                st.session_state[f"backtest_report_{r['id']}"] = api.backtest_rule(
                                    r["id"], window_hours=168
                                )
                                st.toast("Backtest complete")
                            except ApiError as e:
                                st.error(f"Backtest failed: {e.detail}")

                # Stored backtest report (survives reruns within the session).
                stored_report = st.session_state.get(f"backtest_report_{r.get('id', 0)}")
                if stored_report:
                    with st.expander("Backtest report (last 7 days)", expanded=True):
                        _render_backtest_report(stored_report)

    # ─── Create Rule ───
    with tab2:
        if not can_manage_rules():
            st.error("You need admin or analyst permissions to create rules.")
            return

        st.subheader("Create New Rule")

        with st.form("create_rule_form"):
            name = st.text_input("Rule Name", placeholder="e.g., Suspicious PowerShell Execution")
            description = st.text_area("Description", placeholder="What does this rule detect?")

            col1, col2 = st.columns(2)
            with col1:
                severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
            with col2:
                run_interval = st.number_input("Check Interval (seconds)", min_value=60, value=300)

            template = st.selectbox(
                "Start from template",
                list(RULE_TEMPLATES.keys()),
            )

            from collections import defaultdict

            template_vars = defaultdict(
                str,
                {
                    "name": name or "Rule Name",
                    "description": description or "",
                    "severity": severity,
                    "process_name": "python",
                    "port": "4444",
                    "path": "/tmp",  # noqa: S108 — sample rule template value, not a real temp path
                },
            )
            default_yaml = RULE_TEMPLATES[template].format_map(template_vars)
            sigma_yaml = st.text_area("Sigma Rule (YAML)", value=default_yaml, height=300)

            if st.form_submit_button("Preview"):
                st.subheader("Preview")
                st.code(sigma_yaml, language="yaml")

            backtest_clicked = st.form_submit_button("Backtest draft (7d)")

            submitted = st.form_submit_button("Create Rule")
            if backtest_clicked:
                if not sigma_yaml:
                    st.error("Sigma YAML is required to backtest a draft")
                else:
                    with st.spinner("Backtesting draft against stored logs..."):
                        try:
                            st.session_state["draft_backtest_report"] = api.backtest_draft(
                                sigma_yaml, window_hours=168
                            )
                            st.toast("Draft backtest complete")
                        except ApiError as e:
                            st.error(f"Backtest failed: {e.detail}")
            if submitted:
                if not name or not sigma_yaml:
                    st.error("Name and Sigma YAML are required")
                else:
                    with st.spinner("Creating rule..."):
                        try:
                            api.create_rule(
                                {
                                    "name": name,
                                    "description": description,
                                    "sigma_yaml": sigma_yaml,
                                    "severity": severity,
                                    "run_interval": run_interval,
                                }
                            )
                            st.toast(f"Rule '{name}' created")
                            st.success(f"Rule '{name}' created successfully!")
                            st.rerun()
                        except ApiError as e:
                            st.error(f"Failed to create rule: {e.detail}")

        # Stored draft-backtest report (survives reruns within the session).
        draft_report = st.session_state.get("draft_backtest_report")
        if draft_report:
            st.subheader("Draft backtest (last 7 days)")
            _render_backtest_report(draft_report)
