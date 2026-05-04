"""
Alert management and investigation view for SecurityScarletAI dashboard.

Features:
- Filterable alert list with severity badges
- Alert detail expansion with AI explanation
- Related alerts, timeline, MITRE mapping
- Bulk actions (acknowledge, resolve, mark FP, assign)
- Alert export (CSV)
- AI triage integration
- Hunt-from-alert quick action

ALL data fetched through ApiClient — NO direct database access.
Loading states: st.spinner() on fetches, st.toast() on actions, st.status() for AI ops.
"""
import streamlit as st
from dashboard.api_client import ApiClient, ApiError
from dashboard.auth import can_write, get_api_client

SEVERITY_BADGES = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

STATUS_BADGES = {
    "new": "🆕",
    "investigating": "🔍",
    "resolved": "✅",
    "false_positive": "🚫",
    "closed": "📁",
}


def render_alert_list():
    """Render the main alert list view."""
    api = get_api_client()

    # ─── Filters ───
    with st.expander("🔍 Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)

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
            limit = st.number_input("Max alerts", min_value=10, max_value=500, value=100, key="alert_limit")  # noqa: E501
        with col4:
            st.write("")
            st.write("")
            if st.button("🔄 Refresh"):
                st.rerun()

    # ─── Bulk Actions ───
    if can_write():
        st.markdown("### ⚡ Bulk Actions")
        bc1, bc2, bc3, bc4 = st.columns(4)
        with bc1:
            if st.button("✅ Acknowledge All New", key="bulk_ack"):
                with st.spinner("Acknowledging alerts..."):
                    alerts = api.get_alerts(status="new", limit=500)
                    if alerts:
                        ids = [a["id"] for a in alerts]
                        try:
                            api.bulk_acknowledge(ids)
                            st.toast(f"✅ Acknowledged {len(ids)} alerts", icon="✅")
                            st.success(f"Acknowledged {len(ids)} alerts")
                            st.rerun()
                        except ApiError as e:
                            st.error(f"Bulk acknowledge failed: {e.detail}")
                    else:
                        st.info("No new alerts to acknowledge")

        with bc2:
            if st.button("🔚 Resolve Selected", key="bulk_resolve"):
                selected = st.session_state.get("selected_alerts", [])
                if selected:
                    with st.spinner(f"Resolving {len(selected)} alerts..."):
                        try:
                            api.bulk_resolve(selected)
                            st.toast(f"✅ Resolved {len(selected)} alerts", icon="✅")
                            st.session_state.selected_alerts = []
                            st.rerun()
                        except ApiError as e:
                            st.error(f"Bulk resolve failed: {e.detail}")
                else:
                    st.info("No alerts selected. Use the checkboxes below.")

        with bc3:
            if st.button("🚫 Mark FP", key="bulk_fp"):
                selected = st.session_state.get("selected_alerts", [])
                if selected:
                    with st.spinner(f"Marking {len(selected)} alerts as false positive..."):
                        try:
                            api.bulk_false_positive(selected)
                            st.toast(f"🚫 Marked {len(selected)} alerts as FP", icon="🚫")
                            st.session_state.selected_alerts = []
                            st.rerun()
                        except ApiError as e:
                            st.error(f"Bulk FP failed: {e.detail}")
                else:
                    st.info("No alerts selected.")

        with bc4:
            if st.button("📥 Export CSV", key="export_csv"):
                with st.spinner("Exporting alerts..."):
                    try:
                        csv_data = api.export_alerts_csv(
                            status=status_filter.lower() if status_filter != "All" else None,
                            severity=severity_filter.lower() if severity_filter != "All" else None,
                        )
                        st.download_button(
                            "Download CSV",
                            data=csv_data,
                            file_name="alerts_export.csv",
                            mime="text/csv",
                        )
                        st.toast("📥 CSV export ready", icon="📥")
                    except ApiError as e:
                        st.error(f"Export failed: {e.detail}")

    st.divider()

    # ─── Fetch Alerts ───
    status_param = None if status_filter == "All" else status_filter.lower().replace(" ", "_")
    severity_param = None if severity_filter == "All" else severity_filter.lower()

    with st.spinner("Loading alerts...", show_time=True):
        try:
            alerts = api.get_alerts(status=status_param, severity=severity_param, limit=limit)
        except ApiError as e:
            if e.status_code == 401:
                st.error("Session expired. Please log in again.")
                st.session_state.authenticated = False
            else:
                st.error(f"Failed to fetch alerts: {e.detail}")
            return
        except Exception as e:
            st.error(f"Unexpected error: {e}")
            return

    if not alerts:
        st.info("No alerts found matching your criteria.")
        return

    st.caption(f"Showing {len(alerts)} alerts")

    # Initialize selection state
    if "selected_alerts" not in st.session_state:
        st.session_state.selected_alerts = []

    # ─── Alert Table ───
    for a in alerts:
        sev = a.get("severity", "info")
        status_icon = STATUS_BADGES.get(a.get("status", "new"), "❓")
        sev_icon = SEVERITY_BADGES.get(sev, "⚪")

        # Selection checkbox
        if can_write():
            selected = st.checkbox(
                "",
                value=a["id"] in st.session_state.selected_alerts,
                key=f"sel_{a['id']}",
                label_visibility="collapsed",
            )
            if selected and a["id"] not in st.session_state.selected_alerts:
                st.session_state.selected_alerts.append(a["id"])
            elif not selected and a["id"] in st.session_state.selected_alerts:
                st.session_state.selected_alerts.remove(a["id"])

        with st.expander(
            f"{sev_icon} [{sev.upper()}] {a.get('rule_name', 'Unknown')} — "
            f"{a.get('host_name', '')} {status_icon}",
        ):
            render_alert_detail(a, api)


def render_alert_detail(alert: dict, api: ApiClient):
    """Render detailed view of a single alert inside an expander."""
    alert_id = alert.get("id")

    col1, col2 = st.columns([2, 1])

    with col1:
        # ─── Core Info ───
        st.markdown(f"**Description:** {alert.get('description', 'N/A')}")

        ai_summary = alert.get("ai_summary")
        if ai_summary:
            st.markdown(f"**🤖 AI Summary:** {ai_summary}")
        else:
            if st.button("🤖 Generate AI Explanation", key=f"explain_{alert_id}"):
                with st.status("🤖 Generating AI explanation...", expanded=True) as status:
                    try:
                        result = api.ai_explain(alert_id)
                        explanation = result.get("explanation", result.get("ai_summary", "No explanation available"))  # noqa: E501
                        status.update(label="✅ AI explanation generated", state="complete")
                        st.markdown(f"**🤖 AI Explanation:** {explanation}")
                    except ApiError as e:
                        status.update(label="❌ AI explanation failed", state="error")
                        st.warning(f"AI explanation unavailable: {e.detail}")

        st.markdown(f"**Time:** {alert.get('time', '')}")
        risk = alert.get("risk_score")
        if risk:
            st.progress(min(risk / 100, 1.0), text=f"Risk Score: {risk:.0f}/100")

        # ─── MITRE ATT&CK ───
        tactics = alert.get("mitre_tactics", []) or []
        techniques = alert.get("mitre_techniques", []) or []
        if tactics or techniques:
            st.markdown("**MITRE ATT&CK:**")
            if tactics:
                st.markdown("  - Tactics: " + ", ".join(f"`{t}`" for t in tactics))
            if techniques:
                st.markdown("  - Techniques: " + ", ".join(f"`{t}`" for t in techniques))

        # ─── Evidence ───
        evidence = alert.get("evidence")
        if evidence:
            with st.expander("📋 Evidence"):
                if isinstance(evidence, list):
                    for i, ev in enumerate(evidence[:10]):
                        st.json(ev, expanded=False)
                    if len(evidence) > 10:
                        st.caption(f"... and {len(evidence) - 10} more evidence items")
                else:
                    st.json(evidence)

    with col2:
        # ─── Status Update ───
        if can_write():
            st.markdown("**Update Status**")
            current_status = alert.get("status", "new")
            status_options = ["new", "investigating", "resolved", "false_positive", "closed"]
            new_status = st.selectbox(
                "Status",
                status_options,
                index=status_options.index(current_status) if current_status in status_options else 0,  # noqa: E501
                key=f"status_{alert_id}",
                label_visibility="collapsed",
            )

            new_assigned = st.text_input(
                "Assign to",
                value=alert.get("assigned_to", "") or "",
                key=f"assign_{alert_id}",
                placeholder="analyst name",
            )

            if st.button("💾 Save", key=f"save_{alert_id}"):
                update_data = {}
                if new_status != current_status:
                    update_data["status"] = new_status
                if new_assigned and new_assigned != (alert.get("assigned_to") or ""):
                    update_data["assigned_to"] = new_assigned

                if update_data:
                    with st.spinner("Updating alert..."):
                        try:
                            api.update_alert(alert_id, **update_data)
                            st.toast(f"✅ Alert #{alert_id} updated", icon="✅")
                            st.success("Alert updated!")
                            st.rerun()
                        except ApiError as e:
                            st.error(f"Update failed: {e.detail}")
                else:
                    st.info("No changes to save")

            # ─── Quick Actions ───
            st.divider()
            st.markdown("**Quick Actions**")

            if st.button("🔍 Hunt from Alert", key=f"hunt_{alert_id}"):
                with st.status("🔍 Analyzing alert for hunt suggestions...", expanded=True) as status:  # noqa: E501
                    try:
                        result = api.hunt_from_alert(alert_id)
                        hunts = result.get("suggested_hunts", [])
                        if hunts:
                            status.update(label=f"✅ Found {len(hunts)} hunt suggestions", state="complete")  # noqa: E501
                            for hunt in hunts[:5]:
                                st.markdown(f"- **{hunt.get('name', 'Unknown')}**: {hunt.get('description', '')}")  # noqa: E501
                        else:
                            status.update(label="ℹ️ No specific hunt suggestions", state="complete")  # noqa: E501
                            st.info("No specific hunt suggestions for this alert")
                    except ApiError as e:
                        status.update(label="❌ Hunt suggestion failed", state="error")
                        st.warning(f"Hunt suggestion unavailable: {e.detail}")

            if st.button("🤖 AI Triage", key=f"triage_{alert_id}"):
                with st.status("🤖 Running AI triage...", expanded=True) as status:
                    try:
                        result = api.ai_triage(alert_id)
                        prediction = result.get("prediction", {})
                        reasoning = result.get("reasoning", "N/A")
                        status.update(label="✅ AI triage complete", state="complete")
                        st.markdown(f"**Prediction:** {prediction.get('label', 'N/A')} "
                                    f"(confidence: {prediction.get('confidence', 0):.1%})")
                        st.markdown(f"**Reasoning:** {reasoning}")
                    except ApiError as e:
                        status.update(label="❌ AI triage failed", state="error")
                        st.warning(f"AI triage unavailable: {e.detail}")

        # ─── Alert Notes ───
        st.divider()
        st.markdown("**📝 Notes**")

        with st.spinner("Loading notes...", show_time=True):
            try:
                notes = api.get_alert_notes(alert_id) or []
            except ApiError:
                notes = []

        for note in notes[:10]:
            author = note.get("author", "Unknown")
            text = note.get("text", "")
            ts = note.get("timestamp", "")
            if ts and len(ts) > 19:
                ts = ts[:19]
            st.caption(f"*{author} ({ts}):* {text}")

        if can_write():
            with st.form(f"note_form_{alert_id}"):
                note_text = st.text_area("Add note", key=f"note_text_{alert_id}")
                if st.form_submit_button("Add Note") and note_text:
                    with st.spinner("Adding note..."):
                        try:
                            api.add_alert_note(alert_id, note_text)
                            st.toast("📝 Note added", icon="📝")
                            st.success("Note added!")
                            st.rerun()
                        except ApiError as e:
                            st.error(f"Failed to add note: {e.detail}")
