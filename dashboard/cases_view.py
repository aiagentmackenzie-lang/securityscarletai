"""
Case management view for SecurityScarletAI dashboard.

Full cases CRUD — create, update, resolve, and manage investigation cases.
ALL data fetched through ApiClient — NO direct database access.
Loading states: st.spinner() on fetches, st.toast() on actions.
"""
import streamlit as st

from dashboard.api_client import ApiError
from dashboard.auth import can_write, get_api_client, is_admin

# Status flow: open → in_progress → resolved → closed
STATUS_FLOW = ["open", "in_progress", "resolved", "closed"]
STATUS_BADGES = {
    "open": "📂",
    "in_progress": "🔍",
    "resolved": "✅",
    "closed": "📁",
}
SEVERITY_COLORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def render_cases_view():
    """Render the cases management page."""
    api = get_api_client()

    tab1, tab2 = st.tabs(["📋 Case List", "➕ Create Case"])

    # ─── Case List ───
    with tab1:
        _render_case_list(api)

    # ─── Create Case ───
    with tab2:
        _render_create_case(api)


def _render_case_list(api):
    """Render the case list with filters and detailed expansion."""
    # Filter controls
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        status_filter = st.selectbox(
            "Status",
            ["All", "Open", "In Progress", "Resolved", "Closed"],
            key="case_status_filter",
        )
    with col2:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "Critical", "High", "Medium", "Low", "Info"],
            key="case_severity_filter",
        )
    with col3:
        st.write("")  # spacer
    with col4:
        if st.button("🔄 Refresh", key="refresh_cases_btn"):
            st.rerun()

    # Build API query params
    params: dict = {}
    if status_filter != "All":
        params["status_filter"] = status_filter.lower()
    if severity_filter != "All":
        params["severity"] = severity_filter.lower()

    # Fetch cases with loading state
    with st.spinner("Loading cases...", show_time=True):
        try:
            cases = api.get_cases(**params) or []
        except ApiError as e:
            if e.status_code == 401:
                st.error("Session expired. Please log in again.")
            else:
                st.error(f"Failed to load cases: {e.detail}")
            return
        except Exception as e:
            st.error(f"Unexpected error: {e}")
            return

    st.divider()

    if not cases:
        st.info("""
        No investigation cases found.

        **To create a case:**
        1. Go to the **➕ Create Case** tab
        2. Fill in the title, description, and severity
        3. Optionally link alerts to the case

        You can also create a case from any alert in the Alerts page.
        """)
        return

    st.caption(f"Showing {len(cases)} case(s)")

    for case in cases:
        _render_case_card(case, api)


def _render_case_card(case: dict, api):
    """Render a single case as an expandable card."""
    case_id = case.get("id", 0)
    case_status = case.get("status", "open")
    case_severity = case.get("severity", "medium")
    case_title = case.get("title", "Untitled")
    status_icon = STATUS_BADGES.get(case_status, "❓")
    sev_icon = SEVERITY_COLORS.get(case_severity, "⚪")
    assigned = case.get("assigned_to") or "Unassigned"
    alert_count = len(case.get("alert_ids") or [])

    with st.expander(
        f"{status_icon} **#{case_id}** — {case_title} "
        f"{sev_icon} [{case_severity.upper()}] ({alert_count} alerts) "
        f"— *{assigned}*"
    ):
        # Fetch full case detail (including linked alerts) with spinner
        with st.spinner("Loading case details...", show_time=True):
            try:
                case_detail = api.get_case(case_id)
                linked_alerts = case_detail.get("linked_alerts", [])
            except ApiError as e:
                st.error(f"Failed to load case details: {e.detail}")
                linked_alerts = []
                case_detail = case

        # ─── Case Info ───
        col_info1, col_info2 = st.columns([2, 1])
        with col_info1:
            st.markdown(f"**Description:** {case_detail.get('description') or 'No description'}")
            if case_detail.get("lessons_learned"):
                st.markdown(f"**📝 Lessons Learned:** {case_detail['lessons_learned']}")
            if case_detail.get("resolution_note"):
                st.markdown(f"**✏️ Resolution Note:** {case_detail['resolution_note']}")

        with col_info2:
            # Status badge
            st.markdown(f"{status_icon} **Status:** {case_status}")
            st.markdown(f"{sev_icon} **Severity:** {case_severity}")
            st.markdown(f"👤 **Assigned:** {assigned}")

            created = (
                case_detail.get("created_at", "")[:19]
                if case_detail.get("created_at") else ""
            )
            updated = (
                case_detail.get("updated_at", "")[:19]
                if case_detail.get("updated_at") else ""
            )
            st.caption(f"Created: {created}")
            st.caption(f"Updated: {updated}")

        st.divider()

        # ─── Status Management ───
        if can_write():
            _render_status_management(case_id, case_status, case_detail, api)

        st.divider()

        # ─── Linked Alerts ───
        st.markdown("**📋 Linked Alerts**")
        if linked_alerts:
            for a in linked_alerts:
                a_sev = a.get("severity", "info")
                a_icon = SEVERITY_COLORS.get(a_sev, "⚪")
                a_status = a.get("status", "new")
                st.markdown(
                    f"{a_icon} **Alert #{a['id']}** [{a_sev.upper()}] "
                    f"— {a.get('rule_name', 'Unknown')} "
                    f"— {a.get('host_name', '')} — *{a_status}*"
                )
        else:
            st.info("No alerts linked to this case yet.")

        # ─── Link/Unlink Alerts ───
        if can_write():
            _render_alert_linking(case_id, case_detail, linked_alerts, api)

        st.divider()

        # ─── Case Notes ───
        _render_case_notes(case_id, api)

        # ─── Case Deletion (admin only) ───
        if is_admin() and case_status != "closed":
            st.divider()
            if st.button("🗑️ Close & Archive Case", key=f"delete_case_{case_id}", type="secondary"):
                try:
                    api.delete_case(case_id)
                    st.toast("📁 Case archived", icon="📁")
                    st.success("Case has been closed and archived.")
                    st.rerun()
                except ApiError as e:
                    st.error(f"Failed to archive case: {e.detail}")


def _render_status_management(case_id: int, case_status: str, case_detail: dict, api):
    """Render the status management dropdown and lessons learned prompt."""
    current_idx = STATUS_FLOW.index(case_status) if case_status in STATUS_FLOW else 0

    st.markdown("**🔄 Change Status**")

    # If transitioning to resolved, prompt for lessons_learned
    col_status1, col_status2 = st.columns([2, 1])
    with col_status1:
        new_status = st.selectbox(
            "New status",
            STATUS_FLOW,
            index=current_idx,
            key=f"status_select_{case_id}",
        )
    with col_status2:
        st.write("")  # spacer for alignment

    # Lessons learned textarea (only shown when resolving)
    lessons_learned = None
    if new_status in ("resolved", "closed") and case_status not in ("resolved", "closed"):
        lessons_learned = st.text_area(
            "📝 Lessons Learned (required)",
            placeholder=(
                "What did we learn from this investigation? "
                "How can we prevent similar incidents?"
            ),
            key=f"lessons_{case_id}",
        )
        resolution_note = st.text_input(
            "✏️ Resolution Note (optional)",
            placeholder="Brief summary of the resolution",
            key=f"resolution_{case_id}",
        )

    if st.button("Update Status", key=f"update_status_{case_id}"):
        if new_status == case_status:
            st.warning("Status unchanged.")
            return

        # Validate lessons_learned for resolve/close
        if new_status in ("resolved", "closed") and case_status not in ("resolved", "closed"):
            if not lessons_learned or not lessons_learned.strip():
                st.error("❌ Lessons learned is required when resolving or closing a case.")
                return

        try:
            kwargs = {"status": new_status}
            if lessons_learned:
                kwargs["lessons_learned"] = lessons_learned.strip()
            if resolution_note if new_status in ("resolved", "closed") else False:
                kwargs["resolution_note"] = resolution_note.strip()

            api.update_case(case_id, **kwargs)
            status_icon = STATUS_BADGES.get(new_status, "✅")
            st.toast(f"{status_icon} Case status updated to {new_status}", icon=status_icon)
            st.success(f"Case status updated to {new_status}.")
            st.rerun()
        except ApiError as e:
            st.error(f"Failed to update status: {e.detail}")


def _render_alert_linking(case_id: int, case_detail: dict, linked_alerts: list, api):
    """Render the link/unlink alert controls."""
    with st.expander("🔗 Link / Unlink Alerts"):
        # Link a new alert
        col_link1, col_link2 = st.columns([3, 1])
        with col_link1:
            link_alert_id = st.number_input(
                "Alert ID to link",
                min_value=1,
                value=1,
                step=1,
                key=f"link_alert_{case_id}",
            )
        with col_link2:
            st.write("")  # alignment spacer

        if st.button("➕ Link Alert", key=f"link_btn_{case_id}"):
            try:
                api.link_alert_to_case(case_id, link_alert_id)
                st.toast("✅ Alert linked to case", icon="✅")
                st.success(f"Alert #{link_alert_id} linked to case #{case_id}.")
                st.rerun()
            except ApiError as e:
                st.error(f"Failed to link alert: {e.detail}")

        # Unlink existing alerts
        if linked_alerts:
            st.markdown("**Unlink alerts:**")
            for a in linked_alerts:
                aid = a.get("id", 0)
                if st.button(f"✂️ Unlink Alert #{aid}", key=f"unlink_{case_id}_{aid}"):
                    try:
                        api.unlink_alert_from_case(case_id, aid)
                        st.toast("✂️ Alert unlinked", icon="✂️")
                        st.rerun()
                    except ApiError as e:
                        st.error(f"Failed to unlink alert: {e.detail}")


def _render_case_notes(case_id: int, api):
    """Render the case notes timeline and add note form."""
    st.markdown("**📝 Case Notes**")

    with st.spinner("Loading notes...", show_time=True):
        try:
            notes = api.get_case_notes(case_id) or []
        except ApiError:
            notes = []

    if notes:
        for note in notes:
            author = note.get("author", "Unknown")
            text = note.get("text", "")
            timestamp = note.get("timestamp", "")[:19] if note.get("timestamp") else ""
            st.markdown(f"**{author}** ({timestamp}): {text}")
    else:
        st.caption("No notes yet.")

    # Add note
    if can_write():
        with st.form(f"add_note_form_{case_id}"):
            new_note = st.text_input(
                "Add a note",
                placeholder="E.g., Investigating suspicious SSH brute-force...",
                key=f"new_note_{case_id}",
            )
            if st.form_submit_button("📝 Add Note"):
                if new_note and new_note.strip():
                    try:
                        api.add_case_note(case_id, new_note.strip())
                        st.toast("📝 Note added", icon="📝")
                        st.rerun()
                    except ApiError as e:
                        st.error(f"Failed to add note: {e.detail}")
                else:
                    st.warning("Note text is required.")


def _render_create_case(api):
    """Render the Create Case tab."""
    if not can_write():
        st.error("You need analyst permissions or above to create cases.")
        return

    st.subheader("Create New Investigation Case")

    with st.form("create_case_form_v2"):
        title = st.text_input(
            "Case Title *",
            placeholder="E.g., Suspicious SSH brute-force from 10.0.1.50",
        )
        description = st.text_area(
            "Description",
            placeholder="Describe the investigation scope, affected systems, initial findings...",
        )
        severity = st.selectbox(
            "Severity",
            ["info", "low", "medium", "high", "critical"],
            index=2,  # medium default
        )

        # Optional alert linking
        st.markdown("**Optional:** Link alerts to this case (comma-separated alert IDs)")
        alert_ids_str = st.text_input(
            "Alert IDs",
            placeholder="E.g., 1, 5, 12",
            key="create_case_alert_ids",
        )

        # Optional assignment
        assigned_to = st.text_input(
            "Assign To",
            placeholder="E.g., analyst1 (leave empty to auto-assign)",
            key="create_case_assigned_to",
        )

        if st.form_submit_button("📝 Create Case"):
            if not title or not title.strip():
                st.error("❌ Case title is required.")
                return

            # Parse alert IDs
            alert_ids = []
            if alert_ids_str and alert_ids_str.strip():
                try:
                    alert_ids = [
                        int(aid.strip())
                        for aid in alert_ids_str.split(",")
                        if aid.strip().isdigit()
                    ]
                except (ValueError, TypeError):
                    st.error("Invalid alert IDs. Use comma-separated integers.")
                    return

            with st.spinner("Creating case..."):
                try:
                    kwargs = {}
                    if assigned_to and assigned_to.strip():
                        kwargs["assigned_to"] = assigned_to.strip()

                    api.create_case(
                        title=title.strip(),
                        description=description or "",
                        severity=severity,
                        alert_ids=alert_ids if alert_ids else None,
                        **kwargs,
                    )
                    st.toast("✅ Case created", icon="✅")
                    st.success("Case created successfully!")
                    st.rerun()
                except ApiError as e:
                    st.error(f"Failed to create case: {e.detail}")
