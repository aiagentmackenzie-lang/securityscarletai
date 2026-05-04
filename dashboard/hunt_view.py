"""
Threat Hunting view for SecurityScarletAI dashboard.

Features:
- Pre-built hunt templates with real SQL
- MITRE ATT&CK gap analysis
- Hunt execution with results display
- Hunt suggestions from alerts

ALL data fetched through ApiClient — NO direct database access.
Loading states: st.spinner() on fetches, st.status() for executions, st.toast() on actions.
"""
import streamlit as st
import pandas as pd

from dashboard.api_client import ApiError
from dashboard.auth import can_write, get_api_client


def render_hunt_view():
    """Render the threat hunting page."""
    api = get_api_client()

    st.header("🎯 Threat Hunting")

    tab1, tab2, tab3 = st.tabs([
        "🔍 Hunt Templates",
        "📊 MITRE ATT&CK Gaps",
        "⚡ Execute Hunt",
    ])

    # ─── Hunt Templates ───
    with tab1:
        st.subheader("Pre-Built Hunt Templates")

        with st.spinner("Loading hunt templates...", show_time=True):
            try:
                templates = api.get_hunt_templates()
            except ApiError as e:
                if e.status_code == 401:
                    st.error("Session expired. Please log in again.")
                else:
                    st.error(f"Failed to load hunt templates: {e.detail}")
                return
            except Exception as e:
                st.error(f"Unexpected error: {e}")
                return

        if not templates:
            st.info("No hunt templates available. Check that the API is running.")
        else:
            st.caption(f"{len(templates)} hunt templates available")

            # Group by MITRE tactic
            tactics = {}
            for t in templates:
                tactic = t.get("mitre_tactics", ["General"])[0] if t.get("mitre_tactics") else "General"  # noqa: E501
                if tactic not in tactics:
                    tactics[tactic] = []
                tactics[tactic].append(t)

            for tactic, hunts in sorted(tactics.items()):
                with st.expander(f"📁 {tactic} ({len(hunts)} hunts)"):
                    for hunt in hunts:
                        st.markdown(f"**{hunt.get('name', 'Unknown')}**")
                        st.caption(hunt.get("description", ""))
                        techniques = hunt.get("mitre_techniques", [])
                        if techniques:
                            st.markdown(f"MITRE: {', '.join(techniques)}")

                        # Execute button
                        hunt_id = hunt.get("id", hunt.get("name", ""))
                        if can_write():
                            if st.button("▶️ Execute", key=f"exec_{hunt_id}"):
                                execute_and_display(hunt_id, api)

                        st.divider()

    # ─── MITRE ATT&CK Gap Analysis ───
    with tab2:
        st.subheader("MITRE ATT&CK Coverage Gaps")

        col1, col2 = st.columns(2)

        with col1:
            with st.spinner("Loading MITRE gap analysis...", show_time=True):
                try:
                    gaps = api.get_mitre_gaps()

                    covered = gaps.get("covered_techniques", [])
                    uncovered = gaps.get("uncovered_techniques", [])

                    total = len(covered) + len(uncovered)
                    coverage_pct = len(covered) / total * 100 if total > 0 else 0

                    st.metric("Coverage", f"{len(covered)}/{total}", f"{coverage_pct:.1f}%")
                    st.progress(coverage_pct / 100)

                except ApiError as e:
                    uncovered = []
                    covered = []
                    st.error(f"Failed to load MITRE gaps: {e.detail}")

        with col2:
            # Also show what rules cover
            with st.spinner("Loading rule coverage...", show_time=True):
                try:
                    rules = api.get_rules()
                    rule_techniques = set()
                    for r in rules:
                        for t in r.get("mitre_techniques", []) or []:
                            rule_techniques.add(t)
                    st.metric("Rules with MITRE Tags", f"{len(rule_techniques)} techniques")
                except ApiError:
                    st.metric("Rules with MITRE Tags", "N/A")

        # Show uncovered techniques
        if uncovered:
            st.divider()
            st.subheader("⚠️ Uncovered Critical Techniques")

            # Group by tactic
            tactic_groups = {}
            TACTIC_NAMES = {
                "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
                "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
                "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
                "TA0009": "Collection", "TA0011": "Command and Control",
                "TA0010": "Exfiltration", "TA0040": "Impact",
            }

            for tech in uncovered:
                tactic_id = tech.get("tactic", "Unknown")
                tactic_name = TACTIC_NAMES.get(tactic_id, tactic_id)
                if tactic_name not in tactic_groups:
                    tactic_groups[tactic_name] = []
                tactic_groups[tactic_name].append(tech)

            for tactic, techniques in sorted(tactic_groups.items()):
                with st.expander(f"📂 {tactic} ({len(techniques)} gaps)"):
                    for tech in techniques:
                        st.markdown(
                            f"- **{tech.get('id', '')}**: {tech.get('name', '')} "
                            f"— {tech.get('description', '')}"
                        )

        # Show covered techniques
        if covered:
            with st.expander("✅ Covered Techniques"):
                for tech_id in covered:
                    st.markdown(f"- `{tech_id}`")

    # ─── Execute Hunt ───
    with tab3:
        st.subheader("Execute a Hunt")

        hunt_id = st.text_input(
            "Hunt Template ID",
            placeholder="e.g., lateral_movement or enter a custom name",
            key="hunt_id_input",
        )

        if can_write() and hunt_id:
            if st.button("▶️ Execute Hunt", key="execute_hunt_btn"):
                execute_and_display(hunt_id, api)

        st.divider()

        # Hunt from alert
        st.subheader("🎯 Hunt from Alert")
        alert_id = st.number_input("Alert ID", min_value=1, value=1, key="hunt_from_alert_id")

        if st.button("🔍 Suggest Hunts from Alert", key="hunt_from_alert_btn"):
            with st.status("🔍 Analyzing alert and suggesting hunts...", expanded=True) as status:
                try:
                    result = api.hunt_from_alert(alert_id)
                    hunts = result.get("suggested_hunts", [])

                    if hunts:
                        status.update(label=f"✅ Found {len(hunts)} suggested hunts", state="complete")  # noqa: E501
                        st.toast(f"🎯 Found {len(hunts)} hunt suggestions", icon="🎯")
                        for hunt in hunts:
                            with st.expander(f"🎯 {hunt.get('name', 'Unknown')}"):
                                st.write(f"**Description:** {hunt.get('description', '')}")
                                techniques = hunt.get("mitre_techniques", [])
                                if techniques:
                                    st.write(f"**MITRE Techniques:** {', '.join(techniques)}")
                                hunt_id_suggest = hunt.get("id", hunt.get("name", ""))
                                if can_write() and hunt_id_suggest:
                                    if st.button("▶️ Execute", key=f"exec_suggest_{hunt_id_suggest}"):  # noqa: E501
                                        execute_and_display(hunt_id_suggest, api)
                    else:
                        status.update(label="ℹ️ No specific hunt suggestions", state="complete")
                        st.info("No specific hunt suggestions for this alert")

                except ApiError as e:
                    status.update(label="❌ Hunt suggestion failed", state="error")
                    st.error(f"Failed to suggest hunts: {e.detail}")


def execute_and_display(hunt_id: str, api):
    """Execute a hunt and display results."""
    with st.status(f"🎯 Executing hunt '{hunt_id}'...", expanded=True) as status:
        try:
            result = api.execute_hunt(hunt_id)

            # Display hunt info
            status.update(label=f"✅ Hunt '{hunt_id}' completed", state="complete")
            st.toast(f"🎯 Hunt '{hunt_id}' completed", icon="🎯")

            # Show SQL if available
            sql = result.get("sql", "")
            if sql:
                with st.expander("📝 Executed SQL"):
                    st.code(sql, language="sql")

            # Show results
            results = result.get("results", [])
            if results:
                df = pd.DataFrame(results)
                st.dataframe(df, use_container_width=True, hide_index=True)
                st.caption(f"Hunt returned {len(results)} results")
            else:
                st.info("Hunt returned no results — no matching threats found")

            # Show AI analysis if available
            analysis = result.get("analysis", "")
            if analysis:
                with st.expander("🤖 AI Analysis"):
                    st.markdown(analysis)

        except ApiError as e:
            status.update(label="❌ Hunt execution failed", state="error")
            st.error(f"Hunt execution failed: {e.detail}")
        except Exception as e:
            status.update(label="❌ Unexpected error", state="error")
            st.error(f"Unexpected error: {e}")
