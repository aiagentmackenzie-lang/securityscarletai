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
import pandas as pd
import streamlit as st

from dashboard.api_client import ApiError
from dashboard.auth import can_write, get_api_client


def _group_templates(templates: list[dict]) -> dict[str, list[dict]]:
    """Group hunt templates by the API's 'category' field.

    get_hunting_templates() returns {id, name, category, mitre, description}.
    The dashboard previously grouped by 'mitre_tactics' — a field the API
    never sends — so every template landed under "General" and the MITRE
    line never rendered (fixed Phase 1, 2026-09-01).
    """
    grouped: dict[str, list[dict]] = {}
    for t in templates:
        category = t.get("category") or "general"
        grouped.setdefault(category, []).append(t)
    return grouped


def _summarize_gaps(gap_result: dict) -> dict:
    """Map the API's GapAnalysisResponse into display values.

    The API returns total_critical_techniques, total_covered,
    coverage_percentage, gaps (list of technique-ID strings), gap_hunts,
    rule_techniques, hunt_techniques. The dashboard previously read
    covered_techniques/uncovered_techniques — fields that don't exist — so
    the tab always rendered 0/0 with no gap list (fixed Phase 1, 2026-09-01).
    """
    total = gap_result.get("total_critical_techniques", 0)
    covered = gap_result.get("total_covered", 0)
    pct = gap_result.get("coverage_percentage", 0.0)
    technique_gaps = gap_result.get("gaps", []) or []
    gap_hunts = gap_result.get("gap_hunts", []) or []
    return {
        "covered": covered,
        "total": total,
        "pct": pct,
        "gaps": technique_gaps,
        "gap_hunts": gap_hunts,
    }


def _hunts_for_alert(result: dict) -> list[dict]:
    """Combine the two hunt-suggestion lists the API actually returns:
    matching_hunts (template matches by MITRE) + llm_suggestions.
    The dashboard previously read 'suggested_hunts' — a field that doesn't
    exist — so this view always reported "No specific hunt suggestions"
    (P2-43 fixed alerts_view; this page was missed — fixed Phase 1,
    2026-09-01).
    """
    return list(result.get("matching_hunts", []) or []) + list(
        result.get("llm_suggestions", []) or []
    )


def render_hunt_view():
    """Render the threat hunting page."""
    api = get_api_client()

    st.header("Threat Hunting")

    tab1, tab2, tab3 = st.tabs([
        "Hunt Templates",
        "MITRE ATT&CK Gaps",
        "Execute Hunt",
    ])

    # ─── Hunt Templates ───
    with tab1:
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

            # Group by the API's own category field (persistence, collection,
            # command_and_control, ...) — see _group_templates.
            for category, hunts in sorted(_group_templates(templates).items()):
                with st.expander(f"{category} ({len(hunts)} hunts)"):
                    for hunt in hunts:
                        st.markdown(
                            f"**{hunt.get('name', 'Unknown')}**"
                        )
                        st.caption(hunt.get("description", ""))
                        techniques = hunt.get("mitre", []) or []
                        if techniques:
                            st.markdown(f"MITRE: {', '.join(str(t) for t in techniques)}")

                        hunt_id = hunt.get("id", hunt.get("name", ""))
                        if can_write():
                            if st.button("Execute", key=f"exec_{hunt_id}"):
                                execute_and_display(hunt_id, api)

                        st.divider()

    # ─── MITRE ATT&CK Gap Analysis ───
    with tab2:
        col1, col2 = st.columns(2)

        with col1:
            with st.spinner("Loading MITRE gap analysis...", show_time=True):
                try:
                    summary = _summarize_gaps(api.get_mitre_gaps())
                    covered = summary["covered"]
                    total = summary["total"]
                    coverage_pct = summary["pct"]

                    st.metric(
                        "Coverage",
                        f"{covered}/{total}",
                        f"{coverage_pct:.1f}%",
                    )
                    if total > 0:
                        st.progress(min(coverage_pct, 100.0) / 100)

                except ApiError as e:
                    summary = {"gaps": [], "gap_hunts": []}
                    st.error(f"Failed to load MITRE gaps: {e.detail}")

        with col2:
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

        if summary.get("gaps"):
            st.divider()
            st.subheader("Uncovered Critical Techniques")
            gap_lines = ", ".join(f"`{g}`" for g in summary["gaps"])
            st.markdown(gap_lines)

            # Suggested hunts for gap techniques — gap_hunts entries are
            # {technique, hunt_id, hunt_name} from mitre_gap_analysis().
            if summary.get("gap_hunts"):
                st.caption("Suggested hunts covering these gaps:")
                for gap_hunt in summary["gap_hunts"]:
                    if isinstance(gap_hunt, dict):
                        st.markdown(
                            f"- `{gap_hunt.get('technique', '')}` — "
                            f"{gap_hunt.get('hunt_name', 'custom hunt')}"
                        )
                    else:
                        st.markdown(f"- {gap_hunt}")

    # ─── Execute Hunt ───
    with tab3:
        st.subheader("Execute a Hunt")

        hunt_id = st.text_input(
            "Hunt Template ID",
            placeholder="e.g., lateral_movement or enter a custom name",
            key="hunt_id_input",
        )

        if can_write() and hunt_id:
            if st.button("Execute Hunt", key="execute_hunt_btn"):
                execute_and_display(hunt_id, api)

        st.divider()

        st.subheader("Hunt from Alert")
        alert_id = st.number_input("Alert ID", min_value=1, value=1, key="hunt_from_alert_id")

        if st.button("Suggest Hunts from Alert", key="hunt_from_alert_btn"):
            with st.status("Analyzing alert and suggesting hunts...", expanded=True) as status:
                try:
                    result = api.hunt_from_alert(alert_id)
                    # The API returns matching_hunts (template matches by MITRE)
                    # + llm_suggestions — see _hunts_for_alert.
                    hunts = _hunts_for_alert(result)

                    if hunts:
                        status.update(label=f"Found {len(hunts)} suggested hunts", state="complete")
                        st.toast(f"Found {len(hunts)} hunt suggestions")
                        for hunt in hunts:
                            with st.expander(f"{hunt.get('name', 'Unknown')}"):
                                st.write(f"**Description:** {hunt.get('description', '')}")
                                # Template matches carry matched_mitre; LLM
                                # suggestions are name/description only.
                                techniques = (
                                    hunt.get("matched_mitre", [])
                                    or hunt.get("mitre", [])
                                    or []
                                )
                                if techniques:
                                    st.write(f"**MITRE Techniques:** {', '.join(str(t) for t in techniques)}")
                                hunt_id_suggest = hunt.get("id") or ""
                                if can_write() and hunt_id_suggest:
                                    if st.button("Execute", key=f"exec_suggest_{hunt_id_suggest}"):
                                        execute_and_display(hunt_id_suggest, api)
                    else:
                        status.update(label="No specific hunt suggestions", state="complete")
                        st.info("No specific hunt suggestions for this alert")

                except ApiError as e:
                    status.update(label="Hunt suggestion failed", state="error")
                    st.error(f"Failed to suggest hunts: {e.detail}")


def execute_and_display(hunt_id: str, api):
    """Execute a hunt and display results."""
    with st.status(f"Executing hunt '{hunt_id}'...", expanded=True) as status:
        try:
            result = api.execute_hunt(hunt_id)

            status.update(label=f"Hunt '{hunt_id}' completed", state="complete")
            st.toast(f"Hunt '{hunt_id}' completed")

            sql = result.get("sql", "")
            if sql:
                with st.expander("Executed SQL"):
                    st.code(sql, language="sql")

            results = result.get("results", [])
            if results:
                df = pd.DataFrame(results)
                st.dataframe(df, use_container_width=True, hide_index=True)
                st.caption(f"Hunt returned {len(results)} results")
            else:
                st.info("Hunt returned no results — no matching threats found")

            analysis = result.get("analysis", "")
            if analysis:
                with st.expander("AI Analysis"):
                    st.markdown(analysis)

        except ApiError as e:
            status.update(label="Hunt execution failed", state="error")
            st.error(f"Hunt execution failed: {e.detail}")
        except Exception as e:
            status.update(label="Unexpected error", state="error")
            st.error(f"Unexpected error: {e}")
