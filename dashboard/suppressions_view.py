"""
Alert suppression view for SecurityScarletAI dashboard (P4.2).

Surfaces the AI-triage differentiation: analysts suppress (rule_name,
host_name) pairs that are known false positives so the AI triage / alert
stream isn't drowned in noise. Lists active suppressions, lets admins
enable/disable a rule (takes effect immediately — the detection path's
_is_suppressed only matches enabled = TRUE), create a new suppression, and
delete one. Critical/high-severity alerts are NEVER suppressed (enforced in
src/detection/alerts.py::_is_suppressed) — that guard is noted in the UI.

ALL data via ApiClient — NO direct DB access.
"""
import streamlit as st

from dashboard.api_client import ApiError
from dashboard.auth import get_api_client, is_admin


def render_suppressions_view() -> None:
    """Render the alert-suppression management view."""
    st.header("Alert Suppressions")
    st.caption(
        "Whitelist known false positives by (rule_name, host_name) so the AI "
        "triage and alert stream focus on real threats. Critical and high-"
        "severity alerts are never suppressed (enforced server-side)."
    )

    client = get_api_client()
    admin = is_admin()

    # ── Active suppressions ──────────────────────────────────────
    st.subheader("Active Suppression Rules")
    try:
        suppressions: list[dict] = client.list_suppressions()
    except ApiError as e:
        st.error(f"Failed to load suppressions: {e.detail}")
        return

    if not suppressions:
        st.info(
            "No suppression rules configured. Suppressed (rule_name, host_name) "
            "pairs stop generating alerts — useful for known benign activity."
        )
    else:
        cols = st.columns([1, 2, 2, 3, 1, 1, 1])
        for c, label in zip(
            cols,
            ["ID", "Rule", "Host", "Reason", "Enabled", "By", "Actions"],
            strict=False,
        ):
            c.markdown(f"**{label}**")

        for sup in suppressions:
            c1, c2, c3, c4, c5, c6, c7 = st.columns([1, 2, 2, 3, 1, 1, 1])
            c1.write(sup.get("id", "?"))
            c2.write(sup.get("rule_name") or "*")
            c3.write(sup.get("host_name") or "*")
            c4.write(sup.get("reason", ""))
            c5.write("✅ on" if sup.get("enabled") else "⛔ off")

            created_by = sup.get("created_by", "?")
            c6.write(created_by)

            if not admin:
                c7.write("—")
                continue

            current = bool(sup.get("enabled"))
            if c7.button(
                "Disable" if current else "Enable",
                key=f"toggle_sup_{sup.get('id')}",
                help="Toggle enabled (takes effect immediately)",
            ):
                try:
                    client.set_suppression_enabled(int(sup["id"]), not current)
                    st.toast(
                        f"Suppression #{sup['id']} "
                        f"{'enabled' if not current else 'disabled'}"
                    )
                    st.rerun()
                except ApiError as e:
                    st.error(f"Toggle failed: {e.detail}")

            if c7.button(
                "Delete",
                key=f"del_sup_{sup.get('id')}",
                help="Permanently delete this suppression rule",
            ):
                try:
                    client.delete_suppression(int(sup["id"]))
                    st.toast(f"Suppression #{sup['id']} deleted")
                    st.rerun()
                except ApiError as e:
                    st.error(f"Delete failed: {e.detail}")

    st.divider()

    # ── Create a new suppression ─────────────────────────────────
    st.subheader("Create Suppression Rule")
    if not admin:
        st.info("Creating, enabling/disabling, and deleting suppressions is admin-only.")
        return

    with st.form("create_suppression_form"):
        st.markdown(
            "Suppress a **(rule_name, host_name)** pair. At least one of the two "
            "must be set (a rule with both blank would suppress *all* alerts and "
            "is rejected by the API). Use `*`/blank for “any”."
        )
        col_r, col_h = st.columns(2)
        rule_name = col_r.text_input(
            "Rule name (blank = any rule)",
            placeholder="e.g. SSH Brute Force Detected",
        )
        host_name = col_h.text_input(
            "Host name (blank = any host)",
            placeholder="e.g. bastion-prod-01",
        )
        reason = st.text_input(
            "Reason (required)",
            placeholder="e.g. Known scanner, authorized security test",
        )
        submitted = st.form_submit_button("Create Suppression", type="primary")
        if submitted:
            rn = rule_name.strip() or None
            hn = host_name.strip() or None
            if not rn and not hn:
                st.error("Specify at least a rule name or a host name.")
            elif not reason.strip():
                st.error("A reason is required.")
            else:
                try:
                    res = client.create_suppression(rn, hn, reason.strip())
                    st.toast(f"Suppression #{res.get('id')} created")
                    st.rerun()
                except ApiError as e:
                    st.error(f"Create failed: {e.detail}")
