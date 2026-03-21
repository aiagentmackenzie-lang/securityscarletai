"""
Case management view for Streamlit dashboard.

Investigation case creation, assignment, and timeline.
"""
import streamlit as st
import asyncio
from datetime import datetime
from typing import Optional, List, Dict

from src.config.logging import get_logger
from src.db.connection import get_pool
from dashboard.auth import DashboardUser

log = get_logger("dashboard.cases")


async def fetch_cases(
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 50,
) -> List[Dict]:
    """Fetch investigation cases from database."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        conditions = ["1=1"]
        params = []
        
        if status:
            params.append(status)
            conditions.append(f"status = ${len(params)}")
        
        if assigned_to:
            params.append(assigned_to)
            conditions.append(f"assigned_to = ${len(params)}")
        
        where_clause = " AND ".join(conditions)
        params.append(limit)
        
        rows = await conn.fetch(
            f"""
            SELECT id, title, description, status, severity, 
                   assigned_to, alert_ids, created_at, updated_at
            FROM cases
            WHERE {where_clause}
            ORDER BY updated_at DESC
            LIMIT ${len(params)}
            """,
            *params
        )
        return [dict(r) for r in rows]


async def create_case(
    title: str,
    description: str,
    severity: str,
    assigned_to: str,
    alert_ids: List[int],
) -> int:
    """Create a new investigation case."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        case_id = await conn.fetchval(
            """
            INSERT INTO cases (title, description, severity, assigned_to, alert_ids, status)
            VALUES ($1, $2, $3, $4, $5, 'open')
            RETURNING id
            """,
            title,
            description,
            severity,
            assigned_to,
            alert_ids,
        )
        
        # Link alerts to case
        await conn.execute(
            "UPDATE alerts SET case_id = $1 WHERE id = ANY($2)",
            case_id,
            alert_ids,
        )
        
        return case_id


def status_badge(status: str) -> str:
    """Return emoji badge for case status."""
    badges = {
        "open": "📂",
        "in_progress": "🔍",
        "resolved": "✅",
        "closed": "📁",
    }
    return badges.get(status.lower(), "❓")


def render_cases_view(user: DashboardUser):
    """Render the cases management page."""
    st.header("📁 Investigation Cases")
    
    # Tabs
    tab1, tab2 = st.tabs(["📋 Case List", "➕ Create Case"])
    
    with tab1:
        # Filters
        col1, col2, col3 = st.columns([2, 2, 2])
        
        with col1:
            status_filter = st.selectbox(
                "Status",
                ["All", "Open", "In Progress", "Resolved", "Closed"],
                key="case_status_filter",
            )
        
        with col2:
            assigned_filter = st.text_input(
                "Assigned To",
                placeholder="Filter by assignee",
                key="case_assigned_filter",
            )
        
        with col3:
            st.write("")
            st.write("")
            if st.button("🔄 Refresh"):
                st.rerun()
        
        # Fetch cases
        try:
            status_param = None if status_filter == "All" else status_filter.lower().replace(" ", "_")
            cases = asyncio.run(fetch_cases(
                status=status_param,
                assigned_to=assigned_filter if assigned_filter else None,
            ))
        except Exception as e:
            st.error(f"Failed to fetch cases: {e}")
            cases = []
        
        if not cases:
            st.info("No cases found. Create your first case to start an investigation.")
        else:
            st.caption(f"Showing {len(cases)} cases")
            
            for case in cases:
                alert_count = len(case.get("alert_ids", []) or [])
                
                with st.expander(
                    f"{status_badge(case['status'])} Case #{case['id']}: {case['title']} "
                    f"[{case['severity'].upper()}] ({alert_count} alerts)"
                ):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**Description:** {case.get('description', 'N/A')}")
                        st.write(f"**Status:** {case['status']}")
                        st.write(f"**Assigned:** {case.get('assigned_to', 'Unassigned')}")
                        st.write(f"**Created:** {case['created_at']}")
                        st.write(f"**Last Updated:** {case['updated_at']}")
                    
                    with col2:
                        if user.can_write():
                            new_status = st.selectbox(
                                "Update Status",
                                ["open", "in_progress", "resolved", "closed"],
                                index=["open", "in_progress", "resolved", "closed"].index(case['status']),
                                key=f"case_status_{case['id']}",
                            )
                            
                            if st.button("Update", key=f"update_case_{case['id']}"):
                                st.success(f"Status updated to {new_status}")
                                # TODO: Call API to update
    
    with tab2:
        if not user.can_write():
            st.error("You need write permissions to create cases.")
        else:
            st.subheader("Create New Investigation Case")
            
            with st.form("create_case_form"):
                title = st.text_input("Case Title", placeholder="e.g., Suspicious Activity on Web Server")
                description = st.text_area("Description", placeholder="Describe the investigation scope...")
                
                col1, col2 = st.columns(2)
                with col1:
                    severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
                with col2:
                    assignee = st.text_input("Assign To", value=user.username)
                
                # Alert selection (would fetch from API)
                st.write("**Linked Alerts:**")
                st.info("In production, this would show a multi-select of unassigned alerts")
                alert_ids = st.text_input("Alert IDs (comma-separated)", placeholder="e.g., 1, 2, 3")
                
                submitted = st.form_submit_button("Create Case")
                
                if submitted:
                    if not title:
                        st.error("Title is required")
                    else:
                        try:
                            alert_id_list = [int(x.strip()) for x in alert_ids.split(",") if x.strip()]
                            case_id = asyncio.run(create_case(
                                title=title,
                                description=description,
                                severity=severity,
                                assigned_to=assignee,
                                alert_ids=alert_id_list,
                            ))
                            st.success(f"Case #{case_id} created successfully!")
                        except Exception as e:
                            st.error(f"Failed to create case: {e}")


def render_case_detail(case_id: int, user: DashboardUser):
    """Render detailed view of a single case with timeline."""
    st.header(f"Case #{case_id}")
    
    # Timeline visualization placeholder
    st.subheader("📊 Investigation Timeline")
    
    timeline_data = [
        {"time": "2026-03-21 10:00", "event": "Case opened", "user": user.username},
        {"time": "2026-03-21 10:15", "event": "Alert #123 linked", "user": "system"},
        {"time": "2026-03-21 11:30", "event": "Assigned to analyst", "user": user.username},
    ]
    
    for event in timeline_data:
        st.write(f"**{event['time']}** - {event['event']} (by {event['user']})")
    
    # Evidence section
    st.subheader("📝 Evidence & Notes")
    
    if user.can_write():
        with st.form("add_note_form"):
            note = st.text_area("Add Note")
            if st.form_submit_button("Add Note"):
                st.success("Note added!")
