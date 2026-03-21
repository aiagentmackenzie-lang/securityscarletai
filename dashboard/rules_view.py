"""
Rule management view for Streamlit dashboard.

CRUD interface for Sigma detection rules.
"""
import streamlit as st
import asyncio
from typing import Optional

from src.config.logging import get_logger
from dashboard.auth import DashboardUser

log = get_logger("dashboard.rules")


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
}


def render_rules_view(user: DashboardUser):
    """Render the rules management page."""
    st.header("📋 Detection Rules")
    
    if not user.can_manage_rules():
        st.error("You don't have permission to manage rules.")
        return
    
    # Tabs
    tab1, tab2 = st.tabs(["📜 View Rules", "➕ Create Rule"])
    
    with tab1:
        st.subheader("Active Rules")
        
        # Placeholder for rules list
        # In real implementation, fetch from API
        st.info("Rules list would be fetched from API here")
        
        # Example rules table
        sample_rules = [
            {"name": "Brute Force SSH", "severity": "high", "enabled": True, "matches": 5},
            {"name": "Suspicious /tmp Process", "severity": "medium", "enabled": True, "matches": 2},
            {"name": "Launch Agent Persistence", "severity": "high", "enabled": True, "matches": 0},
        ]
        
        for rule in sample_rules:
            col1, col2, col3, col4 = st.columns([3, 2, 2, 2])
            
            with col1:
                st.write(f"**{rule['name']}**")
            with col2:
                st.badge(rule['severity'].upper())
            with col3:
                st.write("✅ Enabled" if rule['enabled'] else "❌ Disabled")
            with col4:
                st.caption(f"{rule['matches']} matches")
            
            st.divider()
    
    with tab2:
        st.subheader("Create New Rule")
        
        # Template selector
        template = st.selectbox(
            "Start from template",
            ["Blank", "Process Execution", "Network Connection", "File Modification"],
        )
        
        # Rule form
        with st.form("create_rule_form"):
            name = st.text_input("Rule Name", placeholder="e.g., Suspicious PowerShell Execution")
            description = st.text_area("Description", placeholder="What does this rule detect?")
            
            col1, col2 = st.columns(2)
            with col1:
                severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
            with col2:
                run_interval = st.number_input("Check Interval (seconds)", min_value=60, value=300)
            
            # Sigma YAML editor
            if template == "Blank":
                default_yaml = """title: {name}
description: {description}
detection:
    selection:
        # Add your detection logic here
    condition: selection
timeframe: 1h
level: {severity}
tags:
    - attack.execution
"""
            else:
                default_yaml = RULE_TEMPLATES.get(template, "")
            
            sigma_yaml = st.text_area(
                "Sigma Rule (YAML)",
                value=default_yaml.format(name=name or "Rule Name", description=description or "", severity=severity, process_name="python", port=4444, path="/tmp"),
                height=300,
            )
            
            # Preview
            if st.form_submit_button("Preview"):
                st.subheader("Preview")
                st.code(sigma_yaml, language="yaml")
            
            # Submit
            submitted = st.form_submit_button("Create Rule")
            if submitted:
                if not name or not sigma_yaml:
                    st.error("Name and Sigma YAML are required")
                else:
                    st.success(f"Rule '{name}' created successfully!")
                    st.info("In production, this would call the API to create the rule")
