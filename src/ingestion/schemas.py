"""
ECS (Elastic Common Schema) field mappings for SecurityScarletAI.
Reference: https://www.elastic.co/guide/en/ecs/current/index.html

Each osquery table maps to an ECS event.category + event.type combination.
"""
from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime


class NormalizedEvent(BaseModel):
    """A single security event normalized to ECS fields."""
    timestamp: datetime = Field(alias="@timestamp")
    
    # Host context
    host_name: str
    host_ip: Optional[str] = None
    
    # Event classification (ECS)
    event_category: str        # process, network, file, authentication, configuration
    event_type: str            # start, end, connection, creation, deletion, change, info
    event_action: Optional[str] = None  # specific action, e.g., "process_started"
    source: str                # osquery table name or ingestion source
    
    # Actor
    user_name: Optional[str] = None
    
    # Process context (when applicable)
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_cmdline: Optional[str] = None
    process_path: Optional[str] = None
    
    # Network context (when applicable)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    
    # File context (when applicable)
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    
    # Raw + enrichment
    raw_data: dict[str, Any]
    enrichment: dict[str, Any] = Field(default_factory=dict)
    
    # Severity for alerting
    severity: Optional[str] = None  # info, low, medium, high, critical

    class Config:
        populate_by_name = True


# Mapping: osquery table name -> ECS category + type
OSQUERY_ECS_MAP: dict[str, dict[str, str]] = {
    "processes":        {"event_category": "process",        "event_type": "info"},
    "process_events":   {"event_category": "process",        "event_type": "start"},
    "listening_ports":  {"event_category": "network",        "event_type": "connection"},
    "open_sockets":     {"event_category": "network",        "event_type": "connection"},
    "logged_in_users":  {"event_category": "authentication", "event_type": "start"},
    "file_events":      {"event_category": "file",           "event_type": "change"},
    "shell_history":    {"event_category": "process",        "event_type": "info"},
    "crontab":          {"event_category": "configuration",  "event_type": "info"},
    "startup_items":    {"event_category": "configuration",  "event_type": "info"},
    "launchd_entries":  {"event_category": "configuration",  "event_type": "info"},
    "user_ssh_keys":    {"event_category": "configuration",  "event_type": "info"},
    "sip_config":       {"event_category": "configuration",  "event_type": "info"},
}
