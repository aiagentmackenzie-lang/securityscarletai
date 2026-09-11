"""AI-usage event ingest contract (V0.4/5 item 3 -- AI as a detection domain).

"The SIEM that watches your AI agents." AI agent / MCP / LLM-usage events
are first-class log sources with the same discipline as the auth source
(V0.3): ONE shape definition shared by producers, generators, and tests;
producers map INTO the closed event_action vocabulary, never fake tokens.

    event_category = 'ai'
    event_action   = ai_agent_run | mcp_tool_call | mcp_tool_denied |
                     ai_prompt_injection
    source         = 'ai_usage'

Field mapping (deliberate, documented):
    user_name    = the ACTOR of the AI action (the requesting human's
                   username, or 'mcp:<session>' for MCP-initiated calls) --
                   selectable by Sigma rules for per-actor aggregation.
    process_name = the MCP tool name (mcp_* kinds) -- the tool acts on the
                   SIEM the way a process acts on a host; it is the only
                   free-form selector a rule needs for tool-level grouping.
    raw_data     = {actor, session, detail, verdict?} -- chain of custody;
                   NOT Sigma-selectable (flat columns only).

Emitters (producers of record):
    - the API agent path (src/api/agents.py): ai_agent_run start/end
    - the SIEM MCP server (src/mcp_server/app.py): mcp_tool_call /
      mcp_tool_denied via POST /ingest with the scoped ingest token --
      the same producer convention as NeuralGuard verdicts (which continue
      to ride ingest as verdict_block; a NeuralGuard prompt-injection
      verdict maps into ai_prompt_injection at its producer)
    - scripts/generate_ai_usage_events.py: the detection-matrix generator
      (synthetic true/false pairs in the EXACT shipper format -- no rule
      can pass on a fake vocabulary)
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Optional

import httpx

from src.config.settings import settings
from src.ingestion.schemas import NormalizedEvent

AI_USAGE_SOURCE = "ai_usage"
AI_USAGE_CATEGORY = "ai"

# The closed kind -> (event_action, event_type) mapping. Producers name a
# KIND; anything outside this table is rejected (fail-closed: an unknown
# kind must not silently become a guessed token).
AI_USAGE_KINDS: dict[str, tuple[str, str]] = {
    "agent_run_start": ("ai_agent_run", "start"),
    "agent_run_end": ("ai_agent_run", "end"),
    "mcp_tool_call": ("mcp_tool_call", "info"),
    "mcp_tool_denied": ("mcp_tool_denied", "info"),
    "prompt_injection_detected": ("ai_prompt_injection", "info"),
}

MCP_KINDS = ("mcp_tool_call", "mcp_tool_denied")


def build_ai_usage_event(
    kind: str,
    *,
    host_name: Optional[str] = None,
    actor: Optional[str] = None,
    tool: Optional[str] = None,
    session: Optional[str] = None,
    detail: Optional[dict] = None,
    severity: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> NormalizedEvent:
    """Build one normalized AI-usage event.

    Args:
        kind: A key from AI_USAGE_KINDS (fail-closed on anything else).
        host_name: The host running the AI component (defaults to this
            machine's hostname -- for containers that is the container
            host; override per deployment with the env if desired).
        actor: The acting identity (human username or 'mcp:<session>') --
            mapped to user_name so per-actor Sigma aggregations work.
        tool: The MCP tool name (mcp_* kinds) -- mapped to process_name.
        session: The MCP session id (raw_data only; not Sigma-selectable).
        detail: Bounded structured context (run id, verdict, reason) --
            raw_data only, chain of custody.
        severity: Optional severity hint for alerting.
        timestamp: Event time (defaults to now, UTC).
    """
    mapped = AI_USAGE_KINDS.get(kind)
    if mapped is None:
        raise ValueError(
            f"unknown AI-usage kind '{kind}' -- producers must map into "
            f"the closed table (valid: {', '.join(sorted(AI_USAGE_KINDS))})"
        )
    event_action, event_type = mapped

    return NormalizedEvent(
        **{
            "@timestamp": timestamp or datetime.now(timezone.utc),
            "host_name": host_name or socket.gethostname(),
            "event_category": AI_USAGE_CATEGORY,
            "event_type": event_type,
            "event_action": event_action,
            "source": AI_USAGE_SOURCE,
            "user_name": actor,
            # ECS-borrowed slot: the MCP tool acts on the SIEM the way a
            # process acts on a host; it gives rules a flat, aggregable
            # tool dimension. Documented in the module docstring.
            "process_name": (tool or None) if kind in MCP_KINDS else None,
            "raw_data": {
                "shipper": AI_USAGE_SOURCE,
                "kind": kind,
                "actor": actor,
                "session": session,
                "detail": detail or {},
            },
            "severity": severity,
        }
    )


def event_to_shipper_line(event: NormalizedEvent) -> str:
    """Serialize an AI-usage event as the NDJSON line the FileShipper
    (normalized format) consumes -- same contract as the auth source."""
    import json

    return json.dumps(event.model_dump(by_alias=True, mode="json"))


async def emit_ai_usage_event(event: NormalizedEvent) -> bool:
    """POST one AI-usage event through the REAL ingest pipe (POST /ingest,
    scoped INGEST_BEARER_TOKEN). Never raises: telemetry emission is
    best-effort (same posture as the file shippers -- the audit chain is
    the source of truth); a failed emission is loudly logged.

    Used by the MCP server (whose DB role is read-only and must not write
    logs directly). In-process producers on the API (the agent path) use
    the writer directly and do not need this helper.
    """
    from src.config.logging import get_logger

    log = get_logger("ingestion.ai_usage")
    url = settings.ai_usage_ingest_url
    if not url:
        return False  # emission disabled by config -- documented, not silent
    token = (
        settings.ingest_bearer_token.get_secret_value()
        if settings.ingest_bearer_token
        else settings.api_bearer_token.get_secret_value()
    )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                url,
                json=[event.model_dump(by_alias=True, mode="json")],
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
        return True
    except Exception as e:
        log.warning(
            "ai_usage_emission_failed",
            kind=event.raw_data.get("kind") if isinstance(event.raw_data, dict) else None,
            error=str(e)[:200],
        )
        return False
