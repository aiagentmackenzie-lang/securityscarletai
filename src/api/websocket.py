"""
WebSocket endpoint for real-time log streaming.

Authentication: Short-lived single-use WebSocket tokens obtained via
a dedicated endpoint (POST /auth/ws-token). WS tokens have 5 min TTL
and are separate from the main JWT, avoiding exposure in query params.
"""
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState

from src.api.auth import require_role, verify_jwt
from src.config.logging import get_logger
from src.ingestion.schemas import NormalizedEvent

router = APIRouter(tags=["websocket"])
log = get_logger("api.websocket")

# Connected clients for broadcasting.
# F-16 (plan phase 5): each client's QUERY FILTERS are kept with the socket
# so broadcast only delivers matching events (it used to broadcast everything
# to everyone, ignoring the filters the dashboard set).
# MAX_CLIENTS caps the registry (LLM10-style unbounded-consumption bounds).
_connected_clients: list[WebSocket] = []
_client_filters: dict[WebSocket, dict[str, Optional[str]]] = {}
_clients_lock = asyncio.Lock()
MAX_WEBSOCKET_CLIENTS = 100

# P2.4: per-send timeout. A slow (never-reading) client used to stall the
# broadcast loop indefinitely — and the loop ran in the INGEST hot path, so
# one stuck dashboard socket could stall event ingestion. Sends are now
# time-capped; a client that exceeds the cap is EVICTED (same cleanup path
# as a disconnected client).
WS_SEND_TIMEOUT_SECONDS = 1.0

# In-memory store for short-lived WS tokens (5 min TTL)
# Key: token string, Value: {"username": ..., "role": ..., "expires": float}
_ws_tokens: dict[str, dict] = {}

# H-05 fix: Periodic cleanup for expired WS tokens that were created but never used
async def _cleanup_expired_ws_tokens():
    """Remove expired WS tokens to prevent memory leak."""
    import time
    now = time.time()
    expired = [k for k, v in _ws_tokens.items() if now > v["expires"] + 300]
    for k in expired:
        _ws_tokens.pop(k, None)
    if expired:
        log.debug("ws_tokens_cleaned", removed=len(expired), remaining=len(_ws_tokens))


@router.post("/auth/ws-token", dependencies=[Depends(require_role("viewer"))])
async def create_ws_token(payload: dict = Depends(verify_jwt)):
    """Generate a short-lived single-use WebSocket token (5 min TTL)."""
    import secrets
    import time

    # H-05 fix: Cleanup expired tokens on every new token request
    await _cleanup_expired_ws_tokens()

    token = secrets.token_urlsafe(32)
    _ws_tokens[token] = {
        "username": payload.get("sub", "unknown"),
        "role": payload.get("role", "viewer"),
        "expires": time.time() + 300,  # 5 minutes
    }
    return {"ws_token": token, "ttl": 300}


def _validate_ws_token(token: str) -> Optional[dict]:
    """Validate and consume a WS token."""
    import time

    data = _ws_tokens.pop(token, None)
    if data is None:
        return None
    if time.time() > data["expires"]:
        return None
    return data


@router.websocket("/ws/logs")
async def websocket_logs(
    websocket: WebSocket,
    token: str = Query(..., description="Short-lived WebSocket token from /auth/ws-token"),
    host_filter: Optional[str] = Query(None, description="Filter by hostname"),
    category_filter: Optional[str] = Query(None, description="Filter by event category"),
    severity_filter: Optional[str] = Query(None, description="Filter by severity"),
):
    """WebSocket endpoint for real-time log streaming.

    Connect with: ws://localhost:8000/api/v1/ws/logs?token=YOUR_WS_TOKEN
    Get token from: POST /api/v1/auth/ws-token (requires JWT auth)
    Optional filters: ?host_filter=hostname&category_filter=process
    """
    # Authenticate with short-lived WS token
    token_data = _validate_ws_token(token)
    if token_data is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    async with _clients_lock:
        # F-16: bound the registry — a flood of connections cannot grow it
        # unbounded; the 101st concurrent client is rejected with 1008.
        if len(_connected_clients) >= MAX_WEBSOCKET_CLIENTS:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            log.warning("ws_rejected_at_capacity", count=len(_connected_clients))
            return
        _connected_clients.append(websocket)
        _client_filters[websocket] = {
            "host_filter": host_filter,
            "category_filter": category_filter,
            "severity_filter": severity_filter,
        }

    await websocket.accept()

    log.info(
        "websocket_connected",
        client=str(websocket.client),
        user=token_data.get("username"),
        filters={"host": host_filter,
        "category": category_filter,
        "severity": severity_filter,
    })

    try:
        while True:
            # Keep connection alive, handle ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
            elif data == "filters":
                # Client can request current filter status
                await websocket.send_json({
                    "type": "filters",
                    "host_filter": host_filter,
                    "category_filter": category_filter,
                    "severity_filter": severity_filter,
                })

    except WebSocketDisconnect:
        log.info("websocket_disconnected", client=str(websocket.client))
    finally:
        async with _clients_lock:
            if websocket in _connected_clients:
                _connected_clients.remove(websocket)
            _client_filters.pop(websocket, None)


async def broadcast_event(event: NormalizedEvent) -> None:
    """Broadcast a log event to all connected WebSocket clients.

    Called by the ingestion pipeline after writing to DB.
    Uses lock to prevent modification-during-iteration race.
    """
    async with _clients_lock:
        clients = list(_connected_clients)  # Snapshot under lock

    if not clients:
        return

    # F-16: honor each client's per-connection filters. host_filter is
    # substring, severity/category exact — same semantics the socket pushed
    # its filter status with.
    message = {
        "type": "log",
        "timestamp": event.timestamp.isoformat(),
        "host_name": event.host_name,
        "source": event.source,
        "event_category": event.event_category,
        "event_type": event.event_type,
        "event_action": event.event_action,
        "user_name": event.user_name,
        "process_name": event.process_name,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "file_path": event.file_path,
    }

    disconnected = []
    for client in clients:
        filters = _client_filters.get(client, {})
        host_f = filters.get("host_filter")
        cat_f = filters.get("category_filter")
        sev_f = filters.get("severity_filter")
        if host_f and host_f.lower() not in (event.host_name or "").lower():
            continue
        if cat_f and cat_f.lower() != (event.event_category or "").lower():
            continue
        if sev_f and sev_f.lower() != (event.severity or "").lower():
            continue
        try:
            if client.client_state == WebSocketState.CONNECTED:
                # P2.4: never let a slow client stall the broadcast (and with
                # it, whatever called us). Timeout → evict the client.
                await asyncio.wait_for(
                    client.send_json(message), timeout=WS_SEND_TIMEOUT_SECONDS
                )
        except asyncio.TimeoutError:
            log.warning(
                "ws_broadcast_slow_client_evicted",
                timeout_seconds=WS_SEND_TIMEOUT_SECONDS,
            )
            disconnected.append(client)
        except Exception as e:  # pragma: no cover — defensive
            log.exception("ws_broadcast_failed", error=str(e))
            disconnected.append(client)

    # Clean up disconnected clients under lock
    if disconnected:
        async with _clients_lock:
            for client in disconnected:
                if client in _connected_clients:
                    _connected_clients.remove(client)
