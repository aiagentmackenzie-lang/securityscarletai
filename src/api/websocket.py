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

# Connected clients for broadcasting
_connected_clients: list[WebSocket] = []
_clients_lock = asyncio.Lock()

# In-memory store for short-lived WS tokens (5 min TTL)
# Key: token string, Value: {"username": ..., "role": ..., "expires": float}
_ws_tokens: dict[str, dict] = {}


@router.post("/auth/ws-token", dependencies=[Depends(require_role("viewer"))])
async def create_ws_token(payload: dict = Depends(verify_jwt)):
    """Generate a short-lived single-use WebSocket token (5 min TTL)."""
    import secrets
    import time

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

    await websocket.accept()

    async with _clients_lock:
        _connected_clients.append(websocket)

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


async def broadcast_event(event: NormalizedEvent) -> None:
    """Broadcast a log event to all connected WebSocket clients.

    Called by the ingestion pipeline after writing to DB.
    Uses lock to prevent modification-during-iteration race.
    """
    async with _clients_lock:
        clients = list(_connected_clients)  # Snapshot under lock

    if not clients:
        return

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
        try:
            if client.client_state == WebSocketState.CONNECTED:
                await client.send_json(message)
        except Exception:
            disconnected.append(client)

    # Clean up disconnected clients under lock
    if disconnected:
        async with _clients_lock:
            for client in disconnected:
                if client in _connected_clients:
                    _connected_clients.remove(client)
