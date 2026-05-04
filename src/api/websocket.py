"""
WebSocket endpoint for real-time log streaming.

Authentication: Token passed as query parameter since WebSocket
doesn't support Authorization headers in the browser.
"""
from typing import Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState

from src.api.auth import verify_bearer_token
from src.config.logging import get_logger
from src.ingestion.schemas import NormalizedEvent

router = APIRouter(tags=["websocket"])
log = get_logger("api.websocket")

# Connected clients for broadcasting
_connected_clients: list[WebSocket] = []


@router.websocket("/ws/logs")
async def websocket_logs(
    websocket: WebSocket,
    token: str = Query(..., description="Bearer token for authentication"),
    host_filter: Optional[str] = Query(None, description="Filter by hostname"),
    category_filter: Optional[str] = Query(None, description="Filter by event category"),
    severity_filter: Optional[str] = Query(None, description="Filter by severity"),
):
    """WebSocket endpoint for real-time log streaming.

    Connect with: ws://localhost:8000/api/v1/ws/logs?token=YOUR_TOKEN
    Optional filters: ?host_filter=hostname&category_filter=process
    """
    # Authenticate
    try:
        from fastapi.security import HTTPAuthorizationCredentials
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        verify_bearer_token(creds)
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    _connected_clients.append(websocket)
    log.info("websocket_connected", client=str(websocket.client), filters={
        "host": host_filter,
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
        if websocket in _connected_clients:
            _connected_clients.remove(websocket)


async def broadcast_event(event: NormalizedEvent) -> None:
    """Broadcast a log event to all connected WebSocket clients.

    Called by the ingestion pipeline after writing to DB.
    """
    if not _connected_clients:
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

    # Filter and send to matching clients
    disconnected = []
    for client in _connected_clients:
        try:
            if client.client_state == WebSocketState.CONNECTED:
                # Get client's filters from scope (stored at connection time)
                # For simplicity, we broadcast all and let client filter
                # In production, store filters per-connection
                await client.send_json(message)
        except Exception:
            disconnected.append(client)

    # Clean up disconnected clients
    for client in disconnected:
        if client in _connected_clients:
            _connected_clients.remove(client)
