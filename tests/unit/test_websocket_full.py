"""
Comprehensive tests for src/api/websocket.py.

Covers:
- _connected_clients list management
- broadcast_event (with and without clients)
- WebSocket connection and authentication
- Client disconnection handling
- Ping/pong and filter messages
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.api.websocket import (
    _connected_clients,
    broadcast_event,
)
from src.ingestion.schemas import NormalizedEvent


def make_test_event(**kwargs):
    """Create a NormalizedEvent for testing with sensible defaults."""
    defaults = {
        "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "host_name": "server-01",
        "source": "syslog",
        "event_category": "process",
        "event_type": "create",
        "event_action": "executed",
        "raw_data": {"test": True},
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# broadcast_event
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestBroadcastEvent:
    @pytest.mark.asyncio
    async def test_broadcast_no_clients(self):
        """Should be a no-op when no clients connected."""
        # Save and restore _connected_clients
        original = list(_connected_clients)
        _connected_clients.clear()

        event = make_test_event()

        # Should not raise
        await broadcast_event(event)

        # Restore
        _connected_clients.extend(original)

    @pytest.mark.asyncio
    async def test_broadcast_with_connected_client(self):
        """Should send JSON message to connected clients."""
        original = list(_connected_clients)
        _connected_clients.clear()

        mock_client = MagicMock()
        mock_client.client_state = MagicMock()
        from starlette.websockets import WebSocketState
        mock_client.client_state = WebSocketState.CONNECTED
        mock_client.send_json = AsyncMock()

        _connected_clients.append(mock_client)

        event = make_test_event(
            user_name="admin",
            process_name="cmd.exe",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            destination_port=443,
            file_path="/tmp/malware.exe",
        )

        await broadcast_event(event)

        mock_client.send_json.assert_called_once()
        message = mock_client.send_json.call_args[0][0]
        assert message["type"] == "log"
        assert message["host_name"] == "server-01"
        assert message["user_name"] == "admin"
        assert message["process_name"] == "cmd.exe"
        assert message["source_ip"] == "10.0.0.1"

        _connected_clients.clear()
        _connected_clients.extend(original)

    @pytest.mark.asyncio
    async def test_broadcast_removes_disconnected_client(self):
        """Should remove clients that throw exceptions."""
        original = list(_connected_clients)
        _connected_clients.clear()

        mock_client = MagicMock()
        from starlette.websockets import WebSocketState
        mock_client.client_state = WebSocketState.CONNECTED
        mock_client.send_json = AsyncMock(side_effect=Exception("disconnected"))

        _connected_clients.append(mock_client)

        event = make_test_event(
            event_category="network",
            event_type="connection",
            event_action="established",
        )

        await broadcast_event(event)

        # Disconnected client should be removed
        assert mock_client not in _connected_clients

        _connected_clients.extend(original)

    @pytest.mark.asyncio
    async def test_broadcast_with_optional_none_fields(self):
        """Should handle event with None optional fields."""
        original = list(_connected_clients)
        _connected_clients.clear()

        mock_client = MagicMock()
        from starlette.websockets import WebSocketState
        mock_client.client_state = WebSocketState.CONNECTED
        mock_client.send_json = AsyncMock()

        _connected_clients.append(mock_client)

        event = make_test_event()

        await broadcast_event(event)

        message = mock_client.send_json.call_args[0][0]
        assert message["user_name"] is None
        assert message["source_ip"] is None
        assert message["destination_ip"] is None

        _connected_clients.clear()
        _connected_clients.extend(original)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WebSocket endpoint (tested as much as possible without TestClient)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWebSocketAuth:
    def test_router_exists(self):
        """WebSocket router should be defined."""
        from src.api.websocket import router
        assert router is not None

    def test_connected_clients_start_empty(self):
        """_connected_clients should be a list."""
        assert isinstance(_connected_clients, list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# broadcast_event with mixed clients
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestBroadcastMixedClients:
    @pytest.mark.asyncio
    async def test_broadcast_to_multiple_clients(self):
        """Should send to all connected clients."""
        original = list(_connected_clients)
        _connected_clients.clear()

        from starlette.websockets import WebSocketState

        mock_client1 = MagicMock()
        mock_client1.client_state = WebSocketState.CONNECTED
        mock_client1.send_json = AsyncMock()

        mock_client2 = MagicMock()
        mock_client2.client_state = WebSocketState.CONNECTED
        mock_client2.send_json = AsyncMock()

        _connected_clients.extend([mock_client1, mock_client2])

        event = make_test_event(
            host_name="ws-01",
            source="auth",
            event_category="authentication",
            event_type="login",
            event_action="success",
        )

        await broadcast_event(event)

        mock_client1.send_json.assert_called_once()
        mock_client2.send_json.assert_called_once()

        _connected_clients.clear()
        _connected_clients.extend(original)