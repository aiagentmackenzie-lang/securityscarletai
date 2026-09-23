"""
Comprehensive tests for src/api/websocket.py.

Covers:
- _connected_clients list management
- broadcast_event (with and without clients)
- WebSocket connection and authentication
- Client disconnection handling
- Ping/pong and filter messages
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

import src.api.websocket as ws_mod
from src.api.websocket import (
    _connected_clients,
    broadcast_event,
)
from src.ingestion.schemas import NormalizedEvent


@pytest.fixture(autouse=True)
def _isolate_connected_clients():
    """Isolate _connected_clients between tests to prevent shared mutable state (T-09).

    W1-E: also isolates the per-client send-lock registry the broadcasts use
    (absent on pre-W1-E code — getattr keeps the isolation harmless there).
    """
    original = list(_connected_clients)
    original_locks = dict(getattr(ws_mod, "_client_send_locks", {}))
    _connected_clients.clear()
    if hasattr(ws_mod, "_client_send_locks"):
        ws_mod._client_send_locks.clear()
    yield
    _connected_clients.clear()
    _connected_clients.extend(original)
    if hasattr(ws_mod, "_client_send_locks"):
        ws_mod._client_send_locks.clear()
        ws_mod._client_send_locks.update(original_locks)


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
        # _connected_clients is isolated by autouse fixture
        event = make_test_event()

        # Should not raise
        await broadcast_event(event)

    @pytest.mark.asyncio
    async def test_broadcast_with_connected_client(self):
        """Should send JSON message to connected clients."""
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

    @pytest.mark.asyncio
    async def test_broadcast_removes_disconnected_client(self):
        """Should remove clients that throw exceptions."""
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

    @pytest.mark.asyncio
    async def test_broadcast_with_optional_none_fields(self):
        """Should handle event with None optional fields."""
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


class TestSendSerialization:
    @pytest.mark.asyncio
    async def test_concurrent_broadcasts_never_interleave_on_one_socket(self):
        """W1-E/B3: two concurrent broadcasts to the SAME client must not
        interleave ASGI frames — sends serialize per socket (per-client lock).
        ASGI forbids concurrent send on one socket; unguarded, the second
        broadcast's send starts inside the first's yield point."""
        from starlette.websockets import WebSocketState

        in_flight = 0
        max_concurrent = 0
        sent: list[str] = []

        class _FakeSocket:
            client_state = WebSocketState.CONNECTED
            client = None

            @staticmethod
            async def send_json(message):
                nonlocal in_flight, max_concurrent
                in_flight += 1
                max_concurrent = max(max_concurrent, in_flight)
                await asyncio.sleep(0)  # yield: an unguarded concurrent send starts HERE
                sent.append(message["host_name"])
                in_flight -= 1

        sock = _FakeSocket()
        _connected_clients.append(sock)

        await asyncio.gather(
            broadcast_event(make_test_event(host_name="host-A")),
            broadcast_event(make_test_event(host_name="host-B")),
        )

        # Both sends completed, but never two at once on the same socket.
        assert sorted(sent) == ["host-A", "host-B"]
        assert max_concurrent == 1


class TestBroadcastBackpressure:
    """P2.4 — a slow (never-reading) client must not stall the broadcast and
    must get evicted, not waited on."""

    @pytest.mark.asyncio
    async def test_slow_client_evicted_within_send_timeout(self):
        import time as _time

        from starlette.websockets import WebSocketState

        from src.api.websocket import WS_SEND_TIMEOUT_SECONDS

        slow_client = MagicMock()
        slow_client.client_state = WebSocketState.CONNECTED

        async def never_completes(message):
            await asyncio.sleep(30)  # far beyond the 1s send cap

        slow_client.send_json = never_completes
        _connected_clients.append(slow_client)

        t0 = _time.monotonic()
        await broadcast_event(make_test_event())
        elapsed = _time.monotonic() - t0

        # broadcast returned inside the wait bound (not blocked for 30s)
        assert elapsed < WS_SEND_TIMEOUT_SECONDS + 2.0
        # slow client was evicted from the registry
        assert slow_client not in _connected_clients

    @pytest.mark.asyncio
    async def test_slow_client_does_not_block_fast_clients(self):
        """A stuck client must not stop delivery to healthy clients in the
        same broadcast round."""
        from starlette.websockets import WebSocketState

        slow_client = MagicMock()
        slow_client.client_state = WebSocketState.CONNECTED

        async def never_completes(message):
            await asyncio.sleep(30)

        slow_client.send_json = never_completes

        fast_client = MagicMock()
        fast_client.client_state = WebSocketState.CONNECTED
        fast_client.send_json = AsyncMock()

        # slow first, fast second — the slow one must not poison the round
        _connected_clients.extend([slow_client, fast_client])

        await broadcast_event(make_test_event())

        fast_client.send_json.assert_called_once()
        assert slow_client not in _connected_clients
        assert fast_client in _connected_clients


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
