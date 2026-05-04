"""
Tests for the dashboard API client module.

Tests the synchronous API client that all dashboard views use for data access.
No direct database access — everything goes through HTTP.
"""
import pytest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

from dashboard.api_client import ApiClient, ApiError


class _SessionState(dict):
    """Dict subclass that mimics Streamlit session_state (has .get, .pop, attribute access)."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"session_state has no attribute '{name}'")

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        try:
            del self[name]
        except KeyError:
            raise AttributeError(f"session_state has no attribute '{name}'")


class TestApiError:
    """Tests for the ApiError exception class."""

    def test_api_error_stores_status_code(self):
        err = ApiError(404, "Not found")
        assert err.status_code == 404
        assert err.detail == "Not found"

    def test_api_error_string_format(self):
        err = ApiError(500, "Server error")
        assert "500" in str(err)
        assert "Server error" in str(err)

    def test_api_error_auth(self):
        err = ApiError(401, "Unauthorized")
        assert err.status_code == 401


class TestHandleResponse:
    """Tests for the response handling logic."""

    def test_handle_200_with_json(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"key": "value"}'
        mock_resp.json.return_value = {"key": "value"}
        result = ApiClient._handle_response(mock_resp)
        assert result == {"key": "value"}

    def test_handle_200_empty(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b""
        result = ApiClient._handle_response(mock_resp)
        assert result is None

    def test_handle_201_created(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"id": 1}'
        mock_resp.json.return_value = {"id": 1}
        result = ApiClient._handle_response(mock_resp)
        assert result == {"id": 1}

    def test_handle_204_no_content(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        result = ApiClient._handle_response(mock_resp)
        assert result is None

    def test_handle_401_raises_auth_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"detail": "Invalid token"}
        with pytest.raises(ApiError) as exc_info:
            ApiClient._handle_response(mock_resp)
        assert exc_info.value.status_code == 401

    def test_handle_403_raises_permission_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"detail": "Insufficient permissions"}
        with pytest.raises(ApiError) as exc_info:
            ApiClient._handle_response(mock_resp)
        assert exc_info.value.status_code == 403

    def test_handle_404_raises_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json.return_value = {"detail": "Not found"}
        with pytest.raises(ApiError) as exc_info:
            ApiClient._handle_response(mock_resp)
        assert exc_info.value.status_code == 404

    def test_handle_500_raises_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"detail": "Internal server error"}
        with pytest.raises(ApiError) as exc_info:
            ApiClient._handle_response(mock_resp)
        assert exc_info.value.status_code == 500

    def test_handle_error_without_json(self):
        """Test error response that doesn't return JSON."""
        mock_resp = MagicMock()
        mock_resp.status_code = 502
        mock_resp.json.side_effect = Exception("No JSON")
        mock_resp.text = "Bad Gateway"
        with pytest.raises(ApiError) as exc_info:
            ApiClient._handle_response(mock_resp)
        assert exc_info.value.status_code == 502
        assert "Bad Gateway" in exc_info.value.detail


class TestApiClientInit:
    def test_default_base_url(self):
        client = ApiClient()
        assert "localhost:8000" in client.base_url

    def test_custom_base_url(self):
        client = ApiClient(base_url="http://custom:9999/api/v1")
        assert client.base_url == "http://custom:9999/api/v1"


class TestApiClientMethods:
    @pytest.fixture
    def client(self):
        return ApiClient()

    def test_headers_include_auth(self, client):
        """Test that headers include Authorization when token exists."""
        mock_state = _SessionState(access_token="test-jwt-token")
        with patch("streamlit.session_state", mock_state):
            headers = client._headers
            assert "Authorization" in headers
            assert headers["Authorization"] == "Bearer test-jwt-token"

    def test_headers_without_auth(self, client):
        """Test that headers work without auth token."""
        mock_state = _SessionState()
        with patch("streamlit.session_state", mock_state):
            headers = client._headers
            assert "Content-Type" in headers

    def test_get_method(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'[{"id": 1}]'
        mock_resp.json.return_value = [{"id": 1}]
        with patch("httpx.get", return_value=mock_resp):
            result = client._get("/test")
            assert result == [{"id": 1}]

    def test_post_method(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"id": 2}'
        mock_resp.json.return_value = {"id": 2}
        with patch("httpx.post", return_value=mock_resp):
            result = client._post("/test", {"key": "value"})
            assert result == {"id": 2}

    def test_put_method(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"id": 1}'
        mock_resp.json.return_value = {"id": 1}
        with patch("httpx.put", return_value=mock_resp):
            result = client._put("/test/1", {"name": "updated"})
            assert result == {"id": 1}

    def test_patch_method(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"id": 1, "status": "investigating"}'
        mock_resp.json.return_value = {"id": 1, "status": "investigating"}
        with patch("httpx.patch", return_value=mock_resp):
            result = client._patch("/test/1", {"status": "investigating"})
            assert result["status"] == "investigating"

    def test_delete_method(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.content = b""
        with patch("httpx.delete", return_value=mock_resp):
            result = client._delete("/test/1")
            assert result is None


class TestApiClientConnectivity:
    @pytest.fixture
    def client(self):
        return ApiClient()

    def test_connect_error_on_get(self, client):
        import httpx
        with patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")):
            with pytest.raises(ApiError) as exc_info:
                client._get("/test")
            assert exc_info.value.status_code == 0
            assert "connect" in exc_info.value.detail.lower()

    def test_timeout_error_on_get(self, client):
        import httpx
        with patch("httpx.get", side_effect=httpx.TimeoutException("Timed out")):
            with pytest.raises(ApiError) as exc_info:
                client._get("/test")
            assert "timed out" in exc_info.value.detail.lower()

    def test_connect_error_on_post(self, client):
        import httpx
        with patch("httpx.post", side_effect=httpx.ConnectError("Connection refused")):
            with pytest.raises(ApiError) as exc_info:
                client._post("/test")

    def test_timeout_error_on_post(self, client):
        import httpx
        with patch("httpx.post", side_effect=httpx.TimeoutException("Timed out")):
            with pytest.raises(ApiError) as exc_info:
                client._post("/test")


class TestApiClientConvenience:
    @pytest.fixture
    def client(self):
        return ApiClient()

    def test_get_alerts_with_filters(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'[{"id": 1}]'
        mock_resp.json.return_value = [{"id": 1}]
        with patch("httpx.get", return_value=mock_resp) as mock_get:
            result = client.get_alerts(status="new", severity="high", limit=50)
            assert result == [{"id": 1}]
            call_args = mock_get.call_args
            assert call_args.kwargs.get("params") or call_args[1].get("params")

    def test_get_alerts_returns_empty_on_none(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"[]"
        mock_resp.json.return_value = []
        with patch("httpx.get", return_value=mock_resp):
            result = client.get_alerts()
            assert result == []

    def test_update_alert_builds_payload(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"id": 1, "status": "investigating"}'
        mock_resp.json.return_value = {"id": 1, "status": "investigating"}
        with patch("httpx.patch", return_value=mock_resp) as mock_patch:
            result = client.update_alert(1, status="investigating", assigned_to="analyst1")
            call_args = mock_patch.call_args
            json_data = call_args.kwargs.get("json") or call_args[1].get("json")
            assert json_data["status"] == "investigating"
            assert json_data["assigned_to"] == "analyst1"

    def test_update_alert_status_only(self, client):
        """Test update with only status change."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"id": 1, "status": "resolved"}'
        mock_resp.json.return_value = {"id": 1, "status": "resolved"}
        with patch("httpx.patch", return_value=mock_resp) as mock_patch:
            result = client.update_alert(1, status="resolved")
            call_args = mock_patch.call_args
            json_data = call_args.kwargs.get("json") or call_args[1].get("json")
            assert "status" in json_data
            assert "assigned_to" not in json_data

    def test_ai_chat_sends_message(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"response": "Check your alerts"}'
        mock_resp.json.return_value = {"response": "Check your alerts"}
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = client.ai_chat("What should I investigate?")
            call_args = mock_post.call_args
            json_data = call_args.kwargs.get("json") or call_args[1].get("json")
            assert json_data["message"] == "What should I investigate?"

    def test_query_sends_question(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"sql": "SELECT ...", "results": []}'
        mock_resp.json.return_value = {"sql": "SELECT ...", "results": []}
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = client.query("Show me failed logins")
            call_args = mock_post.call_args
            json_data = call_args.kwargs.get("json") or call_args[1].get("json")
            assert json_data["question"] == "Show me failed logins"

    def test_bulk_acknowledge_sends_ids(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"count": 3}'
        mock_resp.json.return_value = {"count": 3}
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = client.bulk_acknowledge([1, 2, 3])
            call_args = mock_post.call_args
            json_data = call_args.kwargs.get("json") or call_args[1].get("json")
            assert json_data["alert_ids"] == [1, 2, 3]

    def test_bulk_assign_sends_ids_and_user(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"count": 2}'
        mock_resp.json.return_value = {"count": 2}
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = client.bulk_assign([1, 2], assigned_to="analyst1")
            call_args = mock_post.call_args
            json_data = call_args.kwargs.get("json") or call_args[1].get("json")
            assert json_data["alert_ids"] == [1, 2]
            assert json_data["assigned_to"] == "analyst1"

    def test_get_rules(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'[{"id": 1, "name": "test"}]'
        mock_resp.json.return_value = [{"id": 1, "name": "test"}]
        with patch("httpx.get", return_value=mock_resp):
            result = client.get_rules()
            assert len(result) == 1

    def test_create_rule(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.content = b'{"id": 2, "name": "new"}'
        mock_resp.json.return_value = {"id": 2, "name": "new"}
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = client.create_rule({"name": "new", "sigma_yaml": "test"})
            assert result["name"] == "new"

    def test_delete_rule(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.content = b""
        with patch("httpx.delete", return_value=mock_resp):
            result = client.delete_rule(1)
            assert result is None

    def test_health_check(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"status": "healthy"}'
        mock_resp.json.return_value = {"status": "healthy"}
        with patch("httpx.get", return_value=mock_resp):
            result = client.health()
            assert result["status"] == "healthy"


class TestAuthSessionState:
    """Tests for authentication session state management."""

    def test_is_authenticated_with_token(self):
        mock_state = _SessionState(access_token="valid-jwt")
        with patch("streamlit.session_state", mock_state):
            assert ApiClient.is_authenticated() is True

    def test_is_authenticated_without_token(self):
        mock_state = _SessionState()
        with patch("streamlit.session_state", mock_state):
            assert ApiClient.is_authenticated() is False

    def test_logout_clears_session(self):
        mock_state = _SessionState()
        mock_state["access_token"] = "jwt"
        mock_state["username"] = "admin"
        mock_state["role"] = "admin"
        with patch("streamlit.session_state", mock_state):
            ApiClient.logout()
            assert mock_state.get("access_token") is None
            assert mock_state.get("username") is None
            assert mock_state.get("role") is None