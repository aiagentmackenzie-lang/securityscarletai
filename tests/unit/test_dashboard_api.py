"""
Tests for the dashboard API client module.

Tests the synchronous API client that all dashboard views use for data access.
No direct database access — everything goes through HTTP.
"""

from unittest.mock import MagicMock, patch

import pytest

from dashboard.api_client import ApiClient, ApiError, PasswordChangeRequiredError
from dashboard.auth import require_auth


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


class TestExportAlertsCsv:
    """AUD-060: export_alerts_csv was the only client method using
    r.raise_for_status() (raw httpx.HTTPStatusError) and the only one
    without a TimeoutException -> ApiError wrapper, so a failed export
    escaped the views' `except ApiError` handlers as a raw traceback page.
    The error contract now matches the rest of the client."""

    @pytest.fixture
    def client(self):
        return ApiClient()

    @staticmethod
    def _resp(status_code=200, text="id,rule_name\n1,Test\n", body=None):
        m = MagicMock()
        m.status_code = status_code
        m.text = text
        if body is not None:
            m.json.return_value = body
        else:
            m.json.side_effect = Exception("not json")
        return m

    def test_success_returns_csv_text(self, client):
        with patch("httpx.get", return_value=self._resp()) as mock_get:
            result = client.export_alerts_csv()
        assert result == "id,rule_name\n1,Test\n"
        call_args = mock_get.call_args
        url = call_args.args[0] if call_args.args else call_args[0][0]
        assert url.endswith("/alerts/export/csv")

    def test_filter_params_forwarded(self, client):
        with patch("httpx.get", return_value=self._resp()) as mock_get:
            client.export_alerts_csv(status="new", severity="high")
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params")
        assert params == {"status": "new", "severity": "high"}

    def test_http_error_raises_api_error(self, client):
        resp = self._resp(status_code=500, text="boom", body={"detail": "DB down"})
        with patch("httpx.get", return_value=resp):
            with pytest.raises(ApiError) as exc_info:
                client.export_alerts_csv()
        assert exc_info.value.status_code == 500
        assert exc_info.value.detail == "DB down"

    def test_http_error_without_json_uses_text(self, client):
        resp = self._resp(status_code=502, text="Bad Gateway")
        with patch("httpx.get", return_value=resp):
            with pytest.raises(ApiError) as exc_info:
                client.export_alerts_csv()
        assert exc_info.value.status_code == 502
        assert "Bad Gateway" in exc_info.value.detail

    def test_timeout_raises_api_error(self, client):
        import httpx

        with patch("httpx.get", side_effect=httpx.TimeoutException("Timed out")):
            with pytest.raises(ApiError) as exc_info:
                client.export_alerts_csv()
        assert exc_info.value.status_code == 0
        assert "timed out" in exc_info.value.detail.lower()

    def test_connect_error_raises_api_error(self, client):
        import httpx

        with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
            with pytest.raises(ApiError) as exc_info:
                client.export_alerts_csv()
        assert exc_info.value.status_code == 0
        assert "connect" in exc_info.value.detail.lower()


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


class TestLoginForcePasswordChange:
    """login() captures the 401 PASSWORD_CHANGE_REQUIRED body (which
    _handle_response would discard) and force_change_password() posts with
    the one-off force_change_token as Bearer."""

    @pytest.fixture
    def client(self):
        return ApiClient()

    def _mock_resp(self, status_code, body, body_bytes=None):
        m = MagicMock()
        m.status_code = status_code
        m.content = body_bytes or (str(body).encode())
        m.json.return_value = body
        return m

    def test_login_success_stores_session(self, client):
        body = {"access_token": "tok", "username": "admin", "role": "admin"}
        mock_resp = self._mock_resp(200, body)
        mock_state = _SessionState()
        with patch("httpx.post", return_value=mock_resp):
            with patch("streamlit.session_state", mock_state):
                result = client.login("admin", "pw")
        assert result["access_token"] == "tok"
        assert mock_state["access_token"] == "tok"
        assert mock_state["username"] == "admin"
        assert mock_state["role"] == "admin"

    def test_login_password_change_required_raises_with_token(self, client):
        body = {
            "detail": {
                "message": "Password change required before login",
                "code": "PASSWORD_CHANGE_REQUIRED",
                "force_change_token": "FORCE.JWT.TOKEN",
            }
        }
        mock_resp = self._mock_resp(401, body)
        with patch("httpx.post", return_value=mock_resp):
            with patch("streamlit.session_state", _SessionState()):
                with pytest.raises(PasswordChangeRequiredError) as exc_info:
                    client.login("admin", "admin")
        assert exc_info.value.force_change_token == "FORCE.JWT.TOKEN"
        assert exc_info.value.username == "admin"
        assert exc_info.value.status_code == 401

    def test_login_password_change_required_on_403_raises_with_token(self, client):
        # Live finding 2026-09-07: the API raises 403 (authenticated but
        # forbidden until rotation) — the client only inspected 401, so the
        # first-ever admin login dumped raw JSON into the login form instead
        # of rendering the set-new-password form. The CODE is the contract,
        # not the status.
        body = {
            "detail": {
                "message": "Password change required before login",
                "code": "PASSWORD_CHANGE_REQUIRED",
                "force_change_token": "FORCE.JWT.403",
            }
        }
        mock_resp = self._mock_resp(403, body)
        with patch("httpx.post", return_value=mock_resp):
            with patch("streamlit.session_state", _SessionState()):
                with pytest.raises(PasswordChangeRequiredError) as exc_info:
                    client.login("admin", "admin")
        assert exc_info.value.force_change_token == "FORCE.JWT.403"
        assert exc_info.value.username == "admin"

    def test_login_403_without_code_surfaces_forbidden(self, client):
        # A genuine 403 (no PASSWORD_CHANGE_REQUIRED code) must NOT be
        # swallowed by the force-change path — it surfaces as ApiError(403).
        body = {"detail": "Forbidden"}
        mock_resp = self._mock_resp(403, body)
        with patch("httpx.post", return_value=mock_resp):
            with patch("streamlit.session_state", _SessionState()):
                with pytest.raises(ApiError) as exc_info:
                    client.login("admin", "x")
        assert not isinstance(exc_info.value, PasswordChangeRequiredError)
        assert exc_info.value.status_code == 403

    def test_login_plain_401_raises_invalid_credentials(self, client):
        body = {"detail": "Invalid credentials"}
        mock_resp = self._mock_resp(401, body)
        with patch("httpx.post", return_value=mock_resp):
            with patch("streamlit.session_state", _SessionState()):
                with pytest.raises(ApiError) as exc_info:
                    client.login("admin", "wrong")
        assert exc_info.value.status_code == 401
        assert "Invalid username or password" in exc_info.value.detail

    def test_login_401_without_password_change_code_is_invalid(self, client):
        # 401 body whose detail is a string (no code field) -> not a force-change.
        body = {"detail": "Bad password"}
        mock_resp = self._mock_resp(401, body)
        with patch("httpx.post", return_value=mock_resp):
            with patch("streamlit.session_state", _SessionState()):
                with pytest.raises(ApiError) as exc_info:
                    client.login("admin", "x")
        assert not isinstance(exc_info.value, PasswordChangeRequiredError)
        assert exc_info.value.status_code == 401

    def test_force_change_password_uses_force_token_as_bearer(self, client):
        body = {"message": "Password changed successfully."}
        mock_resp = self._mock_resp(200, body)
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = client.force_change_password("FORCE.JWT.TOKEN", "newpass123")
        assert result["message"].startswith("Password changed")
        call_args = mock_post.call_args
        headers = call_args.kwargs.get("headers") or call_args[1].get("headers")
        assert headers["Authorization"] == "Bearer FORCE.JWT.TOKEN"
        json_data = call_args.kwargs.get("json") or call_args[1].get("json")
        assert json_data == {"new_password": "newpass123"}
        # URL must hit the force-change endpoint, not /auth/login
        url = call_args.args[0] if call_args.args else call_args[0][0]
        assert url.endswith("/auth/force-change-password")


class TestSessionRefresh:
    """W5-A: the dashboard keeps and uses the refresh token.

    Old behavior: login() discarded the refresh_token, so the 15-minute
    access TTL meant a forced logout every 15 minutes (require_auth's
    get_me re-verify 401'd with no recovery path).
    """

    @pytest.fixture
    def client(self):
        return ApiClient()

    def _mock_resp(self, status_code, body):
        m = MagicMock()
        m.status_code = status_code
        m.content = str(body).encode()
        m.json.return_value = body
        return m

    def test_login_stores_refresh_token(self, client):
        body = {"access_token": "tok", "refresh_token": "ref", "username": "admin", "role": "admin"}
        mock_state = _SessionState()
        with patch("httpx.post", return_value=self._mock_resp(200, body)):
            with patch("streamlit.session_state", mock_state):
                client.login("admin", "pw")
        assert mock_state["refresh_token"] == "ref"

    def test_refresh_posts_refresh_token_and_rotates_pair(self, client):
        body = {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "username": "admin",
            "role": "admin",
            "expires_in": 900,
        }
        state = _SessionState(refresh_token="old-refresh", access_token="old-access")
        with patch("httpx.post", return_value=self._mock_resp(200, body)) as mock_post:
            with patch("streamlit.session_state", state):
                data = client.refresh()
        assert data["access_token"] == "new-access"
        assert state["access_token"] == "new-access"
        assert state["refresh_token"] == "new-refresh"  # rotation stored
        call_args = mock_post.call_args
        json_data = call_args.kwargs.get("json") or call_args[1].get("json")
        assert json_data == {"refresh_token": "old-refresh"}
        url = call_args.args[0] if call_args.args else call_args[0][0]
        assert url.endswith("/auth/refresh")

    def test_refresh_without_stored_token_raises(self, client):
        with patch("streamlit.session_state", _SessionState()):
            with pytest.raises(ApiError) as exc_info:
                client.refresh()
        assert exc_info.value.status_code == 401

    def test_require_auth_refreshes_once_and_survives_401(self, monkeypatch):
        # get_me 401s (access expired) -> ONE refresh -> get_me retry OK
        # -> still authenticated, still logged in. THE regression pin for
        # the 15-minute forced logout.
        client = ApiClient()
        client.get_me = MagicMock(
            side_effect=[ApiError(401, "Session expired."), {"username": "admin", "role": "admin"}]
        )
        client.refresh = MagicMock(return_value={"access_token": "new-access"})
        state = _SessionState(
            authenticated=True, access_token="old-token", username="admin", role="admin"
        )
        monkeypatch.setattr("dashboard.auth.get_api_client", lambda: client)
        monkeypatch.setattr("streamlit.session_state", state)
        assert require_auth() is True
        assert client.refresh.call_count == 1  # exactly ONE refresh attempt
        assert client.get_me.call_count == 2  # original + retry
        assert state.get("authenticated") is True

    def test_require_auth_logs_out_when_refresh_also_fails(self, monkeypatch):
        # Refresh fails -> NO get_me retry -> logout. Session dead as before.
        client = ApiClient()
        client.get_me = MagicMock(side_effect=ApiError(401, "Session expired."))
        client.refresh = MagicMock(side_effect=ApiError(401, "No valid refresh token."))
        state = _SessionState(
            authenticated=True, access_token="expired", username="admin", role="admin"
        )
        monkeypatch.setattr("dashboard.auth.get_api_client", lambda: client)
        monkeypatch.setattr("streamlit.session_state", state)
        # logout() POSTs (best-effort) — keep it off the network.
        monkeypatch.setattr("httpx.post", MagicMock())
        assert require_auth() is False
        assert client.refresh.call_count == 1
        assert client.get_me.call_count == 1  # no retry after a failed refresh
        assert state.get("authenticated") is False
