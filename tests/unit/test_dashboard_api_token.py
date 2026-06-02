"""
Tests for Epic 10 dashboard service-to-service auth (DASHBOARD_API_TOKEN).

Verifies:
- DASHBOARD_API_TOKEN is read from env at import time.
- Empty string is treated as unset (not as a real empty bearer).
- ApiClient._headers uses the env token as a fallback when no JWT is
  in streamlit session state.
- ApiClient._headers prefers the session JWT over the env token.
- ApiClient.has_service_auth() reflects whether the env token is set.
"""
from __future__ import annotations

import importlib
import os
import sys
from unittest.mock import MagicMock

import pytest


def _reload_api_client(monkeypatch, env_value):
    """Reload dashboard.api_client with DASHBOARD_API_TOKEN set/unset."""
    if env_value is None:
        monkeypatch.delenv("DASHBOARD_API_TOKEN", raising=False)
    else:
        monkeypatch.setenv("DASHBOARD_API_TOKEN", env_value)
    # Force re-import so the module-level os.environ.get() runs again.
    if "dashboard.api_client" in sys.modules:
        del sys.modules["dashboard.api_client"]
    return importlib.import_module("dashboard.api_client")


@pytest.fixture
def fake_streamlit():
    """Stub streamlit.st.session_state so api_client can read it without
    a running Streamlit server.
    """
    fake_st = MagicMock()
    fake_st.session_state = {}
    # Pre-install the streamlit module mock so the import in api_client
    # resolves to our stub.
    sys.modules["streamlit"] = fake_st
    yield fake_st
    # Don't pop — other tests in the suite import streamlit too.


class TestDashboardApiTokenFallback:
    def test_env_token_unset_means_no_fallback(self, monkeypatch, fake_streamlit):
        mod = _reload_api_client(monkeypatch, env_value=None)
        client = mod.ApiClient()
        # No session JWT, no env token -> no Authorization header
        assert "Authorization" not in client._headers
        assert client.has_service_auth() is False

    def test_empty_env_string_treated_as_unset(self, monkeypatch, fake_streamlit):
        mod = _reload_api_client(monkeypatch, env_value="")
        client = mod.ApiClient()
        assert "Authorization" not in client._headers
        assert client.has_service_auth() is False

    def test_whitespace_only_env_string_treated_as_unset(self, monkeypatch, fake_streamlit):
        mod = _reload_api_client(monkeypatch, env_value="   ")
        client = mod.ApiClient()
        assert "Authorization" not in client._headers
        assert client.has_service_auth() is False

    def test_env_token_used_when_no_session_jwt(self, monkeypatch, fake_streamlit):
        mod = _reload_api_client(monkeypatch, env_value="s2s-token-xyz")
        client = mod.ApiClient()
        headers = client._headers
        assert headers["Authorization"] == "Bearer s2s-token-xyz"
        assert client.has_service_auth() is True

    def test_session_jwt_takes_precedence_over_env_token(self, monkeypatch, fake_streamlit):
        mod = _reload_api_client(monkeypatch, env_value="s2s-token-xyz")
        # Simulate a logged-in user
        fake_streamlit.session_state["access_token"] = "user-jwt-abc"
        client = mod.ApiClient()
        headers = client._headers
        # User JWT wins; the env token is a fallback only.
        assert headers["Authorization"] == "Bearer user-jwt-abc"
