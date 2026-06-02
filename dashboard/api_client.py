"""
Synchronous API client for the SecurityScarletAI dashboard.

ALL dashboard code must use this client — NO direct database access.
This module handles auth, retries, error handling, and response formatting.

M-04 note: This client uses synchronous httpx (not async) because Streamlit
doesn't support async natively. Every API call blocks the Streamlit thread.
This is acceptable for single-user dashboards but may cause sluggishness
under concurrent access (>50 simultaneous users). For v2, consider
st.connection or an async bridge.

Usage in Streamlit views:
    from dashboard.api_client import ApiClient
    api = ApiClient()
    alerts = api.get_alerts(status="new", limit=50)
"""
import os
import re
from typing import Any
from urllib.parse import quote

import httpx
import streamlit as st

# ───────────────────────────────────────────────────────────────
# Configuration — from environment / .env
# ───────────────────────────────────────────────────────────────

API_BASE_URL = os.environ.get("SCARLET_API_URL", "http://localhost:8000/api/v1")
REQUEST_TIMEOUT = 15.0  # seconds (default)
AI_TIMEOUT = 60.0  # seconds (AI chat/explain/hunt — longer for LLM inference)

# Epic 10: static service-to-service auth token for the dashboard
# container. Used as a fallback bearer when no user JWT is in the
# session state (e.g. headless / docker dashboard, scheduled refresh,
# automated screenshot capture). If unset, dashboard behaves as before
# and requires a manual JWT login.
# Set this in docker-compose.yml (dashboard env block) or in .env.
DASHBOARD_API_TOKEN: str | None = os.environ.get("DASHBOARD_API_TOKEN") or None
if DASHBOARD_API_TOKEN is not None and not DASHBOARD_API_TOKEN.strip():
    DASHBOARD_API_TOKEN = None  # treat empty string as unset


class ApiError(Exception):
    """Raised when the API returns a non-200 response."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")


class ApiClient:
    """
    Synchronous HTTP client for the SecurityScarletAI API.

    Handles authentication, error formatting, and response parsing.
    All methods return parsed JSON or raise ApiError on failure.
    """

    def __init__(self, base_url: str | None = None):
        self.base_url = base_url or API_BASE_URL

    @property
    def _headers(self) -> dict[str, str]:
        """Build auth headers.

        Priority:
          1. Session JWT (interactive login) — used by all views.
          2. DASHBOARD_API_TOKEN (env) — used when no JWT is in the
             session (headless / docker dashboard, scheduled refresh).
        The API's unified auth dependency accepts either, so a
        bearer-from-env works as service-to-service auth.
        """
        headers = {"Content-Type": "application/json"}
        token = st.session_state.get("access_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif DASHBOARD_API_TOKEN:
            headers["Authorization"] = f"Bearer {DASHBOARD_API_TOKEN}"
        return headers

    def has_service_auth(self) -> bool:
        """True if the dashboard is configured with a DASHBOARD_API_TOKEN
        and can make API calls without a user login. Useful for the
        login page to skip rendering when running headless in docker.
        """
        return bool(DASHBOARD_API_TOKEN)

    # ───────────────────────────────────────────────────────────
    # Core HTTP methods
    # ───────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> Any:
        """GET request with error handling."""
        try:
            r = httpx.get(
                f"{self.base_url}{path}",
                headers=self._headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            return self._handle_response(r)
        except httpx.ConnectError:
            raise ApiError(0, "Cannot connect to API server. Is it running?")
        except httpx.TimeoutException:
            raise ApiError(0, "API request timed out")

    def _post(self, path: str, json_data: dict | None = None, timeout: float | None = None) -> Any:
        """POST request with error handling. timeout overrides default."""
        try:
            r = httpx.post(
                f"{self.base_url}{path}",
                headers=self._headers,
                json=json_data,
                timeout=timeout or REQUEST_TIMEOUT,
            )
            return self._handle_response(r)
        except httpx.ConnectError:
            raise ApiError(0, "Cannot connect to API server. Is it running?")
        except httpx.TimeoutException:
            raise ApiError(0, "API request timed out")

    def _put(self, path: str, json_data: dict | None = None) -> Any:
        """PUT request with error handling."""
        try:
            r = httpx.put(
                f"{self.base_url}{path}",
                headers=self._headers,
                json=json_data,
                timeout=REQUEST_TIMEOUT,
            )
            return self._handle_response(r)
        except httpx.ConnectError:
            raise ApiError(0, "Cannot connect to API server. Is it running?")
        except httpx.TimeoutException:
            raise ApiError(0, "API request timed out")

    def _patch(self, path: str, json_data: dict | None = None) -> Any:
        """PATCH request with error handling."""
        try:
            r = httpx.patch(
                f"{self.base_url}{path}",
                headers=self._headers,
                json=json_data,
                timeout=REQUEST_TIMEOUT,
            )
            return self._handle_response(r)
        except httpx.ConnectError:
            raise ApiError(0, "Cannot connect to API server. Is it running?")
        except httpx.TimeoutException:
            raise ApiError(0, "API request timed out")

    def _delete(self, path: str) -> Any:
        """DELETE request with error handling."""
        try:
            r = httpx.delete(
                f"{self.base_url}{path}",
                headers=self._headers,
                timeout=REQUEST_TIMEOUT,
            )
            return self._handle_response(r)
        except httpx.ConnectError:
            raise ApiError(0, "Cannot connect to API server. Is it running?")
        except httpx.TimeoutException:
            raise ApiError(0, "API request timed out")

    @staticmethod
    def _handle_response(r: httpx.Response) -> Any:
        """Parse response or raise ApiError."""
        if r.status_code in (200, 201):
            if r.content:
                return r.json()
            return None
        if r.status_code == 204:
            return None
        if r.status_code == 401:
            raise ApiError(401, "Session expired. Please log in again.")
        if r.status_code == 403:
            raise ApiError(403, "Insufficient permissions for this action.")
        # Try to get detail from response
        try:
            detail = r.json().get("detail", r.text[:200])
        except Exception:
            detail = r.text[:200]
        raise ApiError(r.status_code, detail)

    # ───────────────────────────────────────────────────────────
    # Auth endpoints
    # ───────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> dict:
        """Authenticate and store JWT in session state."""
        data = self._post("/auth/login", {"username": username, "password": password})
        if data:
            st.session_state.access_token = data["access_token"]
            st.session_state.username = data["username"]
            st.session_state.role = data["role"]
        return data

    def get_me(self) -> dict:
        """Get current user info."""
        return self._get("/auth/me")

    @staticmethod
    def is_authenticated() -> bool:
        """Check if user is authenticated in session state."""
        return bool(st.session_state.get("access_token"))

    @staticmethod
    def logout():
        """Clear session state — L-09 fix: clear all auth-related keys."""
        for key in list(st.session_state.keys()):
            if key in ("access_token", "username", "role", "authenticated",
                       "user_verified", "last_role_verify", "api_client"):
                st.session_state.pop(key, None)

    # ───────────────────────────────────────────────────────────
    # Health
    # ───────────────────────────────────────────────────────────

    def health(self) -> dict:
        """Check API health."""
        return self._get("/health")

    # L-03 fix: Public method instead of calling _post directly
    def seed_admin(self) -> dict:
        """Seed initial admin user (requires admin auth)."""
        return self._post("/auth/seed-admin")

    # ───────────────────────────────────────────────────────────
    # Alerts
    # ───────────────────────────────────────────────────────────

    def get_alerts(self, status: str | None = None, severity: str | None = None,
                   limit: int = 100, offset: int = 0) -> list[dict]:
        """Fetch alerts with optional filtering."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        return self._get("/alerts", params) or []

    def get_alert(self, alert_id: int) -> dict:
        """Fetch a single alert by ID."""
        return self._get(f"/alerts/{alert_id}")

    def update_alert(self, alert_id: int, status: str | None = None,
                     assigned_to: str | None = None, resolution_note: str | None = None) -> dict:
        """Update alert status, assignment, or add resolution note."""
        data: dict[str, Any] = {}
        if status:
            data["status"] = status
        if assigned_to:
            data["assigned_to"] = assigned_to
        if resolution_note:
            data["resolution_note"] = resolution_note
        return self._patch(f"/alerts/{alert_id}", data)

    def get_alert_stats(self, hours: int | None = None) -> dict:
        """Fetch alert statistics (severity counts, status counts, etc.).

        If hours is None, returns stats for ALL alerts (no time filter).
        If hours is provided, filters to the last N hours.
        """
        params = {}
        if hours is not None:
            params["hours"] = hours
        return self._get("/alerts/stats", params) or {}

    def add_alert_note(self, alert_id: int, text: str) -> dict:
        """Add a note/timeline entry to an alert."""
        return self._post(f"/alerts/{alert_id}/notes", {"text": text})

    def get_alert_notes(self, alert_id: int) -> list[dict]:
        """Get notes for an alert."""
        return self._get(f"/alerts/{alert_id}/notes") or []

    # ───────────────────────────────────────────────────────────
    # Bulk alert operations
    # ───────────────────────────────────────────────────────────

    def bulk_acknowledge(self, alert_ids: list[int]) -> dict:
        """Acknowledge multiple alerts."""
        return self._post("/alerts/bulk/acknowledge", {"alert_ids": alert_ids})

    def bulk_resolve(self, alert_ids: list[int]) -> dict:
        """Resolve multiple alerts."""
        return self._post("/alerts/bulk/resolve", {"alert_ids": alert_ids})

    def bulk_false_positive(self, alert_ids: list[int]) -> dict:
        """Mark multiple alerts as false positive."""
        return self._post("/alerts/bulk/false-positive", {"alert_ids": alert_ids})

    def bulk_assign(self, alert_ids: list[int], assigned_to: str) -> dict:
        """Assign multiple alerts to a user."""
        return self._post("/alerts/bulk/assign", {"alert_ids": alert_ids, "assigned_to": assigned_to})  # noqa: E501

    # ───────────────────────────────────────────────────────────
    # Alert export
    # ───────────────────────────────────────────────────────────

    def export_alerts_csv(self, status: str | None = None, severity: str | None = None) -> str:
        """Export alerts as CSV."""
        params: dict[str, Any] = {}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        try:
            r = httpx.get(
                f"{self.base_url}/alerts/export/csv",
                headers=self._headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            r.raise_for_status()
            return r.text
        except httpx.ConnectError:
            raise ApiError(0, "Cannot connect to API server.")

    # ───────────────────────────────────────────────────────────
    # Rules
    # ───────────────────────────────────────────────────────────

    def get_rules(self) -> list[dict]:
        """Fetch all detection rules."""
        return self._get("/rules") or []

    def get_rule(self, rule_id: int) -> dict:
        """Fetch a single rule by ID."""
        return self._get(f"/rules/{rule_id}")

    def create_rule(self, rule_data: dict) -> dict:
        """Create a new detection rule."""
        return self._post("/rules", rule_data)

    def update_rule(self, rule_id: int, rule_data: dict) -> dict:
        """Update a detection rule."""
        return self._put(f"/rules/{rule_id}", rule_data)

    def delete_rule(self, rule_id: int) -> None:
        """Delete a detection rule."""
        self._delete(f"/rules/{rule_id}")

    # ───────────────────────────────────────────────────────────
    # Logs
    # ───────────────────────────────────────────────────────────

    def get_logs(self, limit: int = 100, category: str | None = None,
                 host: str | None = None, time_minutes: int | None = None) -> list[dict]:
        """Fetch recent logs with optional filtering."""
        params: dict[str, Any] = {"limit": limit}
        if category:
            params["category"] = category
        if host:
            params["host"] = host
        if time_minutes:
            params["time_minutes"] = time_minutes
        return self._get("/logs", params) or []

    # ───────────────────────────────────────────────────────────
    # Correlation
    # ───────────────────────────────────────────────────────────

    def get_correlation_rules(self) -> list[dict]:
        """Fetch correlation rules."""
        return self._get("/correlation/rules") or []

    def run_correlation(self, rule_name: str = "") -> dict:
        """Run correlation rules."""
        if rule_name:
            return self._post(f"/correlation/run/{rule_name}") or {}
        return self._post("/correlation/run") or {}

    # ───────────────────────────────────────────────────────────
    # Threat Intel
    # ───────────────────────────────────────────────────────────

    def get_threat_intel_stats(self) -> dict:
        """Get threat intel statistics."""
        return self._get("/threat-intel/stats") or {}

    def lookup_ip(self, ip: str) -> dict:
        """Look up an IP in threat intel feeds."""
        # Validate IP format to prevent path traversal
        if not re.match(r'^[0-9]{1,3}(\.[0-9]{1,3}){3}$', ip):
            raise ApiError(400, f"Invalid IP address format: {ip}")
        return self._get(f"/threat-intel/lookup/ip/{quote(ip, safe='')}") or {}

    def refresh_threat_intel(self) -> dict:
        """Trigger threat intel feed refresh."""
        return self._post("/threat-intel/refresh") or {}

    # ───────────────────────────────────────────────────────────
    # AI endpoints
    # ───────────────────────────────────────────────────────────

    def ai_train(self, min_samples: int = 50) -> dict:
        """Trigger AI model training."""
        return self._post("/ai/train", {"min_samples": min_samples})

    def ai_status(self) -> dict:
        """Get AI model status."""
        return self._get("/ai/status") or {}

    def ai_triage(self, alert_id: int) -> dict:
        """Get AI triage prediction for an alert."""
        return self._post(f"/ai/triage/{alert_id}", timeout=AI_TIMEOUT) or {}

    def ai_ueba(self, username: str) -> dict:
        """Get UEBA anomaly score for a user."""
        return self._get(f"/ai/ueba/{username}") or {}

    def ai_explain(self, alert_id: int) -> dict:
        """Generate AI explanation for an alert."""
        return self._post(f"/ai/explain/{alert_id}", timeout=AI_TIMEOUT) or {}

    # ───────────────────────────────────────────────────────────
    # AI Chat
    # ───────────────────────────────────────────────────────────

    def ai_chat(self, message: str) -> dict:
        """Send a message to the AI chat."""
        return self._post("/ai/chat", {"message": message}, timeout=AI_TIMEOUT) or {}

    # ───────────────────────────────────────────────────────────
    # NL→SQL Query
    # ───────────────────────────────────────────────────────────

    def query(self, question: str) -> dict:
        """Convert a natural language question to SQL and execute."""
        return self._post("/query", {"question": question}, timeout=AI_TIMEOUT) or {}

    def get_query_templates(self) -> list[dict]:
        """Get available NL→SQL query templates."""
        return self._get("/query/templates") or []

    # ───────────────────────────────────────────────────────────
    # Hunt templates
    # ───────────────────────────────────────────────────────────

    def get_hunt_templates(self) -> list[dict]:
        """Get available hunt templates."""
        return self._get("/hunt/templates") or []

    def execute_hunt(self, hunt_id: str) -> dict:
        """Execute a hunt template."""
        return self._post(f"/hunt/{hunt_id}/execute", timeout=AI_TIMEOUT) or {}

    def get_mitre_gaps(self) -> dict:
        """Get MITRE ATT&CK gap analysis."""
        return self._get("/hunt/gaps") or {}

    def hunt_from_alert(self, alert_id: int) -> dict:
        """Suggest hunts from an alert."""
        return self._post(f"/hunt/from-alert/{alert_id}") or {}

    # ───────────────────────────────────────────────────────────
    # Audit log
    # ───────────────────────────────────────────────────────────

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        """Get audit log entries."""
        return self._get("/audit", {"limit": limit}) or []

    # ───────────────────────────────────────────────────────────
    # Cases
    # ───────────────────────────────────────────────────────────

    def get_cases(self, status: str | None = None, severity: str | None = None,
                  limit: int = 100, offset: int = 0) -> list[dict]:
        """Fetch cases with optional filtering."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status_filter"] = status
        if severity:
            params["severity"] = severity
        return self._get("/cases", params) or []

    def get_case(self, case_id: int) -> dict:
        """Fetch a single case by ID, including linked alerts."""
        return self._get(f"/cases/{case_id}")

    def create_case(self, title: str, description: str = "", severity: str = "medium",
                    alert_ids: list[int] | None = None, assigned_to: str | None = None) -> dict:
        """Create a new case."""
        data: dict[str, Any] = {"title": title, "description": description, "severity": severity}
        if alert_ids:
            data["alert_ids"] = alert_ids
        if assigned_to:
            data["assigned_to"] = assigned_to
        return self._post("/cases", data)

    def update_case(self, case_id: int, **kwargs) -> dict:
        """Update case fields via PATCH."""
        return self._patch(f"/cases/{case_id}", kwargs)

    def delete_case(self, case_id: int) -> None:
        """Soft-delete a case (set status to closed)."""
        self._delete(f"/cases/{case_id}")

    def link_alert_to_case(self, case_id: int, alert_id: int) -> dict:
        """Link an alert to a case."""
        return self._post(f"/cases/{case_id}/alerts", {"alert_id": alert_id})

    def unlink_alert_from_case(self, case_id: int, alert_id: int) -> dict:
        """Unlink an alert from a case."""
        return self._delete(f"/cases/{case_id}/alerts/{alert_id}")

    def add_case_note(self, case_id: int, text: str) -> dict:
        """Add a note to a case."""
        return self._post(f"/cases/{case_id}/notes", {"text": text})

    def get_case_notes(self, case_id: int) -> list[dict]:
        """Get all notes for a case."""
        return self._get(f"/cases/{case_id}/notes") or []

    # ───────────────────────────────────────────────────────────
    # Cases (via alerts API case endpoint)
    # ───────────────────────────────────────────────────────────

    def create_case_from_alert(self, alert_id: int, title: str = "", description: str = "") -> dict:
        """Create a case from an alert via the alerts API."""
        data: dict[str, str] = {}
        if title:
            data["title"] = title
        if description:
            data["description"] = description
        return self._post(f"/alerts/{alert_id}/case", data) or {}
