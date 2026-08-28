"""Esc-sweep trust-boundary tests (remediation Phase 1 — F-01/F-02/F-19).

Rule under test: EVERY value that originates from API/session data inside any
``st.markdown(..., unsafe_allow_html=True)`` passes through esc() — either at
the helper choke point (charts._colored_metric, ui_utils.badge,
ui_utils.colored_metric, cases_view._note_card_html) or at the interpolation
site. Streamlit renders Streamlit-internals, so these tests assert on the HTML
strings handed to st.markdown (the layer where execution would happen).

Order-robustness note: test_dashboard_api_token.py stubs sys.modules["streamlit"]
with a MagicMock and deliberately never restores it, and it re-imports
dashboard.api_client. Therefore every test here resolves the module under test
AT TEST TIME (inside the function) and patches that module's own ``st``
reference — never the globally-imported ``streamlit`` object. This keeps the
tests correct in any collection order, before or after the stub lands.
"""

from dashboard.cases_view import _note_card_html
from dashboard.ui_utils import badge, esc


class TestEscContract:
    """esc() neutralizes every HTML-executable construct."""

    def test_img_onerror(self):
        assert "<img" not in esc('<img src=x onerror=alert(1)>')
        assert "&lt;img" in esc('<img src=x onerror=alert(1)>')

    def test_script_tag(self):
        assert "<script>" not in esc("<script>alert(1)</script>")

    def test_event_handler_quotes(self):
        out = esc('"> <svg onload=alert(1)>')
        assert "<svg" not in out
        assert '"' not in out

    def test_none_and_plain(self):
        assert esc(None) == ""
        assert esc("12 crit / 9 high") == "12 crit / 9 high"


class TestBadgeEscapes:
    """badge() renders data-derived labels (severity/status from API) — the
    helper must escape at the choke point."""

    def test_hostile_label_inert(self):
        out = badge('<img src=x onerror=alert(1)>', "badge-new")
        assert "<img" not in out
        assert "&lt;img" in out
        assert out.startswith('<span class="badge badge-new">')

    def test_legit_label_unchanged(self):
        assert "CRITICAL" in badge("CRITICAL", "badge-critical")


class TestCaseNoteCardEscapes:
    """F-01: case-note author + text are analyst/ingest-controlled and were
    interpolated raw into an unsafe_allow_html block. _note_card_html is a
    pure seam — escaping is asserted without invoking Streamlit."""

    def test_hostile_note_is_inert(self):
        html = _note_card_html(
            '<img src=x onerror=alert(1)>',
            "<script>fetch('/steal?token='+document.cookie)</script>",
            "2026-08-28T17:00:00",
        )
        assert "<img" not in html
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "&lt;img" in html

    def test_plain_note_round_trips(self):
        html = _note_card_html("demo_analyst", "Investigating SSH brute-force.", "ts")
        assert "demo_analyst" in html
        assert "Investigating SSH brute-force." in html
        assert "&lt;" not in html


class TestColoredMetricEscapes:
    """F-02: charts._colored_metric receives host names from ingested events
    via render_host_risk_scores — escaping lives inside the helper."""

    @staticmethod
    def _capture(monkeypatch, module):
        """Patch the module-own ``st`` reference; return the capture list."""
        captured: list[str] = []
        monkeypatch.setattr(
            module.st, "markdown", lambda html, **kw: captured.append(html)
        )
        return captured

    def test_charts_colored_metric_escapes_label_and_value(self, monkeypatch):
        from dashboard import charts

        captured = self._capture(monkeypatch, charts)
        charts._colored_metric(
            '<img src=x onerror=alert(1)>', '<script>evil()</script>'
        )
        assert len(captured) == 1
        html = captured[0]
        assert "<img" not in html
        assert "<script>" not in html
        assert "&lt;img" in html
        assert "&lt;script&gt;" in html

    def test_charts_colored_metric_escapes_delta(self, monkeypatch):
        from dashboard import charts

        captured = self._capture(monkeypatch, charts)
        charts._colored_metric("Total", 35, delta="<b>craft</b>")
        assert captured and "<b>craft</b>" not in captured[0]
        assert "&lt;b&gt;" in captured[0]

    def test_charts_colored_metric_host_like_value(self, monkeypatch):
        """The actual F-02 path: a hostile host_name rendered as the label."""
        from dashboard import charts

        captured = self._capture(monkeypatch, charts)
        charts._colored_metric("evilhost</p><svg onload=alert(1)>", "62 · High")
        assert captured and "<svg" not in captured[0]

    def test_ui_utils_colored_metric_escapes(self, monkeypatch):
        # ui_utils.colored_metric imports streamlit at CALL time, so patch via
        # the sys.modules-resolved target (same object the call site sees).
        from dashboard import ui_utils

        captured: list[str] = []
        monkeypatch.setattr(
            "streamlit.markdown", lambda html, **kw: captured.append(html)
        )
        ui_utils.colored_metric('<img src=x onerror=alert(1)>', "<script>x</script>")
        assert captured and "<img" not in captured[0]
        assert "<script>" not in captured[0]


class TestLogoutBaseUrl:
    """F-19: logout must not silently pin the module-global API_BASE_URL.

    Logout is exercised through the LIVE dashboard.api_client module (test
    time identity), and session state is patched on that module's own ``st``
    reference — see the order-robustness note in the module docstring.
    """

    def test_class_call_uses_module_default(self, monkeypatch):
        posted: list[str] = []

        def fake_post(url, **kwargs):
            posted.append(url)

        monkeypatch.setattr("dashboard.api_client.httpx.post", fake_post)
        monkeypatch.setattr(
            "dashboard.api_client.st.session_state", {"access_token": "tok-123"}
        )
        import dashboard.api_client as live

        live.ApiClient.logout()
        assert posted == [f"{live.API_BASE_URL}/auth/logout"]

    def test_instance_call_uses_instance_base_url(self, monkeypatch):
        posted: list[str] = []

        def fake_post(url, **kwargs):
            posted.append(url)

        monkeypatch.setattr("dashboard.api_client.httpx.post", fake_post)
        monkeypatch.setattr(
            "dashboard.api_client.st.session_state", {"access_token": "tok-123"}
        )
        import dashboard.api_client as live

        client = live.ApiClient("http://custom.example:9999/api/v1")
        client.logout()
        assert posted == ["http://custom.example:9999/api/v1/auth/logout"]

    def test_logout_clears_session_state(self, monkeypatch):
        state = {
            "access_token": "tok-123",
            "username": "u",
            "role": "analyst",
            "authenticated": True,
            "keep_me": "unchanged",
        }
        import dashboard.api_client as live

        monkeypatch.setattr("dashboard.api_client.httpx.post", lambda *a, **k: None)
        monkeypatch.setattr("dashboard.api_client.st.session_state", state)
        live.ApiClient.logout()
        assert "access_token" not in state
        assert "username" not in state
        assert state["keep_me"] == "unchanged"

    def test_logout_never_raises_on_server_error(self, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("server down")

        import dashboard.api_client as live

        monkeypatch.setattr("dashboard.api_client.httpx.post", boom)
        monkeypatch.setattr(
            "dashboard.api_client.st.session_state", {"access_token": "tok-123"}
        )
        live.ApiClient.logout()  # must not raise
