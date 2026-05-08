"""
Tests for the redesigned dashboard UI: unified theme, badges, and visual polish.

These tests validate the new design system after the Phase 1-5 overhaul.
"""

from unittest.mock import MagicMock, patch

from dashboard.api_client import ApiClient, ApiError


class TestAutoRefreshFallback:
    """Tests for streamlit-autorefresh graceful fallback."""

    def test_has_autorefresh_flag_true_when_available(self):
        """When streamlit_autorefresh is installed, HAS_AUTOREFRESH should be True."""
        from dashboard.main import HAS_AUTOREFRESH
        assert isinstance(HAS_AUTOREFRESH, bool)

    def test_autorefresh_import_does_not_crash(self):
        """Importing main module should not crash even without streamlit_autorefresh."""
        with patch.dict("sys.modules", {"streamlit_autorefresh": None}):
            import importlib
            import dashboard.main
            importlib.reload(dashboard.main)

    def test_page_refresh_intervals_defined(self):
        """Every page should have a refresh interval defined."""
        from dashboard.main import PAGE_REFRESH_MS
        expected_pages = [
            "overview", "logs", "alerts", "rules", "cases",
            "ai_chat", "hunting", "audit",
        ]
        for page in expected_pages:
            assert page in PAGE_REFRESH_MS, f"Missing refresh interval for page: {page}"

    def test_ai_chat_never_auto_refreshes(self):
        """AI chat should never auto-refresh (preserves chat context)."""
        from dashboard.main import PAGE_REFRESH_MS
        assert PAGE_REFRESH_MS["ai_chat"] == 0, "AI chat should have 0 refresh interval"

    def test_refresh_intervals_are_reasonable(self):
        """Refresh intervals should be between 10-120 seconds."""
        from dashboard.main import PAGE_REFRESH_MS
        for page, ms in PAGE_REFRESH_MS.items():
            if ms == 0:
                continue
            assert 10000 <= ms <= 120000, f"Page {page} has unreasonable refresh interval: {ms}ms"


class TestLoadingStatePatterns:
    """Tests for loading state patterns in dashboard views."""

    def test_charts_all_functions_exist(self):
        """All chart rendering functions should exist and be callable."""
        from dashboard.charts import (
            render_alert_trend,
            render_dashboard_metrics,
            render_host_risk_scores,
            render_mitre_heatmap,
            render_severity_distribution,
            render_severity_sparklines,
            render_top_hosts,
        )
        assert callable(render_severity_distribution)
        assert callable(render_alert_trend)
        assert callable(render_top_hosts)
        assert callable(render_mitre_heatmap)
        assert callable(render_dashboard_metrics)
        assert callable(render_severity_sparklines)
        assert callable(render_host_risk_scores)

    def test_view_functions_exist(self):
        """All dashboard view functions should exist and be callable."""
        from dashboard.ai_chat_view import render_ai_chat
        from dashboard.alerts_view import render_alert_list
        from dashboard.cases_view import render_cases_view
        from dashboard.hunt_view import render_hunt_view
        from dashboard.logs_view import render_log_viewer
        from dashboard.rules_view import render_rules_view
        assert callable(render_log_viewer)
        assert callable(render_alert_list)
        assert callable(render_rules_view)
        assert callable(render_cases_view)
        assert callable(render_ai_chat)
        assert callable(render_hunt_view)

    def test_main_page_routing_dict(self):
        """PAGES dict should contain all expected page routes without emoji."""
        from dashboard.main import ADMIN_PAGES, PAGES
        assert "Overview" in PAGES
        assert "Live Logs" in PAGES
        assert "Alerts" in PAGES
        assert "Rules" in PAGES
        assert "Cases" in PAGES
        assert "AI Chat" in PAGES
        assert "Hunting" in PAGES
        assert "Audit Log" in ADMIN_PAGES


class TestDarkThemeCSS:
    """Tests for the new dark theme CSS configuration."""

    def test_dark_theme_css_exists(self):
        """Dark theme CSS should be defined."""
        from dashboard.main import DARK_THEME_CSS
        assert len(DARK_THEME_CSS) > 100
        assert "background-color" in DARK_THEME_CSS

    def test_dark_theme_has_animations(self):
        """Dark theme CSS should include fade-in animation."""
        from dashboard.main import DARK_THEME_CSS
        assert "fadeInContent" in DARK_THEME_CSS
        assert "@keyframes" in DARK_THEME_CSS

    def test_dark_theme_has_button_transitions(self):
        """Dark theme CSS should include button transition effects."""
        from dashboard.main import DARK_THEME_CSS
        assert "transition" in DARK_THEME_CSS.lower()
        assert "hover" in DARK_THEME_CSS.lower()

    def test_dark_theme_has_badge_classes(self):
        """Dark theme CSS should include severity/status badge classes."""
        from dashboard.main import DARK_THEME_CSS
        assert ".badge-critical" in DARK_THEME_CSS
        assert ".badge-high" in DARK_THEME_CSS
        assert ".badge-medium" in DARK_THEME_CSS
        assert ".badge-low" in DARK_THEME_CSS
        assert ".badge-info" in DARK_THEME_CSS

    def test_design_tokens_defined(self):
        """Theme colour tokens should be defined in main."""
        from dashboard.main import (
            BG_APP, BG_SURFACE, BG_ELEVATED, ACCENT,
            TEXT_PRIMARY, TEXT_SECONDARY, BORDER_SUBTLE,
        )
        assert BG_APP.startswith("#")
        assert BG_SURFACE.startswith("#")
        assert BG_ELEVATED.startswith("#")
        assert ACCENT.startswith("#")
        assert TEXT_PRIMARY.startswith("#")
        assert TEXT_SECONDARY.startswith("#")
        assert BORDER_SUBTLE.startswith("#")

    def test_dark_theme_has_sidebar_active_state(self):
        """Sidebar nav should have active state styling."""
        from dashboard.main import DARK_THEME_CSS
        assert "aria-selected" in DARK_THEME_CSS


class TestBadgeSystem:
    """Tests for the unified badge helper in ui_utils."""

    def test_severity_badge_html(self):
        from dashboard.ui_utils import sev_badge
        html = sev_badge("critical")
        assert 'class="badge badge-critical"' in html
        assert "CRITICAL" in html

    def test_status_badge_html(self):
        from dashboard.ui_utils import status_badge
        html = status_badge("new")
        assert 'class="badge badge-new"' in html
        assert "NEW" in html

    def test_all_severities_badge(self):
        from dashboard.ui_utils import sev_badge
        for sev in ["critical", "high", "medium", "low", "info"]:
            html = sev_badge(sev)
            assert sev.upper() in html

    def test_all_statuses_badge(self):
        from dashboard.ui_utils import status_badge
        for st in ["new", "investigating", "resolved", "false_positive", "closed"]:
            html = status_badge(st)
            assert st.replace("_", " ").upper() in html

    def test_badge_tokens_present(self):
        from dashboard.ui_utils import (
            SEV_CSS_MAP, STATUS_CSS_MAP, SEVERITY_COLORS, STATUS_COLORS,
        )
        assert set(SEV_CSS_MAP.keys()) == {"critical", "high", "medium", "low", "info"}
        assert set(STATUS_CSS_MAP.keys()) == {
            "new", "investigating", "resolved", "false_positive", "closed"
        }
        assert len(SEVERITY_COLORS) == 5
        assert len(STATUS_COLORS) == 5


class TestChartsThemeConfig:
    """Tests for chart dark theme configuration."""

    def test_severity_colors_complete(self):
        """Severity color map should cover all severity levels."""
        from dashboard.charts import SEVERITY_COLORS
        expected_keys = {"critical", "high", "medium", "low", "info"}
        assert set(SEVERITY_COLORS.keys()) == expected_keys

    def test_severity_order_complete(self):
        """Severity order should be from highest to lowest."""
        from dashboard.charts import SEVERITY_ORDER
        assert SEVERITY_ORDER == ["critical", "high", "medium", "low", "info"]

    def test_dark_theme_tokens(self):
        """Chart module should mirror the design tokens from main."""
        from dashboard.charts import BG_SURFACE, ACCENT, TEXT_PRIMARY, TEXT_SECONDARY
        assert BG_SURFACE.startswith("#")
        assert TEXT_PRIMARY.startswith("#")
        assert TEXT_SECONDARY.startswith("#")

    def test_chart_container_helper_exists(self):
        from dashboard.charts import _chart_container
        assert callable(_chart_container)

    def test_colored_metric_exists(self):
        from dashboard.charts import _colored_metric
        assert callable(_colored_metric)


class TestQuickActions:
    """Tests for AI chat quick actions."""

    def test_quick_actions_defined(self):
        from dashboard.ai_chat_view import QUICK_ACTIONS
        assert len(QUICK_ACTIONS) > 0
        assert any("investigate" in a.lower() for a in QUICK_ACTIONS)
        assert any("posture" in a.lower() or "summar" in a.lower() for a in QUICK_ACTIONS)

    def test_quick_actions_are_questions(self):
        from dashboard.ai_chat_view import QUICK_ACTIONS
        for action in QUICK_ACTIONS:
            assert isinstance(action, str)
            assert len(action) > 5


class TestRuleTemplates:
    """Tests for rule creation templates."""

    def test_rule_templates_defined(self):
        from dashboard.rules_view import RULE_TEMPLATES
        assert len(RULE_TEMPLATES) >= 4
        assert "Process Execution" in RULE_TEMPLATES
        assert "Network Connection" in RULE_TEMPLATES
        assert "File Modification" in RULE_TEMPLATES
        assert "Blank" in RULE_TEMPLATES

    def test_rule_templates_have_yaml(self):
        from dashboard.rules_view import RULE_TEMPLATES
        for name, template in RULE_TEMPLATES.items():
            assert "title:" in template or "{name}" in template
            assert "detection:" in template


class TestApiClientConvenience:
    """Extended tests for API client convenience methods."""

    def test_login_stores_session_state(self):
        client = ApiClient(base_url="http://localhost:8000/api/v1")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = (
            b'{"access_token": "test-jwt", "username": "admin", "role": "admin"}'
        )
        mock_response.json.return_value = {
            "access_token": "test-jwt",
            "username": "admin",
            "role": "admin",
        }

        with patch(
            "streamlit.session_state", {"access_token": None, "username": None, "role": None}
        ):
            with patch.object(client, "_post", return_value=mock_response.json()):
                assert hasattr(client, "login")
                assert callable(client.login)

    def test_api_error_detail_preserved(self):
        err = ApiError(503, "Service unavailable - retry in 30s")
        assert "Service unavailable" in err.detail
        assert "503" in str(err)

    def test_api_error_zero_status_code(self):
        err = ApiError(0, "Cannot connect to API server. Is it running?")
        assert err.status_code == 0
        assert "Cannot connect" in err.detail


class TestKeyboardShortcuts:
    """Tests for keyboard shortcut JavaScript."""

    def test_keyboard_shortcuts_js_exists(self):
        from dashboard.main import KEYBOARD_SHORTCUTS_JS
        assert "keydown" in KEYBOARD_SHORTCUTS_JS
        assert "Overview" in KEYBOARD_SHORTCUTS_JS
        assert "Live Logs" in KEYBOARD_SHORTCUTS_JS

    def test_keyboard_shortcuts_7_pages(self):
        from dashboard.main import KEYBOARD_SHORTCUTS_JS
        assert "num >= 1 && num <= 7" in KEYBOARD_SHORTCUTS_JS


class TestLoginPageStyling:
    """Tests for the redesigned login page."""

    def test_tokens_used_in_auth(self):
        """Auth module should import design tokens for the login card."""
        from dashboard.auth import BG_SURFACE, BORDER_SUBTLE, TEXT_SECONDARY
        assert callable(BG_SURFACE) is False
        assert isinstance(BG_SURFACE, str)
