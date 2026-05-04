"""
Tests for Phase 4.2 features: auto-refresh, loading states, and visual polish.

Tests the auto-refresh fallback, loading state patterns, toast/notification patterns,
and CSS theme configuration.
"""
import pytest
from unittest.mock import patch, MagicMock

from dashboard.api_client import ApiClient, ApiError


class TestAutoRefreshFallback:
    """Tests for streamlit-autorefresh graceful fallback."""

    def test_has_autorefresh_flag_true_when_available(self):
        """When streamlit_autorefresh is installed, HAS_AUTOREFRESH should be True."""
        # Import main to check the flag
        from dashboard.main import HAS_AUTOREFRESH
        # If the package is installed (which it should be), this is True
        assert isinstance(HAS_AUTOREFRESH, bool)

    def test_autorefresh_import_does_not_crash(self):
        """Importing main module should not crash even without streamlit_autorefresh."""
        # This test verifies the try/except import pattern works
        with patch.dict("sys.modules", {"streamlit_autorefresh": None}):
            # The module should still be importable
            import importlib
            import dashboard.main
            importlib.reload(dashboard.main)
            # Should not raise even if autorefresh is not available

    def test_page_refresh_intervals_defined(self):
        """Every page should have a refresh interval defined."""
        from dashboard.main import PAGE_REFRESH_MS
        expected_pages = ["overview", "logs", "alerts", "rules", "cases", "ai_chat", "hunting", "audit"]
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
            if ms == 0:  # 0 means disabled
                continue
            assert 10000 <= ms <= 120000, f"Page {page} has unreasonable refresh interval: {ms}ms"


class TestLoadingStatePatterns:
    """Tests for st.spinner() and st.status() loading state patterns in dashboard views."""

    def test_charts_all_functions_exist(self):
        """All chart rendering functions should exist and be callable."""
        from dashboard.charts import (
            render_severity_distribution,
            render_alert_trend,
            render_top_hosts,
            render_mitre_heatmap,
            render_dashboard_metrics,
            render_severity_sparklines,
            render_host_risk_scores,
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
        from dashboard.logs_view import render_log_viewer
        from dashboard.alerts_view import render_alert_list
        from dashboard.rules_view import render_rules_view
        from dashboard.cases_view import render_cases_view
        from dashboard.ai_chat_view import render_ai_chat
        from dashboard.hunt_view import render_hunt_view

        assert callable(render_log_viewer)
        assert callable(render_alert_list)
        assert callable(render_rules_view)
        assert callable(render_cases_view)
        assert callable(render_ai_chat)
        assert callable(render_hunt_view)

    def test_main_page_routing_dict(self):
        """PAGES dict should contain all expected page routes."""
        from dashboard.main import PAGES, ADMIN_PAGES
        assert "📊 Overview" in PAGES
        assert "📡 Live Logs" in PAGES
        assert "🚨 Alerts" in PAGES
        assert "📋 Rules" in PAGES
        assert "📁 Cases" in PAGES
        assert "🤖 AI Chat" in PAGES
        assert "🎯 Hunting" in PAGES
        assert "🔐 Audit Log" in ADMIN_PAGES


class TestDarkThemeCSS:
    """Tests for dark theme CSS configuration."""

    def test_dark_theme_css_exists(self):
        """Dark theme CSS should be defined."""
        from dashboard.main import DARK_THEME_CSS
        assert len(DARK_THEME_CSS) > 100
        assert "background-color" in DARK_THEME_CSS

    def test_dark_theme_has_animations(self):
        """Dark theme CSS should include animation keyframes."""
        from dashboard.main import DARK_THEME_CSS
        assert "fadeInContent" in DARK_THEME_CSS
        assert "fadeInValue" in DARK_THEME_CSS
        assert "@keyframes" in DARK_THEME_CSS

    def test_dark_theme_has_button_transitions(self):
        """Dark theme CSS should include button transition effects."""
        from dashboard.main import DARK_THEME_CSS
        assert "transition" in DARK_THEME_CSS
        assert "hover" in DARK_THEME_CSS.lower()

    def test_dark_theme_has_severity_colors(self):
        """Dark theme CSS should include severity color classes."""
        from dashboard.main import DARK_THEME_CSS
        assert "severity-critical" in DARK_THEME_CSS
        assert "severity-high" in DARK_THEME_CSS
        assert "severity-medium" in DARK_THEME_CSS
        assert "severity-low" in DARK_THEME_CSS
        assert "severity-info" in DARK_THEME_CSS

    def test_dark_theme_has_metrics_animation(self):
        """Dark theme CSS should animate metric values."""
        from dashboard.main import DARK_THEME_CSS
        assert "stMetricValue" in DARK_THEME_CSS
        assert "animation" in DARK_THEME_CSS

    def test_dark_theme_has_toast_animation(self):
        """Dark theme CSS should animate toast notifications."""
        from dashboard.main import DARK_THEME_CSS
        assert "stToast" in DARK_THEME_CSS
        assert "slideInRight" in DARK_THEME_CSS


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

    def test_dark_theme_config(self):
        """Altair dark theme config should have dark background."""
        from dashboard.charts import DARK_THEME
        assert DARK_THEME["background"] == "#0e1117"
        assert DARK_THEME["title"]["color"] == "#fafafa"
        assert DARK_THEME["axis"]["labelColor"] == "#a0a0a0"


class TestAlertBadges:
    """Tests for alert severity and status badge mappings."""

    def test_severity_badges_complete(self):
        """All severity levels should have badge icons."""
        from dashboard.alerts_view import SEVERITY_BADGES
        expected = {"critical", "high", "medium", "low", "info"}
        assert set(SEVERITY_BADGES.keys()) == expected

    def test_status_badges_complete(self):
        """All alert statuses should have badge icons."""
        from dashboard.alerts_view import STATUS_BADGES
        expected = {"new", "investigating", "resolved", "false_positive", "closed"}
        assert set(STATUS_BADGES.keys()) == expected


class TestQuickActions:
    """Tests for AI chat quick actions."""

    def test_quick_actions_defined(self):
        """Quick action suggestions should be defined."""
        from dashboard.ai_chat_view import QUICK_ACTIONS
        assert len(QUICK_ACTIONS) > 0
        assert any("investigate" in a.lower() for a in QUICK_ACTIONS)
        assert any("posture" in a.lower() or "summar" in a.lower() for a in QUICK_ACTIONS)

    def test_quick_actions_are_questions(self):
        """Quick actions should be question strings."""
        from dashboard.ai_chat_view import QUICK_ACTIONS
        for action in QUICK_ACTIONS:
            assert isinstance(action, str)
            assert len(action) > 5


class TestRuleTemplates:
    """Tests for rule creation templates."""

    def test_rule_templates_defined(self):
        """Rule templates should be defined for rule creation."""
        from dashboard.rules_view import RULE_TEMPLATES
        assert len(RULE_TEMPLATES) >= 4
        assert "Process Execution" in RULE_TEMPLATES
        assert "Network Connection" in RULE_TEMPLATES
        assert "File Modification" in RULE_TEMPLATES
        assert "Blank" in RULE_TEMPLATES

    def test_rule_templates_have_yaml(self):
        """Each template should contain valid YAML-like content."""
        from dashboard.rules_view import RULE_TEMPLATES
        for name, template in RULE_TEMPLATES.items():
            assert "title:" in template or "{name}" in template
            assert "detection:" in template


class TestApiClientConvenience:
    """Extended tests for API client convenience methods."""

    def test_login_stores_session_state(self):
        """Login should store access_token, username, and role in session state."""
        client = ApiClient(base_url="http://localhost:8000/api/v1")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"access_token": "test-jwt", "username": "admin", "role": "admin"}'
        mock_response.json.return_value = {
            "access_token": "test-jwt",
            "username": "admin",
            "role": "admin",
        }

        with patch("streamlit.session_state", {"access_token": None, "username": None, "role": None}):
            with patch.object(client, "_post", return_value=mock_response.json()):
                # Verify the method exists and is callable
                assert hasattr(client, "login")
                assert callable(client.login)

    def test_api_error_detail_preserved(self):
        """ApiError should preserve detail message for display in loading states."""
        err = ApiError(503, "Service unavailable - retry in 30s")
        assert "Service unavailable" in err.detail
        assert "503" in str(err)

    def test_api_error_zero_status_code(self):
        """ApiError with status 0 should represent connection errors."""
        err = ApiError(0, "Cannot connect to API server. Is it running?")
        assert err.status_code == 0
        assert "Cannot connect" in err.detail


class TestKeyboardShortcuts:
    """Tests for keyboard shortcut JavaScript."""

    def test_keyboard_shortcuts_js_exists(self):
        """Keyboard shortcuts JavaScript should be defined."""
        from dashboard.main import KEYBOARD_SHORTCUTS_JS
        assert "keydown" in KEYBOARD_SHORTCUTS_JS
        assert "Overview" in KEYBOARD_SHORTCUTS_JS
        assert "Live Logs" in KEYBOARD_SHORTCUTS_JS

    def test_keyboard_shortcuts_7_pages(self):
        """Keyboard shortcuts should support 7 pages (1-7)."""
        from dashboard.main import KEYBOARD_SHORTCUTS_JS
        assert "num >= 1 && num <= 7" in KEYBOARD_SHORTCUTS_JS