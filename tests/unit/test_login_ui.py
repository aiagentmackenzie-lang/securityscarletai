"""
Tests for the login-page UI revamp (feat/login-ui-revamp).

Covers: brand logo SVG helper, auth-card CSS, the gated operator-setup
expander, the primary Sign In button, favicon assets, and the native dark
theme flags in the compose dashboard command.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

DASHBOARD_DIR = Path(__file__).parent.parent.parent / "dashboard"


class TestLogoSvg:
    """The inline SVG brand mark (no binary assets)."""

    def test_logo_svg_exists_and_is_svg(self):
        from dashboard.ui_utils import logo_svg

        svg = logo_svg(64, "t1")
        assert svg.startswith("<svg")
        assert svg.rstrip().endswith("</svg>")

    def test_logo_uses_size_parameter(self):
        from dashboard.ui_utils import logo_svg

        assert 'width="40"' in logo_svg(40, "t2")
        assert 'width="96"' in logo_svg(96, "t3")

    def test_logo_gradient_ids_are_prefixed(self):
        from dashboard.ui_utils import logo_svg

        svg = logo_svg(64, "abc")
        assert 'id="abc-shield"' in svg
        assert 'url(#abc-shield)' in svg
        # No un-prefixed id collisions across two renders
        svg_b = logo_svg(64, "xyz")
        assert 'id="xyz-shield"' in svg_b and 'id="abc-shield"' not in svg_b

    def test_logo_has_scarlet_shield_and_cyan_pulse(self):
        from dashboard.ui_utils import logo_svg

        svg = logo_svg(64, "t4")
        # Scarlet gradient stops (brand shield)
        assert "#e11d48" in svg
        assert "#9f1239" in svg
        # Cyan EKG pulse (the existing UI accent)
        assert "#00e5ff" in svg

    def test_favicon_assets_exist(self):
        assert (DASHBOARD_DIR / "assets" / "favicon.svg").exists()
        assert (DASHBOARD_DIR / "assets" / "favicon.png").exists()


class TestBrandHeader:
    """The centered logo + wordmark block at the top of the auth card."""

    def test_brand_header_contains_wordmark(self):
        from dashboard.ui_utils import brand_header_html

        html = brand_header_html("bh")
        assert "Security" in html
        assert "Scarlet" in html
        assert "AI-Native SIEM" in html

    def test_wordmark_renders_scarletai_contiguous(self):
        from dashboard.ui_utils import brand_header_html

        html = brand_header_html("bh2")
        # "ScarletAI" must be one contiguous run — a newline/space between
        # spans would render as "Scarlet AI".
        assert "ScarletAI" in html
        assert "Scarlet AI" not in html

    def test_wordmark_ai_is_scarlet_not_cyan(self):
        """Raphael 2026-08-27: the cyan 'AI' in the heading was rejected —
        the whole wordmark brand run is scarlet now."""
        from dashboard.ui_utils import brand_header_html

        html = brand_header_html("bh3")
        assert '#f43f5e;"\u003eScarletAI</span>' in html
        assert "#00bcd4" not in html.split("ScarletAI")[0].split("Security")[1]

    def test_brand_header_uses_given_id_prefix(self):
        from dashboard.ui_utils import brand_header_html

        assert 'id="pp-shield"' in brand_header_html("pp")

    def test_tagline_is_white(self):
        """Raphael 2026-08-27: the AI-NATIVE SIEM tagline must not be grey."""
        from dashboard.ui_utils import brand_header_html

        html = brand_header_html("bh4")
        tagline = html.split("AI-Native SIEM")[0]
        para_start = tagline.rfind("<p")
        assert "#e8ecf1" in tagline[para_start:]  # TEXT_PRIMARY, not #8b95a5


class TestAuthCardCss:
    """The login card: one bordered surface holding brand + form + button."""

    def test_login_card_css_exists(self):
        from dashboard.auth import LOGIN_CARD_CSS

        assert '[data-testid="stForm"]' in LOGIN_CARD_CSS

    def test_card_is_narrow_and_centered(self):
        from dashboard.auth import LOGIN_CARD_CSS

        assert "max-width: 430px" in LOGIN_CARD_CSS
        assert "margin-left: auto" in LOGIN_CARD_CSS
        assert "margin-right: auto" in LOGIN_CARD_CSS

    def test_card_has_shadow_and_radius(self):
        from dashboard.auth import LOGIN_CARD_CSS

        assert "box-shadow" in LOGIN_CARD_CSS
        assert "border-radius: 16px" in LOGIN_CARD_CSS

    def test_card_uses_design_tokens(self):
        from dashboard.auth import LOGIN_CARD_CSS

        # Surface/background/border all come from the shared token system
        assert "#0f1420" in LOGIN_CARD_CSS  # BG_SURFACE
        assert "#1e2636" in LOGIN_CARD_CSS  # BORDER_SUBTLE
        assert "#090c14" in LOGIN_CARD_CSS  # BG_APP (brand glow)

    def test_inputs_are_symmetric_eye_overlay(self):
        """Raphael 2026-08-27: the password input rendered ~50px shorter than
        the username input (eye-toggle consumed width inside the wrapper).
        The toggle must overlay the field, not shrink it."""
        from dashboard.auth import LOGIN_CARD_CSS

        assert "stTextInputRootElement\"] input" in LOGIN_CARD_CSS
        assert "width: 100% !important" in LOGIN_CARD_CSS
        assert "position: absolute" in LOGIN_CARD_CSS

    def test_labels_are_white(self):
        """Raphael 2026-08-27: grey labels were hard to read — field labels
        must be white."""
        from dashboard.auth import LOGIN_CARD_CSS

        assert '[data-testid="stForm"] label' in LOGIN_CARD_CSS
        assert "color: #ffffff" in LOGIN_CARD_CSS
        # The old grey secondary must be gone from the label rule
        label_block = LOGIN_CARD_CSS.split("[data-testid=\"stForm\"] label")[1]
        label_block = label_block[: label_block.find("}}")]
        assert "#8b95a5" not in label_block

    def test_trust_footer_is_not_muted(self):
        from dashboard.auth import LOGIN_CARD_CSS

        footer_block = LOGIN_CARD_CSS.split(".auth-card-footer")[1]
        footer_block = footer_block[: footer_block.find("}}")]
        assert "#e8ecf1" in footer_block  # TEXT_PRIMARY
        assert "#5a6578" not in footer_block  # old TEXT_MUTED

    def test_primary_sign_in_button(self):
        """Sign In must be type="primary" to pick up the accent button CSS."""
        source = (DASHBOARD_DIR / "auth.py").read_text()
        assert 'type="primary"' in source

    def test_sign_in_button_scarlet_with_white_text(self):
        """Raphael 2026-08-27: black-on-cyan Sign In was hard to read —
        the auth-card primary button is white-on-scarlet, scoped to the
        auth card (app-wide primaries stay cyan)."""
        from dashboard.auth import LOGIN_CARD_CSS

        # The hook that actually matches the live DOM: Streamlit 1.40
        # renders the form submit with kind="primaryFormSubmit" inside
        # [data-testid=stFormSubmitButton] (verified via CDP 2026-08-27).
        assert '[data-testid="stFormSubmitButton"] button' in LOGIN_CARD_CSS
        assert 'button[kind="primaryFormSubmit"]' in LOGIN_CARD_CSS
        # White text + scarlet gradient (not cyan/black)
        assert "color: #ffffff" in LOGIN_CARD_CSS
        assert "-webkit-text-fill-color: #ffffff" in LOGIN_CARD_CSS
        # The dark text-shadow (which made white glyphs read grey on scarlet)
        # must be gone; the span layer pins text-shadow: none.
        assert "text-shadow: none" in LOGIN_CARD_CSS
        assert "rgba(0,0,0,0.25)" not in LOGIN_CARD_CSS
        # Inner text layers (div > span) explicitly pinned white
        assert "button span" in LOGIN_CARD_CSS
        assert "#e11d48" in LOGIN_CARD_CSS
        assert "linear-gradient" in LOGIN_CARD_CSS
        # The gradient must NOT be the cyan accent
        assert "#00bcd4" not in LOGIN_CARD_CSS

    def test_no_double_welcome_on_success(self):
        """The st.toast + st.success + rerun flash is gone."""
        source = (DASHBOARD_DIR / "auth.py").read_text()
        # st.success may exist elsewhere in the module, but not in the
        # login success path (which ends in st.toast + st.rerun).
        assert "st.success(f\"Welcome, {result['username']}!\")" not in source


class TestSetupHelpGate:
    """Operator setup notes are off the login screen unless explicitly enabled."""

    def test_disabled_by_default(self):
        from dashboard.auth import _setup_help_enabled

        with patch("dashboard.auth.os.environ", {}):
            assert _setup_help_enabled() is False

    def test_enabled_for_truthy_values(self):
        from dashboard.auth import _setup_help_enabled

        for val in ("1", "true", "yes", "on", "TRUE", "Yes"):
            with patch("dashboard.auth.os.environ", {"DASHBOARD_SHOW_SETUP_HELP": val}):
                assert _setup_help_enabled() is True, val

    def test_disabled_for_other_values(self):
        from dashboard.auth import _setup_help_enabled

        for val in ("", "0", "false", "no", "off", "junk"):
            with patch("dashboard.auth.os.environ", {"DASHBOARD_SHOW_SETUP_HELP": val}):
                assert _setup_help_enabled() is False, val

    def test_setup_text_is_current(self):
        """The gated expander documents the real bootstrap (entrypoint file +
        SEED_ADMIN_ENABLED gate), not the stale always-on curl."""
        source = (DASHBOARD_DIR / "auth.py").read_text()
        assert "data/admin_initial_password" in source
        assert "SEED_ADMIN_ENABLED" in source

    def test_setup_expander_is_gated_in_source(self):
        source = (DASHBOARD_DIR / "auth.py").read_text()
        assert "if _setup_help_enabled():" in source


class TestThemeFlagsInCompose:
    """Native dark theme via Streamlit CLI flags (no .streamlit/config.toml
    needed — the base compose command is inherited by the prod overlay)."""

    @pytest.mark.parametrize(
        "flag",
        [
            "--theme.base=dark",
            "--theme.primaryColor=#00bcd4",
            "--theme.backgroundColor=#090c14",
            "--theme.secondaryBackgroundColor=#0f1420",
            "--theme.textColor=#e8ecf1",
        ],
    )
    def test_dashboard_command_has_theme_flags(self, flag):
        compose = Path(__file__).parent.parent.parent / "docker-compose.yml"
        text = compose.read_text()
        assert flag in text, f"{flag} missing from docker-compose.yml dashboard command"


class TestFaviconWiring:
    """set_page_config uses the brand favicon with an emoji fallback."""

    def test_page_icon_references_favicon(self):
        source = (DASHBOARD_DIR / "main.py").read_text()
        assert "favicon.png" in source
        assert 'else "\U0001f6e1\ufe0f"' in source  # 🛡️ fallback

    def test_sidebar_brand_uses_logo_svg(self):
        source = (DASHBOARD_DIR / "main.py").read_text()
        assert "logo_svg(" in source
        # The old plain-text title is gone
        assert 'st.sidebar.title("SecurityScarletAI")' not in source
