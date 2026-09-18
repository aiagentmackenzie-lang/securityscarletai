"""
Tests for the legacy Slack notifier (src/response/notifications.py).

AUD-055: send_alert_notification was deleted (zero callers — the live
alert formatting + routing is notification_channels.format_alert_message
/ dispatch_alert). Only the direct send_slack_notification path is tested
here.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.response.notifications import send_slack_notification


class TestSendSlackNotification:
    """Test Slack notification sending."""

    @pytest.mark.asyncio
    async def test_slack_not_configured(self):
        """Should return False if Slack webhook not configured."""
        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.slack_webhook_url = None
            result = await send_slack_notification("Test message")
            assert result is False

    @pytest.mark.asyncio
    async def test_slack_sends_successfully(self):
        """Should return True on successful Slack notification."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.slack_webhook_url = "https://hooks.slack.com/services/test"
            with patch("httpx.AsyncClient", return_value=mock_client):
                result = await send_slack_notification("Test alert")
                assert result is True

    @pytest.mark.asyncio
    async def test_slack_with_channel(self):
        """Should include channel in payload if specified."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.slack_webhook_url = "https://hooks.slack.com/services/test"
            with patch("httpx.AsyncClient", return_value=mock_client):
                result = await send_slack_notification("Test", channel="#security")
                assert result is True
                # Verify channel was included
                call_args = mock_client.post.call_args
                payload = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]
                assert "channel" in payload

    @pytest.mark.asyncio
    async def test_slack_http_error(self):
        """Should return False on HTTP error."""
        import httpx

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "Error",
                request=MagicMock(),
                response=MagicMock(status_code=500),
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.slack_webhook_url = "https://hooks.slack.com/services/test"
            with patch("httpx.AsyncClient", return_value=mock_client):
                result = await send_slack_notification("Test alert")
                assert result is False

    @pytest.mark.asyncio
    async def test_slack_connection_error(self):
        """Should return False on connection error."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.slack_webhook_url = "https://hooks.slack.com/services/test"
            with patch("httpx.AsyncClient", return_value=mock_client):
                result = await send_slack_notification("Test alert")
                assert result is False
