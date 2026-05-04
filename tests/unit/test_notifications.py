"""
Tests for notification handlers.

Covers:
- Slack notification sending (success, failure, not configured)
- Email notification (success, failure, not configured)
- Alert notification formatting
- Daily summary formatting
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.response.notifications import (
    send_slack_notification,
    send_alert_notification,
    send_email_notification,
    send_daily_summary,
)


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
        mock_client.post = AsyncMock(side_effect=httpx.HTTPStatusError(
            "Error", request=MagicMock(), response=MagicMock(status_code=500),
        ))
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


class TestSendAlertNotification:
    """Test formatted alert notification."""

    @pytest.mark.asyncio
    async def test_critical_alert_format(self):
        """Critical alerts should use 🔴 emoji."""
        alert = {
            "severity": "critical",
            "rule_name": "SSH Brute Force",
            "host_name": "server01",
            "time": "2025-01-01T12:00:00",
            "description": "Multiple failed logins",
        }
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            result = await send_alert_notification(alert)
            assert result is True
            call_args = mock_slack.call_args[0][0]
            assert "🔴" in call_args
            assert "CRITICAL" in call_args

    @pytest.mark.asyncio
    async def test_high_alert_format(self):
        """High alerts should use 🟠 emoji."""
        alert = {
            "severity": "high",
            "rule_name": "Malware Detected",
            "host_name": "server02",
            "time": "2025-01-01T12:00:00",
            "description": "Suspicious process",
        }
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            result = await send_alert_notification(alert)
            call_args = mock_slack.call_args[0][0]
            assert "🟠" in call_args

    @pytest.mark.asyncio
    async def test_medium_alert_format(self):
        """Medium alerts should use 🟡 emoji."""
        alert = {
            "severity": "medium",
            "rule_name": "Test Rule",
            "host_name": "server03",
            "time": "2025-01-01T12:00:00",
            "description": "Test",
        }
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            result = await send_alert_notification(alert)
            call_args = mock_slack.call_args[0][0]
            assert "🟡" in call_args

    @pytest.mark.asyncio
    async def test_low_alert_format(self):
        """Low alerts should use 🔵 emoji."""
        alert = {
            "severity": "low",
            "rule_name": "Low Priority",
            "host_name": "server04",
            "time": "2025-01-01T12:00:00",
            "description": "Low severity",
        }
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            result = await send_alert_notification(alert)
            call_args = mock_slack.call_args[0][0]
            assert "🔵" in call_args

    @pytest.mark.asyncio
    async def test_alert_notification_includes_rule_name(self):
        """Alert notification should include rule name."""
        alert = {
            "severity": "high",
            "rule_name": "My Test Rule",
            "host_name": "server01",
            "time": "2025-01-01T12:00:00",
            "description": "Test description",
        }
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            await send_alert_notification(alert)
            call_args = mock_slack.call_args[0][0]
            assert "My Test Rule" in call_args

    @pytest.mark.asyncio
    async def test_alert_notification_includes_host(self):
        """Alert notification should include hostname."""
        alert = {
            "severity": "medium",
            "rule_name": "Rule",
            "host_name": "prod-server-01",
            "time": "2025-01-01",
            "description": "Desc",
        }
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            await send_alert_notification(alert)
            call_args = mock_slack.call_args[0][0]
            assert "prod-server-01" in call_args


class TestSendEmailNotification:
    """Test email notification sending."""

    @pytest.mark.asyncio
    async def test_email_not_configured(self):
        """Should return False if SMTP not configured."""
        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.smtp_host = None
            result = await send_email_notification("Subject", "Body")
            assert result is False

    @pytest.mark.asyncio
    async def test_email_no_recipient(self):
        """Should return False if no recipient configured."""
        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_user = "user@example.com"
            mock_settings.smtp_password = "pass"
            mock_settings.alert_email_to = None
            result = await send_email_notification("Subject", "Body")
            assert result is False

    @pytest.mark.asyncio
    async def test_email_send_success(self):
        """Should return True on successful email send."""
        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_user = "user@example.com"
            mock_settings.smtp_password = "pass"
            mock_settings.smtp_port = 587
            mock_settings.alert_email_to = "admin@example.com"

            with patch("aiosmtplib.send", new_callable=AsyncMock):
                result = await send_email_notification("Alert Subject", "Alert Body")
                assert result is True

    @pytest.mark.asyncio
    async def test_email_send_failure(self):
        """Should return False on SMTP error."""
        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_user = "user@example.com"
            mock_settings.smtp_password = "pass"
            mock_settings.smtp_port = 587
            mock_settings.alert_email_to = "admin@example.com"

            with patch("aiosmtplib.send", new_callable=AsyncMock, side_effect=Exception("SMTP error")):
                result = await send_email_notification("Alert", "Body")
                assert result is False

    @pytest.mark.asyncio
    async def test_email_with_custom_recipient(self):
        """Should use custom recipient when specified."""
        with patch("src.response.notifications.settings") as mock_settings:
            mock_settings.smtp_host = "smtp.example.com"
            mock_settings.smtp_user = "user@example.com"
            mock_settings.smtp_password = "pass"
            mock_settings.smtp_port = 587
            mock_settings.alert_email_to = "default@example.com"

            with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send:
                result = await send_email_notification("Subject", "Body", to_email="custom@example.com")
                assert result is True


class TestSendDailySummary:
    """Test daily summary notification."""

    @pytest.mark.asyncio
    async def test_daily_summary_format(self):
        """Summary should include all stats."""
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            result = await send_daily_summary(alert_count=42, critical_count=5, new_rules=3)
            assert result is True
            call_args = mock_slack.call_args[0][0]
            assert "42" in call_args
            assert "5" in call_args
            assert "3" in call_args

    @pytest.mark.asyncio
    async def test_daily_summary_with_zero_counts(self):
        """Should handle zero counts."""
        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True) as mock_slack:
            result = await send_daily_summary(alert_count=0, critical_count=0, new_rules=0)
            assert result is True