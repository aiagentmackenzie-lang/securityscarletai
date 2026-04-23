"""
Notification handlers for Slack and Email alerts.
"""
from typing import Optional

import httpx

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("response.notifications")


async def send_slack_notification(message: str, channel: Optional[str] = None) -> bool:
    """
    Send notification to Slack webhook.
    
    Args:
        message: Message text to send
        channel: Optional override channel
    
    Returns:
        True if sent successfully
    """
    if not settings.slack_webhook_url:
        log.warning("slack_not_configured")
        return False

    payload = {
        "text": message,
        "username": "SecurityScarletAI",
        "icon_emoji": ":shield:",
    }

    if channel:
        payload["channel"] = channel

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                settings.slack_webhook_url,
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            log.info("slack_notification_sent")
            return True
    except Exception as e:
        log.error("slack_notification_failed", error=str(e))
        return False


async def send_alert_notification(alert: dict) -> bool:
    """
    Send formatted alert notification to Slack.
    
    Args:
        alert: Alert dictionary with severity, rule_name, etc.
    """
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(alert.get("severity", "").lower(), "⚪")

    message = f"""{severity_emoji} *Security Alert: {alert.get('severity', 'UNKNOWN').upper()}*

*Rule:* {alert.get('rule_name', 'Unknown')}
*Host:* {alert.get('host_name', 'Unknown')}
*Time:* {alert.get('time', 'Unknown')[:19]}
*Description:* {alert.get('description', 'No description')}

View in Dashboard: http://localhost:8501"""

    return await send_slack_notification(message)


async def send_email_notification(
    subject: str,
    body: str,
    to_email: Optional[str] = None,
) -> bool:
    """
    Send email notification via SMTP.
    
    Args:
        subject: Email subject
        body: Email body (plain text)
        to_email: Override recipient (default uses settings.alert_email_to)
    
    Returns:
        True if sent successfully
    """
    if not all([
        settings.smtp_host,
        settings.smtp_user,
        settings.smtp_password,
    ]):
        log.warning("smtp_not_configured")
        return False

    recipient = to_email or settings.alert_email_to
    if not recipient:
        log.warning("email_no_recipient")
        return False

    try:
        from email.mime.text import MIMEText

        import aiosmtplib

        msg = MIMEText(body)
        msg["Subject"] = f"[SecurityScarletAI] {subject}"
        msg["From"] = settings.smtp_user
        msg["To"] = recipient

        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=True,
        )

        log.info("email_notification_sent", to=recipient)
        return True

    except Exception as e:
        log.error("email_notification_failed", error=str(e))
        return False


async def send_daily_summary(
    alert_count: int,
    critical_count: int,
    new_rules: int,
) -> bool:
    """Send daily summary notification."""
    message = f"""📊 *Daily Security Summary*

• Total Alerts: {alert_count}
• Critical Alerts: {critical_count}
• New Rules Added: {new_rules}

Review in Dashboard: http://localhost:8501"""

    return await send_slack_notification(message)
