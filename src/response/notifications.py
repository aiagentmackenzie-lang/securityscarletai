"""Legacy Slack notifier — the direct-send path shared with the executors.

The W1.7 notification-channel layer (notification_channels.py) is the
generalized, versioned delivery layer; this module keeps only the direct
Slack webhook sender it uses (src/response/executors.py imports it).

AUD-055: send_alert_notification was deleted — it had zero callers in any
src file (the alert-notification formatting + routing live in
notification_channels.format_alert_message / dispatch_alert).
"""

from typing import Optional

from src.config.http_client import get_shared_async_client
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
        # AUD-052: the shared per-loop client — no throwaway AsyncClient
        # (and no new TCP/TLS handshake) per send.
        client = get_shared_async_client()
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
