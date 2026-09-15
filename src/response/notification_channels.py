"""Notification channels (Wave 1 W1.7) -- the generalized delivery layer.

Slack existed (settings.slack_webhook_url, all severities, no retry, no
audit). This module generalizes it: a versioned, fail-closed YAML config
(the response_policy.yaml pattern) routes alerts to Slack / generic
webhooks (HMAC-signed) / PagerDuty / email, with bounded retry + backoff
and every dispatch outcome audited.

Fail-closed everywhere (loaded config can only ever NARROW delivery):
- an unknown file version disables EVERY channel (never guessed)
- an unknown channel type or malformed entry is DROPPED
- a literal secret in the YAML (webhook_url / routing_key / password
  values) REJECTS the channel -- secrets live in the environment,
  referenced via *_env indirection
- a missing/empty secret env at dispatch time refuses THAT delivery
  (audited, logged loudly), never falls back to an unconfigured send
- delivery failure never blocks alert creation (side-effect only)

Backward compatibility: the legacy path (settings.slack_webhook_url ->
Slack, ALL severities) is preserved as an IMPLICIT channel when no YAML
slack channel exists (and never double-sends alongside an explicit
"legacy-slack" channel).
"""

import asyncio
import hashlib
import hmac
import json
import os
import smtplib
import time
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Any, Optional

import httpx
import yaml

from src.config.logging import get_logger
from src.config.settings import settings

log = get_logger("response.notification_channels")

# Closed severity vocabulary (matches alerts.SEVERITY_ORDER).
VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")

# Channel types. Adding a type = adding a sender + a test; unknown types
# are dropped at parse time (fail-closed).
VALID_TYPES = ("slack", "webhook", "pagerduty", "email")

# Delivery bounds (config can tighten, never exceed).
MAX_ATTEMPTS_CAP = 5
MAX_BACKOFF_SECONDS = 30
DEFAULT_TIMEOUT_SECONDS = 10

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "notification_channels.yaml"
)

# PagerDuty Events API v2 severity mapping (their closed vocabulary:
# critical/error/warning/info).
PAGERDUTY_SEVERITY = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


@dataclass(frozen=True)
class ChannelConfig:
    """One delivery channel, parsed + validated (dropped entries never get
    this far)."""

    name: str
    type: str
    severities: tuple[str, ...]
    config: dict[str, Any] = field(default_factory=dict)


def _resolve_env(name: Any) -> tuple[bool, str]:
    """Is the named env var present and non-empty? (fail-closed)."""
    if not isinstance(name, str) or not name.strip():
        return False, ""
    value = os.environ.get(name, "")
    return bool(value.strip()), value.strip()


def parse_channels_document(document: Any) -> list[ChannelConfig]:
    """Pure: parse a notification_channels YAML document into channels.

    Fail-closed: wrong version -> []; malformed/unknown-typed/duplicate
    entries dropped; LITERAL secrets rejected (env indirection only);
    severities validated against the closed vocabulary.
    """
    if not isinstance(document, dict):
        return []
    block = document.get("notification_channels")
    if not isinstance(block, dict):
        log.warning("notification_channels_block_missing")
        return []
    if block.get("version") != 1:
        log.error(
            "notification_channels_version_unsupported_disabling_all",
            version=str(block.get("version")),
        )
        return []
    channels_raw = block.get("channels")
    if not isinstance(channels_raw, list):
        return []

    channels: list[ChannelConfig] = []
    seen_names: set[str] = set()
    for raw in channels_raw:
        if not isinstance(raw, dict):
            log.warning("notification_channel_entry_invalid")
            continue
        name = raw.get("name")
        ctype = raw.get("type")
        if not isinstance(name, str) or not name.strip() or name in seen_names:
            log.warning("notification_channel_name_invalid_or_duplicate", name=str(name))
            continue
        if ctype not in VALID_TYPES:
            log.warning("notification_channel_unknown_type_dropped", name=name, type=str(ctype))
            continue
        if raw.get("enabled") is not True:
            continue  # disabled channels never parse further (default-off)
        severities = tuple(
            s.lower()
            for s in (raw.get("severities") or [])
            if isinstance(s, str) and s.lower() in VALID_SEVERITIES
        )
        if not severities:
            log.warning("notification_channel_no_valid_severities_dropped", name=name)
            continue
        config = raw.get("config") or {}
        if not isinstance(config, dict):
            config = {}
        # Secrets must be env-indirected; a literal value is a rejection.
        literal_secret_key = {
            "slack": "webhook_url",
            "pagerduty": "routing_key",
            "webhook": "hmac_secret",
            "email": "password",
        }[str(ctype)]
        if isinstance(config.get(literal_secret_key), str):
            log.error("notification_channel_literal_secret_rejected", name=name)
            continue
        if ctype == "webhook" and not isinstance(config.get("url"), str):
            log.warning("notification_channel_webhook_url_missing", name=name)
            continue
        if ctype == "email" and (
            not config.get("smtp_host") or not config.get("from_addr") or not config.get("to_addrs")
        ):
            log.warning("notification_channel_email_incomplete_dropped", name=name)
            continue
        seen_names.add(name)
        channels.append(
            ChannelConfig(
                name=name,
                type=str(ctype),
                severities=severities,
                config=config,
            )
        )
    return channels


def load_channels_file(path: str) -> list[ChannelConfig]:
    """Load + parse the channels file. Missing/unreadable -> no channels
    (fail-closed: nothing is ever sent to a half-understood destination)."""
    try:
        with open(path) as f:
            document = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        log.error("notification_channels_load_failed", path=path, error=str(e))
        return []
    return parse_channels_document(document)


async def load_effective_channels() -> list[ChannelConfig]:
    """The channels in force: the YAML file's enabled channels, plus the
    legacy implicit Slack channel (settings.slack_webhook_url, ALL
    severities) when no explicit legacy-slack channel is configured --
    pre-W1.7 deployments keep their behavior, unchanged."""
    channels = list(load_channels_file(CONFIG_PATH))
    if not any(c.name == "legacy-slack" and c.type == "slack" for c in channels):
        if settings.slack_webhook_url:
            channels.append(
                ChannelConfig(
                    name="legacy-slack",
                    type="slack",
                    severities=VALID_SEVERITIES,
                    config={"legacy_webhook_url": settings.slack_webhook_url},
                )
            )
    return channels


def format_alert_message(alert: dict) -> str:
    """The shared alert message text (Slack/email; same format as the
    pre-W1.7 legacy path so existing deployments see no change)."""
    severity_emoji = {
        "critical": ":red_circle:",
        "high": ":large_orange_circle:",
        "medium": ":large_yellow_circle:",
        "low": ":large_blue_circle:",
        "info": ":white_circle:",
    }.get(str(alert.get("severity", "")).lower(), ":white_circle:")
    return (
        f"{severity_emoji} *Security Alert: {str(alert.get('severity', 'UNKNOWN')).upper()}*\n\n"
        f"*Rule:* {alert.get('rule_name', 'Unknown')}\n"
        f"*Host:* {alert.get('host_name', 'Unknown')}\n"
        f"*Time:* {str(alert.get('time', 'Unknown'))[:19]}\n"
        f"*Description:* {alert.get('description', 'No description')}\n\n"
        f"View in Dashboard: {settings.dashboard_public_url}"
    )


def _hmac_signature(secret: str, body: bytes) -> str:
    """X-ScarletAI-Signature: sha256=hex(hmac_sha256(secret, body))."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _backoff_seconds(attempt: int) -> float:
    """Exponential backoff, capped: 1s, 2s, 4s, ..."""
    return min(float(2 ** (attempt - 1)), MAX_BACKOFF_SECONDS)


def _max_attempts(channel: ChannelConfig) -> int:
    try:
        raw = int(channel.config.get("max_attempts", 3))
    except (TypeError, ValueError):
        return 3
    return max(1, min(raw, MAX_ATTEMPTS_CAP))


async def _post_with_retry(
    url: str,
    *,
    json_body: dict,
    headers: dict[str, str],
    timeout: float,
    max_attempts: int,
) -> tuple[bool, int, str]:
    """POST with bounded retry/backoff. 4xx (except 429) is non-retryable
    (a config error fails fast); 5xx and transport errors retry."""
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=json_body, headers=headers, timeout=timeout)
            if resp.status_code < 300:
                return True, attempt, ""
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                return False, attempt, f"http {resp.status_code} (non-retryable)"
            last_error = f"http {resp.status_code}"
        except (httpx.HTTPError, OSError, asyncio.TimeoutError) as e:
            last_error = str(e)
        if attempt < max_attempts:
            await asyncio.sleep(_backoff_seconds(attempt))
    return False, max_attempts, last_error


def _slack_url(channel: ChannelConfig) -> tuple[Optional[str], str]:
    """The channel's webhook URL: env-indirected for YAML channels, direct
    for the legacy implicit channel. Refused (None) when the secret env is
    missing -- fail-closed."""
    env_name = channel.config.get("webhook_url_env")
    if env_name is None:
        return channel.config.get("legacy_webhook_url"), ""
    present, value = _resolve_env(env_name)
    if not present:
        return None, f"secret env '{env_name}' not set (refused, fail-closed)"
    return value, ""


async def _send_slack_channel(channel: ChannelConfig, message: str) -> tuple[bool, int, str]:
    url, refusal = _slack_url(channel)
    if not url:
        return False, 0, refusal
    payload = {"text": message, "username": "SecurityScarletAI", "icon_emoji": ":shield:"}
    return await _post_with_retry(
        str(url),
        json_body=payload,
        headers={"Content-Type": "application/json"},
        timeout=DEFAULT_TIMEOUT_SECONDS,
        max_attempts=_max_attempts(channel),
    )


async def _send_webhook_channel(channel: ChannelConfig, alert: dict) -> tuple[bool, int, str]:
    """Alert webhook: body = {source, sent_at, alert}, HMAC-signed when the
    channel carries hmac_secret_env."""
    body: dict[str, Any] = {
        "source": "securityscarletai",
        "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alert": alert,
    }
    return await _send_webhook_body(channel, body)


async def _send_webhook_body(channel: ChannelConfig, body: dict[str, Any]) -> tuple[bool, int, str]:
    """Generic webhook POST: HMAC-signs the exact canonical body the
    receiver verifies against (sort_keys + compact separators; documented
    in PRODUCTION.md). Reports and alerts share this sender."""
    url = channel.config.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return False, 0, "invalid webhook url (refused, fail-closed)"
    headers = {"Content-Type": "application/json"}
    sig_env = channel.config.get("hmac_secret_env")
    if sig_env:
        present, secret = _resolve_env(sig_env)
        if not present:
            return False, 0, f"hmac secret env '{sig_env}' not set (refused, fail-closed)"
        serialized = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        headers["X-ScarletAI-Signature"] = _hmac_signature(secret, serialized)
    return await _post_with_retry(
        str(url),
        json_body=body,
        headers=headers,
        timeout=float(channel.config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
        max_attempts=_max_attempts(channel),
    )


async def _send_pagerduty_channel(channel: ChannelConfig, alert: dict) -> tuple[bool, int, str]:
    present, routing_key = _resolve_env(channel.config.get("routing_key_env"))
    if not present:
        env_name = channel.config.get("routing_key_env")
        return False, 0, f"secret env '{env_name}' not set (refused, fail-closed)"
    severity = PAGERDUTY_SEVERITY.get(str(alert.get("severity", "")).lower(), "info")
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": (
            f"scarletai/{alert.get('rule_name', 'unknown')}/{alert.get('host_name', 'unknown')}"
        ),
        "payload": {
            "summary": (
                f"SecurityScarletAI {alert.get('severity', 'alert')}: "
                f"{alert.get('rule_name', 'unknown')} on {alert.get('host_name', 'unknown')}"
            ),
            "source": str(alert.get("host_name", "securityscarletai")),
            "severity": severity,
            "timestamp": str(alert.get("time", "")),
            "custom_details": {
                "rule": str(alert.get("rule_name", "")),
                "description": str(alert.get("description", "")),
                "severity": str(alert.get("severity", "")),
            },
        },
    }
    return await _post_with_retry(
        "https://events.pagerduty.com/v2/enqueue",
        json_body=payload,
        headers={"Content-Type": "application/json"},
        timeout=DEFAULT_TIMEOUT_SECONDS,
        max_attempts=_max_attempts(channel),
    )


async def _send_email_channel(
    channel: ChannelConfig, message: str, subject: str
) -> tuple[bool, int, str]:
    """Text email; the subject is explicit (alerts and reports share the
    sender, only the subject differs)."""
    host = channel.config.get("smtp_host")
    port = int(channel.config.get("smtp_port", 587))
    use_tls = bool(channel.config.get("use_tls", True))
    from_addr = channel.config.get("from_addr")
    to_addrs = channel.config.get("to_addrs") or []
    if not host or not from_addr or not to_addrs:
        return False, 0, "email channel incomplete (refused, fail-closed)"

    username: Optional[str] = None
    password: Optional[str] = None
    user_env = channel.config.get("username_env")
    pass_env = channel.config.get("password_env")
    if pass_env:
        present, password = _resolve_env(pass_env)
        if not present:
            return False, 0, f"password env '{pass_env}' not set (refused, fail-closed)"
        if user_env:
            _, username = _resolve_env(user_env)

    max_attempts = _max_attempts(channel)
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        try:
            await asyncio.to_thread(
                _smtp_send,
                str(host),
                port,
                use_tls,
                username,
                password,
                str(from_addr),
                [str(t) for t in to_addrs],
                subject,
                message,
            )
            return True, attempt, ""
        except (smtplib.SMTPException, OSError, asyncio.TimeoutError) as e:
            last_error = str(e)
        if attempt < max_attempts:
            await asyncio.sleep(_backoff_seconds(attempt))
    return False, max_attempts, last_error


def _smtp_send(
    host: str,
    port: int,
    use_tls: bool,
    username: Optional[str],
    password: Optional[str],
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
) -> None:
    """Blocking SMTP send (run via asyncio.to_thread)."""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    with smtplib.SMTP(host, port, timeout=DEFAULT_TIMEOUT_SECONDS) as smtp:
        if use_tls:
            smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.sendmail(from_addr, to_addrs, msg.as_string())


async def dispatch_alert(alert: dict) -> dict[str, Any]:
    """Route one alert to every matching channel; deliver with retry;
    audit each outcome. Never raises (notifications are side-effect only).

    Returns {"matched": [names], "results": [{channel, type, outcome,
    attempts, detail?}], "delivered": n, "failed": n}.
    """
    severity = str(alert.get("severity", "")).lower()
    channels = await load_effective_channels()
    matched = [c for c in channels if severity in c.severities]
    results: list[dict[str, Any]] = []
    for channel in matched:
        ok, attempts, outcome, detail = False, 0, "failed", ""
        try:
            if channel.type == "slack":
                ok, attempts, detail = await _send_slack_channel(
                    channel, format_alert_message(alert)
                )
            elif channel.type == "webhook":
                ok, attempts, detail = await _send_webhook_channel(channel, alert)
            elif channel.type == "pagerduty":
                ok, attempts, detail = await _send_pagerduty_channel(channel, alert)
            else:  # email
                ok, attempts, detail = await _send_email_channel(
                    channel, format_alert_message(alert), _alert_email_subject(alert)
                )
            outcome = "delivered" if ok else "failed"
        except Exception as e:  # a sender bug must never break alert creation
            detail = f"sender error: {e}"
        results.append(
            {
                "channel": channel.name,
                "type": channel.type,
                "outcome": outcome,
                "attempts": attempts,
                **({"detail": detail} if detail else {}),
            }
        )
        await _audit_dispatch(alert, channel, outcome, attempts, detail)

    delivered = sum(1 for r in results if r["outcome"] == "delivered")
    return {
        "matched": [c.name for c in matched],
        "results": results,
        "delivered": delivered,
        "failed": len(results) - delivered,
    }


def _alert_email_subject(alert: dict) -> str:
    """The alert email subject (alerts and reports share the sender)."""
    return (
        f"[SecurityScarletAI] {str(alert.get('severity', 'ALERT')).upper()} "
        f"{alert.get('rule_name', 'alert')} on {alert.get('host_name', 'unknown')}"
    )


async def send_to_channel(
    channel: ChannelConfig,
    *,
    text: str,
    subject: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
) -> tuple[bool, int, str]:
    """One generic delivery on one channel (public: the scheduled-reports
    path shares the alert senders so the two can never drift).

    slack -> text; webhook -> payload (HMAC-signed when configured) else
    text; email -> text with the explicit subject; pagerduty -> refused
    (it routes ALERTS, not reports).
    """
    if channel.type == "slack":
        return await _send_slack_channel(channel, text)
    if channel.type == "webhook":
        if payload is not None:
            return await _send_webhook_body(
                channel,
                {
                    "source": "securityscarletai",
                    "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    **payload,
                },
            )
        return await _send_webhook_body(channel, {"source": "securityscarletai", "text": text})
    if channel.type == "email":
        return await _send_email_channel(channel, text, subject or "[SecurityScarletAI] report")
    return False, 0, f"channel type '{channel.type}' is not a report destination (refused)"


async def _audit_dispatch(
    alert: dict, channel: ChannelConfig, outcome: str, attempts: int, detail: str = ""
) -> None:
    """One audited dispatch outcome per channel (never raises; reuses the
    audit helper's never-break contract)."""
    try:
        from src.api.audit import log_audit_action

        await log_audit_action(
            actor="system",
            action="notification.attempt",
            target_type="notification_channel",
            target_id=None,
            new_values={
                "channel": channel.name,
                "type": channel.type,
                "severity": alert.get("severity"),
                "rule_name": alert.get("rule_name"),
                "host_name": alert.get("host_name"),
                "outcome": outcome,
                "attempts": attempts,
                **({"detail": detail} if detail else {}),
            },
        )
    except Exception as e:
        log.warning("notification_audit_failed", channel=channel.name, error=str(e))
