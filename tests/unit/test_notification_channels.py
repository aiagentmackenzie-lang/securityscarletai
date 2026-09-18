"""W1.7 notification channels -- unit gates.

Covers the fail-closed config parsing (version gate, unknown types, literal
secret rejection, severity vocabulary, legacy implicit Slack channel), the
routing (per-severity), the HMAC signature, retry semantics (4xx fail fast,
5xx retry), the audit trail, and the backward-compatible wiring into
create_alert (legacy deployments keep their behavior).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.response.notification_channels import (
    ChannelConfig,
    _hmac_signature,
    dispatch_alert,
    format_alert_message,
    load_effective_channels,
    parse_channels_document,
)


def _channel(name="soc-webhook", ctype="webhook", severities=("critical",), config=None):
    return ChannelConfig(name=name, type=ctype, severities=severities, config=config or {})


class TestParseChannelsDocument:
    def test_empty_and_malformed_documents_yield_no_channels(self):
        assert parse_channels_document(None) == []
        assert parse_channels_document({}) == []
        assert parse_channels_document({"notification_channels": {}}) == []
        assert parse_channels_document({"notification_channels": {"channels": []}}) == []

    @pytest.mark.asyncio
    async def test_wrong_version_disables_everything(self):
        doc = {
            "notification_channels": {
                "version": 2,
                "channels": [
                    {
                        "name": "x",
                        "type": "slack",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": {"webhook_url_env": "E"},
                    }
                ],
            }
        }
        assert parse_channels_document(doc) == []

    def test_unknown_type_and_malformed_entries_dropped(self):
        doc = {
            "notification_channels": {
                "version": 1,
                "channels": [
                    {
                        "name": "a",
                        "type": "carrier_pigeon",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": {},
                    },
                    {
                        "name": "b",
                        "type": "slack",
                        "enabled": True,
                        "severities": ["bogus"],
                        "config": {"webhook_url_env": "E"},
                    },
                    {
                        "name": "dup",
                        "type": "slack",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": {"webhook_url_env": "E"},
                    },
                    # A duplicate of an ACCEPTED name is dropped; a name whose
                    # earlier entry was dropped for another reason does not
                    # reserve the name (a is dropped by type above).
                    {
                        "name": "dup",
                        "type": "slack",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": {"webhook_url_env": "E"},
                    },
                    {"type": "slack", "enabled": True, "severities": ["critical"]},
                    {
                        "name": "off",
                        "type": "slack",
                        "enabled": False,
                        "severities": ["critical"],
                        "config": {"webhook_url_env": "E"},
                    },
                    {
                        "name": "d",
                        "type": "slack",
                        "enabled": True,
                        "severities": ["CRITICAL"],
                        "config": {"webhook_url_env": "E"},
                    },
                ],
            }
        }
        channels = parse_channels_document(doc)
        assert [c.name for c in channels] == ["dup", "d"]
        assert channels[-1].severities == ("critical",)  # case-normalized

    def test_literal_secret_rejects_channel(self):
        doc = {
            "notification_channels": {
                "version": 1,
                "channels": [
                    {
                        "name": "bad",
                        "type": "slack",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": {"webhook_url": "https://hooks.slack.com/services/XX"},
                    },
                ],
            }
        }
        assert parse_channels_document(doc) == []

    def test_webhook_requires_url_and_email_requires_completeness(self):
        doc = {
            "notification_channels": {
                "version": 1,
                "channels": [
                    {
                        "name": "w",
                        "type": "webhook",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": {},
                    },
                    {
                        "name": "e",
                        "type": "email",
                        "enabled": True,
                        "severities": ["critical"],
                        "config": {"smtp_host": "h", "from_addr": "f@x", "to_addrs": ["t"]},
                    },
                ],
            }
        }
        assert [c.name for c in parse_channels_document(doc)] == ["e"]


class TestLegacyImplicitChannel:
    @pytest.mark.asyncio
    async def test_no_config_with_settings_webhook_keeps_legacy_behavior(self):
        with (
            patch("src.response.notification_channels.load_channels_file", return_value=[]),
            patch("src.response.notification_channels.settings") as mock_settings,
        ):
            mock_settings.slack_webhook_url = "https://hooks.slack.com/services/LEGACY"
            channels = await load_effective_channels()
        assert len(channels) == 1
        assert channels[0].name == "legacy-slack"
        assert channels[0].type == "slack"
        # Pre-W1.7 behavior: ALL severities.
        assert set(channels[0].severities) == {"info", "low", "medium", "high", "critical"}

    @pytest.mark.asyncio
    async def test_explicit_legacy_channel_prevents_double_send(self):
        explicit = [
            ChannelConfig(
                name="legacy-slack",
                type="slack",
                severities=("critical",),
                config={"webhook_url_env": "LEGACY_URL"},
            )
        ]
        with (
            patch("src.response.notification_channels.load_channels_file", return_value=explicit),
            patch("src.response.notification_channels.settings") as mock_settings,
        ):
            mock_settings.slack_webhook_url = "https://hooks.slack.com/services/ALSO"
            channels = await load_effective_channels()
        assert len(channels) == 1  # the implicit one is NOT appended


class TestRoutingAndDelivery:
    @pytest.mark.asyncio
    async def test_dispatch_routes_by_severity_and_audits(self):
        channels = [
            ChannelConfig(
                name="crit-only",
                type="slack",
                severities=("critical",),
                config={"webhook_url_env": "U1"},
            ),
            ChannelConfig(
                name="high-plus",
                type="webhook",
                severities=("high", "critical"),
                config={"url": "https://soc.internal/x"},
            ),
        ]
        with (
            patch(
                "src.response.notification_channels.load_effective_channels",
                AsyncMock(return_value=channels),
            ),
            patch(
                "src.response.notification_channels._send_slack_channel",
                AsyncMock(return_value=(True, 1, "")),
            ) as slack_send,
            patch(
                "src.response.notification_channels._send_webhook_channel",
                AsyncMock(return_value=(True, 2, "")),
            ) as webhook_send,
            patch("src.api.audit.log_audit_action", new=AsyncMock()) as audit,
        ):
            result = await dispatch_alert(
                {"severity": "critical", "rule_name": "R", "host_name": "H"}
            )
        assert set(result["matched"]) == {"crit-only", "high-plus"}
        assert result["delivered"] == 2
        assert slack_send.await_count == 1
        assert webhook_send.await_count == 1
        assert audit.await_count == 2
        assert audit.await_args_list[0].kwargs["action"] == "notification.attempt"

    @pytest.mark.asyncio
    async def test_dispatch_low_severity_matches_nothing(self):
        with (
            patch(
                "src.response.notification_channels.load_effective_channels",
                AsyncMock(
                    return_value=[
                        ChannelConfig(
                            name="c",
                            type="slack",
                            severities=("critical",),
                            config={"webhook_url_env": "U1"},
                        )
                    ]
                ),
            ),
            patch("src.response.notification_channels._send_slack_channel", AsyncMock()) as send,
            patch("src.response.notification_channels._audit_dispatch", AsyncMock()),
        ):
            result = await dispatch_alert({"severity": "low"})
        assert result["matched"] == []
        assert send.await_count == 0

    @pytest.mark.asyncio
    async def test_sender_never_breaks_dispatch(self):
        with (
            patch(
                "src.response.notification_channels.load_effective_channels",
                AsyncMock(
                    return_value=[
                        ChannelConfig(
                            name="c",
                            type="slack",
                            severities=("critical",),
                            config={"webhook_url_env": "U1"},
                        )
                    ]
                ),
            ),
            patch(
                "src.response.notification_channels._send_slack_channel",
                AsyncMock(side_effect=RuntimeError("bug")),
            ),
            patch("src.response.notification_channels._audit_dispatch", AsyncMock()),
        ):
            result = await dispatch_alert({"severity": "critical"})
        assert result["results"][0]["outcome"] == "failed"
        assert "bug" in result["results"][0]["detail"]

    @pytest.mark.asyncio
    async def test_missing_secret_env_refuses_delivery(self):
        channel = ChannelConfig(
            name="c",
            type="slack",
            severities=("critical",),
            config={"webhook_url_env": "SCARLET_MISSING_ENV_XYZ"},
        )
        from src.response.notification_channels import _send_slack_channel

        with patch.dict("os.environ", {}, clear=True):
            ok, attempts, detail = await _send_slack_channel(channel, "msg")
        assert ok is False
        assert attempts == 0
        assert "refused, fail-closed" in detail

    @pytest.mark.asyncio
    async def test_hmac_signature_shape(self):
        sig = _hmac_signature("secret", b"body")
        assert sig.startswith("sha256=")
        assert len(sig) == 7 + 64
        # Deterministic + secret-dependent.
        assert sig == _hmac_signature("secret", b"body")
        assert sig != _hmac_signature("other", b"body")


class TestRetrySemantics:
    # AUD-052: _post_with_retry uses the SHARED per-loop client — created
    # once per loop, so the tests patch httpx.AsyncClient (the constructor
    # seam) and put the post mock directly on the returned client (no
    # `async with` anymore).
    @pytest.mark.asyncio
    async def test_4xx_fails_fast_non_retryable(self):
        from src.response.notification_channels import _post_with_retry

        response = MagicMock(status_code=400)
        response.raise_for_status = MagicMock()
        post = AsyncMock(return_value=response)
        with patch("src.response.notification_channels.httpx.AsyncClient") as client_cls:
            client_cls.return_value.post = post
            ok, attempts, detail = await _post_with_retry(
                "https://x", json_body={}, headers={}, timeout=1, max_attempts=3
            )
        assert ok is False
        assert attempts == 1  # fail fast
        assert "non-retryable" in detail
        assert post.await_count == 1

    @pytest.mark.asyncio
    async def test_5xx_retries_then_fails(self):
        from src.response.notification_channels import _post_with_retry

        response = MagicMock(status_code=503)
        post = AsyncMock(return_value=response)
        with (
            patch("src.response.notification_channels.httpx.AsyncClient") as client_cls,
            patch("src.response.notification_channels.asyncio.sleep", AsyncMock()) as sleeper,
        ):
            client_cls.return_value.post = post
            ok, attempts, detail = await _post_with_retry(
                "https://x", json_body={}, headers={}, timeout=1, max_attempts=3
            )
        assert ok is False
        assert attempts == 3
        assert post.await_count == 3
        assert sleeper.await_count == 2  # backoff between attempts

    @pytest.mark.asyncio
    async def test_client_created_once_per_loop_not_per_attempt(self):
        """AUD-052: one AsyncClient for the whole retry loop, not one per
        attempt (the old shape built up to max_attempts throwaway clients —
        a fresh TCP/TLS handshake every retry)."""
        from src.response.notification_channels import _post_with_retry

        response = MagicMock(status_code=503)
        post = AsyncMock(return_value=response)
        with (
            patch("src.config.http_client.httpx.AsyncClient") as client_cls,
            patch("src.response.notification_channels.asyncio.sleep", AsyncMock()),
        ):
            client_cls.return_value.post = post
            ok, attempts, detail = await _post_with_retry(
                "https://x", json_body={}, headers={}, timeout=1, max_attempts=5
            )
        assert attempts == 5
        assert post.await_count == 5
        # ONE constructor call for the loop — the cache serves attempts 2..5.
        assert client_cls.call_count == 1


class TestCreateAlertWiring:
    @pytest.mark.asyncio
    async def test_create_alert_dispatches_through_channels(self):
        from src.detection.alerts import create_alert

        pool = MagicMock()
        conn = MagicMock()
        acquirer = MagicMock()
        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquirer)

        # create_alert uses the pool repeatedly; the alert insert returns an id.
        async def fetchrow(sql, *params):
            if "SELECT id FROM alerts" in sql:
                return None  # no dedup hit
            return None

        async def fetchval(sql, *args):
            if "INSERT INTO alerts" in sql:
                return 77
            return 0  # escalation check returns 0 recent alerts

        async def execute(sql, *args):
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow)
        conn.fetchval = AsyncMock(side_effect=fetchval)
        conn.execute = AsyncMock(return_value="UPDATE 1")

        dispatch = AsyncMock(
            return_value={"matched": ["x"], "delivered": 1, "failed": 0, "results": []}
        )
        with (
            patch("src.detection.alerts.get_pool", new=AsyncMock(return_value=pool)),
            patch("src.response.notification_channels.dispatch_alert", dispatch),
        ):
            alert_id = await create_alert(
                rule_id=1,
                rule_name="R",
                severity="critical",
                host_name="H",
                description="D",
            )
        assert alert_id == 77
        dispatch.assert_awaited_once()
        assert dispatch.await_args.args[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_dispatch_runs_after_connection_released(self):
        """AUD-003: notification dispatch must not run while the pool
        connection is still held (network I/O under a held conn could
        starve the pool during an incident)."""
        from src.detection.alerts import create_alert

        released = {"flag": False}

        pool = MagicMock()
        conn = MagicMock()
        acquirer = MagicMock()

        async def _exit(*_a, **_kw):
            released["flag"] = True
            return False

        acquirer.__aenter__ = AsyncMock(return_value=conn)
        acquirer.__aexit__ = AsyncMock(side_effect=_exit)
        pool.acquire = MagicMock(return_value=acquirer)

        async def fetchrow(sql, *params):
            return None  # no dedup hit, no suppression match

        async def fetchval(sql, *args):
            if "INSERT INTO alerts" in sql:
                return 88
            return 0

        conn.fetchrow = fetchrow
        conn.fetchval = fetchval
        conn.execute = AsyncMock(return_value="UPDATE 1")

        async def dispatch_side_effect(alert):
            # The connection MUST already be released when dispatch runs.
            assert released["flag"] is True, (
                "AUD-003: dispatch awaited while the pool connection was held"
            )
            return {"matched": ["x"], "delivered": 1, "failed": 0, "results": []}

        with (
            patch("src.detection.alerts.get_pool", new=AsyncMock(return_value=pool)),
            patch(
                "src.response.notification_channels.dispatch_alert",
                AsyncMock(side_effect=dispatch_side_effect),
            ),
        ):
            alert_id = await create_alert(
                rule_id=1,
                rule_name="R",
                severity="high",
                host_name="H",
                description="D",
            )
        assert alert_id == 88

    def test_shared_formatter_matches_legacy_shape(self):
        from src.config.settings import settings

        msg = format_alert_message(
            {
                "severity": "high",
                "rule_name": "R",
                "host_name": "H",
                "time": "2026-09-15T12:00:00",
                "description": "D",
            }
        )
        assert "Security Alert: HIGH" in msg
        assert settings.dashboard_public_url in msg
