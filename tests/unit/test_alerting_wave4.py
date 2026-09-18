"""
Wave-4 audit-fix tests (AUD-003, AUD-009, AUD-028, AUD-052, AUD-055).

- AUD-003: notification dispatch runs AFTER the pool connection is
  released (behavioral pin lives in test_notification_channels.py
  TestCreateAlertWiring; here: the source-shape guard).
- AUD-009: the advisory-lock key is sha256-stable — PROVEN across
  subprocesses with different PYTHONHASHSEED (the old hash() key failed
  exactly there).
- AUD-028: the Ollama client reuses ONE client per loop and never closes
  it (no `async with`).
- AUD-052: the shared per-loop client (src/config/http_client.py) —
  per-loop caching semantics.
- AUD-055: send_alert_notification is GONE from src/response/notifications.py.
"""

import asyncio
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config.http_client import get_shared_async_client
from src.detection.alerts import _alert_lock_key

REPO_ROOT = Path(__file__).parents[2]

# ───────────────────────────────────────────────────────────────
# AUD-009 — stable advisory-lock key
# ───────────────────────────────────────────────────────────────


class TestAlertLockKey:
    def test_deterministic_within_process(self):
        assert _alert_lock_key(1, "R", "host-a") == _alert_lock_key(1, "R", "host-a")

    def test_distinct_pairs_get_distinct_keys(self):
        """Sampled distinctness — different (rule, host) pairs must not
        routinely collide (the modulus keeps a bounded keyspace by design;
        collisions only serialize, never corrupt)."""
        keys = {
            _alert_lock_key(rule, "R", host)
            for rule, host in ((1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e"))
        }
        keys.add(_alert_lock_key(None, "rule-name", "host-e"))
        assert len(keys) == 6

    def test_correlation_origin_uses_rule_name(self):
        """rule_id=None locks on the rule NAME (correlation-origin alerts)."""
        a = _alert_lock_key(None, "brute", "h")
        b = _alert_lock_key(None, "brute2", "h")
        assert a != b

    def test_key_fits_signed_int4_space(self):
        for rule_id, host in ((1, "a"), (10**9, "x"), (None, "y")):
            key = _alert_lock_key(rule_id, "R" if rule_id is None else "R", host)
            assert 0 <= key < 2**31

    def test_stable_across_processes_with_different_hash_seeds(self):
        """AUD-009's actual failure mode: Python's hash() is salted per
        PROCESS (PYTHONHASHSEED), so two uvicorn workers computed different
        keys for the same (rule, host) pair. Two subprocesses with different
        seeds must agree."""
        probe = textwrap.dedent(
            """
            import os
            os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
            os.environ.setdefault("API_SECRET_KEY", "x" * 64)
            os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)
            from src.detection.alerts import _alert_lock_key
            print(_alert_lock_key(1, "R", "host-a"))
            """
        )
        env = dict(os.environ)
        outputs = []
        for seed in ("1", "2"):
            env["PYTHONHASHSEED"] = seed
            proc = subprocess.run(  # noqa: S603 — fixed probe, no user input
                [sys.executable, "-c", probe],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
                env=env,
                timeout=120,
            )
            assert proc.returncode == 0, f"seed={seed}: {proc.stderr[-500:]}"
            outputs.append(proc.stdout.strip())
        assert outputs[0] != "", "probe produced no key"
        assert outputs[0] == outputs[1], (
            f"lock key depends on PYTHONHASHSEED: {outputs} — "
            "the dedup advisory lock would break across workers"
        )

    def test_no_hash_call_in_lock_key_source(self):
        """Cheap source guard: the key builder must not CALL Python's salted
        hash() — AST-based so the docstring's prose doesn't false-positive."""
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(_alert_lock_key))
        hash_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "hash"
        ]
        assert not hash_calls, "AUD-009 regression: _alert_lock_key calls salted hash()"


# ───────────────────────────────────────────────────────────────
# AUD-003 — dispatch order guard (source shape)
# ───────────────────────────────────────────────────────────────


def test_dispatch_is_not_inside_the_connection_block():
    """AUD-003 source-shape guard: the Step-6 dispatch call must sit AFTER
    the `async with pool.acquire()` block (dedent to 4 spaces), not inside
    it (8). The behavioral pin is
    test_notification_channels::test_dispatch_runs_after_connection_released;
    this catches an accidental re-indent without running the DB path."""
    import inspect

    from src.detection import alerts

    src = inspect.getsource(alerts.create_alert)
    dispatch_line = next(
        line for line in src.splitlines() if "await _send_alert_notification(" in line
    )
    indent = len(dispatch_line) - len(dispatch_line.lstrip())
    assert indent == 4, (
        f"AUD-003 regression: _send_alert_notification is indented at {indent} — "
        "it must run OUTSIDE the pool connection block (indent 4), not inside it (8+)"
    )


# ───────────────────────────────────────────────────────────────
# AUD-028 — ollama client reuses the shared per-loop client
# ───────────────────────────────────────────────────────────────


def _ollama_response(text="ok", counts=True):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = (
        {"response": text, "eval_count": 5, "prompt_eval_count": 10}
        if counts
        else {"response": text}
    )
    response.raise_for_status = MagicMock()
    return response


class TestOllamaSharedClient:
    @pytest.mark.asyncio
    async def test_two_calls_construct_the_client_once(self):
        from src.ai.ollama_client import query_llm

        with patch("src.config.http_client.httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.post = AsyncMock(return_value=_ollama_response("Hello"))
            client_cls.return_value = client

            r1 = await query_llm("prompt one")
            r2 = await query_llm("prompt two")

        assert r1.ok is True and r2.ok is True
        assert r1.source == "ollama" and r2.source == "ollama"
        # AUD-028: ONE AsyncClient for the loop, two POSTs through it.
        assert client_cls.call_count == 1
        assert client.post.await_count == 2

    @pytest.mark.asyncio
    async def test_shared_client_is_never_closed(self):
        """The shared client must not be used as a context manager — closing
        it on exit would kill connection reuse for every later call."""
        from src.ai.ollama_client import query_llm

        with patch("src.config.http_client.httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.post = AsyncMock(return_value=_ollama_response("Hello"))
            client_cls.return_value = client

            await query_llm("prompt")

        client.__aenter__.assert_not_called()
        client.__aexit__.assert_not_called()

    @pytest.mark.asyncio
    async def test_is_ollama_available_uses_shared_client(self):
        from src.ai.ollama_client import is_ollama_available

        with patch("src.config.http_client.httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.get = AsyncMock(return_value=MagicMock(status_code=200))
            client_cls.return_value = client

            assert await is_ollama_available() is True
            # the health probe passes its own 3s deadline
            assert client.get.await_args.kwargs["timeout"] == 3


# ───────────────────────────────────────────────────────────────
# AUD-052 — the shared client helper itself
# ───────────────────────────────────────────────────────────────


class TestSharedHttpClient:
    @pytest.mark.asyncio
    async def test_same_client_returned_within_a_loop(self):
        c1 = get_shared_async_client(default_timeout=5)
        c2 = get_shared_async_client(default_timeout=99)
        assert c1 is c2  # the default_timeout only applies at creation

    def test_per_loop_isolation(self):
        """A different loop gets a different client; the same loop is stable
        (pytest per-test loops + any future multi-loop deploy)."""
        from src.config import http_client

        async def _capture():
            return get_shared_async_client()

        loop1 = asyncio.new_event_loop()
        loop2 = asyncio.new_event_loop()
        try:
            c1 = loop1.run_until_complete(_capture())
            c2 = loop2.run_until_complete(_capture())
            assert c1 is not c2
            assert c1 is loop1.run_until_complete(_capture())
        finally:
            loop1.close()
            loop2.close()
            http_client._clients.clear()  # noqa: SLF001 — drop the closed-loop entries

    @pytest.mark.asyncio
    async def test_send_slack_reuses_shared_client(self):
        from src.response.notifications import send_slack_notification

        with (
            patch("src.response.notifications.settings") as mock_settings,
            patch("src.config.http_client.httpx.AsyncClient") as client_cls,
        ):
            mock_settings.slack_webhook_url = "https://hooks.slack.com/services/test"
            client = AsyncMock()
            client.post = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))
            client_cls.return_value = client

            ok1 = await send_slack_notification("one")
            ok2 = await send_slack_notification("two")

        assert ok1 is True and ok2 is True
        assert client_cls.call_count == 1
        assert client.post.await_count == 2


# ───────────────────────────────────────────────────────────────
# AUD-055 — the dead formatter path is gone
# ───────────────────────────────────────────────────────────────


def test_send_alert_notification_is_deleted():
    """AUD-055: send_alert_notification had zero callers; alert notification
    formatting/routing lives in notification_channels. It must not come
    back on this module."""
    import src.response.notifications as notifications

    assert not hasattr(notifications, "send_alert_notification")
    assert hasattr(notifications, "send_slack_notification")
