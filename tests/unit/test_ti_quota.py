"""P2.5 — AbuseIPDB quota protection: negative cache + hourly budget.

Before this fix, every IOC-cache miss with an API key configured fired a
LIVE AbuseIPDB check — an attacker spraying fresh IPs burned the daily
quota and every subsequent enrichment (and the ingest pipeline that calls
it) flew blind.

Covered here:
- A clean result is negative-cached (Redis, 1h TTL): the SECOND lookup for
  the same clean IP does NOT hit the live client.
- A THREAT result is not negative-cached (it goes to the IOC store) — live
  lookups still happen for threat IPs until the IOC cache covers them.
- Budget exhaustion skips the live call entirely.
- Redis down → behavior identical to pre-P2.5 (fail-open), no crash.

The Redis client is the shared singleton from src.api.redis_client, faked
here with the same in-memory substitute used by the auth tests.
"""
from __future__ import annotations

import os
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("DB_PASSWORD", "test_password_long_enough")
os.environ.setdefault("API_SECRET_KEY", "x" * 64)
os.environ.setdefault("API_BEARER_TOKEN", "y" * 32)

from src.intel.threat_intel import _TI_NEG_KEY, enrich_ip_with_threat_intel


class _FakeRedis:
    """Async in-memory Redis substitute (subset used by the TI guards)."""

    def __init__(self) -> None:
        self._kv: dict[str, str] = {}
        self._ttls: dict[str, int] = {}

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self._kv[key] = value
        self._ttls[key] = ttl

    async def get(self, key: str) -> str | None:
        return self._kv.get(key)

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -2)

    async def exists(self, key: str) -> int:
        return 1 if key in self._kv else 0

    async def incr(self, key: str) -> int:
        cur = int(self._kv.get(key, "0")) + 1
        self._kv[key] = str(cur)
        return cur

    async def expire(self, key: str, ttl: int) -> None:
        self._ttls[key] = ttl

    async def aclose(self) -> None:
        pass

    async def ping(self) -> bool:
        return True


@pytest.fixture()
def fake_redis():
    from src.api import redis_client

    fake = _FakeRedis()
    redis_client._client = fake  # noqa: SLF001
    yield fake
    redis_client._client = None  # noqa: SLF001


@pytest.fixture(autouse=True)
def _abuseipdb_key(monkeypatch):
    """The live-call path is gated on settings.abuseipdb_api_key — set a
    test key so the quota-guard code paths actually run."""
    from src.config.settings import settings

    monkeypatch.setattr(settings, "abuseipdb_api_key", "test-key-for-quota-tests")


def _clean_result() -> dict:
    return {
        "ip": "1.2.3.4",
        "abuse_confidence": 0,
        "total_reports": 0,
        "country": "US",
        "isp": "test-isp",
        "domain": None,
        "threat_type": None,
    }


def _threat_result() -> dict:
    return {
        "ip": "6.6.6.6",
        "abuse_confidence": 95,
        "total_reports": 40,
        "country": "RU",
        "isp": "bad-isp",
        "domain": None,
        "threat_type": "malicious_ip",
    }


def _patched_live(live) -> ExitStack:
    """Context manager: IOC-cache miss + live client mocked with `live`."""
    stack = ExitStack()
    stack.enter_context(
        patch(
            "src.intel.threat_intel.check_ioc_match",
            AsyncMock(return_value=None),
        )
    )
    stack.enter_context(
        patch(
            "src.intel.threat_intel.AbuseIPDBClient.check_ip",
            AsyncMock(side_effect=live),
        )
    )
    return stack


class TestNegativeCache:
    async def test_second_clean_lookup_skips_live_call(self, fake_redis):
        calls = {"n": 0}

        async def live(ip):
            calls["n"] += 1
            return _clean_result()

        with _patched_live(live):
            await enrich_ip_with_threat_intel("1.2.3.4")  # live call happens
            await enrich_ip_with_threat_intel("1.2.3.4")  # negative cache hit
        assert calls["n"] == 1
        # and the negative marker exists with the documented prefix
        assert "scarletai:v1:ti_neg:1.2.3.4" in fake_redis._kv

    async def test_threat_ip_not_negative_cached(self, fake_redis):
        """A THREAT result goes to the IOC cache — never the negative cache."""
        with _patched_live(lambda ip: _threat_result()), patch(
            "src.intel.threat_intel.cache_ioc", AsyncMock()
        ):
            enrichment = await enrich_ip_with_threat_intel("6.6.6.6")
        assert enrichment["threat_intel"]["match"] is True
        assert fake_redis._kv.get(f"{_TI_NEG_KEY}6.6.6.6") is None

    async def test_api_error_not_negative_cached(self, fake_redis):
        """check_ip returning None (API error/timeout) must NOT poison the
        negative cache — the IP gets retried on the next lookup."""
        calls = {"n": 0}

        async def failing(ip):
            calls["n"] += 1
            return None

        with _patched_live(failing):
            await enrich_ip_with_threat_intel("7.7.7.7")
            await enrich_ip_with_threat_intel("7.7.7.7")
        assert calls["n"] == 2  # retried: errors are never cached as clean


class TestHourlyBudget:
    async def test_budget_exhaustion_skips_live_call(self, fake_redis, monkeypatch):
        from src.config.settings import settings

        monkeypatch.setattr(settings, "abuseipdb_hourly_budget", 2)
        calls = {"n": 0}

        async def live(ip):
            calls["n"] += 1
            return _clean_result()

        with _patched_live(live):
            await enrich_ip_with_threat_intel("10.0.0.1")  # slot 1
            await enrich_ip_with_threat_intel("10.0.0.2")  # slot 2
            await enrich_ip_with_threat_intel("10.0.0.3")  # over budget → skipped
        assert calls["n"] == 2

    async def test_budget_window_uses_hour_bucket(self, fake_redis):
        """The counter key embeds the UTC hour bucket (rolls without a timer)."""
        import time as _time

        with _patched_live(lambda ip: _clean_result()):
            await enrich_ip_with_threat_intel("10.1.0.1")
        bucket = int(_time.time() // 3600)
        key = f"scarletai:v1:ti_budget:abuseipdb:{bucket}"
        assert int(fake_redis._kv.get(key, "0")) == 1


class TestRedisDownFailOpen:
    async def test_no_redis_behaves_like_pre_p25(self, monkeypatch):
        """With Redis unavailable: no negative cache, no budget accounting —
        the lookup proceeds live (the documented availability tradeoff)."""
        from src.api import redis_client

        redis_client._client = None  # noqa: SLF001
        monkeypatch.setattr(redis_client, "_last_failure_ts", 0.0)
        calls = {"n": 0}

        async def live(ip):
            calls["n"] += 1
            return _clean_result()

        with _patched_live(live):
            enrichment = await enrich_ip_with_threat_intel("1.2.3.4")
        assert calls["n"] == 1
        # clean live result — same enrichment shape as pre-P2.5 (match False,
        # live details present; the negative cache only suppresses REPEATS)
        assert enrichment == {
            "threat_intel": {
                "match": False,
                "source": "abuseipdb",
                "threat_type": None,
                "confidence": 0,
                "country": "US",
                "isp": "test-isp",
            }
        }
