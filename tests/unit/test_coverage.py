"""Unit tests — V0.3 evidence-driven coverage (detectability map)."""

from src.detection.coverage import (
    CORRELATION_REQUIREMENTS,
    INGESTED_CATEGORIES,
    _bucket_present,
    _correlation_armed,
    extract_sigma_requirements,
)

SIGMA_REVERSE_SHELL = """
title: Reverse Shell Pattern Detected
logsource:
    category: process
detection:
    selection_bash_tcp:
        process_cmdline|contains: /dev/tcp
    selection_bash_i:
        process_cmdline: bash -i
    condition: selection_bash_tcp or selection_bash_i
level: critical
tags:
    - attack.t1059
"""

SIGMA_AUTH_TOKEN = """
title: SSH Brute Force
logsource:
    category: authentication
detection:
    selection:
        event_action|contains: failed
    condition: selection | count(source_ip) by host_name > 5
timeframe: 5m
level: high
tags:
    - attack.t1110
"""

SIGMA_FUTURE_SOURCE = """
title: Kerberoasting Anomalous
logsource:
    category: authentication
detection:
    selection:
        event_action: tgs_request
    condition: selection
level: high
tags:
    - attack.t1558
"""

SIGMA_CONFIG_TABLE = """
title: Cron Modification
logsource:
    category: configuration
detection:
    selection:
        file_path|contains: cron
    condition: selection
level: medium
"""


class TestExtractSigmaRequirements:
    def test_reverse_shell_has_no_action_requirement(self):
        req = extract_sigma_requirements(SIGMA_REVERSE_SHELL)
        assert req["category"] == "process"
        assert req["action_tokens"] == []

    def test_action_token_extracted(self):
        req = extract_sigma_requirements(SIGMA_AUTH_TOKEN)
        assert req["category"] == "authentication"
        assert req["action_tokens"] == ["failed"]

    def test_exact_action_token_extracted(self):
        req = extract_sigma_requirements(SIGMA_FUTURE_SOURCE)
        assert req["action_tokens"] == ["tgs_request"]

    def test_empty_yaml_is_safe(self):
        req = extract_sigma_requirements("")
        assert req == {"category": None, "action_tokens": [], "fields": []}


class TestBucketPresent:
    BUCKETS = {
        ("process", "process_start"): 10,
        ("network", "network_connection"): 5,
        ("authentication", "auth_failed"): 7,
        ("authentication", "auth_success"): 2,
        ("file", "file_created"): 1,
    }

    def test_exact_token(self):
        assert _bucket_present(self.BUCKETS, "authentication", "auth_failed") is True

    def test_contains_semantics(self):
        # 'failed' matches 'auth_failed' via contains
        assert _bucket_present(self.BUCKETS, "authentication", "failed") is True

    def test_future_verbs_do_not_arm(self):
        assert _bucket_present(self.BUCKETS, "authentication", "tgs_request") is False
        assert _bucket_present(self.BUCKETS, "authentication", "ntlm_auth") is False

    def test_any_action_in_category(self):
        assert _bucket_present(self.BUCKETS, "file", None) is True
        assert _bucket_present(self.BUCKETS, "configuration", None) is False

    def test_category_only(self):
        assert _bucket_present(self.BUCKETS, None, "process_start") is True


class TestCorrelationArmed:
    def _buckets(self, extra: dict | None = None):
        base = {
            ("process", "process_start"): 10,
            ("network", "network_connection"): 5,
            ("file", "file_created"): 2,
        }
        if extra:
            base.update(extra)
        return base

    def test_brute_force_dormant_without_auth_events(self):
        armed, _ = _correlation_armed("brute_force_success", self._buckets(), probed_names=set())
        assert armed is False

    def test_brute_force_armed_with_both_tokens(self):
        buckets = self._buckets(
            extra={
                ("authentication", "auth_failed"): 6,
                ("authentication", "auth_success"): 1,
            }
        )
        armed, _ = _correlation_armed("brute_force_success", buckets, probed_names=set())
        assert armed is True

    def test_ai_verdict_dormant_without_neuralguard(self):
        armed, _ = _correlation_armed("ai_verdict_block_sustained", self._buckets(), set())
        assert armed is False

    def test_priv_esc_needs_sudo_probe(self):
        armed, _ = _correlation_armed("privilege_escalation_chain", self._buckets(), set())
        assert armed is False  # process_start present but no sudo probe
        armed, _ = _correlation_armed(
            "privilege_escalation_chain",
            self._buckets(),
            probed_names={"sudo"},
        )
        assert armed is True

    def test_unknown_rule(self):
        armed, _ = _correlation_armed("nonexistent_rule", self._buckets(), set())
        assert armed is False

    def test_every_correlation_rule_has_requirements(self):
        from src.detection.correlation import CORRELATION_RULES

        missing = set(CORRELATION_RULES) - set(CORRELATION_REQUIREMENTS)
        assert not missing, f"chains without coverage requirements: {missing}"


class TestIngestedCategories:
    def test_all_parser_categories_ingested(self):
        from src.ingestion.schemas import OSQUERY_ECS_MAP

        for mapping in OSQUERY_ECS_MAP.values():
            assert mapping["event_category"] in INGESTED_CATEGORIES, mapping["event_category"]
