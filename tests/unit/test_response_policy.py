"""
Tests for the V0.4 response policy engine (pure logic, no DB).

The policy engine is the bounded response authority: allow /
approval_required / never, blast-radius limits, and fail-closed behavior.
"""

from src.response.policy import (
    ALLOW,
    APPROVAL_REQUIRED,
    NEVER,
    PolicyEntry,
    evaluate_action,
    load_policy_file,
    parse_policy_document,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Parsing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestParsePolicyDocument:
    def test_parse_full_document(self):
        doc = {
            "response_policy": {
                "version": 1,
                "default_effect": "never",
                "actions": {
                    "notify_slack": {
                        "effect": "allow",
                        "max_per_day": 100,
                        "requires_case": False,
                        "description": "send a message",
                    },
                    "disable_siem_user": {
                        "effect": "approval_required",
                        "max_per_day": 5,
                        "requires_case": True,
                        "rollback_note": "re-enable",
                    },
                },
            }
        }
        entries = parse_policy_document(doc)
        assert set(entries) == {"notify_slack", "disable_siem_user"}
        assert entries["notify_slack"].effect == ALLOW
        assert entries["notify_slack"].requires_case is False
        assert entries["disable_siem_user"].effect == APPROVAL_REQUIRED
        assert entries["disable_siem_user"].rollback_note == "re-enable"

    def test_parse_empty_or_malformed_returns_empty(self):
        assert parse_policy_document(None) == {}
        assert parse_policy_document({}) == {}
        assert parse_policy_document({"response_policy": {}}) == {}
        assert parse_policy_document({"response_policy": {"actions": "oops"}}) == {}

    def test_invalid_effect_entry_dropped(self):
        doc = {
            "response_policy": {
                "actions": {
                    "bad_action": {"effect": "whenever", "max_per_day": 5},
                    "good_action": {"effect": "allow", "max_per_day": 1},
                }
            }
        }
        entries = parse_policy_document(doc)
        assert "bad_action" not in entries  # dropped -> NEVER downstream
        assert "good_action" in entries

    def test_non_int_max_per_day_becomes_zero(self):
        doc = {
            "response_policy": {
                "actions": {"notify_slack": {"effect": "allow", "max_per_day": "many"}}
            }
        }
        entries = parse_policy_document(doc)
        assert entries["notify_slack"].max_per_day == 0  # 0 -> disabled -> fail-closed


class TestDefaultEffectRetired:
    """AUD-057: the dead default_effect() reader and evaluate_action's unused
    default_effect parameter are GONE. An action type missing from the policy
    file is ALWAYS NEVER — hardcoded, deliberately not operator-overridable
    (a per-call default would have been a fail-open switch on the authority
    gate). evaluate_action no longer even ACCEPTS the parameter."""

    def test_evaluate_action_rejects_default_effect_kwarg(self):
        import pytest as _pytest

        entries = parse_policy_document({"response_policy": {"actions": {}}})
        with _pytest.raises(TypeError):
            evaluate_action(
                "anything",
                entries,
                has_case=True,
                actions_today=0,
                default_effect=ALLOW,  # type: ignore[call-arg]
            )

    def test_missing_action_is_hardcoded_never(self):
        entries = parse_policy_document({"response_policy": {"actions": {}}})
        decision = evaluate_action("unlisted_action", entries, has_case=True, actions_today=0)
        assert decision.effect == NEVER
        assert decision.allowed is False


class TestShippedPolicyFile:
    """The shipped config/response_policy.yaml must parse and contain the
    full action vocabulary with fail-closed defaults."""

    def test_shipped_policy_parses(self):
        import os

        path = os.path.join("config", "response_policy.yaml")
        entries = load_policy_file(path)
        # All six action types the executors implement
        assert set(entries) == {
            "notify_slack",
            "disable_siem_user",
            "quarantine_host",
            "pf_block_ip",
            "disable_macos_user",
            "isolate_host_fleet",
        }

    def test_shipped_policy_containment_requires_approval(self):
        import os

        path = os.path.join("config", "response_policy.yaml")
        entries = load_policy_file(path)
        for action in (
            "disable_siem_user",
            "quarantine_host",
            "pf_block_ip",
            "disable_macos_user",
            "isolate_host_fleet",
        ):
            assert entries[action].effect == APPROVAL_REQUIRED, action
            assert entries[action].requires_case is True, action
            assert entries[action].max_per_day > 0, action

    def test_shipped_policy_missing_file_is_never(self):
        entries = load_policy_file("/nonexistent/policy.yaml")
        assert entries == {}  # fail-closed


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# evaluate_action
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _entry(effect: str, *, max_per_day: int = 5, requires_case: bool = True) -> PolicyEntry:
    return PolicyEntry(
        effect=effect,
        max_per_day=max_per_day,
        requires_case=requires_case,
        description="test",
    )


class TestEvaluateAction:
    def test_unknown_action_is_never(self):
        decision = evaluate_action("nuke_from_orbit", {}, has_case=True, actions_today=0)
        assert decision.effect == NEVER
        assert decision.allowed is False
        assert "fail-closed" in decision.reason

    def test_never_policy_refused(self):
        decision = evaluate_action("x", {"x": _entry(NEVER)}, has_case=True, actions_today=0)
        assert decision.allowed is False
        assert decision.reason == "action 'x' is policy: never"

    def test_max_per_day_zero_disabled(self):
        decision = evaluate_action(
            "x", {"x": _entry(ALLOW, max_per_day=0)}, has_case=True, actions_today=0
        )
        assert decision.allowed is False
        assert "disabled" in decision.reason

    def test_blast_radius_limit_reached(self):
        decision = evaluate_action(
            "x", {"x": _entry(ALLOW, max_per_day=3)}, has_case=True, actions_today=3
        )
        assert decision.allowed is False
        assert "blast-radius" in decision.reason

    def test_requires_case_enforced(self):
        decision = evaluate_action(
            "x", {"x": _entry(APPROVAL_REQUIRED)}, has_case=False, actions_today=0
        )
        assert decision.allowed is False
        assert "requires a case" in decision.reason

    def test_approval_required_allowed_to_request(self):
        decision = evaluate_action(
            "x", {"x": _entry(APPROVAL_REQUIRED)}, has_case=True, actions_today=0
        )
        assert decision.allowed is True  # allowed to be REQUESTED
        assert decision.requires_approval is True  # execution needs HITL

    def test_allow_executes_immediately(self):
        decision = evaluate_action(
            "x", {"x": _entry(ALLOW, requires_case=False)}, has_case=False, actions_today=0
        )
        assert decision.allowed is True
        assert decision.requires_approval is False

    def test_exact_limit_boundary_still_allowed(self):
        """actions_today == max_per_day - 1 must pass (the strict >= check)."""
        decision = evaluate_action(
            "x", {"x": _entry(ALLOW, max_per_day=3)}, has_case=True, actions_today=2
        )
        assert decision.allowed is True
