"""Response action policy engine (V0.4 "Trusted Loop").

Decides, for every proposed response action, whether it may execute
(allow), needs HITL approval (approval_required), or is refused (never).
Loaded from a versioned YAML file; FAIL-CLOSED everywhere:

- an action type missing from the policy file is NEVER
- a missing, unreadable, or unparseable policy file is NEVER for
  everything (a broken policy must not widen authority)
- max_per_day <= 0 means the action is disabled
- the pure decision function is separated from the DB so the gate is
  unit-testable without a database (same pattern as check_audit_grants).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import yaml

from src.config.logging import get_logger

log = get_logger("response.policy")

ALLOW = "allow"
APPROVAL_REQUIRED = "approval_required"
NEVER = "never"
VALID_EFFECTS = (ALLOW, APPROVAL_REQUIRED, NEVER)


@dataclass(frozen=True)
class PolicyEntry:
    """One action's authority, parsed from the policy file."""

    effect: str
    max_per_day: int
    requires_case: bool
    description: str
    rollback_note: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome of evaluating a proposed action against the policy."""

    action_type: str
    effect: str
    allowed: bool
    requires_approval: bool
    reason: str
    entry: PolicyEntry | None = None


def parse_policy_document(document: dict | None) -> dict[str, PolicyEntry]:
    """Pure: parse a policy YAML document into {action_type: PolicyEntry}.

    Unknown/malformed entries are DROPPED (they become NEVER downstream,
    because the registry only executes action types with a known executor
    AND a policy entry). The default_effect applies to anything absent.
    """
    entries: dict[str, PolicyEntry] = {}
    if not isinstance(document, dict):
        return entries
    policy = document.get("response_policy")
    if not isinstance(policy, dict):
        return entries
    actions = policy.get("actions")
    if not isinstance(actions, dict):
        return entries

    for action_type, spec in actions.items():
        if not isinstance(spec, dict):
            log.warning("response_policy_invalid_entry", action_type=str(action_type))
            continue
        effect = spec.get("effect")
        if effect not in VALID_EFFECTS:
            log.warning(
                "response_policy_invalid_effect",
                action_type=str(action_type),
                effect=str(effect),
            )
            continue
        try:
            max_per_day = int(spec.get("max_per_day", 0))
        except (TypeError, ValueError):
            max_per_day = 0
        entries[str(action_type)] = PolicyEntry(
            effect=str(effect),
            max_per_day=max_per_day,
            requires_case=bool(spec.get("requires_case", True)),
            description=str(spec.get("description", "")),
            rollback_note=spec.get("rollback_note"),
        )
    return entries


def load_policy_file(path: str) -> dict[str, PolicyEntry]:
    """Load and parse the policy file. Missing/unreadable -> empty dict
    (fail-closed: every action evaluates to NEVER)."""
    try:
        with open(path) as f:
            document = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        log.error("response_policy_load_failed", path=path, error=str(e))
        return {}
    return parse_policy_document(document)


def default_effect(document: dict | None) -> str:
    """The file's declared default effect; NEVER unless explicitly set."""
    if isinstance(document, dict):
        policy = document.get("response_policy")
        if isinstance(policy, dict) and policy.get("default_effect") in VALID_EFFECTS:
            return str(policy["default_effect"])
    return NEVER


def evaluate_action(
    action_type: str,
    entries: dict[str, PolicyEntry],
    *,
    has_case: bool,
    actions_today: int,
    default_effect: str = NEVER,
    today: datetime | None = None,
) -> PolicyDecision:
    """Pure policy decision. Given the parsed entries and the request
    context (does the action reference a case, how many actions of this
    type have already been taken today), decide what may happen."""
    entry = entries.get(action_type)
    if entry is None:
        return PolicyDecision(
            action_type=action_type,
            effect=NEVER,
            allowed=False,
            requires_approval=False,
            reason=f"action '{action_type}' is not in the response policy (fail-closed)",
        )

    if entry.effect == NEVER:
        return PolicyDecision(
            action_type=action_type,
            effect=NEVER,
            allowed=False,
            requires_approval=False,
            reason=f"action '{action_type}' is policy: never",
            entry=entry,
        )

    if entry.max_per_day <= 0:
        return PolicyDecision(
            action_type=action_type,
            effect=entry.effect,
            allowed=False,
            requires_approval=False,
            reason=f"action '{action_type}' is disabled (max_per_day=0)",
            entry=entry,
        )

    if actions_today >= entry.max_per_day:
        return PolicyDecision(
            action_type=action_type,
            effect=entry.effect,
            allowed=False,
            requires_approval=False,
            reason=(
                f"blast-radius limit reached: {actions_today} '{action_type}' "
                f"actions today (max_per_day={entry.max_per_day})"
            ),
            entry=entry,
        )

    if entry.requires_case and not has_case:
        return PolicyDecision(
            action_type=action_type,
            effect=entry.effect,
            allowed=False,
            requires_approval=False,
            reason=f"action '{action_type}' requires a case (operating-unit rule)",
            entry=entry,
        )

    if entry.effect == APPROVAL_REQUIRED:
        return PolicyDecision(
            action_type=action_type,
            effect=APPROVAL_REQUIRED,
            allowed=True,  # allowed to be REQUESTED; execution needs approval
            requires_approval=True,
            reason=(f"action '{action_type}' is policy: approval_required (HITL, four-eyes)"),
            entry=entry,
        )

    # effect == allow
    return PolicyDecision(
        action_type=action_type,
        effect=ALLOW,
        allowed=True,
        requires_approval=False,
        reason=f"action '{action_type}' is policy: allow",
        entry=entry,
    )
