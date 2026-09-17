"""W2.3 — rule-authority separation audit (regression tests).

The disclosed vulnerability class this wave item targets: detection-rule
authorship accidentally granting or widening response/containment authority
(a rule author who can also approve or execute containment actions is a
single point of covert failure — rule changes are routine, containment is
not).

This module pins the separation as tests so drift fails CI:

1. ROLE MATRIX (admin=3 / analyst=2 / viewer=1): require_role() exercised
   over every (role x gate) pair that matters, INCLUDING the fleet "ingest"
   role (level 0 by design — never a containment principal).
2. ENDPOINT WIRING MAP: every rule-CRUD and response endpoint's auth
   dependency asserted against its intended minimum role — including
   patch_rule, which the P1-12 test in test_api_rules_full.py does not cover.
3. WRITE-AUTHORITY SINGLE-SITING: the ONLY module that may write
   response_actions (INSERT/UPDATE/DELETE) or call the executors is
   src/api/response.py. Read consumers (evidence pack, decisions timeline,
   MCP read contract) are allowed to SELECT only.
4. POLICY IMMUTABILITY: the response policy is loaded READ-ONLY from a
   server-side settings path; no rule-CRUD module references the policy or
   the executors, so authoring a rule cannot reshape containment policy.
5. AUDIT NAMESPACE SEPARATION: rule mutations are audited under rule.*,
   response governance under response.* — a rule change is never recorded
   as a containment approval and vice versa.

Design notes:
- Wiring + source tests are static (inspect/AST/text) on purpose: they must
  pass without a database and fail loudly on drift, which is the point of a
  separation audit.
- Functional four-eyes / never-auto-execute behaviour is already pinned in
  test_response_api.py (TestApproveEndpoint, TestExecuteEndpoint) and is
  deliberately NOT duplicated here.
"""

import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.params import Depends as DependsClass

from src.api.auth import ROLE_HIERARCHY, require_role

REPO_ROOT = Path(__file__).resolve().parents[2]


# ───────────────────────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────────────────────


def _wired_auth(fn) -> str:
    """Resolve the auth dependency wired into an endpoint's `user` param.

    Returns "admin"/"analyst"/"viewer" for require_role(...) gates or
    "get_current_user" for plain-authenticated endpoints. Asserts that SOME
    auth dependency is wired (no endpoint ships without one).
    """
    dep = inspect.signature(fn).parameters["user"].default
    assert isinstance(dep, DependsClass), f"{fn.__name__}: no auth dependency wired on `user`"
    inner = dep.dependency
    name = getattr(inner, "__name__", "")
    if name == "get_current_user":
        return "get_current_user"
    if name == "_check_role":
        # require_role's closure captures (min_role: str, min_level: int,
        # ROLE_HIERARCHY: dict). Recover the captured min_role string.
        for cell in inner.__closure__ or ():
            val = cell.cell_contents
            if isinstance(val, str) and val in ROLE_HIERARCHY:
                return val
        raise AssertionError(f"{fn.__name__}: _check_role without a captured min_role")
    raise AssertionError(f"{fn.__name__}: unexpected auth dependency {name!r}")


def _python_files(rel_dirs: tuple[str, ...]) -> list[Path]:
    """All .py files under the given repo-relative directories (no pycache)."""
    files: list[Path] = []
    for rel in rel_dirs:
        for p in sorted((REPO_ROOT / rel).rglob("*.py")):
            if "__pycache__" not in p.parts:
                files.append(p)
    return files


def _files_containing(rel_dirs: tuple[str, ...], needle: str) -> set[str]:
    return {
        str(p.relative_to(REPO_ROOT))
        for p in _python_files(rel_dirs)
        if needle in p.read_text(encoding="utf-8", errors="replace")
    }


def _audit_actions(rel_path: str) -> list[str]:
    """Extract every literal `action=` value from log_audit_action calls."""
    tree = ast.parse((REPO_ROOT / rel_path).read_text(encoding="utf-8"))
    actions: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "log_audit_action"
        ):
            for kw in node.keywords:
                if kw.arg == "action" and isinstance(kw.value, ast.Constant):
                    actions.append(kw.value.value)
    return actions


# ───────────────────────────────────────────────────────────────
# 1. Role matrix (admin=3 / analyst=2 / viewer=1)
# ───────────────────────────────────────────────────────────────


class TestRoleHierarchy:
    def test_hierarchy_is_admin3_analyst2_viewer1(self):
        """The three-role ladder the whole RBAC map is built on."""
        assert ROLE_HIERARCHY == {"admin": 3, "analyst": 2, "viewer": 1}

    @pytest.mark.asyncio
    async def test_unknown_and_fleet_roles_have_zero_level(self):
        """A role outside the hierarchy (unknown token claim, fleet 'ingest')
        carries level 0 — it can never pass even the viewer gate."""
        check = require_role("viewer")
        with patch(
            "src.api.auth.get_current_user",
            return_value={"sub": "fleet:host", "role": "ingest"},
        ):
            with pytest.raises(HTTPException) as exc_info:
                await check(credentials=MagicMock())
            assert exc_info.value.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user_role", "min_role", "allowed"),
    [
        ("viewer", "viewer", True),
        ("viewer", "analyst", False),
        ("viewer", "admin", False),
        ("analyst", "viewer", True),
        ("analyst", "analyst", True),
        ("analyst", "admin", False),
        ("admin", "viewer", True),
        ("admin", "analyst", True),
        ("admin", "admin", True),
    ],
)
async def test_role_matrix(user_role, min_role, allowed):
    """The full (role x gate) matrix. Rule CRUD sits behind the admin gate,
    response request/read behind analyst, approve/reject/execute behind
    admin — this test pins what each level can pass."""
    check = require_role(min_role)
    with patch("src.api.auth.get_current_user", return_value={"sub": "u", "role": user_role}):
        if allowed:
            payload = await check(credentials=MagicMock())
            assert payload["role"] == user_role
        else:
            with pytest.raises(HTTPException) as exc_info:
                await check(credentials=MagicMock())
            assert exc_info.value.status_code == 403


# ───────────────────────────────────────────────────────────────
# 2. Endpoint wiring map
# ───────────────────────────────────────────────────────────────


class TestRuleEndpointsWiring:
    """Rule CRUD: mutations admin-only (P1-12), reads any authenticated user."""

    def test_mutations_are_admin(self):
        from src.api.rules import create_rule, delete_rule, patch_rule, update_rule

        for fn in (create_rule, update_rule, patch_rule, delete_rule):
            assert _wired_auth(fn) == "admin", f"{fn.__name__} must be admin-only"

    def test_reads_are_any_authenticated(self):
        from src.api.rules import get_rule, list_rules

        for fn in (list_rules, get_rule):
            assert _wired_auth(fn) == "get_current_user"


class TestResponseEndpointsWiring:
    """Response: request/read = analyst+, approve/reject/execute = admin."""

    def test_request_and_read_are_analyst(self):
        from src.api.response import get_action, list_actions, request_action

        for fn in (request_action, list_actions, get_action):
            assert _wired_auth(fn) == "analyst"

    def test_containment_decisions_are_admin(self):
        from src.api.response import approve_action, execute_action, reject_action

        for fn in (approve_action, reject_action, execute_action):
            assert _wired_auth(fn) == "admin", (
                f"{fn.__name__} widens containment authority if it drops "
                "below admin — the exact W2.3 vulnerability class"
            )


class TestDetectionRuleAdjacentWiring:
    """Backtest (rule-adjacent write path) is analyst+ AND read-only."""

    def test_backtest_is_analyst(self):
        from src.api.detection import detection_backtest

        assert _wired_auth(detection_backtest) == "analyst"

    def test_backtest_endpoint_is_read_only_by_contract(self):
        source = (REPO_ROOT / "src/api/detection.py").read_text(encoding="utf-8")
        assert "INSERT INTO response_actions" not in source
        assert "never persists" in source or "read-only" in source


# ───────────────────────────────────────────────────────────────
# 3. Write-authority single-siting
# ───────────────────────────────────────────────────────────────


class TestWriteAuthoritySingleSiting:
    """Containment writes exist in exactly ONE module — the response router."""

    def test_response_actions_writes_are_single_sited(self):
        writers: set[str] = set()
        for verb_sql in (
            "INSERT INTO response_actions",
            "UPDATE response_actions",
            "DELETE FROM response_actions",
        ):
            writers |= _files_containing(("src", "scripts"), verb_sql)
        assert writers == {"src/api/response.py"}, (
            f"response_actions writes found outside the response router: {writers}"
        )

    def test_executor_imports_are_single_sited(self):
        importers = _files_containing(("src",), "from src.response.executors import")
        assert importers == {"src/api/response.py"}

    def test_rules_module_has_no_response_surface(self):
        source = (REPO_ROOT / "src/api/rules.py").read_text(encoding="utf-8")
        assert "response_actions" not in source
        assert "executor" not in source

    def test_detection_pipeline_never_writes_response_actions(self):
        """The scheduler / alerts / correlation / ingestion paths produce
        alerts, correlation matches and CASES — never containment."""
        hits: set[str] = set()
        for verb_sql in (
            "INSERT INTO response_actions",
            "UPDATE response_actions",
        ):
            hits |= _files_containing(
                ("src/detection", "src/ingestion", "src/enrichment"), verb_sql
            )
        assert hits == set(), f"detection pipeline writing response actions: {hits}"


# ───────────────────────────────────────────────────────────────
# 4. Policy immutability
# ───────────────────────────────────────────────────────────────


class TestPolicyImmutability:
    def test_policy_path_is_settings_only(self):
        """The policy file path comes from server settings; exactly one API
        module consumes it (the response router) and nothing else."""
        consumers = _files_containing(("src",), "response_policy_path")
        assert consumers == {"src/config/settings.py", "src/api/response.py"}

    def test_policy_loader_opens_read_only(self):
        source = (REPO_ROOT / "src/response/policy.py").read_text(encoding="utf-8")
        assert "open(path)" in source, "policy loader must open the file read-only"
        import re

        assert re.search(r"open\([^)]*,\s*[\"'][wax+]", source) is None, (
            "a write-mode open() appeared in the policy loader — policy files "
            "are operator-managed, never agent- or API-writable"
        )

    def test_rules_module_never_references_policy(self):
        source = (REPO_ROOT / "src/api/rules.py").read_text(encoding="utf-8")
        assert "response_policy" not in source


# ───────────────────────────────────────────────────────────────
# 5. Audit namespace separation
# ───────────────────────────────────────────────────────────────


class TestAuditNamespaceSeparation:
    """Rule changes and response approvals are audited in disjoint
    namespaces — the audit chain must never conflate authorship with
    containment authority."""

    def test_rule_mutations_audited_under_rule_namespace(self):
        actions = _audit_actions("src/api/rules.py")
        assert actions, "rules.py audits nothing — P2-23 regression"
        assert {"rule.create", "rule.update", "rule.delete"} <= set(actions)
        assert all(a.startswith("rule.") for a in actions), actions

    def test_response_governance_audited_under_response_namespace(self):
        actions = _audit_actions("src/api/response.py")
        assert actions, "response.py audits nothing"
        assert all(a.startswith("response.") for a in actions), actions
        # The containment decision records must be present.
        assert {"response.approved", "response.rejected", "response.execute"} <= set(actions)

    def test_backtest_audited_under_rule_namespace(self):
        assert _audit_actions("src/api/detection.py") == ["rule.backtest"]

    def test_namespaces_are_disjoint(self):
        rule_actions = set(_audit_actions("src/api/rules.py"))
        response_actions = set(_audit_actions("src/api/response.py"))
        assert not (rule_actions & response_actions), (
            "an audit action string is shared between rule CRUD and response "
            "governance — the separation in the audit chain is broken"
        )
