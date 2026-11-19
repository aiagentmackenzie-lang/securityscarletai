"""SS-036 / SS-037: grant verification must see inherited privileges.

Both verifiers asked `information_schema.table_privileges` /
`role_table_grants` filtered by `grantee = <role>`, which returns DIRECT grants
only. On PostgreSQL, `app_role` with direct INSERT/SELECT plus membership of a
role holding UPDATE/DELETE passed both checks — while `has_table_privilege`
answered true and an actual UPDATE succeeded. The control that backs the
two-role append-only claim (and the MCP blast-radius claim) was blind to the
exact misconfiguration it exists to catch.

These tests pin the truth source: effective privileges via
`has_table_privilege` (inheritance- and ownership-aware) plus `pg_auth_members`.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from scripts.check_audit_grants import (
    AUDIT_TABLES,
    evaluate_append_only,
    evaluate_audit_posture,
)
from src.mcp_server.tools import evaluate_scoped_role


def _report(table: str, privileges, owner="scarletai_owner", member_of=()) -> dict:
    return {
        "table_name": table,
        "privileges": None if privileges is None else set(privileges),
        "table_owner": owner,
        "member_of": list(member_of),
    }


class TestAuditGrantPosture:
    def test_inherited_update_is_caught(self):
        """The defect: direct INSERT/SELECT + inherited UPDATE passed."""
        report = {
            "audit_logs": _report("audit_logs", {"INSERT", "SELECT", "UPDATE"}, member_of=["mut"]),
            "audit_log": _report("audit_log", {"INSERT", "SELECT"}),
        }
        enforced, problems = evaluate_audit_posture(report, app_role="scarletai_app")
        assert not enforced
        assert any("audit_logs" in p and "UPDATE" in p for p in problems)

    def test_clean_two_role_posture_passes(self):
        report = {
            "audit_logs": _report("audit_logs", {"INSERT", "SELECT"}),
            "audit_log": _report("audit_log", {"INSERT", "SELECT"}),
        }
        enforced, problems = evaluate_audit_posture(report, app_role="scarletai_app")
        assert enforced
        assert problems == []

    def test_owner_role_is_flagged(self):
        """An owner bypasses REVOKE — append-only is by convention only."""
        report = {
            "audit_logs": _report("audit_logs", {"INSERT", "SELECT"}, owner="scarletai_app"),
            "audit_log": _report("audit_log", {"INSERT", "SELECT"}),
        }
        enforced, problems = evaluate_audit_posture(report, app_role="scarletai_app")
        assert not enforced
        assert any("owner" in p.lower() for p in problems)

    def test_missing_table_fails_closed(self):
        report = {
            "audit_logs": _report("audit_logs", None),
            "audit_log": _report("audit_log", {"INSERT", "SELECT"}),
        }
        enforced, problems = evaluate_audit_posture(report, app_role="scarletai_app")
        assert not enforced
        assert any("audit_logs" in p and "missing" in p.lower() for p in problems)

    def test_legacy_grants_shape_still_supported(self):
        """`evaluate_append_only` (the pure helper the old tests pin) keeps its
        contract: a direct-grants map is still evaluated."""
        enforced, problems = evaluate_append_only({"audit_logs": {"INSERT", "SELECT"}})
        assert enforced and problems == []
        enforced, problems = evaluate_append_only({"audit_logs": {"INSERT", "DELETE"}})
        assert not enforced

    def test_audit_tables_constant_unchanged(self):
        assert set(AUDIT_TABLES) == {"audit_logs", "audit_log"}


class TestScopedRoleEvaluation:
    BASE = {
        "logs": {"SELECT"},
        "alerts": {"SELECT"},
        "rules": {"SELECT"},
        "correlation_matches": {"SELECT"},
        "cases": {"SELECT"},
        "case_events": {"SELECT"},
        "response_actions": {"SELECT"},
        "agent_investigations": {"SELECT", "INSERT", "UPDATE"},
        "audit_log": {"INSERT", "SELECT"},
        "audit_logs": {"INSERT", "SELECT"},
        "ai_usage": {"INSERT", "SELECT"},
    }

    def test_clean_role_has_no_violations(self):
        assert evaluate_scoped_role(self.BASE) == []

    def test_inherited_update_on_siem_data_is_caught(self):
        """Same blind spot: a scoped role with direct SELECT + inherited
        UPDATE kept the tool surface open."""
        grants = dict(self.BASE)
        grants["logs"] = {"SELECT", "UPDATE"}
        violations = evaluate_scoped_role(grants)
        assert any("logs" in v and "UPDATE" in v for v in violations)

    def test_inherited_delete_on_audit_is_caught(self):
        grants = dict(self.BASE)
        grants["audit_logs"] = {"INSERT", "SELECT", "DELETE"}
        violations = evaluate_scoped_role(grants)
        assert any("audit_logs" in v and "DELETE" in v for v in violations)

    def test_owner_is_flagged_as_unscoped(self):
        violations = evaluate_scoped_role(self.BASE, owned_tables={"logs"})
        assert any("logs" in v and "owner" in v.lower() for v in violations)

    def test_missing_select_on_contract_table_is_caught(self):
        grants = dict(self.BASE)
        grants.pop("cases")
        violations = evaluate_scoped_role(grants)
        assert any("cases" in v and "SELECT" in v for v in violations)

    def test_unexpected_readable_table_is_a_violation(self):
        """SS-056: the contract is a closed set. A table the role can read but
        that is not in the allowlist must fail closed."""
        violations = evaluate_scoped_role(self.BASE, readable_tables={*self.BASE, "api_tokens"})
        assert any("api_tokens" in v for v in violations)

    def test_readable_tables_inside_the_contract_are_fine(self):
        assert evaluate_scoped_role(self.BASE, readable_tables=set(self.BASE)) == []

    def test_membership_is_reported_in_the_violation(self):
        grants = dict(self.BASE)
        grants["logs"] = {"SELECT", "UPDATE"}
        violations = evaluate_scoped_role(grants, member_of=["writer_group"])
        assert any("writer_group" in v for v in violations)


class TestNoDirectGrantQueryRemains:
    """A future edit must not reintroduce the grantee-filtered query."""

    def test_check_audit_grants_uses_has_table_privilege(self):
        from pathlib import Path

        src = Path("scripts/check_audit_grants.py").read_text()
        assert "has_table_privilege" in src
        assert "pg_auth_members" in src
        # No grantee-filtered information_schema query left in the SQL.
        assert "FROM information_schema.table_privileges" not in src

    def test_mcp_verifier_uses_has_table_privilege(self):
        from pathlib import Path

        src = Path("src/mcp_server/tools.py").read_text()
        assert "has_table_privilege" in src
        assert "pg_auth_members" in src
        assert "FROM information_schema.role_table_grants" not in src


def test_import_guard():
    # keeps pytest imported for parametrised future cases
    assert pytest is not None


# ───────────────────────────────────────────────────────────────
# Wave E: MCP protocol/error hygiene (SS-055, SS-039)
# ───────────────────────────────────────────────────────────────


class TestMcpParamsType:
    def test_array_params_are_rejected_as_invalid_params(self):
        """SS-055: JSON-RPC 2.0 permits positional array params; they passed
        parse_rpc then crashed on `.get` -> 500."""
        from src.mcp_server.protocol import INVALID_PARAMS, parse_rpc

        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["explain"]}
        parsed, error = parse_rpc(body)
        assert parsed is None
        assert error is not None
        assert error["error"]["code"] == INVALID_PARAMS

    def test_dict_params_are_accepted(self):
        from src.mcp_server.protocol import parse_rpc

        parsed, error = parse_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}}
        )
        assert error is None
        assert parsed is not None

    def test_params_string_is_rejected(self):
        from src.mcp_server.protocol import parse_rpc

        parsed, error = parse_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "x"}
        )
        assert parsed is None and error is not None

    def test_absent_params_is_fine(self):
        from src.mcp_server.protocol import parse_rpc

        parsed, error = parse_rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert error is None and parsed is not None


class TestMcpToolErrorDoesNotEchoInternals:
    @pytest.mark.asyncio
    async def test_internal_error_text_is_not_returned(self):
        """SS-039: DB/planner text reached the MCP consumer."""
        from src.mcp_server import tools as tools_mod

        async def _boom(args, actor, audit):
            raise RuntimeError('relation "siem_users" does not exist at CHARACTER 15')

        with patch.dict(tools_mod.TOOL_IMPLEMENTATIONS, {"explain": _boom}):
            _result, err = await tools_mod.call_tool(
                "explain", {}, actor="tester", audit=AsyncMock()
            )

        assert err is not None
        assert "siem_users" not in err, err
        assert "CHARACTER" not in err
        assert "correlation" in err.lower() or "ref" in err.lower()
