"""Tests for the audit grant check logic (P1-C)."""
from scripts.check_audit_grants import AUDIT_TABLES, MUTATE_PRIVILEGES, evaluate_append_only


class TestEvaluateAppendOnly:
    def test_no_mutate_privileges_is_enforced(self):
        grants = {"audit_logs": {"INSERT", "SELECT"}, "audit_log": {"INSERT", "SELECT"}}
        enforced, problems = evaluate_append_only(grants)
        assert enforced
        assert problems == []

    def test_update_is_not_enforced(self):
        grants = {"audit_logs": {"INSERT", "SELECT", "UPDATE"}, "audit_log": {"INSERT", "SELECT"}}
        enforced, problems = evaluate_append_only(grants)
        assert not enforced
        assert any("audit_logs" in p and "UPDATE" in p for p in problems)
        # audit_log is fine — only audit_logs is flagged.
        assert not any("audit_log:" in p for p in problems)

    def test_delete_and_truncate_flagged(self):
        grants = {
            "audit_logs": {"SELECT", "DELETE", "TRUNCATE"},
            "audit_log": {"INSERT", "SELECT", "DELETE"},
        }
        enforced, problems = evaluate_append_only(grants)
        assert not enforced
        assert len(problems) == 2

    def test_missing_table_treated_as_no_privs(self):
        # If a table isn't in the grants map (no privileges granted), it's
        # append-only by default — no mutate privilege present.
        grants = {"audit_logs": {"INSERT", "SELECT"}}
        enforced, problems = evaluate_append_only(grants)
        assert enforced
        assert problems == []

    def test_empty_grants_enforced(self):
        enforced, problems = evaluate_append_only({})
        assert enforced
        assert problems == []

    def test_mutate_privileges_constant(self):
        # Sanity: the mutate set is exactly the row-mutating privileges.
        assert MUTATE_PRIVILEGES == frozenset({"UPDATE", "DELETE", "TRUNCATE"})
        assert "INSERT" not in MUTATE_PRIVILEGES
        assert "SELECT" not in MUTATE_PRIVILEGES

    def test_audit_tables_constant(self):
        assert set(AUDIT_TABLES) == {"audit_logs", "audit_log"}