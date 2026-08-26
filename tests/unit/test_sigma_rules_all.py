"""
Whole-ruleset guard for the Sigma -> SQL engine (P0-01/P0-04).

The pySigma PostgreSQLBackend produced invalid SQL (Python list-repr injected
into WHERE) and dropped aggregation selections to TRUE. sigma_to_sql now
routes every rule through the legacy SigmaParser. This test asserts that no
shipped rule regresses to either failure mode:

- no ``['`` / ``["`` (list-repr in WHERE)
- no ``(TRUE)`` (aggregation selection dropped)

It does NOT execute the SQL (that requires a live Postgres — covered by the
integration tests in tests/integration/); it is the minimum guard that runs in
CI without a database.
"""

from pathlib import Path

from src.detection.sigma import sigma_to_sql

RULES_DIR = Path(__file__).parent.parent.parent / "rules" / "sigma"


def _all_rule_files() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def test_every_rule_file_exists_and_count():
    files = _all_rule_files()
    assert files, "no Sigma rules found under rules/sigma/"
    # Guard against silent rule deletion; update this count when rules are
    # intentionally added/removed.
    assert len(files) == 100, f"expected 100 Sigma rules, found {len(files)}"


def test_no_rule_produces_list_repr_or_true_where():
    """No rule may produce invalid SQL (list-repr in WHERE) or drop its
    selection to (TRUE) — the two pySigma-backend failure modes (P0-01)."""
    bad: list[tuple[str, str]] = []
    for rule_file in _all_rule_files():
        sql, _params = sigma_to_sql(rule_file.read_text())
        if "['" in sql or '["' in sql:
            bad.append((rule_file.name, f"list-repr in SQL: {sql[:80]}"))
        if "(TRUE)" in sql:
            bad.append((rule_file.name, f"selection dropped to (TRUE): {sql[:80]}"))
    assert not bad, "rules producing invalid/over-firing SQL:\n" + "\n".join(
        f"  {n}: {msg}" for n, msg in bad
    )


def test_every_rule_uses_legacy_parameterized_path():
    """Every generated query must use $N placeholders (parameterized) and the
    INTERVAL '1 second' * $N lookback form — the legacy path's signature. Every
    rule must produce NON-EMPTY parameterized SQL (the lookback always adds at
    least one $N param)."""
    for rule_file in _all_rule_files():
        sql, params = sigma_to_sql(rule_file.read_text())
        assert "$" in sql, f"{rule_file.name}: no placeholders in SQL: {sql[:80]}"
        assert "INTERVAL '1 second'" in sql, f"{rule_file.name}: no safe lookback: {sql[:80]}"
        assert params is not None
        assert len(params) > 0, f"{rule_file.name}: empty params (no parameterized values): {sql[:80]}"


def test_every_rule_has_mitre_tags():
    """P4.1: every Sigma rule carries a MITRE ATT&CK technique (attack.t*) and a
    tactic (attack.ta*) tag so the dashboard MITRE heatmap is meaningful."""
    from src.detection.sigma import parse_sigma_rule

    for rule_file in _all_rule_files():
        rule = parse_sigma_rule(rule_file.read_text())
        assert rule.mitre_techniques, f"{rule_file.name}: no attack.t* technique tag"
        assert rule.mitre_tactics, f"{rule_file.name}: no attack.ta* tactic tag"


def test_corpus_covers_key_mitre_tactics():
    """P4.1: the 100-rule corpus spans the five MITRE tactics the moat markets
    (Credential Access, Persistence, Defense Evasion, Lateral Movement,
    Exfiltration). Guards against a corpus that's all one tactic."""
    from src.detection.sigma import parse_sigma_rule

    required = {
        "TA0006",  # Credential Access
        "TA0003",  # Persistence
        "TA0005",  # Defense Evasion
        "TA0008",  # Lateral Movement
        "TA0010",  # Exfiltration
    }
    found: set[str] = set()
    for rule_file in _all_rule_files():
        rule = parse_sigma_rule(rule_file.read_text())
        found.update(rule.mitre_tactics)
    missing = required - found
    assert not missing, f"corpus missing required MITRE tactics: {sorted(missing)}"
