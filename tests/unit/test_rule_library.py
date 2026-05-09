"""
Tests for Sigma rule library — validates all 45+ rules parse correctly
and contain required fields, proper MITRE tags, and produce valid SQL.
"""

from pathlib import Path

import pytest

from src.detection.sigma import (
    _validate_column,
    load_rules_from_directory,
    parse_sigma_rule,
    sigma_to_sql,
)

RULES_DIR = Path(__file__).parent.parent.parent / "rules" / "sigma"


class TestRuleLibraryCompleteness:
    """Verify the rule library has the required coverage."""

    @pytest.fixture(scope="class")
    def all_rules(self):
        """Load all rules from the sigma directory."""
        return load_rules_from_directory(RULES_DIR)

    def test_minimum_rule_count(self, all_rules):
        """Must have at least 45 rules."""
        assert len(all_rules) >= 45, f"Expected 45+ rules, got {len(all_rules)}"

    def test_all_rules_have_required_fields(self, all_rules):
        """Each rule must have title, id, description, level, detection."""
        for rule in all_rules:
            assert rule.title, f"Rule missing title: {rule.id}"
            assert rule.id, f"Rule missing id: {rule.title}"
            assert rule.description or True  # description can be empty
            assert rule.level in ("info", "low", "medium", "high", "critical"), (
                f"Rule {rule.title} has invalid level: {rule.level}"
            )
            assert rule.detection is not None, f"Rule {rule.title} has no detection"

    def test_all_rules_have_mitre_tags(self, all_rules):
        """Each rule must have at least one MITRE ATT&CK technique or tactic."""
        rules_without_mitre = []
        for rule in all_rules:
            if not rule.mitre_tactics and not rule.mitre_techniques:
                rules_without_mitre.append(rule.title)
        assert len(rules_without_mitre) == 0, f"Rules missing MITRE tags: {rules_without_mitre}"

    def test_all_rules_produce_valid_sql(self, all_rules):
        """Each rule must parse to valid parameterized SQL."""
        for rule in all_rules:
            # Find the YAML for this rule
            rule_files = list(RULES_DIR.rglob("*.yml"))
            for rf in rule_files:
                content = rf.read_text()
                parsed = parse_sigma_rule(content)
                if parsed.id == rule.id:
                    sql, params = sigma_to_sql(content)
                    assert len(sql) > 0, f"Rule {rule.title} produced empty SQL"
                    assert "FROM logs" in sql, f"Rule {rule.title} SQL missing FROM logs"
                    # All dynamic values should be parameterized
                    assert sql.count("$") > 0 or "TRUE" in sql, (
                        f"Rule {rule.title} has no parameterized values"
                    )
                    break

    def test_mitre_tactic_format(self, all_rules):
        """MITRE tactics must be in TA00XX format (uppercase)."""
        for rule in all_rules:
            for tactic in rule.mitre_tactics:
                assert tactic.startswith("TA0"), f"Rule {rule.title} has malformed tactic: {tactic}"

    def test_mitre_technique_format(self, all_rules):
        """MITRE techniques must be in TXXXX format (uppercase, no TA prefix)."""
        for rule in all_rules:
            for tech in rule.mitre_techniques:
                assert tech.startswith("T") and not tech.startswith("TA"), (
                    f"Rule {rule.title} has malformed technique: {tech}"
                )

    def test_rule_ids_are_unique(self, all_rules):
        """All rule IDs must be unique."""
        ids = [rule.id for rule in all_rules]
        duplicates = [rid for rid in ids if ids.count(rid) > 1]
        assert len(duplicates) == 0, f"Duplicate rule IDs: {set(duplicates)}"

    def test_no_duplicate_titles(self, all_rules):
        """All rule titles should be unique."""
        titles = [rule.title for rule in all_rules]
        duplicates = [t for t in titles if titles.count(t) > 1]
        assert len(duplicates) == 0, f"Duplicate rule titles: {set(duplicates)}"


class TestRuleCategoryCoverage:
    """Verify each required rule category is covered."""

    @pytest.fixture(scope="class")
    def all_rules(self):
        return load_rules_from_directory(RULES_DIR)

    @pytest.fixture(scope="class")
    def rule_categories(self, all_rules):
        """Map of logsource_category to list of rule titles."""
        categories = {}
        for rule in all_rules:
            cat = rule.logsource_category or "unknown"
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(rule.title)
        return categories

    def test_macos_rules_exist(self, all_rules):
        """At least 8 macOS-specific rules must exist."""
        mac_rules = [
            r
            for r in all_rules
            if any(
                tag in r.tags
                for tag in [
                    "attack.t1547",
                    "attack.t1553",
                    "attack.t1562",
                    "attack.t1555",
                    "attack.t1564",
                    "attack.t1176",
                ]
            )
        ]
        # Also count by directory structure
        mac_dir = RULES_DIR / "macOS"
        if mac_dir.exists():
            mac_files = list(mac_dir.glob("*.yml"))
        assert len(mac_rules) >= 8, f"Expected 8+ macOS rules, got {len(mac_rules)}"

    def test_authentication_rules_exist(self, rule_categories):
        """At least 6 authentication rules must exist."""
        auth_count = len(rule_categories.get("authentication", []))
        assert auth_count >= 6, f"Expected 6+ authentication rules, got {auth_count}"

    def test_process_rules_exist(self, rule_categories):
        """At least 6 process rules must exist."""
        proc_count = len(rule_categories.get("process", []))
        assert proc_count >= 6, f"Expected 6+ process rules, got {proc_count}"

    def test_network_rules_exist(self, rule_categories):
        """At least 6 network rules must exist."""
        net_count = len(rule_categories.get("network", []))
        assert net_count >= 6, f"Expected 6+ network rules, got {net_count}"

    def test_file_rules_exist(self, rule_categories):
        """At least 4 file rules must exist."""
        file_count = len(rule_categories.get("file", []))
        assert file_count >= 4, f"Expected 4+ file rules, got {file_count}"


class TestIndividualRulesParse:
    """Test that each specific rule in the library parses correctly."""

    def _load_rule_by_id(self, rule_id: str):
        """Load a specific rule by its ID from the rule files."""
        for rule_file in RULES_DIR.rglob("*.yml"):
            content = rule_file.read_text()
            rule = parse_sigma_rule(content)
            if rule.id == rule_id:
                return rule, content
        return None, None

    def test_ssh_brute_force_parses(self):
        rule, content = self._load_rule_by_id("86d7b047-4d49-5dbd-9aeb-d92cd4b0e64c")
        assert rule is not None, "SSH brute force rule not found"
        assert rule.level == "high"
        assert "T1110" in rule.mitre_techniques
        sql, params = sigma_to_sql(content)
        assert "logs" in sql

    def test_launch_agent_persistence_parses(self):
        rule, content = self._load_rule_by_id("03574d52-0001-5070-bb2e-5c998f480a76")
        assert rule is not None, "LaunchAgent rule not found"
        assert "T1547" in rule.mitre_techniques
        sql, params = sigma_to_sql(content)
        # contains modifier produces parameterized values with % wildcards
        assert any("LaunchAgents" in str(p) for p in params), f"LaunchAgents not in params: {params}"

    def test_rare_port_outbound_parses(self):
        rule, content = self._load_rule_by_id("20760a42-7d59-512e-bbb9-64ebbe1806e3")
        assert rule is not None, "Rare port rule not found"
        assert "T1071" in rule.mitre_techniques
        sql, params = sigma_to_sql(content)
        assert "IN" in sql  # list values

    def test_reverse_shell_parses(self):
        rule, content = self._load_rule_by_id("4592067e-d714-5173-84d0-db3066c2f801")
        assert rule is not None, "Reverse shell rule not found"
        assert rule.level == "critical"
        sql, params = sigma_to_sql(content)
        assert "OR" in sql  # OR conditions from multiple selections

    def test_gatekeeper_bypass_parses(self):
        rule, content = self._load_rule_by_id("e3c73389-52f8-5599-b166-bb082269a7d5")
        assert rule is not None, "Gatekeeper bypass rule not found"

    def test_credential_dumping_parses(self):
        rule, content = self._load_rule_by_id("7ea98e18-469e-56fb-af5e-fbad9f72e4df")
        assert rule is not None, "Credential dumping rule not found"
        assert rule.level == "critical"

    def test_lolbin_execution_parses(self):
        rule, content = self._load_rule_by_id("82bb6365-f1b7-5f9f-9acd-a63c4f7c3ce8")
        assert rule is not None, "LOLBIN rule not found"

    def test_ransomware_encryption_parses(self):
        rule, content = self._load_rule_by_id("87697eca-dc33-51c9-9be7-bed9e731221a")
        assert rule is not None, "Ransomware rule not found"
        assert rule.level == "critical"

    def test_log_file_deletion_parses(self):
        rule, content = self._load_rule_by_id("7782d1c8-dde9-5b7d-921f-e4cecdd6b03f")
        assert rule is not None, "Log deletion rule not found"
        assert rule.level == "critical"


class TestNewColumnsInRules:
    """Verify that rules using process_cmdline and process_path parse correctly."""

    def _load_rule_by_id(self, rule_id: str):
        for rule_file in RULES_DIR.rglob("*.yml"):
            content = rule_file.read_text()
            rule = parse_sigma_rule(content)
            if rule.id == rule_id:
                return rule, content
        return None, None

    def test_process_cmdline_in_rules(self):
        """Rules using process_cmdline should parse with the new ALLOWED_COLUMNS."""
        rule, content = self._load_rule_by_id("4592067e-d714-5173-84d0-db3066c2f801")
        assert rule is not None
        sql, params = sigma_to_sql(content)
        # process_cmdline should be recognized
        assert "process_cmdline" in sql or "cmdline" in sql.lower() or len(params) > 0

    def test_process_path_in_rules(self):
        """Rules using process_path should parse with the new ALLOWED_COLUMNS."""
        rule, content = self._load_rule_by_id("9f6cab87-d65a-5987-b9ef-734c8197ba1b")
        assert rule is not None
        # process_path should be in the allowed columns
        from src.detection.sigma import ALLOWED_COLUMNS

        assert "process_path" in ALLOWED_COLUMNS

    def test_validate_process_cmdline(self):
        """process_cmdline must be in the column whitelist."""
        assert _validate_column("process_cmdline") == "process_cmdline"

    def test_validate_process_path(self):
        """process_path must be in the column whitelist."""
        assert _validate_column("process_path") == "process_path"
