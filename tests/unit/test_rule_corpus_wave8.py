"""Fix Wave 8 rule-corpus pins (AUD-076, AUD-077, AUD-078, AUD-079, AUD-081).

Every changed rule gets a compile-shape pin, and the corpus gains the
duplicate-detection guard that AUD-078/081 make enforceable: no two rule
files may compile to IDENTICAL detection SQL (same WHERE, same bound params,
same aggregation shape). The verification sweep that discovered the DNS twin
pair (dns_tunneling + suspicious_dns compiled identically — a pair the audit
index did not carry) ran over the whole corpus; this test pins it at zero so
a future duplicate cannot ship silently.

Per-rule pins:
- AUD-076  c2_beaconing groups by DESTINATION (the description's claim), and
           counts the destination column so the NULL-destination bucket stays
           at zero.
- AUD-077  both RFC1918 filter lists carry per-octet 172.16-31 prefixes — the
           old startswith shortcuts ('172.2', '172.3') suppressed PUBLIC
           172.32-39 / 172.200-255.
- AUD-078  ntlm_relay_attempt.yml is deleted; the pass_the_hash survivor
           carries BOTH technique hypotheses (T1550 + T1557).
- AUD-079a suspicious_tmp_process selects process_path (the parser sets
           file_path ONLY on file-category rows — the old rule could never
           match).
- AUD-079b scp_exfil_external is reworked to tool-level scp/sftp/rsync (the
           literal-"external" cmdline condition had no producer).
"""

from pathlib import Path

import pytest

from src.detection.coverage import WAIVED_FUTURE_SOURCES
from src.detection.sigma import SigmaParser, sigma_to_sql
from src.ingestion.parser import parse_osquery_line

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "sigma"

# The complete RFC1918 172.16-31/12 private block, per-octet (AUD-077).
PRIVATE_172_PREFIXES = {f"172.{n}." for n in range(16, 32)}


def _compile(relpath: str):
    yaml_text = (RULES_DIR / relpath).read_text()
    parser = SigmaParser()
    rule = parser.parse(yaml_text)
    where, params, agg = parser.compile_where(rule)
    return rule, parser, where, params, agg


class TestC2BeaconingGroupsByDestination:
    """AUD-076: the aggregation must measure what the description claims."""

    def test_group_by_is_destination_ip(self):
        _rule, _parser, _where, _params, agg = _compile("network/c2_beaconing.yml")
        assert agg is not None
        assert agg.group_by == "destination_ip"
        assert agg.group_by != "source_ip"

    def test_compiled_sql_groups_by_destination_and_counts_it(self):
        sql, _params = sigma_to_sql((RULES_DIR / "network/c2_beaconing.yml").read_text())
        assert "GROUP BY destination_ip" in sql
        assert "GROUP BY source_ip" not in sql
        # COUNT(destination_ip), not COUNT(*): the NULL-destination bucket
        # counts zero, so connection rows without a remote address never alert.
        assert "COUNT(destination_ip)" in sql
        assert "COUNT(*)" not in sql


class TestRFC1918ShortcutListsArePerOctet:
    """AUD-077: the 172.16-31/12 block needs per-octet prefix entries."""

    @pytest.mark.parametrize(
        "relpath",
        ["authentication/login_unusual_geography.yml", "network/data_exfiltration_volume.yml"],
    )
    def test_list_is_the_exact_private_block(self, relpath):
        _rule, _parser, _where, params, _agg = _compile(relpath)
        p172 = {p for p in params if isinstance(p, str) and p.startswith("172.")}
        assert p172 == PRIVATE_172_PREFIXES, (relpath, sorted(p172))
        # The other two private /8-/16 blocks keep their correct prefix forms.
        assert "10." in params and "192.168." in params
        # The buggy bare shortcuts must never come back.
        assert "172.2" not in params and "172.3" not in params


class TestNtlmRelayTwinMerged:
    """AUD-078: one detection, one alert — the relay twin is gone."""

    def test_ntlm_relay_file_deleted(self):
        assert not (RULES_DIR / "network/ntlm_relay_attempt.yml").exists()

    def test_survivor_carries_both_technique_hypotheses(self):
        rule, parser, _where, _params, _agg = _compile("network/pass_the_hash_smb.yml")
        assert parser.warnings == []
        assert set(rule.mitre_techniques) == {"T1550", "T1557"}
        assert "TA0008" in rule.mitre_tactics and "TA0006" in rule.mitre_tactics

    def test_waiver_registry_tracks_the_merge(self):
        assert "ntlm_relay_attempt" not in WAIVED_FUTURE_SOURCES
        assert "pass_the_hash_smb_authentication" in WAIVED_FUTURE_SOURCES


class TestSuspiciousTmpProcessUsesProcessPath:
    """AUD-079a: process rows carry process_path, never file_path."""

    def test_selection_binds_process_path(self):
        sql, _params = sigma_to_sql((RULES_DIR / "process/suspicious_tmp_process.yml").read_text())
        assert "process_path LIKE" in sql
        assert "file_path LIKE" not in sql

    def test_parser_contract_process_rows_have_process_path_not_file_path(self):
        """The parser contract the fix rides on, pinned directly: a process
        row maps `path` -> process_path and NEVER file_path; a file row maps
        `target_path` -> file_path."""
        import json

        process_row = parse_osquery_line(
            json.dumps(
                {
                    "name": "processes",
                    "hostIdentifier": "h1",
                    "unixTime": 1758200000,
                    "columns": {
                        "pid": "42",
                        "name": "implant",
                        "path": "/tmp/implant",
                        "cmdline": "/tmp/implant --beacon",
                    },
                    "action": "added",
                }
            )
        )
        assert process_row is not None
        assert process_row.process_path == "/tmp/implant"
        assert process_row.file_path is None
        assert process_row.event_category == "process"

        file_row = parse_osquery_line(
            json.dumps(
                {
                    "name": "file_events",
                    "hostIdentifier": "h1",
                    "unixTime": 1758200000,
                    "columns": {"target_path": "/tmp/drop", "action": "CREATED"},
                    "action": "added",
                }
            )
        )
        assert file_row is not None
        assert file_row.file_path == "/tmp/drop"
        assert file_row.process_path is None


class TestScpTransferReworkedToToolLevel:
    """AUD-079b: the literal-'external' selection could never fire."""

    def test_old_file_gone_rework_in_place(self):
        assert not (RULES_DIR / "process/scp_exfil_external.yml").exists()
        assert (RULES_DIR / "process/scp_sftp_rsync_transfer.yml").exists()

    def test_selection_is_the_tool_list_without_the_dead_condition(self):
        rule, parser, _where, params, _agg = _compile("process/scp_sftp_rsync_transfer.yml")
        assert parser.warnings == []
        assert {"scp", "sftp", "rsync"} <= set(params)
        assert "external" not in params
        assert rule.level == "medium"
        assert rule.title == "SCP/SFTP/Rsync File Transfer Execution"
        assert "attack.t1048" in rule.tags

    def test_reworked_rule_still_compiles_to_bounded_sql(self):
        sql, params = sigma_to_sql((RULES_DIR / "process/scp_sftp_rsync_transfer.yml").read_text())
        assert "process_name IN" in sql
        assert "INTERVAL '1 second'" in sql
        assert len(params) > 0


class TestDNSTwinMerged:
    """AUD-081 (found by the Wave-8 duplicate sweep): dns_tunneling and
    suspicious_dns compiled identically — every future resolver event would
    have fired two alerts under two names."""

    def test_suspicious_dns_file_deleted(self):
        assert not (RULES_DIR / "network/suspicious_dns.yml").exists()

    def test_survivor_is_the_honest_placeholder(self):
        rule, parser, _where, _params, _agg = _compile("network/dns_tunneling.yml")
        assert parser.warnings == []
        assert rule.title == "DNS Activity Indicator (port 53)"
        assert rule.level == "low"

    def test_impossible_event_type_dropped(self):
        """network-category rows are 'connection'/'end' — event_type 'start'
        can never occur, so the old selection could never match."""
        sql, _params = sigma_to_sql((RULES_DIR / "network/dns_tunneling.yml").read_text())
        assert "event_type = " not in sql

    def test_waiver_registry_tracks_the_rename(self):
        assert "dns_tunneling_indicators" not in WAIVED_FUTURE_SOURCES
        assert "suspicious_dns_query" not in WAIVED_FUTURE_SOURCES
        assert "dns_activity_indicator_port_53" in WAIVED_FUTURE_SOURCES


class TestNoDuplicateDetectionsInCorpus:
    """The corpus-wide guard AUD-078/081 make enforceable (compile-level).

    Two rules compiling to identical (WHERE, params, aggregation) shape are
    one detection wearing two names: every matching event fires twice. If
    this test fails with a legitimate pair, the pair is the finding —
    merge it, or make the detections actually differ.
    """

    def test_all_rule_compiles_are_unique(self):
        groups: dict[tuple, list[str]] = {}
        for rule_file in sorted(RULES_DIR.rglob("*.yml")):
            parser = SigmaParser()
            rule = parser.parse(rule_file.read_text())
            where, params, agg = parser.compile_where(rule)
            key = (
                where,
                tuple(repr(p) for p in params),
                (agg.group_by if agg else None, agg.threshold if agg else None),
            )
            groups.setdefault(key, []).append(f"{rule_file.parent.name}/{rule_file.name}")
        duplicates = {k: v for k, v in groups.items() if len(v) > 1}
        assert not duplicates, (
            "duplicate detections found (one event would fire multiple alerts):\n"
            + "\n".join(f"  {v}" for v in duplicates.values())
        )
