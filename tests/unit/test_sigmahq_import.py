"""Tests for the SigmaHQ import pipeline (W2.1).

Covers:
- classification ladder: imported / needs_rewrite / unsupported with named
  reasons — authentic SigmaHQ dialect fixtures (CamelCase fields, logsource
  category/product taxonomy, condition inside detection)
- the no-silent-drops guarantee (every candidate file yields a verdict)
- staging: imported rules born `enabled: false` + tagged source.sigmahq,
  written OUTSIDE rules/sigma/; needs-rewrite/unsupported never staged
- the boot reconciler's `enabled` frontmatter extension (promoted imports
  enter the DB DISABLED; shipped rules default True — unchanged)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.detection.sigmahq import (
    OUTCOME_IMPORTED,
    OUTCOME_NEEDS_REWRITE,
    OUTCOME_UNSUPPORTED,
    classify_directory,
    classify_rule,
    generate_report,
    write_staged_rules,
)


def _rule(yaml_body: str) -> str:
    return yaml_body


POWERSHELL_RULE = _rule(
    """
title: Suspicious PowerShell Encoded Command
id: 7AE71C74-0E38-4A3D-9C1B-A1B0E1B24D0A
status: stable
description: Detects encoded command usage
references:
    - https://example.com/att
author: Florian Roth
date: 2019/01/16
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection
falsepositives:
    - Admin scripts
level: high
"""
)


class TestClassifyRule:
    def test_imported_process_creation(self):
        v = classify_rule("windows/pwsh.yml", POWERSHELL_RULE)
        assert v.outcome == OUTCOME_IMPORTED
        assert v.reasons == []
        assert v.translated_yaml is not None
        assert "source.sigmahq" in v.translated_yaml
        assert "enabled: false" in v.translated_yaml
        assert "logsource" in v.translated_yaml
        data = __import__("yaml").safe_load(v.translated_yaml)
        assert data["logsource"]["category"] == "process"
        assert data["detection"]["selection"]["process_path|endswith"] == "\\powershell.exe"
        assert data["detection"]["selection"]["process_cmdline|contains"] == " -enc "
        assert data["id"] == "7AE71C74-0E38-4A3D-9C1B-A1B0E1B24D0A"  # provenance kept

    def test_imported_file_event(self):
        v = classify_rule(
            "file.yml",
            _rule(
                """
title: Suspicious File Drop
id: 11111111-2222-3333-4444-555566667777
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\\Temp\\'
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_IMPORTED
        assert "file_path|contains" in v.translated_yaml

    def test_imported_network_eq_int_port(self):
        v = classify_rule(
            "net.yml",
            _rule(
                """
title: Outbound to Odd Port
id: 22222222-2222-3333-4444-555566667777
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: 10.0.0.5
        DestinationPort: 4444
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_IMPORTED
        assert "destination_port: 4444" in v.translated_yaml

    def test_imported_aggregation_condition(self):
        v = classify_rule(
            "agg.yml",
            _rule(
                """
title: Multiple Encoded Commands
id: 33333333-2222-3333-4444-555566667777
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection | count() by CommandLine > 3
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_IMPORTED
        assert "count(*) by process_cmdline > 3" in v.translated_yaml

    def test_imported_and_not_condition(self):
        v = classify_rule(
            "andnot.yml",
            _rule(
                """
title: PowerShell But Not Admin
id: 33333333-2222-3333-4444-555566667778
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    filter_admin:
        User|contains: 'admin'
    condition: selection and not filter_admin
level: low
"""
            ),
        )
        assert v.outcome == OUTCOME_IMPORTED, v.reasons

    def test_needs_rewrite_unmapped_field(self):
        v = classify_rule(
            "parent.yml",
            _rule(
                """
title: Office Spawning Process
id: 33333333-2222-3333-4444-555566667779
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\winword.exe'
        Image|contains: 'powershell'
    condition: selection
level: high
"""
            ),
        )
        assert v.outcome == OUTCOME_NEEDS_REWRITE
        assert any("ParentImage" in r for r in v.reasons)
        assert v.translated_yaml is None

    def test_needs_rewrite_wildcard_plain_value(self):
        v = classify_rule(
            "wild.yml",
            _rule(
                """
title: Wildcard Path
id: 33333333-2222-3333-4444-55556666777a
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\\Users\\*\\powershell.exe'
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_NEEDS_REWRITE
        assert any("wildcard" in r for r in v.reasons)

    def test_needs_rewrite_glob_inside_pattern(self):
        v = classify_rule(
            "glob.yml",
            _rule(
                """
title: Glob In Contains
id: 33333333-2222-3333-4444-55556666777b
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '* -enc *'
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_NEEDS_REWRITE
        assert any("glob" in r for r in v.reasons)

    def test_needs_rewrite_unsupported_modifier(self):
        v = classify_rule(
            "all.yml",
            _rule(
                """
title: All Modifier
id: 33333333-2222-3333-4444-55556666777c
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' -enc '
            - ' -w '
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_NEEDS_REWRITE
        assert any("contains|all" in r for r in v.reasons)

    def test_needs_rewrite_null_selector(self):
        v = classify_rule(
            "null.yml",
            _rule(
                """
title: Null Selector
id: 33333333-2222-3333-4444-55556666777d
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: null
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_NEEDS_REWRITE
        assert any("null" in r for r in v.reasons)

    def test_needs_rewrite_compiler_warning_missing_selection(self):
        v = classify_rule(
            "oneof.yml",
            _rule(
                """
title: One-Of Condition
id: 33333333-2222-3333-4444-55556666777e
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        Image|endswith: '\\a.exe'
    selection_other:
        Image|endswith: '\\b.exe'
    condition: 1 of selection_*
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_NEEDS_REWRITE
        assert any("compiler warning" in r for r in v.reasons)

    def test_needs_rewrite_aggregation_group_unmapped(self):
        v = classify_rule(
            "agggroup.yml",
            _rule(
                """
title: Count By Unmapped
id: 33333333-2222-3333-4444-55556666777e
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\a.exe'
    condition: selection | count() by ParentImage > 2
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_NEEDS_REWRITE
        assert any("ParentImage" in r for r in v.reasons)

    def test_unsupported_logsource_category(self):
        v = classify_rule(
            "web.yml",
            _rule(
                """
title: Webshell Probe
id: 33333333-2222-3333-4444-55556666777f
logsource:
    category: webserver
    product: windows
detection:
    selection:
        cs-method: GET
    condition: selection
level: high
"""
            ),
        )
        assert v.outcome == OUTCOME_UNSUPPORTED
        assert any("webserver" in r for r in v.reasons)

    def test_unsupported_product_cloud(self):
        v = classify_rule(
            "cloud.yml",
            _rule(
                """
title: Azure suspicious sign-in
id: 33333333-2222-3333-4444-555566667780
logsource:
    category: process_creation
    product: azure
detection:
    selection:
        Image|endswith: '\\a.exe'
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_UNSUPPORTED
        assert any("azure" in r for r in v.reasons)

    def test_unsupported_no_mappable_field(self):
        v = classify_rule(
            "dns.yml",
            _rule(
                """
title: DNS Query
id: 33333333-2222-3333-4444-555566667781
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        Query|contains: 'evil.example'
    condition: selection
level: medium
"""
            ),
        )
        assert v.outcome == OUTCOME_UNSUPPORTED
        assert any("no selection field maps" in r for r in v.reasons)

    def test_unsupported_missing_title(self):
        v = classify_rule("x.yml", "logsource:\n  category: process_creation\n  product: windows\n")
        assert v.outcome == OUTCOME_UNSUPPORTED
        assert any("title" in r for r in v.reasons)

    def test_unsupported_invalid_yaml(self):
        v = classify_rule("y.yml", "title: [unclosed\n  bad")
        assert v.outcome == OUTCOME_UNSUPPORTED
        assert any("invalid YAML" in r for r in v.reasons)


class TestDirectoryAndReport:
    def _corpus(self, tmp_path) -> Path:
        (tmp_path / "windows" / "process_creation").mkdir(parents=True)
        (tmp_path / "windows" / "process_creation" / "good.yml").write_text(POWERSHELL_RULE)
        (tmp_path / "windows" / "process_creation" / "bad.yml").write_text("title: [broken")
        (tmp_path / "cloud").mkdir(parents=True)
        (tmp_path / "cloud" / "azure.yml").write_text(
            _rule(
                """
title: Azure thing
id: 44444444-2222-3333-4444-555566667782
logsource:
    category: process_creation
    product: azure
detection:
    selection:
        Image|endswith: 'a.exe'
    condition: selection
level: low
"""
            )
        )
        return tmp_path

    def test_every_file_yields_a_verdict(self, tmp_path):
        corpus = self._corpus(tmp_path)
        verdicts = classify_directory(corpus)
        assert len(verdicts) == 3  # no silent drops
        outcomes = {v.outcome for v in verdicts}
        assert OUTCOME_IMPORTED in outcomes
        assert OUTCOME_UNSUPPORTED in outcomes

    def test_report_counts_and_markdown(self, tmp_path):
        verdicts = classify_directory(self._corpus(tmp_path))
        report = generate_report(verdicts)
        assert report["total"] == 3
        assert sum(report["counts"].values()) == report["total"]
        md = __import__("src.detection.sigmahq", fromlist=["report_markdown"]).report_markdown(
            report
        )
        assert "good.yml" in md
        assert "bad.yml" in md
        assert "azure.yml" in md
        assert "No silent drops" in md

    def test_staging_writes_imported_only_born_disabled(self, tmp_path):
        verdicts = classify_directory(self._corpus(tmp_path))
        staging = tmp_path / "staging"
        staged = write_staged_rules(verdicts, staging)
        assert staged == 1
        # staged files live OUTSIDE rules/sigma (staging dir here is tmp)
        files = list(staging.rglob("*.yml"))
        assert len(files) == 1
        content = files[0].read_text()
        assert "enabled: false" in content
        assert "source.sigmahq" in content
        assert files[0].parent.name == "process"  # OUR category, not sigmahq's

    def test_classify_directory_missing_dir_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            classify_directory(tmp_path / "nope")

    def test_slug_and_title(self):
        v = classify_rule("s.yml", POWERSHELL_RULE)
        assert v.title == "Suspicious PowerShell Encoded Command"


class TestReconcilerEnabledFlag:
    """The W2.1 import extension: `enabled: false` frontmatter inserts the
    rule DISABLED — arming stays an explicit operator decision."""

    async def _reconcile(self, tmp_path, yaml_text: str):
        from src.api.main import load_sigma_rules

        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock(return_value=None)
        mock_conn.fetch = AsyncMock(return_value=[])

        class AsyncCtx:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(return_value=AsyncCtx())
        (Path(tmpdir := tmp_path) / "rule.yml").write_text(yaml_text)
        with (
            patch("src.api.main.get_pool", AsyncMock(return_value=mock_pool)),
            patch("src.api.main.RULES_DIR", Path(tmpdir)),
        ):
            await load_sigma_rules()
        # AUD-012: the batch rides ONE executemany call; row tuple index 4
        # is the `enabled` positional.
        return mock_conn.executemany.await_args.args[1][0]

    async def test_import_rule_inserts_disabled(self, tmp_path):
        call = await self._reconcile(
            tmp_path,
            "title: Imported Rule\nlogsource:\n  category: process\n"
            "detection:\n  selection:\n    process_name: x.exe\n  condition: selection\n"
            "enabled: false\n",
        )
        assert call[4] is False  # the enabled positional

    async def test_shipped_rule_defaults_enabled(self, tmp_path):
        call = await self._reconcile(
            tmp_path,
            "title: Shipped Rule\nlogsource:\n  category: process\n"
            "detection:\n  selection:\n    process_name: x.exe\n  condition: selection\n",
        )
        assert call[4] is True
