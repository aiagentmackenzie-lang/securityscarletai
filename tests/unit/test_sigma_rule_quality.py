"""Sigma rule-quality gate (V0.3 -- CI-enforced detection engineering).

Three honest gates over every rule in rules/sigma/:
  1. STRUCTURE -- parses via the real Sigma engine loader, carries the
     required fields (id as UUID, title, status, level, logsource.category,
     detection.condition, MITRE tags).
  2. VOCABULARY -- for rules aimed at ingested categories: every
     event_action token must match the closed ingest vocabulary (equal to
     or a substring of a known token, mirroring |contains semantics). The
     P1.2b live-fire proved the old tokens (auth_failure, outbound_connection,
     tgs_request, …) match NOTHING the pipeline produces -- a rule with a
     dead token is not a detection, it's a decoration.
  3. WAIVER DISCIPLINE -- future-source rules must be listed in
     WAIVED_FUTURE_SOURCES (single registry shared with the coverage map),
     and every registered waiver must correspond to an existing rule. No
     silent drift on either side.
"""

import uuid
from pathlib import Path

import pytest
import yaml

from src.detection.coverage import (
    INGESTED_CATEGORIES,
    WAIVED_FUTURE_SOURCES,
    _waiver_key,
)
from src.detection.sigma import load_rules_from_directory
from src.ingestion import schemas as vocabulary

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "sigma"

# The closed vocabulary every non-waived rule must select from.
# Parser tokens + the auth-shipper contract + NeuralGuard verdicts.
KNOWN_TOKENS = {
    vocabulary.EVENT_ACTION_PROCESS_START,
    vocabulary.EVENT_ACTION_PROCESS_END,
    vocabulary.EVENT_ACTION_NETWORK_CONNECTION,
    vocabulary.EVENT_ACTION_NETWORK_DISCONNECT,
    vocabulary.EVENT_ACTION_NETWORK_LISTEN,
    vocabulary.EVENT_ACTION_AUTH_SUCCESS,
    vocabulary.EVENT_ACTION_SESSION_CLOSED,
    vocabulary.EVENT_ACTION_FILE_CREATED,
    vocabulary.EVENT_ACTION_FILE_MODIFIED,
    vocabulary.EVENT_ACTION_FILE_DELETED,
    vocabulary.EVENT_ACTION_FILE_OPENED,
    vocabulary.EVENT_ACTION_FILE_EVENT,
    vocabulary.EVENT_ACTION_CONFIG_OBSERVED,
    vocabulary.EVENT_ACTION_COMMAND_OBSERVED,
    vocabulary.EVENT_ACTION_ACCOUNT_CREATED,  # windows_events 4720 (V0.6b)
    vocabulary.EVENT_ACTION_AUTH_FAILED,
    vocabulary.EVENT_ACTION_VERDICT_BLOCK,
    # AI-usage domain (V0.4/5 item 3)
    vocabulary.EVENT_ACTION_AI_AGENT_RUN,
    vocabulary.EVENT_ACTION_MCP_TOOL_CALL,
    vocabulary.EVENT_ACTION_MCP_TOOL_DENIED,
    vocabulary.EVENT_ACTION_AI_PROMPT_INJECTION,
    # Deception domain (W1.5: HONEYTRAP / canary playbook)
    vocabulary.EVENT_ACTION_DECEPTION_SERVICE_PROBE,
    vocabulary.EVENT_ACTION_DECEPTION_CANARY_ACCESS,
    vocabulary.EVENT_ACTION_DECEPTION_TOKEN_USE,
}

# Legal event_type values per category -- a rule demanding event_type=start
# on file rows can never fire (FIM rows are 'change'); this gate catches it.
LEGAL_EVENT_TYPES = {
    "process": {"start", "end", "info"},
    "network": {"connection", "end"},
    "file": {"change"},
    "authentication": {"start", "end"},
    "configuration": {"info"},
    "intrusion_detection": {"info"},
    "ai": {"info", "start", "end"},
    "deception": {"info"},
}

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "level",
    "tags",
)


def _all_rule_files():
    files = sorted(RULES_DIR.rglob("*.yml"))
    assert files, "sigma rules directory is empty -- nothing to gate"
    return files


def _token_compliant(token: str) -> bool:
    """|contains semantics: exact match or substring of a known token."""
    t = token.lower()
    return any(t == v or t in v for v in KNOWN_TOKENS)


class TestSigmaStructuralQuality:
    def test_every_rule_loads_through_the_engine(self):
        rules = load_rules_from_directory(RULES_DIR)
        files = _all_rule_files()
        assert len(rules) == len(files), "engine loaded fewer rules than files exist"

    def test_required_fields_present(self):
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            for field in REQUIRED_FIELDS:
                assert doc.get(field), f"{path.name}: missing required field '{field}'"

    def test_ids_are_valid_uuids(self):
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            try:
                uuid.UUID(str(doc.get("id")))
            except (ValueError, AttributeError, TypeError):
                pytest.fail(f"{path.name}: id is not a valid UUID")

    def test_levels_are_known(self):
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            level = str(doc.get("level", "")).lower()
            assert level in {"info", "low", "medium", "high", "critical"}, (
                f"{path.name}: invalid level '{level}'"
            )

    def test_mitre_tags_present(self):
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            tags = doc.get("tags") or []
            assert any(str(t).startswith("attack.t") for t in tags), (
                f"{path.name}: no MITRE technique tag"
            )

    def test_condition_present(self):
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            detection = doc.get("detection") or {}
            assert detection.get("condition"), f"{path.name}: detection.condition missing"

    def test_event_type_matches_category_pipeline(self):
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            if _waiver_key(str(doc.get("title", ""))) in WAIVED_FUTURE_SOURCES:
                continue  # dormant-by-source regardless of event_type
            category = (doc.get("logsource") or {}).get("category")
            legal = LEGAL_EVENT_TYPES.get(category)
            if legal is None:
                continue  # future-source category (waiver handles)
            detection = doc.get("detection") or {}
            for key, selection in detection.items():
                if key in ("condition", "timeframe") or not isinstance(selection, dict):
                    continue
                et_key = next((k for k in selection if k.split("|")[0] == "event_type"), None)
                if et_key is not None and et_key is not None:
                    values = selection[et_key]
                    values = values if isinstance(values, list) else [values]
                    for v in values:
                        assert str(v) in legal, (
                            f"{path.name}: event_type '{v}' can never occur for "
                            f"category '{category}' (legal: {sorted(legal)})"
                        )


class TestSigmaVocabularyCompliance:
    """event_action tokens must match the closed ingest vocabulary."""

    def test_non_waived_ingested_rules_use_known_tokens(self):
        violations = []
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            title = str(doc.get("title", ""))
            if _waiver_key(title) in WAIVED_FUTURE_SOURCES:
                continue  # documented future-source rule -- exempt
            category = (doc.get("logsource") or {}).get("category")
            if category not in INGESTED_CATEGORIES:
                violations.append(f"{path.name}: category '{category}' not ingested -- waive it")
                continue
            detection = doc.get("detection") or {}
            for key, selection in detection.items():
                if key in ("condition", "timeframe") or not isinstance(selection, dict):
                    continue
                for sel_key in selection:
                    if sel_key.split("|")[0].strip() != "event_action":
                        continue
                    value = selection[sel_key]
                    tokens = value if isinstance(value, list) else [value]
                    for tok in tokens:
                        tok = str(tok)
                        if "|contains" in sel_key:
                            if not _token_compliant(tok):
                                violations.append(
                                    f"{path.name}: event_action|contains '{tok}' matches no "
                                    "vocabulary token -- dead rule"
                                )
                        elif tok.lower() not in KNOWN_TOKENS:
                            violations.append(
                                f"{path.name}: event_action '{tok}' is not a vocabulary "
                                "token -- dead rule (fix or waive)"
                            )
        assert not violations, "vocabulary violations:\n" + "\n".join(violations)

    def test_waiver_registry_is_bidirectional(self):
        """Every registered waiver exists on disk; every future-source rule
        on disk is registered. Drift on either side is a CI failure."""
        titles = {}
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            titles[_waiver_key(str(doc["title"]))] = path.name

        stale = set(WAIVED_FUTURE_SOURCES) - set(titles)
        assert not stale, f"waivers pointing at nonexistent rules: {stale}"

        # Rules whose category is ingested but tokens can never match MUST
        # be registered (otherwise the compliance gate already failed them) --
        # this check catches the inverse: ingested-category rules with DEAD
        # tokens that someone tried to exempt silently.
        for path in _all_rule_files():
            doc = yaml.safe_load(path.read_text())
            key = _waiver_key(str(doc["title"]))
            category = (doc.get("logsource") or {}).get("category")
            if key in WAIVED_FUTURE_SOURCES and category in INGESTED_CATEGORIES:
                # waiver only valid if the rule actually selects non-ingestable
                # vocabulary or a source we don't have -- the reason must say so
                reason = WAIVED_FUTURE_SOURCES[key]
                assert reason.startswith("future source:"), (
                    f"{path.name}: waiver reason must document the future source"
                )

    def test_waiver_reasons_are_documented(self):
        for key, reason in WAIVED_FUTURE_SOURCES.items():
            assert len(reason) > 15, f"waiver '{key}' needs a real reason"
            assert "future source" in reason
