"""SigmaHQ community-rule import pipeline (W2.1) — classify, never silently
drop, and never auto-arm an external rule.

The pipeline turns a local SigmaHQ rules checkout (the operator clones
https://github.com/SigmaHQ/sigma and points this tool at the rules
directory — the import path itself never touches the network) into an
honest classification report:

  imported       — the rule translates into OUR Sigma dialect and compiles
                   through the PRODUCTION parser with zero warnings. It is
                   staged (NOT under rules/sigma/, so the boot reconciler
                   cannot auto-arm it) with `enabled: false` in its
                   frontmatter; an operator promotes + arms it explicitly.
  needs_rewrite  — one explicit, named problem away from importable (an
                   unmapped field, a wildcard in a value, an unsupported
                   modifier, a complex condition, a parser warning). The
                   rule is NOT staged; the report names the reason.
  unsupported    — no viable mapping at all (logsource we do not ingest,
                   invalid YAML, missing detection/condition). Report-only.

No silent drops: every candidate file appears in the report with a reason.

Why classification is conservative: our compiler's plain (eq) values are
exact string comparisons — a Sigma glob value like `C:\\*` compiled as
equality would be silently narrower, and an unmapped selection field raises
a hard parser error. A rule whose semantics we cannot represent faithfully
is a needs-rewrite or unsupported, never an approximation (the F-20
fail-safe doctrine applied to import: never widen, never guess).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from src.config.logging import get_logger
from src.detection.sigma import SigmaParser

log = get_logger("detection.sigmahq")

# The marker tag added to every staged rule (the assessment contract:
# "rules tagged source: sigmahq").
SIGMAHQ_TAG = "source.sigmahq"
# Born disabled: the frontmatter `enabled` flag (an import extension the
# boot reconciler respects — W2.1) keeps staged-then-promoted rules from
# arming before an operator reviews them.
BORN_DISABLED = False

# SigmaHQ logsource products our fleet actually ingests. Anything else
# (azure / gcp / okta / office365 / ...) is unsupported, stated per rule.
SIGMAHQ_PRODUCTS_INGESTED = {"windows", "linux", "unix", "macos"}

# SigmaHQ logsource.category → our event_category. Only categories whose
# FIELD vocabulary can plausibly map are listed; everything else is
# unsupported with a named reason (the report is the honest artifact).
SIGMAHQ_CATEGORY_MAP = {
    "process_creation": "process",
    "file_event": "file",
    "file_change": "file",
    "file_rename": "file",
    "file_delete": "file",
    "network_connection": "network",
    "dns_query": "network",
}

# SigmaHQ CamelCase selection fields → ingested columns (keys lowercase).
# A field absent from this map is NOT dropped — it classifies the rule
# needs-rewrite naming the field (dropping a selection term would WIDEN
# the match — the one direction we never go).
SIGMAHQ_FIELD_MAP = {
    "image": "process_path",
    "processname": "process_name",
    "commandline": "process_cmdline",
    "user": "user_name",
    "username": "user_name",
    "targetfilename": "file_path",
    "hashes": "file_hash",
    "hash": "file_hash",
    "destinationip": "destination_ip",
    "destinationport": "destination_port",
    "sourceip": "source_ip",
    "host": "host_name",
    "hostname": "host_name",
    "computername": "host_name",
    "workstationname": "host_name",
}

# Modifiers our production parser compiles faithfully (sigma.py MODIFIERS).
SUPPORTED_MODIFIERS = {"contains", "endswith", "startswith", "re"}
# Sigma glob wildcards. Inside a LIKE-family modifier value they would be
# SQL-literal (narrower than Sigma semantics); in plain equality they are
# literal too. Both classify needs-rewrite — wildcard translation is the
# operator's rewrite decision, never an import guess.
GLOB_CHARS = ("*", "?")

OUTCOME_IMPORTED = "imported"
OUTCOME_NEEDS_REWRITE = "needs_rewrite"
OUTCOME_UNSUPPORTED = "unsupported"


@dataclass
class ImportVerdict:
    """The classification of ONE candidate rule — no silent drops."""

    source_file: str
    outcome: str
    title: str
    reasons: list[str] = field(default_factory=list)
    translated_yaml: str | None = None  # set for imported rules


def _slugify(title: str) -> str:
    """Title → a filesystem-safe rule-file stem."""
    lowered = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "_", lowered.lower()).strip("_")
    return slug or "untitled_rule"


def _field_parts(raw_field: str) -> tuple[str, str | None]:
    """'Image|endswith' -> ('image', 'endswith'); 'Image' -> ('image', None)."""
    if "|" in raw_field:
        name, _, modifier = raw_field.partition("|")
        return name.strip().lower(), modifier.strip()
    return raw_field.strip().lower(), None


def _value_problems(
    selection_name: str, display_field: str, modifier: str | None, value: Any
) -> list[str]:
    """Semantic checks on ONE field value; returns named problems."""
    problems: list[str] = []
    if value is None:
        problems.append(
            f"selection '{selection_name}': field '{display_field}' is a null "
            "selector — our compiler does not represent null semantics"
        )
        return problems

    if modifier is not None and modifier not in SUPPORTED_MODIFIERS:
        # Unknown/nested modifiers (all, base64, exists, gt, ...): the
        # parser would silently compile them as (narrower) equality. Once
        # per FIELD — not once per list element.
        problems.append(
            f"selection '{selection_name}': modifier '|{modifier}' on "
            f"field '{display_field}' is unsupported — rewrite with a "
            "supported modifier (contains/endswith/startswith/re)"
        )
        return problems

    values = value if isinstance(value, list) else [value]
    for v in values:
        if isinstance(v, (dict, list)):
            problems.append(
                f"selection '{selection_name}': field '{display_field}' carries a "
                f"nested structure ({type(v).__name__}) the compiler cannot represent"
            )
            continue
        if isinstance(v, str) and any(c in v for c in GLOB_CHARS):
            if modifier is None:
                problems.append(
                    f"selection '{selection_name}': field '{display_field}' has a "
                    f"wildcard value ({v!r}) in plain equality — rewrite with an "
                    "explicit modifier (contains/endswith/startswith)"
                )
            else:
                problems.append(
                    f"selection '{selection_name}': field '{display_field}' has a "
                    f"glob character inside a pattern value ({v!r}) — Sigma "
                    "wildcards are not SQL LIKE wildcards; rewrite the value"
                )
    return problems


_AGG_BY_RE = re.compile(r"by\s+(\w+)")
_AGG_COUNT_RE = re.compile(r"count\((\w+)\)")


def _translate_condition(condition: str) -> tuple[str, list[str]]:
    """Rewrite SigmaHQ field names inside an AGGREGATION condition (the
    count-by pipe compiles group/count fields directly against the column
    whitelist — untranslated names are hard parser errors)."""
    problems: list[str] = []

    def _by(match: re.Match[str]) -> str:
        column = SIGMAHQ_FIELD_MAP.get(match.group(1).strip().lower())
        if column is None:
            problems.append(f"aggregation group field '{match.group(1)}' has no ingested column")
            return match.group(0)
        return f"by {column}"

    def _count(match: re.Match[str]) -> str:
        column = SIGMAHQ_FIELD_MAP.get(match.group(1).strip().lower())
        if column is None:
            problems.append(f"aggregation count field '{match.group(1)}' has no ingested column")
            return match.group(0)
        return f"count({column})"

    translated = _AGG_BY_RE.sub(_by, condition)
    translated = _AGG_COUNT_RE.sub(_count, translated)
    # Our aggregation grammar requires a count argument — SigmaHQ's bare
    # count() means count(*) to us (the documented rewrite, same semantics).
    translated = re.sub(r"count\(\s*\)", "count(*)", translated)
    return translated, problems


def _translate_detection(detection: dict) -> tuple[dict, list[str], int]:
    """Rewrite a SigmaHQ detection block into OUR dialect: mapped field
    names, modifiers preserved, structure untouched. Returns (translated,
    problems, mapped_field_count) — problems carry the file's unmapped
    pieces verbatim; a dropped term would widen the match, so none drop."""
    translated: dict[str, Any] = {}
    problems: list[str] = []
    mapped_fields = 0

    for selection_name, selection in detection.items():
        if selection_name == "condition" or not isinstance(selection, dict):
            # The condition (and any timeframe key) passes through; a
            # non-mapping selection value is reported by the compiler.
            translated[selection_name] = selection
            continue
        new_selection: dict[str, Any] = {}
        for raw_field, value in selection.items():
            name, modifier = _field_parts(raw_field)
            column = SIGMAHQ_FIELD_MAP.get(name)
            if column is None:
                problems.append(
                    f"selection '{selection_name}': field '{raw_field}' has no "
                    "ingested column — rewrite for our telemetry (do NOT drop: "
                    "a dropped term widens the match)"
                )
                continue
            mapped_fields += 1
            problems.extend(_value_problems(selection_name, raw_field, modifier, value))
            new_selection[f"{column}|{modifier}" if modifier else column] = value
        translated[selection_name] = new_selection if new_selection else selection

    return translated, problems, mapped_fields


def _translated_rule_dict(data: dict, our_category: str) -> dict:
    """The staged frontmatter: SigmaHQ provenance + our dialect + born-disabled."""
    return {
        "title": data.get("title", ""),
        "id": data.get("id", ""),
        "status": data.get("status", "experimental"),
        "description": data.get("description", ""),
        "references": data.get("references", []),
        "author": data.get("author", "SigmaHQ (imported)"),
        "date": data.get("date", ""),
        "tags": list(data.get("tags", [])) + [SIGMAHQ_TAG],
        "logsource": {
            "category": our_category,
            "product": data.get("logsource", {}).get("product"),
        },
        "detection": data.get("detection", {}),
        "falsepositives": data.get("falsepositives", []),
        "level": data.get("level", "medium"),
        "enabled": BORN_DISABLED,  # extension: the boot reconciler reads this
    }


def classify_rule(source_file: str, yaml_text: str) -> ImportVerdict:
    """Classify ONE candidate SigmaHQ rule (the full ladder, no silent drops)."""

    def _refused(reason: str) -> ImportVerdict:
        return ImportVerdict(
            source_file, OUTCOME_UNSUPPORTED, _title_from(yaml_text, source_file), [reason]
        )

    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        return _refused(f"invalid YAML: {e}")
    if not isinstance(data, dict):
        return _refused("YAML document is not a mapping")
    title = str(data.get("title") or "")
    if not title:
        return _refused("rule has no title")
    detection = data.get("detection")
    if not isinstance(detection, dict) or not detection:
        return _refused("rule has no detection block")
    if not detection.get("condition"):
        return _refused("rule has no condition")

    logsource = data.get("logsource")
    if not isinstance(logsource, dict):
        return _refused("logsource is not a mapping")
    category = logsource.get("category")
    product = logsource.get("product")
    our_category = SIGMAHQ_CATEGORY_MAP.get(str(category or ""))
    if our_category is None:
        return _refused(
            f"logsource category '{category}' does not map to an ingested event category"
        )
    if str(product or "").lower() not in SIGMAHQ_PRODUCTS_INGESTED:
        return _refused(f"logsource product '{product}' is not an ingested telemetry source")

    translated, problems, mapped_count = _translate_detection(detection)
    if mapped_count == 0:
        return ImportVerdict(
            source_file,
            OUTCOME_UNSUPPORTED,
            title,
            problems + ["no selection field maps to an ingested column — nothing to import"],
        )
    # Aggregation conditions reference field names directly — translate them.
    translated_condition, cond_problems = _translate_condition(str(detection.get("condition")))
    problems.extend(cond_problems)
    translated = {**translated, "condition": translated_condition}
    if problems:
        return ImportVerdict(source_file, OUTCOME_NEEDS_REWRITE, title, problems)

    staged = _translated_rule_dict({**data, "detection": translated}, our_category)
    staged_text = yaml.safe_dump(staged, sort_keys=False, allow_unicode=True)

    # The production parser is the ONLY judge of importability. Any parse or
    # compile exception, and ANY fail-safe warning, means the rule is not
    # faithful yet — needs-rewrite, never a silent semantic drift.
    parser = SigmaParser()
    try:
        rule = parser.parse(staged_text)
        _, _, _ = parser.compile_where(rule)
    except Exception as e:  # noqa: BLE001 — a candidate must never crash the pipeline
        return ImportVerdict(
            source_file,
            OUTCOME_NEEDS_REWRITE,
            title,
            [f"our compiler refused the translated rule: {e}"],
        )
    if parser.warnings:
        return ImportVerdict(
            source_file,
            OUTCOME_NEEDS_REWRITE,
            title,
            [f"compiler warning: {w}" for w in parser.warnings],
        )
    return ImportVerdict(source_file, OUTCOME_IMPORTED, title, [], staged_text)


def _title_from(yaml_text: str, source_file: str) -> str:
    """Best-effort title for a verdict on a rule we could not classify."""
    try:
        data = yaml.safe_load(yaml_text)
        if isinstance(data, dict) and data.get("title"):
            return str(data["title"])
    except yaml.YAMLError:
        pass
    return Path(source_file).stem


def classify_directory(source_dir: Path) -> list[ImportVerdict]:
    """Classify every *.yml candidate under a SigmaHQ rules checkout.
    Every file yields a verdict — the no-silent-drops guarantee."""
    verdicts: list[ImportVerdict] = []
    if not source_dir.exists():
        raise FileNotFoundError(f"SigmaHQ rules directory not found: {source_dir}")
    for rule_file in sorted(source_dir.rglob("*.yml")):
        rel = str(rule_file.relative_to(source_dir))
        try:
            verdicts.append(
                classify_rule(rel, rule_file.read_text(encoding="utf-8", errors="replace"))
            )
        except Exception as e:  # noqa: BLE001 — report, never crash, never drop
            verdicts.append(
                ImportVerdict(rel, OUTCOME_UNSUPPORTED, Path(rel).stem, [f"classifier error: {e}"])
            )
    log.info(
        "sigmahq_classified",
        files=len(verdicts),
        imported=sum(1 for v in verdicts if v.outcome == OUTCOME_IMPORTED),
        needs_rewrite=sum(1 for v in verdicts if v.outcome == OUTCOME_NEEDS_REWRITE),
        unsupported=sum(1 for v in verdicts if v.outcome == OUTCOME_UNSUPPORTED),
    )
    return verdicts


def generate_report(verdicts: list[ImportVerdict]) -> dict:
    """The import report: counts + every candidate with its reasons."""
    entries = [
        {"file": v.source_file, "outcome": v.outcome, "title": v.title, "reasons": v.reasons}
        for v in verdicts
    ]
    return {
        "total": len(verdicts),
        "counts": {
            "imported": sum(1 for v in verdicts if v.outcome == OUTCOME_IMPORTED),
            "needs_rewrite": sum(1 for v in verdicts if v.outcome == OUTCOME_NEEDS_REWRITE),
            "unsupported": sum(1 for v in verdicts if v.outcome == OUTCOME_UNSUPPORTED),
        },
        "entries": entries,
    }


def report_markdown(report: dict) -> str:
    """Human-readable report (the review artifact for the promote/arm step)."""
    lines = [
        "# SigmaHQ import report (W2.1)",
        "",
        f"Candidates: {report['total']} — "
        f"imported {report['counts']['imported']} · "
        f"needs-rewrite {report['counts']['needs_rewrite']} · "
        f"unsupported {report['counts']['unsupported']}",
        "",
        "| File | Outcome | Reasons |",
        "|------|---------|---------|",
    ]
    for e in report["entries"]:
        reasons = ("; ".join(e["reasons"]) if e["reasons"] else "—").replace("\n", " ")
        lines.append(f"| {e['file']} | {e['outcome']} | {reasons} |")
    lines.append("")
    lines.append("No silent drops: every candidate file appears above.")
    return "\n".join(lines)


def write_staged_rules(verdicts: list[ImportVerdict], staging_dir: Path) -> int:
    """Write the IMPORTED rules into the staging area (NOT under
    rules/sigma/ — the boot reconciler cannot auto-arm them). Returns the
    staged count. needs-rewrite / unsupported rules are never staged."""
    written = 0
    for v in verdicts:
        if v.outcome != OUTCOME_IMPORTED or not v.translated_yaml:
            continue
        data = yaml.safe_load(v.translated_yaml) or {}
        category = str((data.get("logsource") or {}).get("category") or "imported")
        out_dir = staging_dir / category
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{_slugify(v.title)}.yml").write_text(v.translated_yaml, encoding="utf-8")
        written += 1
    return written
