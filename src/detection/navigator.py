"""ATT&CK Navigator layer export (Wave 1 W1.9) -- the analyst-standard
coverage artifact.

Merges the evidence-driven coverage map (armed/dormant per rule, V0.3) with
the rule lifecycle scorecard (FP ratios, V0.7b) into an ATT&CK Navigator
LAYER-FILE-FORMAT v4.5 document (the spec the Navigator imports; verified
against mitre-attack/attack-navigator layers/spec/v4.5/layerformat.md).

Per technique:
- score  = armed coverage: armed rules / rules mapped to the technique,
           scaled 0-100 (red->green gradient).
- comment = armed counts + the scorecard FP ratio WHERE DISPOSITIONS EXIST
           (the same honesty gate as the backtest: unmeasured is labeled,
           never a fake number) + the contributing rule names (capped).

Doctrine: read-only derivation of two existing read-only reports. The
layer declares "attack": "14" because the technique mappings were built
against the repo's v14-pinned STIX cache -- never the latest version
(honesty: the Navigator offers its own upgrade flow for newer datasets).
"""

from datetime import datetime, timezone
from typing import Any, Optional

from src.config.logging import get_logger
from src.detection.coverage import compute_coverage
from src.detection.scorecard import compute_rule_scorecard

log = get_logger("detection.navigator")

# Navigator layer-file format v4.5 (spec: layers/spec/v4.5/layerformat.md):
# versions.layer must be "4.5"; versions.navigator >= "4.9.0"; versions.attack
# defaults to the current ATT&CK version -- we PIN it to the version our
# technique mappings were actually built against (the v14-pinned STIX cache),
# because claiming a newer version would lie about what the mappings cover.
LAYER_FORMAT_VERSION = "4.5"
NAVIGATOR_VERSION = "5.2.0"
ATTACK_VERSION = "14"

# Comment hygiene: the rule-name list in a technique comment is capped --
# some techniques carry dozens of rules and Navigator tooltips choke on it.
MAX_RULE_NAMES_IN_COMMENT = 4

# Default gradient: the spec's own red->yellow->green example, 0-100.
_GRADIENT = {
    "colors": ["#ff6666", "#ffe766", "#8ec843"],
    "minValue": 0,
    "maxValue": 100,
}


def _rule_fp_index(scorecard: dict) -> dict[tuple[str, str], dict[str, Any]]:
    """(kind, name) -> measured FP data for rules that have dispositions.

    Rules without adjudicated dispositions are OMITTED here (never a fake
    ratio) -- they simply do not contribute to the technique aggregate.
    """
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for rule in scorecard.get("rules", []):
        dispositions = rule.get("dispositions") or 0
        if dispositions:
            index[(rule.get("kind", "sigma"), rule.get("name", ""))] = {
                "false_positives": rule.get("false_positives") or 0,
                "dispositions": dispositions,
                "fp_ratio": rule.get("fp_ratio"),
            }
    return index


def _aggregate_fp(rule_entries: list[dict], fp_by_rule) -> tuple[int, int]:
    """Sums (false_positives, dispositions) across the technique's rules
    that HAVE dispositions -- a weighted aggregate, unmeasured rules excluded."""
    fp_sum = 0
    disp_sum = 0
    for r in rule_entries:
        fp = fp_by_rule.get((r.get("kind", "sigma"), r.get("name", "")))
        if fp:
            fp_sum += fp["false_positives"]
            disp_sum += fp["dispositions"]
    return fp_sum, disp_sum


def _rule_names_note(rule_entries: list[dict]) -> str:
    """Bounded rule-name list for the comment (capped, with an overflow)."""
    names = [r.get("name", "?") for r in rule_entries]
    shown = names[:MAX_RULE_NAMES_IN_COMMENT]
    extra = len(names) - len(shown)
    note = "; ".join(shown)
    if extra > 0:
        note += f" +{extra} more"
    return note


def build_layer_techniques(
    coverage: dict, fp_by_rule: dict[tuple[str, str], dict[str, Any]]
) -> list[dict[str, Any]]:
    """Per-technique Navigator entries (sorted by techniqueID, stable)."""
    rules_by_technique: dict[str, list[dict]] = {}
    for rule in coverage.get("rules", []):
        for tech in rule.get("mitre_techniques") or []:
            rules_by_technique.setdefault(tech, []).append(rule)

    techniques: list[dict[str, Any]] = []
    for tech, rule_entries in rules_by_technique.items():
        total = len(rule_entries)
        armed = sum(1 for r in rule_entries if r.get("armed"))
        score = round(armed / total * 100) if total else 0

        fp_sum, disp_sum = _aggregate_fp(rule_entries, fp_by_rule)
        if disp_sum:
            fp_note = f"FP ratio {fp_sum / disp_sum:.2f} ({disp_sum} dispositions)"
        else:
            fp_note = "FP ratio unmeasured (no adjudicated alerts)"

        comment = (
            f"armed {armed}/{total} ({score}%) | {fp_note} | rules: "
            f"{_rule_names_note(rule_entries)}"
        )
        techniques.append(
            {
                "techniqueID": tech,
                "score": score,
                "comment": comment,
                "enabled": True,
                "showSubtechniques": False,
            }
        )

    techniques.sort(key=lambda t: t["techniqueID"])
    return techniques


async def build_navigator_layer(
    lookback_hours: int = 168,
    as_of: Optional[datetime] = None,
) -> dict[str, Any]:
    """Build an ATT&CK Navigator layer (v4.5) from coverage + scorecard.

    Read-only merge of the two existing detection-engineering reports:
    - coverage (armed/dormant per rule, evidence-driven) drives the scores;
    - scorecard (lifecycle metrics) contributes FP ratios into the comments.
    """
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    coverage = await compute_coverage(lookback_hours=lookback_hours, as_of=as_of)
    scorecard = await compute_rule_scorecard(window_hours=lookback_hours, as_of=as_of)
    fp_by_rule = _rule_fp_index(scorecard)

    summary = coverage.get("summary", {})
    layer = {
        "name": "SecurityScarletAI detection coverage",
        "description": (
            "Self-reported detection coverage from SecurityScarletAI. "
            "Score = armed coverage (armed rules / rules mapped to the "
            "technique, 0-100, over the lookback window). Comments carry "
            "per-technique rule counts, the scorecard FP ratio (only where "
            "adjudicated dispositions exist), and contributing rule names. "
            "Read-only export of GET /api/v1/detection/coverage/navigator."
        ),
        "versions": {
            "layer": LAYER_FORMAT_VERSION,
            "navigator": NAVIGATOR_VERSION,
            # The mappings were built against the repo's v14-pinned STIX
            # cache -- the layer claims exactly that, never the latest.
            "attack": ATTACK_VERSION,
        },
        "domain": "enterprise-attack",
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": build_layer_techniques(coverage, fp_by_rule),
        "gradient": _GRADIENT,
        "metadata": [
            {"name": "generated", "value": as_of.strftime("%Y-%m-%dT%H:%M:%SZ")},
            {
                "name": "source",
                "value": "SecurityScarletAI /api/v1/detection/coverage/navigator",
            },
            {"name": "lookback_hours", "value": str(lookback_hours)},
            {
                "name": "coverage",
                "value": (f"armed {summary.get('armed', 0)}/{summary.get('total_rules', 0)} rules"),
            },
        ],
    }
    return layer
