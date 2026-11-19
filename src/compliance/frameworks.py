"""Compliance framework mapping loader (V0.7).

Loads config/compliance_mappings.yaml -- the surface-based mapping of SIEM
product surfaces to regulatory control views. FAIL-CLOSED (the
response_policy pattern): a missing, unreadable, or unparseable file
yields NO mappings; the API layer turns that into a 503 rather than
fabricating coverage. Entries without a `surface` field are dropped (a
mapping that names no evidencing surface is a claim, not a mapping).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml

from src.config.logging import get_logger

log = get_logger("compliance.frameworks")

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "compliance_mappings.yaml"

# SS-061: the accepted objective vocabulary. The constant existed but was never
# consulted; it also under-described the shipped data (the NIST CSF controls use
# GOVERN/IDENTIFY/... with a "(GV)" suffix). An objective outside this set is
# dropped with a warning rather than displayed as if the framework said it.
VALID_OBJECTIVES = frozenset({"A", "B", "C", "D"})
_NIST_CSF_OBJECTIVES = frozenset({"GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"})


def _objective_token(value: str) -> str:
    """Normalize an objective for validation ('GOVERN (GV)' -> 'GOVERN')."""
    return value.strip().split(" (")[0].strip().upper()


def parse_frameworks_document(document: Any) -> dict:
    """Pure parser: validate + normalize a mappings document.

    Returns {"version": int, "frameworks": {id: {...}}} with every control
    carrying id, requirement, surface; controls missing id/requirement/
    surface are dropped (fail-closed against fabricated claims).
    """
    if not isinstance(document, dict):
        return {}
    body = document.get("compliance_frameworks")
    if not isinstance(body, dict):
        return {}
    version = body.get("version")
    if not isinstance(version, int):
        return {}
    frameworks_in = body.get("frameworks")
    if not isinstance(frameworks_in, dict):
        return {}

    frameworks: dict[str, dict] = {}
    for fw_id, fw in frameworks_in.items():
        if not isinstance(fw, dict):
            continue
        controls_raw = fw.get("controls")
        if not isinstance(controls_raw, list):
            continue
        controls: list[dict] = []
        for entry in controls_raw:
            if not isinstance(entry, dict):
                continue
            cid = entry.get("id")
            requirement = entry.get("requirement")
            surface = entry.get("surface")
            if not (cid and requirement and surface):
                log.warning(
                    "compliance_mapping_incomplete_control",
                    framework=str(fw_id),
                    control=str(cid),
                )
                continue
            control = {
                "id": str(cid),
                "requirement": str(requirement),
                "surface": str(surface),
            }
            objective = entry.get("objective")
            if objective:
                # SS-061: VALID_OBJECTIVES existed but was never consulted, so
                # a typo'd objective appeared in the compliance view as if
                # valid. Unknown objectives are dropped (and logged) rather
                # than displayed as a claim the framework does not make.
                token = _objective_token(str(objective))
                if token in VALID_OBJECTIVES or token in _NIST_CSF_OBJECTIVES:
                    control["objective"] = str(objective).strip()
                else:
                    log.warning(
                        "compliance_mapping_unknown_objective_dropped",
                        framework=str(fw_id),
                        control=str(cid),
                        objective=str(objective)[:16],
                    )
            if entry.get("principle"):
                control["principle"] = str(entry["principle"])
            if entry.get("evidence"):
                control["evidence"] = str(entry["evidence"])
            controls.append(control)
        if not controls:
            continue
        frameworks[str(fw_id)] = {
            "name": str(fw.get("name", fw_id)),
            "description": str(fw.get("description", "")),
            "controls": controls,
        }
    return {"version": version, "frameworks": frameworks}


def load_frameworks_file(path: Optional[Path] = None) -> dict:
    """Load + parse. Missing/unreadable -> {"version": None, "frameworks": {}}
    (the API layer reports the honest absence, never fabricates)."""
    try:
        document = (path or CONFIG_PATH).read_text()
        parsed = parse_frameworks_document(yaml.safe_load(document))
        if parsed:
            return parsed
    except (OSError, yaml.YAMLError) as e:
        log.error("compliance_mappings_load_failed", error=str(e))
    return {"version": None, "frameworks": {}}
