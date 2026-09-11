"""Canonical JSONB-read normalization (LRN-20260911-001).

In this repo's asyncpg usage (no explicit set_type_codec), JSONB columns can
come back from queries as ``str`` instead of dict. Reading them with
``.get(...)`` / ``dict(...)`` crashes (ValueError / AttributeError) -- found
live three times on 2026-09-11 (response-action execution, decisions view,
case payloads).

This module is the SINGLE implementation of the normalization. Existing
call sites keep their local names as aliases:

    - src/api/response.py: _load_json  (imported from here)
    - src/api/decisions.py: _load_json (imported from here)

New code reading a JSONB column imports ``load_jsonb`` directly. Behavior:
str -> parsed JSON ({} on unparseable, with a warning); dict/list pass
through; None/"" -> {}. Anything else is returned as-is (the caller owns
the shape it asked for).
"""

from __future__ import annotations

import json
from typing import Any

from src.config.logging import get_logger

log = get_logger("db.jsonb")


def load_jsonb(value: Any, *, source: str = "jsonb") -> Any:
    """Normalize a JSONB column value that may arrive as a raw string.

    Args:
        value: The raw column value (str, dict, list, None, ...).
        source: Short module tag for the unparseable warning (triage aid).
    """
    if value is None or value == "":
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            log.warning(
                "jsonb_unparseable",
                source=source,
                preview=str(value)[:80],
            )
            return {}
    return value
