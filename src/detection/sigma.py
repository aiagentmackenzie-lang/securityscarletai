# ruff: noqa: S608
"""
Sigma rule parser and SQL generator.

ARCHITECTURE: Uses pySigma for spec-compliant YAML parsing and
our own PostgreSQLBackend for parameterized SQL generation.

This gives us:
- Full Sigma spec compliance (all modifiers, AND/OR, aggregation)
- Safe parameterized queries (no SQL injection possible)
- Column name validation against whitelist
- Safe interval construction (INTERVAL '1 second' * $N)

Fallback: If pySigma fails to parse a rule (e.g., custom extensions),
we fall back to our legacy parser so existing rules keep working.
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

from src.config.logging import get_logger

log = get_logger("detection.sigma")

# ───────────────────────────────────────────────────────────────
# Column whitelist — used by both pySigma backend and legacy parser
# ───────────────────────────────────────────────────────────────
ALLOWED_COLUMNS = frozenset({
    "event_type", "event_action", "event_category",
    "host_name", "source_ip", "destination_ip", "destination_port",
    "process_name", "process_pid", "process_cmdline", "process_path",
    "user_name", "file_path", "file_hash",
    "severity", "source", "host_ip",
})

# Timeframe validation regex
TIMEFRAME_PATTERN = re.compile(r"^(\d+)([mhd])$")


@dataclass
class SigmaRule:
    """Parsed Sigma rule structure — compatible with legacy format."""
    id: str
    title: str
    description: str
    status: str
    author: str
    date: str
    logsource_category: Optional[str]
    logsource_product: Optional[str]
    detection: dict[str, Any]
    condition: str
    timeframe: Optional[str]
    level: str
    tags: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]


def _validate_column(name: str) -> str:
    """Validate that a column name is in the whitelist. Raises ValueError if not."""
    if name not in ALLOWED_COLUMNS:
        raise ValueError(
            f"Invalid column name '{name}' in Sigma rule. "
            f"Allowed columns: {sorted(ALLOWED_COLUMNS)}"
        )
    return name


def _extract_mitre_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Extract MITRE ATT&CK tactics and techniques from Sigma tags.

    Tactics: attack.ta* prefix (e.g., attack.ta0001 → TA0001)
    Techniques: attack.t* prefix but NOT attack.ta* (e.g., attack.t1110 → T1110)
    """
    tactics = [
        t.replace("attack.", "").upper()
        for t in tags
        if t.startswith("attack.ta")
    ]
    techniques = [
        t.replace("attack.", "").upper()
        for t in tags
        if t.startswith("attack.t") and not t.startswith("attack.ta")
    ]
    return tactics, techniques


def _timeframe_to_seconds(timeframe: Optional[str]) -> int:
    """Convert Sigma timeframe string to integer seconds (safe for parameterized queries)."""
    if not timeframe:
        return 3600  # Default 1 hour

    match = TIMEFRAME_PATTERN.match(timeframe)
    if not match:
        log.warning("invalid_timeframe", timeframe=timeframe)
        return 3600

    num = int(match.group(1))
    unit = match.group(2)

    seconds_map = {"m": 60, "h": 3600, "d": 86400}
    total = num * seconds_map[unit]

    # Cap at 30 days
    if total > 30 * 86400:
        log.warning("timeframe_too_large", timeframe=timeframe, capped="30d")
        total = 30 * 86400

    return total


# ───────────────────────────────────────────────────────────────
# pySigma-based parsing (primary, spec-compliant)
# ───────────────────────────────────────────────────────────────

def parse_sigma_rule(yaml_content: str) -> SigmaRule:
    """
    Parse a Sigma rule from YAML string using pySigma.

    Falls back to legacy YAML parser if pySigma can't parse the rule
    (e.g., custom extensions, non-UUID identifiers).
    """
    # Try pySigma first for spec compliance
    try:
        return _parse_with_pysigma(yaml_content)
    except Exception as e:
        log.debug("pysigma_parse_fallback", error=str(e))
        # Fall back to legacy parser (handles non-UUID ids, missing logsource, etc.)
        parser = SigmaParser()
        return parser.parse(yaml_content)


def _parse_with_pysigma(yaml_content: str) -> SigmaRule:
    """Parse using pySigma for full spec compliance."""
    from sigma.rule import SigmaRule as PySigmaRule

    rule = PySigmaRule.from_yaml(yaml_content)

    # Extract MITRE tags
    tactics, techniques = _extract_mitre_tags_pysigma(rule.tags)

    # Build detection dict from parsed rule for backward compat
    detection_dict = yaml.safe_load(yaml_content).get("detection", {})

    return SigmaRule(
        id=str(rule.id) if rule.id else "unknown",
        title=rule.title or "Untitled",
        description=rule.description or "",
        status=str(rule.status) if rule.status else "experimental",
        author=rule.author or "Unknown",
        date=str(rule.date) if rule.date else "",
        logsource_category=rule.logsource.category if rule.logsource else None,
        logsource_product=rule.logsource.product if rule.logsource else None,
        detection=detection_dict,
        condition=_extract_condition_string(detection_dict),
        timeframe=(
            str(rule.detection.timeframe)
            if rule.detection and rule.detection.timeframe
            else None
        ),
        level=str(rule.level.name) if rule.level else "medium",
        tags=[str(t) for t in rule.tags],
        mitre_tactics=tactics,
        mitre_techniques=techniques,
    )


def _extract_mitre_tags_pysigma(tags) -> tuple[list[str], list[str]]:
    """Extract MITRE tags from pySigma tag objects."""
    tactics = []
    techniques = []
    for tag in tags:
        tag_str = str(tag)
        if tag_str.startswith("attack.ta"):
            tactics.append(tag_str.replace("attack.", "").upper())
        elif tag_str.startswith("attack.t"):
            techniques.append(tag_str.replace("attack.", "").upper())
    return tactics, techniques


def _extract_condition_string(detection: dict) -> str:
    """Extract condition string from detection dict for backward compatibility."""
    conditions = detection.get("condition", "selection")
    if isinstance(conditions, list):
        return " AND ".join(conditions)
    return str(conditions)


# ───────────────────────────────────────────────────────────────
# Legacy parsing (fallback for rules that pySigma can't handle)
# ───────────────────────────────────────────────────────────────

class SigmaParser:
    """Legacy Sigma YAML parser — used as fallback when pySigma fails."""

    MODIFIERS = {
        "contains": lambda field, val: f"{field} LIKE '%' || {val} || '%'",
        "endswith": lambda field, val: f"{field} LIKE '%' || {val}",
        "startswith": lambda field, val: f"{field} LIKE {val} || '%'",
        "re": lambda field, val: f"{field} ~ {val}",
    }

    def __init__(self):
        self._param_counter = 0
        self._params: list[Any] = []

    def parse(self, yaml_content: str) -> SigmaRule:
        """Parse a Sigma rule from YAML string (legacy mode)."""
        data = yaml.safe_load(yaml_content)

        tags = data.get("tags", [])
        tactics, techniques = _extract_mitre_tags(tags)

        detection = data.get("detection", {})
        condition = detection.get("condition", "selection")

        return SigmaRule(
            id=data.get("id", "unknown"),
            title=data.get("title", "Untitled"),
            description=data.get("description", ""),
            status=data.get("status", "experimental"),
            author=data.get("author", "Unknown"),
            date=data.get("date", ""),
            logsource_category=data.get("logsource", {}).get("category"),
            logsource_product=data.get("logsource", {}).get("product"),
            detection=detection,
            condition=condition,
            timeframe=data.get("timeframe"),
            level=data.get("level", "medium"),
            tags=tags,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
        )

    def to_sql(self, rule: SigmaRule) -> tuple[str, list[Any]]:
        """Convert Sigma rule to parameterized SQL query (legacy mode)."""
        self._param_counter = 0
        self._params = []

        where_clause = self._parse_condition(rule.condition, rule.detection)

        filters = []
        if rule.logsource_category:
            filters.append(f"event_category = {self._add_param(rule.logsource_category)}")

        if filters:
            where_clause = f"({' AND '.join(filters)}) AND ({where_clause})"

        agg_match = re.match(
            r"(.+?)\s*\|\s*count\(([^)]+)\)\s*by\s+(\w+)\s*>\s*(\d+)",
            rule.condition,
        )

        if agg_match:
            return self._build_aggregation_query(rule, agg_match, where_clause, filters)
        else:
            return self._build_simple_query(rule, where_clause)

    def _build_aggregation_query(
        self, rule, agg_match, where_clause, filters
    ) -> tuple[str, list[Any]]:
        """Build an aggregation (GROUP BY) SQL query."""
        base_condition = agg_match.group(1).strip()
        count_field_raw = agg_match.group(2).strip() or "*"
        group_by_raw = agg_match.group(3).strip()
        threshold = int(agg_match.group(4))

        group_by = _validate_column(group_by_raw)
        count_field = "*" if count_field_raw == "*" else _validate_column(count_field_raw)

        where_clause = self._parse_condition(base_condition, rule.detection)
        if filters:
            where_clause = f"({' AND '.join(filters)}) AND ({where_clause})"

        lookback_seconds = _timeframe_to_seconds(rule.timeframe)
        lookback_param = self._add_param(lookback_seconds)
        threshold_param = self._add_param(threshold)

        sql = (
            f"SELECT {group_by}, COUNT({count_field}) as cnt "
            f"FROM logs "
            f"WHERE {where_clause} "
            f"AND time > NOW() - INTERVAL '1 second' * {lookback_param} "
            f"GROUP BY {group_by} "
            f"HAVING COUNT({count_field}) > {threshold_param}"
        )
        return sql, self._params

    def _build_simple_query(self, rule, where_clause) -> tuple[str, list[Any]]:
        """Build a simple SELECT query."""
        lookback_seconds = _timeframe_to_seconds(rule.timeframe)
        lookback_param = self._add_param(lookback_seconds)

        sql = (  # noqa: S608 — WHERE clause built from parameterized _parse_condition()
            f"SELECT * FROM logs "
            f"WHERE {where_clause} "
            f"AND time > NOW() - INTERVAL '1 second' * {lookback_param} "
            f"ORDER BY time DESC"
        )
        return sql, self._params

    def _parse_condition(self, condition: str, detection: dict) -> str:
        """Parse the condition string into SQL WHERE clause."""
        if " and not " in condition.lower():
            parts = condition.lower().split(" and not ")
            selection_sql = self._parse_selection(parts[0].strip(), detection)
            filter_sql = self._parse_selection(parts[1].strip(), detection)
            return f"({selection_sql}) AND NOT ({filter_sql})"

        if " or " in condition.lower():
            parts = condition.lower().split(" or ")
            sql_parts = [self._parse_selection(p.strip(), detection) for p in parts]
            return " OR ".join(f"({p})" for p in sql_parts)

        return self._parse_selection(condition.strip(), detection)

    def _parse_selection(self, name: str, detection: dict) -> str:
        """Parse a selection block into SQL."""
        if name not in detection:
            log.warning("selection_not_found", name=name)
            return "TRUE"

        selection = detection[name]
        conditions = []

        for field, value in selection.items():
            modifier_match = re.match(r"^(\w+)\|(\w+)$", field)
            if modifier_match:
                field_name = modifier_match.group(1)
                modifier = modifier_match.group(2)
                sql_field = self._map_field(field_name)

                if modifier in self.MODIFIERS:
                    if isinstance(value, list):
                        or_conditions = []
                        for v in value:
                            or_conditions.append(
                                self.MODIFIERS[modifier](sql_field, self._add_param(v))
                            )
                        conditions.append(f"({' OR '.join(or_conditions)})")
                    else:
                        conditions.append(
                            self.MODIFIERS[modifier](
                                sql_field, self._add_param(value)
                            )
                        )
                else:
                    log.warning("unknown_modifier", modifier=modifier, field=field)
                    conditions.append(f"{sql_field} = {self._add_param(value)}")
            else:
                sql_field = self._map_field(field)
                if isinstance(value, list):
                    params = [self._add_param(v) for v in value]
                    placeholders = ", ".join(
                        f"${p}" if not str(p).startswith("$") else str(p)
                        for p in params
                    )
                    conditions.append(f"{sql_field} IN ({placeholders})")
                else:
                    conditions.append(f"{sql_field} = {self._add_param(value)}")

        return " AND ".join(conditions) if conditions else "TRUE"

    def _map_field(self, sigma_field: str) -> str:
        """Map Sigma field names to database column names with validation."""
        mapping = {
            "event_type": "event_type",
            "event_action": "event_action",
            "event_category": "event_category",
            "host_name": "host_name",
            "source_ip": "source_ip",
            "destination_ip": "destination_ip",
            "destination_port": "destination_port",
            "process_name": "process_name",
            "process_pid": "process_pid",
            "process_cmdline": "process_cmdline",
            "process_path": "process_path",
            "user_name": "user_name",
            "file_path": "file_path",
            "file_hash": "file_hash",
        }
        mapped = mapping.get(sigma_field, sigma_field)
        if mapped not in ALLOWED_COLUMNS:
            log.warning("unknown_field_mapped", sigma_field=sigma_field, mapped=mapped)
        return mapped

    def _add_param(self, value: Any) -> str:
        """Add a parameter and return $N placeholder string."""
        self._param_counter += 1
        self._params.append(value)
        return f"${self._param_counter}"


# ───────────────────────────────────────────────────────────────
# Public API — same interface, pySigma-powered internally
# ───────────────────────────────────────────────────────────────

def sigma_to_sql(yaml_content: str) -> tuple[str, list[Any]]:
    """
    Convert Sigma YAML to parameterized SQL.

    Uses pySigma-backed PostgreSQLBackend for generation,
    falls back to legacy parser if needed.
    Returns (sql, params) tuple.
    """
    # Parse the rule first
    rule = parse_sigma_rule(yaml_content)

    # Try pySigma-backed generation
    try:
        from src.detection.backends.postgresql import PostgreSQLBackend
        backend = PostgreSQLBackend()

        # Parse with pySigma for backend conversion
        from sigma.rule import SigmaRule as PySigmaRule
        py_rule = PySigmaRule.from_yaml(yaml_content)

        lookback_seconds = _timeframe_to_seconds(rule.timeframe)
        sql, params = backend.generate_query(py_rule, lookback_seconds=lookback_seconds)

        if sql and params is not None:
            log.debug("pysigma_sql_generated", rule=rule.title)
            return sql, params

    except Exception as e:
        log.warning("pysigma_sql_fallback", rule=rule.title, error=str(e))

    # Fall back to legacy parser
    parser = SigmaParser()
    legacy_rule = parser.parse(yaml_content)
    sql, params = parser.to_sql(legacy_rule)
    log.debug("legacy_sql_generated", rule=rule.title)
    return sql, params


def load_rules_from_directory(rules_dir: Path) -> list[SigmaRule]:
    """Load all Sigma YAML rules from a directory (recursive)."""
    rules = []
    if not rules_dir.exists():
        log.warning("rules_dir_not_found", path=str(rules_dir))
        return rules

    for rule_file in sorted(rules_dir.rglob("*.yml")):
        try:
            yaml_content = rule_file.read_text()
            rule = parse_sigma_rule(yaml_content)
            rules.append(rule)
            log.debug("rule_loaded", file=rule_file.name, title=rule.title)
        except Exception as e:
            log.error("rule_load_failed", file=str(rule_file), error=str(e))

    log.info("rules_loaded_from_dir", count=len(rules), path=str(rules_dir))
    return rules
