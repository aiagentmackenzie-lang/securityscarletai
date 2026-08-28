# ruff: noqa: S608
"""
Sigma rule parser and SQL generator.

ARCHITECTURE: Rules are parsed and converted to parameterized SQL by our own
legacy SigmaParser. The pySigma-backed PostgreSQLBackend (src/detection/backends)
was the primary path but produced invalid/semantically-wrong SQL (Python
list-repr injected into WHERE, aggregation selections dropped to TRUE); it is
retained only as a standalone, unit-tested module and is no longer on the
production detection path (P0-01/P0-04).

The legacy parser gives us:
- Safe parameterized queries (no SQL injection possible) — every value is a
  $N placeholder; INTERVAL is built as INTERVAL '1 second' * $N.
- Column name validation against a whitelist.
- AND / OR / AND-NOT / plain-AND conditions and Sigma aggregation (count by).
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

# INET-typed columns. LIKE-family modifiers (contains/startswith/endswith/re)
# are not defined for inet in Postgres ("operator does not exist: inet ~~ text"),
# so LIKE comparisons use the text form host(col)::text. Equality on inet with a
# valid IP string still works without a cast.
INET_COLUMNS = frozenset({"source_ip", "destination_ip", "host_ip"})

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
    Parse a Sigma rule from YAML string.

    Uses the legacy SigmaParser (the pySigma-first path was dead — it always
    fell back here via a deliberate AttributeError; see P0-04). The legacy parser
    handles non-UUID ids, missing logsource, and all shipped rules.
    """
    parser = SigmaParser()
    return parser.parse(yaml_content)


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

        filters = []
        if rule.logsource_category:
            filters.append(f"event_category = {self._add_param(rule.logsource_category)}")

        # Aggregation (count-by) rules parse the condition exactly once on the
        # base condition (the part before the `| count(...) by ...` pipe). We
        # must NOT parse the full condition first and then re-parse the base —
        # that double parse (P2-10) leaves the first parse's $N placeholders
        # unreferenced in the final SQL, which asyncpg cannot type
        # ("could not determine data type of parameter $1").
        agg_match = re.match(
            r"(.+?)\s*\|\s*count\(([^)]+)\)\s*by\s+(\w+)\s*>\s*(\d+)",
            rule.condition,
        )

        if agg_match:
            return self._build_aggregation_query(rule, agg_match, filters)

        where_clause = self._parse_condition(rule.condition, rule.detection)
        if filters:
            where_clause = f"({' AND '.join(filters)}) AND ({where_clause})"

        return self._build_simple_query(rule, where_clause)

    def _build_aggregation_query(
        self, rule, agg_match, filters
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

        # P2-42: plain " and " (e.g. webshell_creation.yml uses
        # `selection_web_dir and selection_shell_content`). Checked after
        # `and not` (above) so `and not` is not mis-split, and after `or`.
        if " and " in condition.lower():
            parts = condition.lower().split(" and ")
            sql_parts = [self._parse_selection(p.strip(), detection) for p in parts]
            return " AND ".join(f"({p})" for p in sql_parts)

        return self._parse_selection(condition.strip(), detection)

    def _parse_selection(self, name: str, detection: dict) -> str:
        """Parse a selection block into SQL."""
        if name not in detection:
            # F-20 (fail-safe): a typo'd selection name used to parse as TRUE
            # — a match-everything alert storm. A missing selection now makes
            # the rule match NOTHING and logs loudly.
            log.warning("selection_not_found_rule_never_matches", name=name)
            return "FALSE"

        selection = detection[name]
        conditions = []

        for field, value in selection.items():
            modifier_match = re.match(r"^(\w+)\|(\w+)$", field)
            if modifier_match:
                field_name = modifier_match.group(1)
                modifier = modifier_match.group(2)
                sql_field = self._map_field(field_name)

                if modifier in self.MODIFIERS:
                    # LIKE-family operators don't exist for inet; compare on the
                    # text form (e.g. host(source_ip)::text LIKE '10.%').
                    like_field = (
                        f"host({sql_field})::text"
                        if sql_field in INET_COLUMNS
                        else sql_field
                    )
                    if isinstance(value, list):
                        or_conditions = []
                        for v in value:
                            or_conditions.append(
                                self.MODIFIERS[modifier](like_field, self._add_param(v))
                            )
                        conditions.append(f"({' OR '.join(or_conditions)})")
                    else:
                        conditions.append(
                            self.MODIFIERS[modifier](
                                like_field, self._add_param(value)
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
                elif value == "*":
                    # Sigma wildcard-all: field is present (any value).
                    conditions.append(f"{sql_field} IS NOT NULL")
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
            raise ValueError(
                f"Invalid Sigma field '{sigma_field}' (mapped to '{mapped}') — "
                f"not in allowed columns: {sorted(ALLOWED_COLUMNS)}"
            )
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

    Routes through the legacy SigmaParser (P0-01/P0-04). The pySigma-backed
    PostgreSQLBackend produced invalid SQL (list-repr in WHERE) and dropped
    aggregation selections to TRUE; it is no longer on this path.
    Returns (sql, params) tuple.
    """
    parser = SigmaParser()
    rule = parser.parse(yaml_content)
    sql, params = parser.to_sql(rule)
    log.debug("legacy_sql_generated", rule=rule.title)
    return sql, params


def load_rules_from_directory(rules_dir: Path) -> list[SigmaRule]:
    """Load all Sigma YAML rules from a directory (recursive)."""
    rules: list[SigmaRule] = []
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
