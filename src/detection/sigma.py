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

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

import yaml

from src.config.logging import get_logger

log = get_logger("detection.sigma")

# P2.8: hard cap on rows fetched per simple-detection run — a broad rule
# on a chatty host used to pull unbounded rows into memory per evaluation.
MAX_DETECTION_ROWS = 1000

# ───────────────────────────────────────────────────────────────
# Column whitelist — used by both pySigma backend and legacy parser
# ───────────────────────────────────────────────────────────────
ALLOWED_COLUMNS = frozenset(
    {
        "event_type",
        "event_action",
        "event_category",
        "host_name",
        "source_ip",
        "destination_ip",
        "destination_port",
        "process_name",
        "process_pid",
        "process_cmdline",
        "process_path",
        "user_name",
        "file_path",
        "file_hash",
        "severity",
        "source",
        "host_ip",
    }
)

# INET-typed columns. LIKE-family modifiers (contains/startswith/endswith/re)
# are not defined for inet in Postgres ("operator does not exist: inet ~~ text"),
# so LIKE comparisons use the text form host(col)::text. Equality on inet with a
# valid IP string still works without a cast.
INET_COLUMNS = frozenset({"source_ip", "destination_ip", "host_ip"})

# INTEGER-typed columns. Equality params must be Python ints for asyncpg; a str
# value binds as "expected int, got str".
INT_COLUMNS = frozenset({"process_pid", "destination_port"})

# Sigma field name -> logs column. Fields are validated against ALLOWED_COLUMNS
# by _map_field; the backtester (W1.1) uses the same mapping to pick the
# "top offending values" columns for a compiled rule.
FIELD_MAPPING: dict[str, str] = {
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


class UnsupportedSigmaValue(ValueError):
    """A Sigma detection value the SQL compiler cannot represent faithfully.

    Raised during selection parsing; the selection is failed SAFE to FALSE
    (match nothing, log loudly) — never widened to TRUE (F-20 pattern).
    Examples: mapping values (YAML `- /node:` parses as {"/node": None}),
    null values, non-numeric strings against INTEGER columns, non-IP strings
    against INET equality.
    """


# Timeframe validation regex
TIMEFRAME_PATTERN = re.compile(r"^(\d+)([mhd])$")


@dataclass
class SigmaAggregation:
    """Parsed Sigma aggregation condition (`| count(field) by group > N`).

    Exposed for the backtester (W1.1): the aggregation grammar lives in the
    parser, so the parsed parts (count field, group-by column, threshold)
    are returned alongside the compiled WHERE instead of being re-matched
    (and re-validated) outside the parser.
    """

    count_field: Optional[str]  # None = COUNT(*)
    group_by: str
    threshold: int


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
    tactics = [t.replace("attack.", "").upper() for t in tags if t.startswith("attack.ta")]
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
        # W1.1 backtesting: fail-safe compilations are collected here so a
        # caller (backtest UI) can report "this rule would compile to
        # match-nothing" honestly instead of showing a fake 0-hit result.
        self.warnings: list[str] = []

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

    def compile_where(self, rule: SigmaRule) -> tuple[str, list[Any], Optional[SigmaAggregation]]:
        """Compile the rule's WHERE clause (selections + logsource filter).

        Returns (where_clause, params, aggregation):
        - where_clause: the parameterized base-condition WHERE (for
          aggregation rules, the part BEFORE the `| count(...) by ...` pipe
          -- parsed exactly once, the P2-10 rule).
        - aggregation: parsed SigmaAggregation when the condition is an
          aggregation, else None. Aggregation grammar is validated HERE
          (unknown group-by/count fields raise ValueError), so callers get
          the same hard-failure behavior as to_sql.

        Public on purpose: the backtester (W1.1) reuses the PRODUCTION
        selection compilation and wraps it in its own bounded window queries
        instead of re-implementing the grammar.
        """
        self._param_counter = 0
        self._params = []
        self.warnings = []

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
            count_field_raw = agg_match.group(2).strip() or "*"
            group_by = _validate_column(agg_match.group(3).strip())
            count_field = "*" if count_field_raw == "*" else _validate_column(count_field_raw)
            base_condition = agg_match.group(1).strip()
            where_clause = self._parse_condition(base_condition, rule.detection)
            if filters:
                where_clause = f"({' AND '.join(filters)}) AND ({where_clause})"
            agg = SigmaAggregation(
                count_field=count_field,
                group_by=group_by,
                threshold=int(agg_match.group(4)),
            )
            return where_clause, self._params, agg

        where_clause = self._parse_condition(rule.condition, rule.detection)
        if filters:
            where_clause = f"({' AND '.join(filters)}) AND ({where_clause})"
        return where_clause, self._params, None

    def to_sql(self, rule: SigmaRule) -> tuple[str, list[Any]]:
        """Convert Sigma rule to parameterized SQL query (legacy mode)."""
        where_clause, _, agg = self.compile_where(rule)
        if agg is not None:
            return self._build_aggregation_query(rule, where_clause, agg)
        return self._build_simple_query(rule, where_clause)

    def _build_aggregation_query(
        self, rule, where_clause, agg: SigmaAggregation
    ) -> tuple[str, list[Any]]:
        """Build an aggregation (GROUP BY) SQL query."""
        group_by = agg.group_by
        count_field = agg.count_field or "*"
        threshold = agg.threshold

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

    def _build_simple_query(
        self, rule, where_clause, max_rows: Optional[int] = None
    ) -> tuple[str, list[Any]]:
        """Build a simple SELECT query.

        P2.8: every simple query carries a bounded LIMIT (MAX_DETECTION_ROWS,
        overridable per call) — a broad rule on a chatty host used to fetch
        unbounded rows into memory per run.
        """
        lookback_seconds = _timeframe_to_seconds(rule.timeframe)
        lookback_param = self._add_param(lookback_seconds)
        limit_param = self._add_param(max_rows or MAX_DETECTION_ROWS)

        sql = (  # noqa: S608 — WHERE clause built from parameterized _parse_condition()
            f"SELECT * FROM logs "
            f"WHERE {where_clause} "
            f"AND time > NOW() - INTERVAL '1 second' * {lookback_param} "
            f"ORDER BY time DESC "
            f"LIMIT {limit_param}"
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
            self.warnings.append(
                f"selection '{name}' does not exist in the detection block; "
                "compiled fail-safe to FALSE (rule matches nothing)"
            )
            return "FALSE"

        selection = detection[name]
        conditions = []

        try:
            for field, value in selection.items():
                modifier_match = re.match(r"^(\w+)\|(\w+)$", field)
                if modifier_match:
                    field_name = modifier_match.group(1)
                    modifier = modifier_match.group(2)
                    sql_field = self._map_field(field_name)

                    if modifier in self.MODIFIERS:
                        # LIKE-family operators don't exist for inet ("operator
                        # does not exist: inet ~~ text") or for integer columns;
                        # compare on the text form (e.g. host(source_ip)::text
                        # LIKE '10.%', destination_port::text LIKE '44%').
                        if sql_field in INET_COLUMNS:
                            like_field = f"host({sql_field})::text"
                        elif sql_field in INT_COLUMNS:
                            like_field = f"{sql_field}::text"
                        else:
                            like_field = sql_field
                        if isinstance(value, list):
                            or_conditions = []
                            for v in value:
                                or_conditions.append(
                                    self.MODIFIERS[modifier](
                                        like_field,
                                        self._add_param(
                                            self._coerce_param(sql_field, v, usage="pattern")
                                        ),
                                    )
                                )
                            conditions.append(f"({' OR '.join(or_conditions)})")
                        else:
                            conditions.append(
                                self.MODIFIERS[modifier](
                                    like_field,
                                    self._add_param(
                                        self._coerce_param(sql_field, value, usage="pattern")
                                    ),
                                )
                            )
                    else:
                        log.warning("unknown_modifier", modifier=modifier, field=field)
                        self.warnings.append(
                            f"field '{field}' uses unknown modifier '|{modifier}'; "
                            "compiled as exact equality (narrower than intended)"
                        )
                        conditions.append(
                            f"{sql_field} = {self._add_param(self._coerce_param(sql_field, value))}"
                        )
                else:
                    sql_field = self._map_field(field)
                    if isinstance(value, list):
                        coerced = [self._coerce_param(sql_field, v) for v in value]
                        params = [self._add_param(v) for v in coerced]
                        placeholders = ", ".join(
                            f"${p}" if not str(p).startswith("$") else str(p) for p in params
                        )
                        conditions.append(f"{sql_field} IN ({placeholders})")
                    elif value == "*":
                        # Sigma wildcard-all: field is present (any value).
                        conditions.append(f"{sql_field} IS NOT NULL")
                    else:
                        conditions.append(
                            f"{sql_field} = {self._add_param(self._coerce_param(sql_field, value))}"
                        )
        except UnsupportedSigmaValue as exc:
            # Fail-safe (F-20 pattern): a value the compiler cannot represent
            # faithfully must make the selection match NOTHING, never widen it
            # (dropping one condition of a selection would match MORE). Rule
            # 91/100 class: unbindable params crashed EVERY run with asyncpg
            # "expected str, got int/dict".
            log.warning(
                "selection_unsupported_value_rule_never_matches",
                field=field,
                reason=str(exc),
            )
            self.warnings.append(
                f"selection '{name}' contains an unsupported value on field "
                f"'{field}': {exc} -- compiled fail-safe to FALSE (rule matches nothing)"
            )
            return "FALSE"

        if not conditions:
            # Empty selection ({}): previously compiled to TRUE — another
            # match-everything alert storm. Fail-safe to FALSE.
            log.warning("empty_selection_rule_never_matches", name=name)
            self.warnings.append(
                f"selection '{name}' is empty; compiled fail-safe to FALSE (rule matches nothing)"
            )
            return "FALSE"

        return " AND ".join(conditions)

    def _coerce_param(self, column: str, value: Any, *, usage: str = "eq") -> Any:
        """Coerce a Sigma selection value to the type asyncpg can bind.

        usage="pattern": LIKE-family / regex context — the comparison runs on
        the text form of the column, so the param is always a str.
        usage="eq": bind per the schema column type (TEXT/INTEGER/INET).

        Raises UnsupportedSigmaValue for anything that cannot be represented
        faithfully; callers fail the selection to FALSE.
        """
        if isinstance(value, Mapping) or isinstance(value, (list, tuple)):
            raise UnsupportedSigmaValue(f"mapping/sequence value not supported: {value!r}")
        if value is None:
            raise UnsupportedSigmaValue("null value (Sigma null-selector unsupported)")

        if usage == "pattern":
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, (str, int, float)):
                return str(value)
            raise UnsupportedSigmaValue(f"unusable pattern value: {value!r}")

        # usage == "eq"
        if column in INT_COLUMNS:
            if isinstance(value, bool):
                raise UnsupportedSigmaValue("boolean against an INTEGER column")
            if isinstance(value, int):
                return value
            if isinstance(value, float) and value.is_integer():
                return int(value)
            if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
                return int(value)
            raise UnsupportedSigmaValue(
                f"non-numeric value against INTEGER column {column}: {value!r}"
            )

        if column in INET_COLUMNS:
            if not isinstance(value, str):
                raise UnsupportedSigmaValue(f"non-string against INET column {column}: {value!r}")
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise UnsupportedSigmaValue(
                    f"invalid IP for INET equality on {column}: {value!r}"
                ) from exc
            return value

        # TEXT columns: str as-is; scalars coerced to their string form.
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (str, int, float)):
            return str(value)
        raise UnsupportedSigmaValue(f"unusable value for column {column}: {value!r}")

    def _map_field(self, sigma_field: str) -> str:
        """Map Sigma field names to database column names with validation."""
        mapped = FIELD_MAPPING.get(sigma_field, sigma_field)
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
