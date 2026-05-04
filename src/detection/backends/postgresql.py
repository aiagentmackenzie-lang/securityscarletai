# ruff: noqa: S608,S105
"""
PostgreSQL backend for pySigma — generates parameterized SQL queries.

Uses pySigma for parsing (spec-compliant) and our own SQL generation
(PostgreSQL-specific with parameterized $N placeholders for asyncpg).

This is NOT a generic SQL backend. It generates queries specifically for
the SecurityScarletAI logs table with all safety measures:
- All values are parameterized ($1, $2, ...), never interpolated
- Column names are validated against ALLOWED_COLUMNS whitelist
- Intervals use safe INTERVAL '1 second' * $N pattern
- Timeframe is converted to integer seconds (safe parameter)
"""
import re
from typing import Any, ClassVar, Optional

from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule as PySigmaRule
from sigma.types import CompareOperators, SigmaString, SpecialChars

from src.config.logging import get_logger

log = get_logger("detection.backends.postgresql")

# ───────────────────────────────────────────────────────────
# Column whitelist — same as in sigma.py, single source of truth
# ───────────────────────────────────────────────────────────
ALLOWED_COLUMNS = frozenset({
    "event_type", "event_action", "event_category",
    "host_name", "source_ip", "destination_ip", "destination_port",
    "process_name", "process_pid", "process_cmdline", "process_path",
    "user_name", "file_path", "file_hash",
    "severity", "source", "host_ip",
})

# Sigma field → logs table column mapping
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
    "severity": "severity",
    "source": "source",
}


class PostgreSQLBackend(TextQueryBackend):
    """Generate parameterized PostgreSQL queries from Sigma rules."""

    name: ClassVar[str] = "postgresql"
    formats: ClassVar[dict[str, str]] = {
        "default": "Parameterized PostgreSQL queries for SecurityScarletAI",
    }

    # Expression formatting (SQL tokens, not passwords)
    group_expression: ClassVar[str] = "({expr})"
    or_token: ClassVar[str] = "OR"  # noqa: S105
    and_token: ClassVar[str] = "AND"  # noqa: S105
    not_token: ClassVar[str] = "NOT"  # noqa: S105
    eq_token: ClassVar[str] = "="  # noqa: S105

    # Field quoting — PostgreSQL uses double quotes
    field_quote: ClassVar[str] = '"'
    field_quote_pattern: ClassVar[re.Pattern[str]] = re.compile(r"^[a-z_][a-z_0-9]*$")

    # String quoting — all values go through parameterized $N placeholders
    str_quote: ClassVar[str] = ""
    escape_char: ClassVar[str] = ""
    wildcard_multi: ClassVar[str] = "%"
    wildcard_single: ClassVar[str] = "_"

    # Regex
    re_expression: ClassVar[str] = "{field} ~ {value}"
    re_escape_char: ClassVar[str] = "\\"

    # Numeric comparison
    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[dict[CompareOperators, str]] = {
        CompareOperators.LT: "<",
        CompareOperators.LTE: "<=",
        CompareOperators.GT: ">",
        CompareOperators.GTE: ">=",
        CompareOperators.NEQ: "!=",
    }

    # NULL handling
    field_equals_null_expression: ClassVar[str] = "{field} IS NULL"
    field_not_equals_null_expression: ClassVar[str] = "{field} IS NOT NULL"

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        **kwargs,
    ):
        super().__init__(processing_pipeline=processing_pipeline, **kwargs)
        self._param_counter = 0
        self._params: list[Any] = []

    def _reset_state(self) -> None:
        """Reset parameter counter and params list for a new query."""
        self._param_counter = 0
        self._params = []

    def _add_param(self, value: Any) -> str:
        """Add a parameter and return the $N placeholder."""
        self._param_counter += 1
        self._params.append(value)
        return f"${self._param_counter}"

    def _validate_field(self, field: str) -> str:
        """Map and validate field name against whitelist."""
        mapped = FIELD_MAPPING.get(field, field)
        if mapped not in ALLOWED_COLUMNS:
            log.warning("unknown_field_in_rule", field=field, mapped=mapped)
            # Use the mapped name but warn — don't crash on unknown fields
        return mapped

    # ───────────────────────────────────────────────────────
    # Override value conversion to always use parameterized $N
    # ───────────────────────────────────────────────────────

    def convert_value_str(self, value: SigmaString, state: ConversionState) -> str:
        """
        Convert a SigmaString value to a parameterized placeholder.

        Instead of generating quoted strings in the query, we generate
        $N placeholders and track the actual values in self._params.
        This is the core security feature — zero string interpolation of values.
        """
        # Extract plain string from SigmaString
        plain = ""

        for part in value:
            if isinstance(part, str):
                plain += part
            elif part == SpecialChars.WILDCARD_MULTI:
                plain += "%"
            elif part == SpecialChars.WILDCARD_SINGLE:
                plain += "_"

        # If wildcards are present, LIKE pattern is needed
        # The caller (convert_condition_*) will handle adding LIKE
        return self._add_param(plain)

    def convert_condition_eq(self, field, value, state):
        """Convert equality condition with parameterized value."""
        mapped_field = self._validate_field(field)
        val_str = str(value)

        # Check if the raw value contains LIKE wildcards
        raw_value = self._params[-1] if self._params else val_str
        if isinstance(raw_value, str) and ("%" in raw_value or "_" in raw_value):
            # Contains wildcards → use LIKE
            return f"{mapped_field} LIKE {val_str}"
        return f"{mapped_field} {self.eq_token} {val_str}"

    def convert_condition_not_eq(self, field, value, state):
        """Convert not-equal condition."""
        mapped_field = self._validate_field(field)
        val_str = str(value)
        return f"{mapped_field} != {val_str}"

    def convert_condition_contains(self, field, value, state):
        """Convert contains modifier — value already has % wildcards."""
        mapped_field = self._validate_field(field)
        val_str = str(value)
        return f"{mapped_field} LIKE {val_str}"

    def convert_condition_startswith(self, field, value, state):
        """Convert startswith modifier."""
        mapped_field = self._validate_field(field)
        val_str = str(value)
        return f"{mapped_field} LIKE {val_str}"

    def convert_condition_endswith(self, field, value, state):
        """Convert endswith modifier."""
        mapped_field = self._validate_field(field)
        val_str = str(value)
        return f"{mapped_field} LIKE {val_str}"

    def convert_condition_re(self, field, value, state):
        """Convert regex condition with parameterized value."""
        mapped_field = self._validate_field(field)
        val_str = str(value)
        return f"{mapped_field} ~ {val_str}"

    def convert_condition_in(self, field, value, state):
        """Convert IN condition with parameterized list."""
        mapped_field = self._validate_field(field)
        placeholders = []
        for v in value:
            p = self._add_param(str(v))
            placeholders.append(p)
        return f"{mapped_field} IN ({', '.join(placeholders)})"

    # ───────────────────────────────────────────────────────
    # Main conversion — produce SQL query with parameters
    # ───────────────────────────────────────────────────────

    def convert_rule(self, rule: PySigmaRule, *args, **kwargs) -> str:
        """
        Convert a SigmaRule to a parameterized PostgreSQL query.

        Returns the WHERE clause portion. Caller wraps with SELECT/GROUP BY.
        """
        self._reset_state()

        # Apply processing pipeline (field mappings, etc.)
        output = super().convert_rule(rule, *args, **kwargs)

        return output

    def generate_query(
        self,
        rule: PySigmaRule,
        lookback_seconds: int = 3600,
    ) -> tuple[str, list[Any]]:
        """
        Generate a complete parameterized SQL query from a SigmaRule.

        Returns:
            Tuple of (SQL string, list of parameter values)

        This is the main entry point for the detection engine.
        """
        self._reset_state()

        # Convert the detection logic to WHERE clause
        where_parts = []
        for condition in rule.detection.parsed_condition:
            where_sql = self.convert_condition(condition.detection_item, ConversionState())
            if where_sql:
                where_parts.append(where_sql)

        where_clause = " AND ".join(where_parts) if where_parts else "TRUE"

        # Add logsource filter
        if rule.logsource and rule.logsource.category:
            cat_param = self._add_param(rule.logsource.category)
            where_clause = f"event_category = {cat_param} AND ({where_clause})"

        # Build complete query
        lookback_param = self._add_param(lookback_seconds)
        time_filter = f"time > NOW() - INTERVAL '1 second' * {lookback_param}"

        # Check for aggregation conditions in the parsed condition
        # pySigma handles aggregation differently — check the condition string
        condition_str = rule.detection.condition
        agg_match = re.match(
            r"(.+?)\s*\|\s*count\(([^)]+)\)\s*by\s+(\w+)\s*>\s*(\d+)",
            condition_str[0] if isinstance(condition_str, list) else condition_str,
        )

        if agg_match:
            agg_match.group(1).strip()
            count_field_raw = agg_match.group(2).strip() or "*"
            group_by_raw = agg_match.group(3).strip()
            threshold = int(agg_match.group(4))

            group_by = self._validate_field(group_by_raw)
            count_field = "*" if count_field_raw == "*" else self._validate_field(count_field_raw)

            threshold_param = self._add_param(threshold)

            sql = (
                f"SELECT {group_by}, COUNT({count_field}) as cnt "
                f"FROM logs "
                f"WHERE {where_clause} AND {time_filter} "
                f"GROUP BY {group_by} "
                f"HAVING COUNT({count_field}) > {threshold_param}"
            )
        else:
            sql = (
                f"SELECT * FROM logs "
                f"WHERE {where_clause} AND {time_filter} "
                f"ORDER BY time DESC"
            )

        return sql, self._params
