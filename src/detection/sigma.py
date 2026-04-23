"""
Sigma rule parser and SQL generator.

Implements a subset of the Sigma specification:
- logsource.category/product mapping
- selection/filter conditions
- Field modifiers: |contains, |endswith, |startswith, |re
- Aggregation: count() by field > threshold

Generates parameterized SQL queries to prevent injection.
"""
import re
from dataclasses import dataclass
from typing import Any, Optional

import yaml

from src.config.logging import get_logger

log = get_logger("detection.sigma")


@dataclass
class SigmaRule:
    """Parsed Sigma rule structure."""
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


class SigmaParser:
    """Parse Sigma YAML rules and generate SQL."""

    # Field modifiers and their SQL equivalents
    MODIFIERS = {
        "contains": lambda field, val: f"{field} LIKE '%' || ${val} || '%'",
        "endswith": lambda field, val: f"{field} LIKE '%' || ${val}",
        "startswith": lambda field, val: f"{field} LIKE ${val} || '%'",
        "re": lambda field, val: f"{field} ~ ${val}",  # PostgreSQL regex
    }

    def __init__(self):
        self._param_counter = 0
        self._params: list[Any] = []

    def parse(self, yaml_content: str) -> SigmaRule:
        """Parse a Sigma rule from YAML string."""
        data = yaml.safe_load(yaml_content)

        # Extract MITRE tags
        tags = data.get("tags", [])
        mitre_tactics = [t.replace("attack.", "") for t in tags if t.startswith("attack.t") and len(t) == 8]
        mitre_techniques = [t.replace("attack.", "") for t in tags if t.startswith("attack.t") and len(t) > 8]

        # Extract condition from detection
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
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
        )

    def to_sql(self, rule: SigmaRule) -> tuple[str, list[Any]]:
        """
        Convert Sigma rule to parameterized SQL query.
        
        Returns:
            Tuple of (SQL query string, list of parameters)
        """
        self._param_counter = 0
        self._params = []

        # Build WHERE clause from condition
        where_clause = self._parse_condition(rule.condition, rule.detection)

        # Add logsource filter if specified
        filters = []
        if rule.logsource_category:
            filters.append(f"event_category = ${self._add_param(rule.logsource_category)}")

        if filters:
            where_clause = f"({' AND '.join(filters)}) AND ({where_clause})"

        # Check for aggregation
        agg_match = re.match(r"(.+?)\s*\|\s*count\(([^)]+)\)\s*by\s+(\w+)\s*>\s*(\d+)", rule.condition)
        if agg_match:
            base_condition = agg_match.group(1).strip()
            count_field = agg_match.group(2).strip() or "*"
            group_by = agg_match.group(3).strip()
            threshold = int(agg_match.group(4))

            where_clause = self._parse_condition(base_condition, rule.detection)
            if filters:
                where_clause = f"({' AND '.join(filters)}) AND ({where_clause})"

            # Aggregation query
            lookback = self._parse_timeframe(rule.timeframe)
            sql = f"""
                SELECT {group_by}, COUNT({count_field}) as cnt
                FROM logs
                WHERE {where_clause}
                  AND time > NOW() - INTERVAL '{lookback}'
                GROUP BY {group_by}
                HAVING COUNT({count_field}) > ${self._add_param(threshold)}
            """.strip()
        else:
            # Simple SELECT query
            lookback = self._parse_timeframe(rule.timeframe)
            sql = f"""
                SELECT *
                FROM logs
                WHERE {where_clause}
                  AND time > NOW() - INTERVAL '{lookback}'
                ORDER BY time DESC
            """.strip()

        return sql, self._params

    def _parse_condition(self, condition: str, detection: dict) -> str:
        """Parse the condition string into SQL WHERE clause."""
        # Handle 'selection and not filter'
        if " and not " in condition.lower():
            parts = condition.lower().split(" and not ")
            selection_sql = self._parse_selection(parts[0].strip(), detection)
            filter_sql = self._parse_selection(parts[1].strip(), detection)
            return f"({selection_sql}) AND NOT ({filter_sql})"

        # Handle 'selection or filter'
        if " or " in condition.lower():
            parts = condition.lower().split(" or ")
            sql_parts = [self._parse_selection(p.strip(), detection) for p in parts]
            return " OR ".join(f"({p})" for p in sql_parts)

        # Simple selection
        return self._parse_selection(condition.strip(), detection)

    def _parse_selection(self, name: str, detection: dict) -> str:
        """Parse a selection block into SQL."""
        if name not in detection:
            log.warning("selection_not_found", name=name)
            return "TRUE"

        selection = detection[name]
        conditions = []

        for field, value in selection.items():
            # Check for field modifiers
            modifier_match = re.match(r"^(\w+)\|(\w+)$", field)
            if modifier_match:
                field_name = modifier_match.group(1)
                modifier = modifier_match.group(2)
                sql_field = self._map_field(field_name)

                if modifier in self.MODIFIERS:
                    if isinstance(value, list):
                        # Multiple values with OR
                        or_conditions = []
                        for v in value:
                            or_conditions.append(self.MODIFIERS[modifier](sql_field, self._add_param(v)))
                        conditions.append(f"({' OR '.join(or_conditions)})")
                    else:
                        conditions.append(self.MODIFIERS[modifier](sql_field, self._add_param(value)))
                else:
                    log.warning("unknown_modifier", modifier=modifier, field=field)
                    conditions.append(f"{sql_field} = ${self._add_param(value)}")
            else:
                # Simple equality
                sql_field = self._map_field(field)
                if isinstance(value, list):
                    # IN clause for list values
                    params = [self._add_param(v) for v in value]
                    placeholders = ", ".join(f"${p}" for p in params)
                    conditions.append(f"{sql_field} IN ({placeholders})")
                else:
                    conditions.append(f"{sql_field} = ${self._add_param(value)}")

        return " AND ".join(conditions) if conditions else "TRUE"

    def _map_field(self, sigma_field: str) -> str:
        """Map Sigma field names to database column names."""
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
            "user_name": "user_name",
            "file_path": "file_path",
            "file_hash": "file_hash",
        }
        return mapping.get(sigma_field, sigma_field)

    def _add_param(self, value: Any) -> int:
        """Add a parameter and return its index (1-based for PostgreSQL)."""
        self._param_counter += 1
        self._params.append(value)
        return self._param_counter

    def _parse_timeframe(self, timeframe: Optional[str]) -> str:
        """Convert Sigma timeframe to PostgreSQL interval."""
        if not timeframe:
            return "1 hour"  # Default

        # Sigma format: 5m, 1h, 1d
        match = re.match(r"(\d+)([mhd])", timeframe)
        if match:
            num, unit = match.groups()
            unit_map = {"m": "minutes", "h": "hours", "d": "days"}
            return f"{num} {unit_map[unit]}"

        return "1 hour"


def parse_sigma_rule(yaml_content: str) -> SigmaRule:
    """Convenience function to parse a Sigma rule."""
    parser = SigmaParser()
    return parser.parse(yaml_content)


def sigma_to_sql(yaml_content: str) -> tuple[str, list[Any]]:
    """Convenience function to convert Sigma YAML to SQL."""
    parser = SigmaParser()
    rule = parser.parse(yaml_content)
    return parser.to_sql(rule)
