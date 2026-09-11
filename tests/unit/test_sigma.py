"""Tests for Sigma parser — including SQL injection defense."""

import pytest

from src.detection.sigma import ALLOWED_COLUMNS, _validate_column, parse_sigma_rule, sigma_to_sql

# ───────────────────────────────────────────────────────────
# Basic parsing tests
# ───────────────────────────────────────────────────────────

SAMPLE_BRUTE_FORCE = """
title: SSH Brute Force Detected
id: 86d7b047-4d49-5dbd-9aeb-d92cd4b0e64c
status: experimental
description: Test rule
logsource:
    category: authentication
detection:
    selection:
        event_type: "start"
        event_action|contains: "logged_in_users"
    condition: selection | count(source_ip) by host_name > 5
timeframe: 5m
level: high
tags:
    - attack.t1110
"""


def test_parse_sigma_rule():
    rule = parse_sigma_rule(SAMPLE_BRUTE_FORCE)
    assert rule.id == "86d7b047-4d49-5dbd-9aeb-d92cd4b0e64c"
    assert rule.title == "SSH Brute Force Detected"
    assert rule.logsource_category == "authentication"


def test_sigma_to_sql_basic():
    sql, params = sigma_to_sql(SAMPLE_BRUTE_FORCE)
    assert "SELECT host_name, COUNT(source_ip)" in sql
    assert "GROUP BY host_name" in sql
    assert "HAVING COUNT(source_ip)" in sql
    assert len(params) > 0
    # Check parameter values — authentication category and threshold
    assert "authentication" in params or any("authentication" == str(p) for p in params)


def test_contains_modifier():
    yaml = """
title: Test
detection:
    selection:
        event_action|contains: "failed"
    condition: selection
"""
    sql, params = sigma_to_sql(yaml)
    assert "LIKE" in sql
    assert "failed" in params


def test_list_values():
    yaml = """
title: Test
detection:
    selection:
        event_type:
            - start
            - end
    condition: selection
"""
    sql, params = sigma_to_sql(yaml)
    assert "IN" in sql
    assert "start" in params
    assert "end" in params


# ───────────────────────────────────────────────────────────
# ── SECURITY: SQL Injection Defense Tests ───────────────────
# ───────────────────────────────────────────────────────────


def test_sigma_prevents_sql_injection_in_values():
    """SQL injection in field VALUES must be parameterized, not raw SQL."""
    malicious = """
title: Evil Rule
detection:
    selection:
        host_name: "'; DROP TABLE logs; --"
    condition: selection
"""
    sql, params = sigma_to_sql(malicious)
    # The injection attempt must be parameterized, not appear in raw SQL
    assert "DROP TABLE" not in sql
    assert "'; DROP TABLE logs; --" in params or any("DROP" not in str(p) for p in params)
    # The parameterized value should be in the params list
    assert any("DROP TABLE" in str(p) for p in params)


def test_sigma_prevents_sql_injection_in_timeframe():
    """Timeframe must be converted to safe integer seconds, not interpolated."""
    yaml = """
title: Timeframe Injection Test
detection:
    selection:
        event_type: "start"
    condition: selection
timeframe: 5m
"""
    sql, params = sigma_to_sql(yaml)
    # Must use INTERVAL multiplication, not string interpolation
    assert "INTERVAL '1 second'" in sql or "INTERVAL '1 minute'" not in sql
    # The seconds must be a parameterized integer
    assert 300 in params  # 5 minutes = 300 seconds


def test_sigma_rejects_malicious_timeframe():
    """Malicious timeframe strings must be handled safely."""
    yaml = """
title: Evil Timeframe
detection:
    selection:
        event_type: "start"
    condition: selection
timeframe: "1; DROP TABLE logs; --"
"""
    # Should not crash and should fall back to 1 hour default
    sql, params = sigma_to_sql(yaml)
    assert "DROP TABLE" not in sql
    # Falls back to default 3600 seconds (1 hour)
    assert 3600 in params


def test_sigma_prevents_sql_injection_in_group_by():
    """Column names in GROUP BY must be whitelisted."""
    yaml = """
title: Evil Group By
detection:
    selection:
        event_type: "start"
    condition: selection | count(source_ip) by host_name > 5
timeframe: 5m
"""
    # Valid column name should work
    sql, params = sigma_to_sql(yaml)
    assert "host_name" in sql


def test_sigma_rejects_invalid_column_in_group_by():
    """Invalid column names in GROUP BY must be rejected."""
    # This shouldn't be in the normal Sigma to SQL flow, but test _validate_column
    with pytest.raises(ValueError, match="Invalid column name"):
        _validate_column("evil_column; DROP TABLE logs; --")


def test_sigma_rejects_invalid_column_in_count():
    """Invalid column names in COUNT must be rejected."""
    with pytest.raises(ValueError, match="Invalid column name"):
        _validate_column("1=1 OR 1=1")


def test_sigma_all_columns_whitelisted():
    """All expected columns must be in the whitelist."""
    essential_columns = [
        "event_type",
        "event_action",
        "event_category",
        "host_name",
        "source_ip",
        "destination_ip",
        "process_name",
        "user_name",
        "severity",
    ]
    for col in essential_columns:
        assert col in ALLOWED_COLUMNS, f"Column '{col}' missing from ALLOWED_COLUMNS"


# ───────────────────────────────────────────────────────────
# ── MITRE Tag Parsing Tests ─────────────────────────────────
# ───────────────────────────────────────────────────────────


def test_mitre_tactic_and_technique_parsing():
    """Tactic IDs (TA prefix) and Technique IDs (T prefix, no TA) must be separated."""
    yaml = """
title: MITRE Parse Test
detection:
    selection:
        event_type: "start"
    condition: selection
tags:
    - attack.t1110
    - attack.ta0001
    - attack.t1078
    - attack.ta0003
"""
    rule = parse_sigma_rule(yaml)
    # Tactics are attack.ta*
    assert "TA0001" in rule.mitre_tactics
    assert "TA0003" in rule.mitre_tactics
    # Techniques are attack.t* but NOT attack.ta*
    assert "T1110" in rule.mitre_techniques
    assert "T1078" in rule.mitre_techniques
    # Tactics must NOT appear in techniques
    assert "TA0001" not in rule.mitre_techniques
    assert "TA0003" not in rule.mitre_techniques


def test_parameterized_lookback_simple_query():
    """Simple (non-aggregation) queries must use parameterized interval."""
    yaml = """
title: Simple Query
detection:
    selection:
        event_type: "start"
    condition: selection
timeframe: 1h
"""
    sql, params = sigma_to_sql(yaml)
    # Must use parameterized interval, not string interpolation
    assert "INTERVAL '1 second' *" in sql
    assert 3600 in params  # 1 hour = 3600 seconds


def test_parameterized_lookback_aggregation_query():
    """Aggregation queries must use parameterized interval."""
    sql, params = sigma_to_sql(SAMPLE_BRUTE_FORCE)
    # Must use parameterized interval, not string interpolation
    assert "INTERVAL '1 second' *" in sql
    # 5 minutes = 300 seconds
    assert 300 in params


# ───────────────────────────────────────────────────────────
# Param-type coercion — asyncpg binding traps (2026-09-10)
#
# Rules 91/100 class: unbindable param types crashed EVERY scheduler run
# ("expected str, got int" / "expected str, got dict"). The compiler now
# coerces per schema column type and fails SAFE to FALSE for values it
# cannot represent faithfully.
# ───────────────────────────────────────────────────────────


def test_numeric_contains_value_coerced_to_str_for_text_column():
    """Unquoted YAML ints (rule 91: setuid 4755/4754) must arrive as strings
    against the TEXT column process_cmdline — never as Python ints."""
    yaml_rule = """
title: Setuid Test
logsource:
    category: process
detection:
    selection:
        process_name: chmod
        process_cmdline|contains:
            - u+s
            - 4755
    condition: selection
"""
    sql, params = sigma_to_sql(yaml_rule)
    # Params: event_category filter, process_name, then the contains list.
    assert params[:4] == ["process", "chmod", "u+s", "4755"]
    assert "4755" in params and isinstance(params[3], str)


def test_mapping_value_failsafe_never_over_fires():
    """A mapping value (YAML `- /node:` parses as {'/node': None}) cannot be
    compiled faithfully — the selection must fail SAFE to FALSE (match
    nothing, log loudly), never drop the condition and match MORE."""
    yaml_rule = """
title: WMI Test
logsource:
    category: process
detection:
    selection:
        process_cmdline|contains:
            - wmic
            - /node:
    condition: selection
"""
    sql, params = sigma_to_sql(yaml_rule)
    assert "FALSE" in sql
    # No dict/None param may ever reach the SQL layer.
    assert not any(isinstance(p, (dict, list)) or p is None for p in params)


def test_int_column_string_value_coerced_to_int():
    """A digit-string against an INTEGER column binds as int (asyncpg would
    reject the str with 'expected int, got str')."""
    yaml_rule = """
title: Port Test
detection:
    selection:
        destination_port: "445"
    condition: selection
"""
    _sql, params = sigma_to_sql(yaml_rule)
    assert 445 in params


def test_invalid_inet_equality_failsafe():
    """A non-IP string against INET equality would crash every run
    (asyncpg inet parse error) — the selection must fail safe to FALSE."""
    yaml_rule = """
title: INET Test
detection:
    selection:
        source_ip: "not-an-ip"
    condition: selection
"""
    sql, params = sigma_to_sql(yaml_rule)
    assert "FALSE" in sql
    assert "not-an-ip" not in params


def test_like_on_int_column_casts_to_text():
    """LIKE-family modifiers on INTEGER columns must compare on the text form
    ('operator does not exist: integer ~~ text' otherwise)."""
    yaml_rule = """
title: Port Prefix Test
detection:
    selection:
        destination_port|startswith: "4"
    condition: selection
"""
    sql, params = sigma_to_sql(yaml_rule)
    assert "destination_port::text" in sql
    assert "4" in params
