"""
Tests for the Sigma -> SQL value/condition conversion — the parameterized-SQL
security core. Since P0-01/P0-04 the production path is the legacy SigmaParser
(src/detection/sigma.py); the pySigma PostgreSQLBackend was DELETED (W5-G: it
was off-path, its docstring claimed an enforced whitelist that only warned,
and it carried a fail-open WHERE TRUE fallback — the opposite of this
codebase's fail-safe-FALSE doctrine). These tests exercise sigma_to_sql
(legacy) to lock in safe parameterized output: values land as $N placeholders
carried in params, never interpolated into SQL.
"""

import pytest

from src.detection.sigma import sigma_to_sql


def _rule(modifier_line: str, logsource: str = "process") -> str:
    return f"""
title: Backend Modifier Test
status: experimental
logsource:
    category: {logsource}
detection:
    selection:
{modifier_line}
    condition: selection
"""


def test_startswith_emits_like_with_trailing_wildcard_param():
    sql, params = sigma_to_sql(_rule('        process_name|startswith: "/tmp"'))
    # legacy startswith -> `LIKE $N || '%'`; the value is a parameter and the
    # trailing % lives in the SQL (concatenation), never interpolated.
    assert "LIKE" in sql
    assert "/tmp" in params
    assert "DROP" not in sql


def test_endswith_emits_like_with_leading_wildcard_param():
    sql, params = sigma_to_sql(_rule('        file_path|endswith: ".exe"'))
    # legacy endswith -> `LIKE '%' || $N`; value parameterized, % in SQL.
    assert "LIKE" in sql
    assert ".exe" in params


def test_wildcard_multi_in_value_is_parameterized_not_interpolated():
    # Legacy equality (no modifier) keeps the value verbatim as a $N param.
    # (Sigma `*` -> SQL `%` wildcard conversion is a backend feature not
    # present in the legacy parser; no shipped rule relies on it.) The key
    # guarantee: the value is parameterized, never interpolated.
    sql, params = sigma_to_sql(_rule('        process_name: "*.py"'))
    assert "*.py" in params
    assert "DROP" not in sql


def test_wildcard_single_in_value_is_parameterized_not_interpolated():
    sql, params = sigma_to_sql(_rule('        process_name: "a?b"'))
    assert "a?b" in params
    assert "DROP" not in sql


def test_not_condition_emits_not_operator():
    # Legacy `_parse_condition` handles `selection and not filter` (bare `not`
    # alone is not supported by the legacy parser, but no shipped rule uses it).
    sql, params = sigma_to_sql(
        'title: t\nlogsource:\n  category: process\ndetection:\n  s:\n    process_name: "x"\n  f:\n    process_name: "y"\n  condition: s and not f\n'
    )
    assert "NOT" in sql
    assert "x" in params
    assert "y" in params


def test_regex_modifier_does_not_crash_or_interpolate():
    # The regex modifier must never interpolate the pattern into raw SQL — it's
    # either parameterized or safely degraded. The value must not leak as SQL.
    sql, params = sigma_to_sql(_rule('        process_name|re: "evil\'; DROP TABLE logs; --"'))
    assert "DROP TABLE" not in sql


def test_sql_injection_in_startswith_value_is_parameterized():
    malicious = _rule('        process_name|startswith: "\'; DROP TABLE logs; --"')
    sql, params = sigma_to_sql(malicious)
    assert "DROP TABLE" not in sql
    assert any("DROP TABLE" in str(p) for p in params)


def test_unknown_field_is_rejected_not_silently_dropped():
    # The legacy parser validates field names against ALLOWED_COLUMNS and raises
    # ValueError for unknown fields (a malformed rule is rejected at load rather
    # than over-firing as TRUE).
    with pytest.raises(ValueError):
        sigma_to_sql(_rule('        bogus_unknown_field: "value"'))


def test_backends_module_stays_gone():
    # W5-G: the pySigma PostgreSQLBackend was deleted (off-path dead code
    # with a lying docstring — warn-only whitelist, fail-open WHERE TRUE,
    # eq->LIKE underscore widening). This pin keeps it from returning.
    with pytest.raises(ImportError):
        import src.detection.backends  # noqa: F401
