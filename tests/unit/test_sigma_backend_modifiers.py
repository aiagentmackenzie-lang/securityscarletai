"""
Tests for the pySigma PostgreSQL backend's value/condition conversion — the
parameterized-SQL security core in src/detection/backends/postgresql.py.

These exercise convert_value_str (wildcard multi/single), convert_condition_eq
(LIKE branch), startswith, endswith, not, and the field-validation path via
realistic Sigma rules with a logsource (so the pySigma path is taken, not the
legacy fallback). Values must end up as $N placeholders with the transformed
string in params — never interpolated into SQL.
"""

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
    # startswith appends % to the value, carried as a parameter (never interpolated)
    assert "/tmp%" in params
    assert "DROP" not in sql


def test_endswith_emits_like_with_leading_wildcard_param():
    sql, params = sigma_to_sql(_rule('        file_path|endswith: ".exe"'))
    # endswith prepends % to the value, carried as a parameter
    assert "%.exe" in params


def test_wildcard_multi_in_value_becomes_percent_param():
    # Sigma '*' maps to SQL '%' inside the value, parameterized
    sql, params = sigma_to_sql(_rule('        process_name: "*.py"'))
    assert "%.py" in params


def test_wildcard_single_in_value_becomes_underscore_param():
    # Sigma '?' maps to SQL '_' inside the value, parameterized
    sql, params = sigma_to_sql(_rule('        process_name: "a?b"'))
    assert "a_b" in params


def test_not_condition_emits_not_operator():
    sql, params = sigma_to_sql(
        "title: t\nlogsource:\n  category: process\ndetection:\n  s:\n    process_name: \"x\"\n  condition: not s\n"
    )
    assert "NOT" in sql
    assert "x" in params


def test_regex_modifier_does_not_crash_or_interpolate():
    # The backend's regex support is partial (pySigma may fall back), but it must
    # never interpolate the pattern into raw SQL — it's either parameterized or
    # safely degraded. The value must not leak as raw SQL.
    sql, params = sigma_to_sql(_rule('        process_name|re: "evil\'; DROP TABLE logs; --"'))
    assert "DROP TABLE" not in sql


def test_sql_injection_in_startswith_value_is_parameterized():
    malicious = _rule('        process_name|startswith: "\'; DROP TABLE logs; --"')
    sql, params = sigma_to_sql(malicious)
    assert "DROP TABLE" not in sql
    assert any("DROP TABLE" in str(p) for p in params)


def test_unknown_field_is_warned_not_fatal():
    # A field absent from FIELD_MAPPING must not crash conversion; it passes
    # through (with a warning) so detection still runs.
    sql, params = sigma_to_sql(_rule('        bogus_unknown_field: "value"'))
    # conversion completes and produces a query
    assert "SELECT" in sql or "WHERE" in sql


def test_validate_field_known_column_passes():
    from src.detection.backends.postgresql import PostgreSQLBackend

    b = PostgreSQLBackend()
    assert b._validate_field("source_ip") == "source_ip"
    assert b._validate_field("process_name") == "process_name"


def test_validate_field_unknown_column_warns_but_returns():
    from src.detection.backends.postgresql import PostgreSQLBackend

    b = PostgreSQLBackend()
    # not in FIELD_MAPPING -> returns the raw name (with a warning), no raise
    result = b._validate_field("not_a_real_column")
    assert result == "not_a_real_column"


def test_add_param_increments_counter_and_returns_placeholder():
    from src.detection.backends.postgresql import PostgreSQLBackend

    b = PostgreSQLBackend()
    b._reset_state()
    assert b._add_param("a") == "$1"
    assert b._add_param("b") == "$2"
    assert b._params == ["a", "b"]


def test_reset_state_clears_params():
    from src.detection.backends.postgresql import PostgreSQLBackend

    b = PostgreSQLBackend()
    b._add_param("x")
    assert b._params == ["x"]
    b._reset_state()
    assert b._params == []
    assert b._param_counter == 0


class TestBackendConditionMethods:
    """Directly exercise the convert_condition_* overrides (the parameterized
    SQL generators). pySigma's pipeline routes some modifiers through eq, so
    these methods are unit-tested in isolation to lock in their behavior."""

    def _backend(self):
        from src.detection.backends.postgresql import PostgreSQLBackend

        b = PostgreSQLBackend()
        b._reset_state()
        return b

    def test_eq_without_wildcard_uses_equals_token(self):
        from sigma.conversion.state import ConversionState
        from sigma.types import SigmaString

        b = self._backend()
        st = ConversionState()
        placeholder = b.convert_value_str(SigmaString("1.2.3.4"), st)
        assert b.convert_condition_eq("source_ip", placeholder, st) == "source_ip = $1"
        assert b._params == ["1.2.3.4"]

    def test_eq_with_wildcard_uses_like(self):
        from sigma.conversion.state import ConversionState
        from sigma.types import SigmaString

        b = self._backend()
        st = ConversionState()
        placeholder = b.convert_value_str(SigmaString("ab*cd"), st)
        assert b.convert_condition_eq("process_name", placeholder, st) == "process_name LIKE $1"
        assert b._params == ["ab%cd"]

    def test_not_eq(self):
        from sigma.conversion.state import ConversionState

        b = self._backend()
        assert b.convert_condition_not_eq("source_ip", "$1", ConversionState()) == "source_ip != $1"

    def test_contains(self):
        from sigma.conversion.state import ConversionState

        b = self._backend()
        assert b.convert_condition_contains("process_name", "$1", ConversionState()) == "process_name LIKE $1"

    def test_startswith(self):
        from sigma.conversion.state import ConversionState

        b = self._backend()
        assert b.convert_condition_startswith("process_name", "$1", ConversionState()) == "process_name LIKE $1"

    def test_endswith(self):
        from sigma.conversion.state import ConversionState

        b = self._backend()
        assert b.convert_condition_endswith("file_path", "$1", ConversionState()) == "file_path LIKE $1"

    def test_regex(self):
        from sigma.conversion.state import ConversionState

        b = self._backend()
        assert b.convert_condition_re("process_name", "$1", ConversionState()) == "process_name ~ $1"

    def test_in(self):
        from sigma.conversion.state import ConversionState

        b = self._backend()
        result = b.convert_condition_in("source_ip", ["1.1.1.1", "2.2.2.2"], ConversionState())
        assert result == "source_ip IN ($1, $2)"
        assert b._params == ["1.1.1.1", "2.2.2.2"]

    def test_convert_value_str_plain(self):
        from sigma.conversion.state import ConversionState
        from sigma.types import SigmaString

        b = self._backend()
        out = b.convert_value_str(SigmaString("hello"), ConversionState())
        assert out == "$1"
        assert b._params == ["hello"]
