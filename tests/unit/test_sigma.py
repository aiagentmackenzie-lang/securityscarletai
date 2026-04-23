from src.detection.sigma import parse_sigma_rule, sigma_to_sql

SAMPLE_BRUTE_FORCE = """
title: SSH Brute Force Detected
id: scarlet-001
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
    assert rule.id == "scarlet-001"
    assert rule.title == "SSH Brute Force Detected"
    assert rule.logsource_category == "authentication"
    assert "t1110" in rule.mitre_techniques


def test_sigma_to_sql_basic():
    sql, params = sigma_to_sql(SAMPLE_BRUTE_FORCE)
    assert "SELECT host_name, COUNT(source_ip)" in sql
    assert "GROUP BY host_name" in sql
    assert "HAVING COUNT(source_ip)" in sql
    assert len(params) > 0
    # Check parameter values
    assert "start" in params or any("start" == str(p) for p in params)


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
