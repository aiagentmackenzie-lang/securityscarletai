"""V0.7 compliance & reporting -- unit gates.

Covers: the evidence-pack builder (chain assembly, provenance, cadence
dates, 404 honesty), the fail-closed framework mapping loader, the
retention-policy evidence (configured truth + fail-closed Timescale
probe), the shipper-in-demo posture check (the Sep-12 gap), and endpoint
wiring.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.compliance.evidence import build_evidence_pack
from src.compliance.frameworks import parse_frameworks_document
from src.compliance.retention import _timescaledb_policy_state, retention_policy_evidence

AS_OF = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)


def _pool_mock(conn):
    mock_pool = MagicMock()
    acquirer = MagicMock()
    acquirer.__aenter__ = AsyncMock(return_value=conn)
    acquirer.__aexit__ = AsyncMock(return_value=None)
    mock_pool.acquire = MagicMock(return_value=acquirer)
    return mock_pool


class TestEvidencePackBuilder:
    @pytest.mark.asyncio
    async def test_missing_alert_is_none(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        with patch("src.compliance.evidence.get_pool", return_value=_pool_mock(conn)):
            assert await build_evidence_pack(999, AS_OF) is None

    @pytest.mark.asyncio
    async def test_pack_shape_and_cadence_dates(self):
        alert_time = AS_OF - timedelta(hours=10)
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": 7,
                "time": alert_time,
                "rule_id": 1,
                "rule_name": "Reverse Shell Pattern Detected",
                "severity": "critical",
                "status": "investigating",
                "host_name": "web-01",
                "description": "Detection: reverse shell",
                "mitre_tactics": ["TA0002"],
                "mitre_techniques": ["T1059"],
                "evidence": '{"match": {"correlation_id": "corr-abc"}}',
                "risk_score": 0.9,
                "assigned_to": "analyst",
                "resolved_at": None,
                "resolution_note": None,
                "case_id": None,
                "created_at": alert_time,
                "updated_at": alert_time,
                "notes": None,
            }
        )
        conn.fetch = AsyncMock(return_value=[])

        async def fetch_side_effect(sql, *params):
            if "match_data->>'correlation_id'" in sql:
                assert params[0] == "corr-abc"  # resolved from alert evidence
                return [
                    {
                        "id": 3,
                        "correlation_rule": "payload_callback",
                        "severity": "critical",
                        "match_data": {"correlation_id": "corr-abc"},
                        "trigger_event_id": None,
                        "seen": False,
                        "created_at": alert_time,
                    }
                ]
            return []

        conn.fetch = AsyncMock(side_effect=fetch_side_effect)
        with patch("src.compliance.evidence.get_pool", return_value=_pool_mock(conn)):
            pack = await build_evidence_pack(7, AS_OF)

        assert pack["incident"]["alert_id"] == 7
        assert pack["reporting_cadence"]["initial_notification_due"] == (
            (alert_time + timedelta(hours=24)).isoformat()
        )
        assert pack["reporting_cadence"]["final_report_due"] == (
            (alert_time + timedelta(hours=72)).isoformat()
        )
        assert pack["correlation"][0]["correlation_rule"] == "payload_callback"
        # Case block honest for a case-less alert; quarantine probed anyway.
        assert pack["case"]["case"] is None
        # Every section names its sources.
        assert pack["incident"]["sources"] == ["alerts"]
        assert pack["correlation"][0]["sources"] == ["correlation_matches"]

    @pytest.mark.asyncio
    async def test_case_chain_and_audit_receipts(self):
        alert_time = AS_OF - timedelta(days=1)
        conn = AsyncMock()

        async def fetchrow_side_effect(sql, *params):
            if "FROM cases" in sql:
                return {
                    "id": 3,
                    "title": "Reverse shell on web-01",
                    "description": "investigation",
                    "status": "in_progress",
                    "severity": "high",
                    "assigned_to": "analyst",
                    "lessons_learned": None,
                    "resolution_note": None,
                    "resolved_at": None,
                    "created_at": alert_time,
                    "updated_at": alert_time,
                }
            return {
                "id": 9,
                "time": alert_time,
                "rule_id": 1,
                "rule_name": "Alert",
                "severity": "high",
                "status": "investigating",
                "host_name": "web-01",
                "description": None,
                "mitre_tactics": [],
                "mitre_techniques": [],
                "evidence": "{}",
                "risk_score": None,
                "assigned_to": None,
                "resolved_at": None,
                "resolution_note": None,
                "case_id": 3,
                "created_at": alert_time,
                "updated_at": alert_time,
                "notes": '[{"author": "analyst", "text": "looked", "time": "..."}]',
            }

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side_effect)

        async def fetch_side_effect(sql, *params):
            if "FROM case_events" in sql:
                return [
                    {
                        "id": 1,
                        "event_type": "verdict",
                        "actor": "analyst",
                        "actor_kind": "human",
                        "payload": {"verdict": "true_positive", "rationale": "real"},
                        "alert_id": 9,
                        "action_id": None,
                        "created_at": alert_time,
                    }
                ]
            if "FROM response_actions" in sql:
                return [
                    {
                        "id": 2,
                        "action_type": "quarantine_host",
                        "params": {"host": "web-01"},
                        "policy_effect": "approval_required",
                        "status": "verified",
                        "requested_by": "a",
                        "justification": "j",
                        "approved_by": "b",
                        "approval_note": None,
                        "rejection_reason": None,
                        "executed_at": alert_time,
                        "verified_at": alert_time,
                        "evidence": {"before": 1, "after": 0},
                        "rollback_note": "rb",
                        "created_at": alert_time,
                        "updated_at": alert_time,
                    }
                ]
            if "FROM quarantined_hosts" in sql:
                return [
                    {
                        "host_name": "web-01",
                        "reason": "r",
                        "quarantined_by": "b",
                        "quarantined_at": alert_time,
                    }
                ]
            if "FROM audit_log" in sql:
                # target_type in (alert, case, response_action)
                return [
                    {
                        "id": 20,
                        "actor": "b",
                        "action": "response.approve",
                        "target_type": "response_action",
                        "target_id": 2,
                        "created_at": alert_time,
                    }
                ]
            return []

        conn.fetch = AsyncMock(side_effect=fetch_side_effect)
        with patch("src.compliance.evidence.get_pool", return_value=_pool_mock(conn)):
            pack = await build_evidence_pack(9, AS_OF)

        assert pack["case"]["case"]["id"] == 3
        assert pack["case"]["timeline"][0]["event_type"] == "verdict"
        assert pack["case"]["timeline"][0]["payload"]["verdict"] == "true_positive"
        ra = pack["case"]["response_actions"][0]
        assert ra["approved_by"] == "b"
        assert ra["status"] == "verified"
        assert ra["verification_evidence"] == {"before": 1, "after": 0}
        assert pack["case"]["quarantine"][0]["host_name"] == "web-01"
        receipts = pack["audit_receipts"]
        assert receipts and receipts[0]["action"] == "response.approve"


class TestFrameworkMappingsLoader:
    def test_parse_valid_document(self):
        doc = {
            "compliance_frameworks": {
                "version": 1,
                "frameworks": {
                    "uk_csr": {
                        "name": "UK CS&R",
                        "description": "d",
                        "controls": [
                            {
                                "id": "c1",
                                "requirement": "notify within 24h",
                                "surface": "GET /api/v1/compliance/incidents/1/evidence-pack",
                            },
                            # missing surface -> dropped (fail-closed)
                            {"id": "c2", "requirement": "no surface"},
                        ],
                    }
                },
            }
        }
        result = parse_frameworks_document(doc)
        assert result["version"] == 1
        assert list(result["frameworks"].keys()) == ["uk_csr"]
        controls = result["frameworks"]["uk_csr"]["controls"]
        assert len(controls) == 1  # incomplete control dropped
        assert controls[0]["id"] == "c1"

    def test_fail_closed_on_garbage(self):
        for garbage in (None, {}, {"compliance_frameworks": None}, [], "text"):
            assert parse_frameworks_document(garbage) == {}

    def test_shipped_config_loads_with_frameworks(self):
        from src.compliance.frameworks import load_frameworks_file

        doc = load_frameworks_file()
        assert doc["version"] == 1
        assert "uk_csr_bill" in doc["frameworks"]
        assert "caf_v4" in doc["frameworks"]
        for fw in doc["frameworks"].values():
            assert fw["controls"], f"{fw['name']} has no valid controls"
            for c in fw["controls"]:
                assert c["surface"], f"control {c['id']} names no surface"

    def test_missing_file_is_honest_empty(self, tmp_path):
        from src.compliance.frameworks import load_frameworks_file

        doc = load_frameworks_file(tmp_path / "nonexistent.yaml")
        assert doc == {"version": None, "frameworks": {}}


class TestRetentionPolicyEvidence:
    @pytest.mark.asyncio
    async def test_configured_truth_reported(self):
        with patch(
            "src.compliance.retention._timescaledb_policy_state",
            return_value={"timescaledb": False, "policies": [], "note": "n/a"},
        ):
            doc = await retention_policy_evidence(AS_OF)
        tables = {e["table"]: e for e in doc["configured"]}
        assert set(tables.keys()) == {
            "logs",
            "alerts",
            "audit_logs",
            "audit_log",
            "correlation_matches",
            "ai_usage",
        }
        assert tables["logs"]["window_days"] >= 0
        assert doc["engine"]["timescaledb"] is False

    @pytest.mark.asyncio
    async def test_timescale_probe_fail_closed(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(side_effect=Exception("no such table: timescaledb_information"))
        with patch("src.compliance.retention.get_pool", return_value=_pool_mock(conn)):
            engine = await _timescaledb_policy_state()
        assert engine["timescaledb"] is False
        assert "vanilla PostgreSQL" in engine["note"]


class TestShipperInDemoPostureCheck:
    def test_demo_with_shipper_is_violation(self):
        from scripts.posture_check import check_shipper_in_demo

        problem = check_shipper_in_demo(
            {"DEMO_SEED_ENABLED": "true", "ENABLE_INGESTION_SHIPPER": "true"}
        )
        assert problem is not None
        assert "4,239" in problem.detail

    def test_demo_without_shipper_passes(self):
        from scripts.posture_check import check_shipper_in_demo

        assert (
            check_shipper_in_demo(
                {"DEMO_SEED_ENABLED": "true", "ENABLE_INGESTION_SHIPPER": "false"}
            )
            is None
        )
        assert check_shipper_in_demo({"DEMO_SEED_ENABLED": "true"}) is None

    def test_prod_with_shipper_is_normal(self):
        # The standing prod posture carries the shipper by design.
        from scripts.posture_check import check_shipper_in_demo

        assert (
            check_shipper_in_demo({"DEMO_SEED_ENABLED": "", "ENABLE_INGESTION_SHIPPER": "true"})
            is None
        )

    @pytest.mark.asyncio
    async def test_run_checks_flags_the_leak(self):
        from scripts.posture_check import run_checks

        problems = await run_checks(
            {"DEMO_SEED_ENABLED": "true", "ENABLE_INGESTION_SHIPPER": "true"}
        )
        assert any(p.check == "shipper-in-demo" for p in problems)
