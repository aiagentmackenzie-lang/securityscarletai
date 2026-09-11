"""Correlation-chain matrix (V0.3 rule-quality CI) -- true/false event pairs
per chain, DB-backed.

The P1.2b lesson: unit tests hand-construct events in whatever vocabulary
the rules "expected" and passed while the live engine fired nothing. This
matrix is the CI-enforced answer: for EVERY correlation chain, seed the
exact events the pipeline produces (closed vocabulary from
src/ingestion/schemas.py -- the same tokens the auth shipper, the osquery
parser, and NeuralGuard emit) and assert:

    TRUE sequence  -> the chain FIRES (>= 1 match)
    FALSE sequence -> the chain is SILENT (0 matches)

End-to-end (shipper -> parser -> detect -> persist) is verified separately in
the live-fire drill (docs/PRODUCTION.md §1.4); this matrix pins the
per-chain detection LOGIC against Postgres. Runs in CI (postgres service,
RUN_INTEGRATION_TESTS=1).
"""

from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.integration

from src.db.connection import close_pool, get_pool  # noqa: E402
from src.detection.correlation import (  # noqa: E402
    CORRELATION_RULES,
    detect_ai_verdict_block_sustained,
    detect_brute_force_then_success,
    detect_credential_theft_exfil,
    detect_data_exfiltration,
    detect_defense_evasion_cleanup,
    detect_payload_callback,
    detect_persistence_activated,
    detect_privilege_escalation_chain,
)

NOW = datetime.now(timezone.utc)
MATRIX_HOST = "it-matrix-host"
EXTERNAL_IP = "198.51.100.77"  # TEST-NET-2 -- never a real destination


def _row(at: datetime, category: str, event_type: str, action: str | None, **extra) -> dict:
    return {
        "time": at,
        "host_name": MATRIX_HOST,
        "source": extra.pop("source", "osquery"),
        "event_category": category,
        "event_type": event_type,
        "event_action": action,
        "severity": extra.pop("severity", None),
        **extra,
    }


async def _insert(conn, rows: list[dict]) -> None:
    """Insert matrix rows with the FULL column set the detectors filter on
    (process_name, source_ip, file_path, …) -- the writer-shaped subset used
    by the NeuralGuard test would silently NULL the fields the chains key
    on and every test would lie."""
    import json

    INGESTABLE_COLUMNS = (
        "time",
        "host_name",
        "source",
        "event_category",
        "event_type",
        "event_action",
        "severity",
        "user_name",
        "process_name",
        "process_pid",
        "process_cmdline",
        "process_path",
        "source_ip",
        "destination_ip",
        "destination_port",
        "file_path",
        "file_hash",
        "enrichment",
    )
    values = []
    for r in rows:
        raw = r.get("raw_data") or {"matrix": r.get("event_action")}
        raw_json = json.dumps(raw)
        normalized = {
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in r.items()
            if k != "raw_data"
        }
        row_vals = []
        for col in INGESTABLE_COLUMNS:
            v = r.get(col)
            if col == "enrichment" and isinstance(v, dict):
                v = json.dumps(v)
            row_vals.append(v)
        values.append((*row_vals, raw_json, json.dumps(normalized)))
    cols = ", ".join(INGESTABLE_COLUMNS)
    placeholders = ", ".join(
        f"${i}::jsonb" if col in ("enrichment",) else f"${i}"
        for i, col in enumerate(INGESTABLE_COLUMNS, start=1)
    )
    raw_idx = len(INGESTABLE_COLUMNS) + 1
    norm_idx = raw_idx + 1
    await conn.executemany(
        f"""INSERT INTO logs ({cols}, raw_data, normalized)
        VALUES ({placeholders}, ${raw_idx}::jsonb, ${norm_idx}::jsonb)""",
        values,
    )


async def _insert_alert(conn, at: datetime, severity: str) -> None:
    await conn.execute(
        """
        INSERT INTO alerts (time, rule_name, severity, host_name, description)
        VALUES ($1, 'it-matrix-alert', $2, $3, 'matrix test alert')
        """,
        at,
        severity,
        MATRIX_HOST,
    )


async def _cleanup(conn) -> None:
    await conn.execute(
        "DELETE FROM correlation_matches WHERE match_data->>'host_name' = $1", MATRIX_HOST
    )
    await conn.execute("DELETE FROM alerts WHERE host_name = $1", MATRIX_HOST)
    await conn.execute("DELETE FROM logs WHERE host_name = $1", MATRIX_HOST)


@pytest.fixture
async def matrix_db():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await _cleanup(conn)
    yield pool
    async with pool.acquire() as conn:
        await _cleanup(conn)
    await close_pool()


# ───────────────────────────────────────────────────────────────
# Per-chain TRUE / FALSE sequences (pipeline-vocabulary events)
# ───────────────────────────────────────────────────────────────


class TestBruteForceSuccess:
    async def test_true_fires(self, matrix_db):
        base = NOW - timedelta(minutes=10)
        rows = [
            _row(
                base + timedelta(seconds=i * 30),
                "authentication",
                "start",
                "auth_failed",
                source="auth_shipper",
                source_ip=EXTERNAL_IP,
                user_name="admin",
            )
            for i in range(3)
        ] + [
            _row(
                base + timedelta(minutes=4),
                "authentication",
                "start",
                "auth_success",
                source="auth_shipper",
                source_ip=EXTERNAL_IP,
                user_name="admin",
            )
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_brute_force_then_success(conn, NOW)
        assert len(matches) >= 1

    async def test_false_below_threshold(self, matrix_db):
        base = NOW - timedelta(minutes=10)
        rows = [
            _row(
                base + timedelta(seconds=i * 30),
                "authentication",
                "start",
                "auth_failed",
                source="auth_shipper",
                source_ip=EXTERNAL_IP,
                user_name="admin",
            )
            for i in range(2)
        ] + [
            _row(
                base + timedelta(minutes=2),
                "authentication",
                "start",
                "auth_success",
                source="auth_shipper",
                source_ip=EXTERNAL_IP,
                user_name="admin",
            )
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_brute_force_then_success(conn, NOW)
        assert len(matches) == 0

    async def test_false_partitioned_by_source_ip(self, matrix_db):
        """Failures from IP-A, success from IP-B -- the (host, ip) window
        partition must NOT join across sources."""
        base = NOW - timedelta(minutes=10)
        rows = [
            _row(
                base + timedelta(seconds=i * 30),
                "authentication",
                "start",
                "auth_failed",
                source="auth_shipper",
                source_ip="198.51.100.10",
                user_name="admin",
            )
            for i in range(4)
        ] + [
            _row(
                base + timedelta(minutes=2),
                "authentication",
                "start",
                "auth_success",
                source="auth_shipper",
                source_ip="198.51.100.99",
                user_name="admin",
            )
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_brute_force_then_success(conn, NOW)
        assert len(matches) == 0


class TestPayloadCallback:
    async def test_true_fires(self, matrix_db):
        base = NOW - timedelta(minutes=5)
        rows = [
            _row(
                base,
                "process",
                "start",
                "process_start",
                process_name="implant",
                process_path="/tmp/implant",
            ),
            _row(
                base + timedelta(minutes=1),
                "network",
                "connection",
                "network_connection",
                destination_ip=EXTERNAL_IP,
                destination_port=4444,
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_payload_callback(conn, NOW)
        assert len(matches) >= 1

    async def test_false_legitimate_path(self, matrix_db):
        base = NOW - timedelta(minutes=5)
        rows = [
            _row(
                base,
                "process",
                "start",
                "process_start",
                process_name="python3",
                process_path="/opt/homebrew/bin/python3",
            ),
            _row(
                base + timedelta(minutes=1),
                "network",
                "connection",
                "network_connection",
                destination_ip=EXTERNAL_IP,
                destination_port=443,
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_payload_callback(conn, NOW)
        assert len(matches) == 0


class TestPersistenceActivated:
    async def test_true_fires(self, matrix_db):
        base = NOW - timedelta(minutes=20)
        rows = [
            _row(
                base,
                "file",
                "change",
                "file_created",
                file_path="/Users/admin/Library/LaunchAgents/com.evil.agent.plist",
            ),
            _row(
                base + timedelta(minutes=2),
                "process",
                "start",
                "process_start",
                process_name="launchctl",
                process_cmdline="launchctl load com.evil.agent.plist",
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_persistence_activated(conn, NOW)
        assert len(matches) >= 1

    async def test_false_created_elsewhere(self, matrix_db):
        base = NOW - timedelta(minutes=20)
        rows = [
            _row(base, "file", "change", "file_created", file_path="/Users/admin/notes.txt"),
            _row(
                base + timedelta(minutes=2),
                "process",
                "start",
                "process_start",
                process_name="launchctl",
                process_cmdline="launchctl load com.evil.agent.plist",
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_persistence_activated(conn, NOW)
        assert len(matches) == 0


class TestDataExfiltration:
    @staticmethod
    def _own(matches: list[dict]) -> list[dict]:
        """Scope matches to the matrix host -- the standing test DB holds REAL
        telemetry (other hosts burst-connect legitimately), and the detector
        scans all hosts by design."""
        return [m for m in matches if m["host_name"] == MATRIX_HOST]

    async def test_true_burst_path_fires_on_real_telemetry(self, matrix_db):
        """The connection-burst path: many outbound connections to ONE
        external IP -- no enrichment bytes required (real osquery telemetry)."""
        base = NOW - timedelta(minutes=30)
        rows = [
            _row(
                base + timedelta(seconds=i * 5),
                "network",
                "connection",
                "network_connection",
                destination_ip=EXTERNAL_IP,
                destination_port=443,
            )
            for i in range(10)  # threshold lowered via the detector param
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_data_exfiltration(conn, NOW, connection_threshold=5)
        assert len(self._own(matches)) >= 1
        assert self._own(matches)[0]["signal_type"] == "connection_burst"

    async def test_false_below_threshold(self, matrix_db):
        base = NOW - timedelta(minutes=5)
        rows = [
            _row(
                base + timedelta(seconds=i * 30),
                "network",
                "connection",
                "network_connection",
                destination_ip=EXTERNAL_IP,
                destination_port=443,
            )
            for i in range(3)
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_data_exfiltration(conn, NOW, connection_threshold=5)
        assert len(self._own(matches)) == 0


class TestPrivilegeEscalationChain:
    async def test_true_fires(self, matrix_db):
        base = NOW - timedelta(minutes=5)
        rows = [
            _row(
                base,
                "process",
                "start",
                "process_start",
                process_name="sudo",
                user_name="admin",
                process_cmdline="sudo -i",
            ),
            _row(
                base + timedelta(minutes=1),
                "process",
                "start",
                "process_start",
                process_name="python3",
                process_path="/tmp/py",
                user_name="0",
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_privilege_escalation_chain(conn, NOW)
        assert len(matches) >= 1

    async def test_false_daemon_respawn_not_chain_worthy(self, matrix_db):
        """Root launchd respawn from a system path after sudo = noise, not
        escalation evidence (the production FP control)."""
        base = NOW - timedelta(minutes=5)
        rows = [
            _row(base, "process", "start", "process_start", process_name="sudo", user_name="admin"),
            _row(
                base + timedelta(minutes=1),
                "process",
                "start",
                "process_start",
                process_name="mdworker",
                process_path="/usr/libexec/mdworker",
                user_name="0",
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_privilege_escalation_chain(conn, NOW)
        assert len(matches) == 0


class TestCredentialTheftExfil:
    async def test_true_cmdline_path_fires(self, matrix_db):
        base = NOW - timedelta(minutes=10)
        rows = [
            _row(
                base,
                "process",
                "start",
                "process_start",
                process_name="cat",
                process_cmdline="cat /Users/admin/.ssh/id_rsa",
                user_name="admin",
            ),
            _row(
                base + timedelta(minutes=2),
                "network",
                "connection",
                "network_connection",
                destination_ip=EXTERNAL_IP,
                destination_port=443,
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_credential_theft_exfil(conn, NOW)
        assert len(matches) >= 1

    async def test_false_ssh_client_excluded(self, matrix_db):
        """The interactive ssh client touching .ssh is implicit key use --
        excluded by the detector's FP control."""
        base = NOW - timedelta(minutes=10)
        rows = [
            _row(
                base,
                "process",
                "start",
                "process_start",
                process_name="ssh",
                process_cmdline="ssh -F /Users/admin/.ssh/config host",
                user_name="admin",
            ),
            _row(
                base + timedelta(minutes=2),
                "network",
                "connection",
                "network_connection",
                destination_ip=EXTERNAL_IP,
                destination_port=443,
            ),
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_credential_theft_exfil(conn, NOW)
        assert len(matches) == 0


class TestDefenseEvasionCleanup:
    async def test_true_alert_driven_fires(self, matrix_db):
        base = NOW - timedelta(minutes=20)
        async with matrix_db.acquire() as conn:
            await _insert_alert(conn, base, "critical")
            await _insert(
                conn,
                [
                    _row(
                        base + timedelta(minutes=3),
                        "process",
                        "start",
                        "process_start",
                        process_name="rm",
                        process_cmdline="rm -rf /var/log/system.log",
                    ),
                ],
            )
            matches = await detect_defense_evasion_cleanup(conn, NOW)
        assert len(matches) >= 1

    async def test_false_low_severity_alert(self, matrix_db):
        base = NOW - timedelta(minutes=20)
        async with matrix_db.acquire() as conn:
            await _insert_alert(conn, base, "low")
            await _insert(
                conn,
                [
                    _row(
                        base + timedelta(minutes=3),
                        "process",
                        "start",
                        "process_start",
                        process_name="rm",
                        process_cmdline="rm -rf /var/log/system.log",
                    ),
                ],
            )
            matches = await detect_defense_evasion_cleanup(conn, NOW)
        assert len(matches) == 0

    async def test_false_deletion_before_alert(self, matrix_db):
        """Time order matters: the cleanup must FOLLOW the alert."""
        base = NOW - timedelta(minutes=20)
        async with matrix_db.acquire() as conn:
            await _insert(
                conn,
                [
                    _row(
                        base,
                        "process",
                        "start",
                        "process_start",
                        process_name="rm",
                        process_cmdline="rm -rf /var/log",
                    ),
                ],
            )
            await _insert_alert(conn, base + timedelta(minutes=5), "critical")
            matches = await detect_defense_evasion_cleanup(conn, NOW)
        assert len(matches) == 0


class TestAiVerdictBlockSustained:
    async def test_true_fires(self, matrix_db):
        base = NOW - timedelta(minutes=5)
        rows = [
            {
                "time": base + timedelta(seconds=i * 10),
                "host_name": MATRIX_HOST,
                "source": "neuralguard",
                "event_category": "intrusion_detection",
                "event_type": "info",
                "event_action": "verdict_block",
                "severity": "critical",
                "raw_data": {"neuralguard": {"tenant_id": "it-matrix-tenant"}},
            }
            for i in range(12)
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_ai_verdict_block_sustained(
                conn, NOW, block_threshold=10, time_window_minutes=5
            )
        assert len(matches) >= 1

    async def test_false_below_threshold(self, matrix_db):
        base = NOW - timedelta(minutes=5)
        rows = [
            {
                "time": base + timedelta(seconds=i * 10),
                "host_name": MATRIX_HOST,
                "source": "neuralguard",
                "event_category": "intrusion_detection",
                "event_type": "info",
                "event_action": "verdict_block",
                "severity": "critical",
                "raw_data": {"neuralguard": {"tenant_id": "it-matrix-tenant-2"}},
            }
            for i in range(5)
        ]
        async with matrix_db.acquire() as conn:
            await _insert(conn, rows)
            matches = await detect_ai_verdict_block_sustained(
                conn, NOW, block_threshold=10, time_window_minutes=5
            )
        assert len(matches) == 0


class TestMatrixCompleteness:
    def test_every_correlation_chain_is_covered_by_a_test_class(self):
        """Adding a chain without a matrix class fails CI."""
        covered = {
            "brute_force_success",
            "payload_callback",
            "persistence_activated",
            "data_exfiltration",
            "privilege_escalation_chain",
            "credential_theft_exfil",
            "defense_evasion_cleanup",
            "ai_verdict_block_sustained",
        }
        assert covered == set(CORRELATION_RULES), (
            f"matrix out of sync with CORRELATION_RULES: {covered ^ set(CORRELATION_RULES)}"
        )
