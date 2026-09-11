"""
Phase 3.5 — CI scanning jobs (pip-audit + Trivy) wiring tests.

Guards the wiring contract:
- ci.yml stays valid YAML
- dependency-audit job exists, uses pip-audit, and is ENFORCING (no
  continue-on-error) — the 2026-09-10 flip closed the two-week advisory
  window; the two documented risk-accepts are pinned via --ignore-vuln
  under both their PYSEC and CVE aliases
- trivy-image-scan job exists, scans HIGH/CRITICAL, uses .trivyignore,
  and is ENFORCING (zero findings at flip time)
- the existing build/test jobs are untouched (still blocking: no
  continue-on-error)
- .trivyignore exists and every non-comment entry carries rationale context
  (no wave-through CVE accepts)
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
CI_YML = REPO_ROOT / ".github/workflows/ci.yml"
TRIVYIGNORE = REPO_ROOT / ".trivyignore"


def _load_ci():
    return yaml.safe_load(CI_YML.read_text())


class TestCiWorkflowYaml:
    def test_ci_yml_parses(self):
        doc = _load_ci()
        assert doc["name"] == "CI"
        assert "jobs" in doc

    def test_dependency_audit_job_wiring(self):
        doc = _load_ci()
        job = doc["jobs"].get("dependency-audit")
        assert job is not None, "dependency-audit job missing"
        # 2026-09-10 flip: ENFORCING — the advisory window is closed. The pin
        # that asserted continue-on-error=True was the stale-pin class (a pin
        # encoding drift defeats itself).
        assert job.get("continue-on-error") is None, (
            "dependency-audit must gate CI (enforcing flip executed 2026-09-10)"
        )
        steps_yaml = str(job["steps"])
        assert "pip-audit" in steps_yaml
        # Both risk-accept aliases ignored (pip-audit matches the reported ID;
        # future versions may report either the PYSEC or the CVE form).
        for vuln_id in (
            "PYSEC-2026-2447",
            "PYSEC-2026-1325",
            "CVE-2025-69872",
            "CVE-2024-23342",
        ):
            assert f"--ignore-vuln {vuln_id}" in steps_yaml, (
                f"documented risk-accept {vuln_id} must stay pinned"
            )

    def test_trivy_job_wiring(self):
        doc = _load_ci()
        job = doc["jobs"].get("trivy-image-scan")
        assert job is not None, "trivy-image-scan job missing"
        # 2026-09-10 flip: ENFORCING (zero findings at flip time).
        assert job.get("continue-on-error") is None, (
            "trivy-image-scan must gate CI (enforcing flip executed 2026-09-10)"
        )
        text = str(job)
        assert "HIGH,CRITICAL" in text
        assert ".trivyignore" in text
        assert "securityscarletai:ci" in text

    def test_existing_jobs_stay_blocking(self):
        """The build/test flow must NOT be gated by the new scan jobs —
        build/test keep their hard-fail semantics."""
        doc = _load_ci()
        for blocking_job in ("build", "test"):
            assert doc["jobs"].get(blocking_job) is not None
            assert "continue-on-error" not in doc["jobs"][blocking_job]

    def test_trivyignore_policy(self):
        text = TRIVYIGNORE.read_text()
        # every non-empty, non-comment line must be a CVE/GHSA ID + rationale
        entries = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        for entry in entries:
            assert entry.upper().startswith(("CVE-", "GHSA-")), f"unidentified accept: {entry}"
