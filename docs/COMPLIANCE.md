# SecurityScarletAI -- Compliance & Reporting Runbook (V0.7)

The product surfaces a duty-holder actually uses when a regulator (or a
client's auditor) asks questions. Every mapping below is SURFACE-BASED:
it points at the endpoint/table that evidences the control in this
deployment -- never at an aspirational claim.

- Framework source of truth: `config/compliance_mappings.yaml`
  (versioned; the API serves it fail-closed -- a missing/unparseable file
  is a 503, never fabricated coverage).
- The tamper-evident source of truth for EVERYTHING in this document is
  the append-only audit chain (`audit_log`/`audit_logs`, DB-enforced
  append-only in the two-role posture; verify with
  `python -m scripts.check_audit_grants --strict`).

## 1. The UK CS&R incident duty (24h/72h)

The UK Cyber Security & Resilience regime requires in-scope entities to
notify within **24 hours** of becoming aware of a reportable incident and
file the full report within **72h** (pre-positioning included). The SIEM
supplies the evidence and the timeline; the duty-holder files the report.

Workflow:

1. **Detection**: the SIEM fires the alert (Sigma + correlation). The
   alert's `time` is the detection timestamp the pack computes from.
2. **Evidence pack**: `GET /api/v1/compliance/incidents/{alert_id}/evidence-pack`
   (analyst+). The export is audited (`compliance.evidence_pack_export`).
   The pack carries:
   - `reporting_cadence`: `initial_notification_due` (detected + 24h) and
     `final_report_due` (detected + 72h), with the honest note that the
     duty-holder's awareness clock may differ.
   - `incident`: the alert with provenance (`alerts`).
   - `correlation`: matched chain(s), resolved via the match's
     correlation_id embedded in the alert evidence.
   - `case`: the case object + `case_events` timeline (verdicts with
     mandatory rationale = the governed decision record).
   - `response_actions`: the four-eyes trail (requested_by != approved_by),
     policy effect, execution + verification evidence (the re-query proof),
     rollback notes.
   - `quarantine`: enforcement state.
   - `audit_receipts`: the chain rows for the incident's objects.
3. **The pack is an input, not the report**: the operator drafts the
   regulator filing from it. Never ship raw_data payloads inside filings
   without reviewing them (the pack carries the alert's evidence blob
   verbatim; review before filing).

## 2. The standing reports

| Endpoint | Answers |
|---|---|
| `GET /compliance/reports/coverage` | "What can you actually detect?" -- the evidence-driven armed/dormant map, not a rule-count claim |
| `GET /compliance/reports/posture` | "How did we do?" -- alert counts by severity/status, MTTR, rule-scorecard summary for the window, + the UEBA-ready outliers view (per-host alert-volume and per-user auth-failure outliers via robust median/MAD z-scores over the window's own population; read-only from alerts/logs, no persisted baselines -- V0.8 UEBA supersedes the statistics, not the shape) |
| `GET /compliance/frameworks` | "Which framework controls do you evidence?" -- the versioned surface mapping (UK CS&R Bill, CAF v4.0, NIS2/DORA, NIST CSF, SOC2/ISO) |
| `GET /compliance/retention-policy` | "How long do you keep logs?" -- configured windows AS CONFIGURED (0 = keep forever, reported honestly) + TimescaleDB policy state when present |

All four are auth'd reads. Nothing here mutates state.

## 3. Framework notes

- **CAF v4.0** (NCSC): the monitoring/response principles map to the
  scheduler + coverage map + bounded response authority. The v4.0 AI
  governance expectations map to `agent_investigations` (HITL state),
  the decisions view, and the OWASP ASI mapping.
- **NIS2/DORA**: the evidence pack + retention evidence are the
  incident-handling and logging views.
- **UK CS&R Bill**: the reporting cadence block is the 24/72h spec.
- **SOC 2 / ISO 27001 / NIST CSF**: the audit chain + retention evidence
  are the generic logging/monitoring views.

## 4. Retention as evidence

`GET /compliance/retention-policy` reports per-table windows
(`logs`, `alerts`, `audit_logs`, `audit_log`, `correlation_matches`,
`ai_usage`) with the enforcement mechanism named. The M-Trends dwell-time
data puts the industry bar at >= 1 year for high-value sources; the
DEFAULT logs window is 30 days (Timescale retention policy) -- operators
answering to a regime that demands more MUST raise it here and the
endpoint will evidence the new value on the next read. Cold-storage
archive mechanics are the documented V0.8+ remainder.

## 5. What this surface is NOT (honest scope)

- Not an automated compliance report generator for specific regulators --
  it is the evidence layer a report is drafted from.
- Not a legal determination of scope or reportability.
- Not a certification artifact; the audit chain + these endpoints are the
  EVIDENCE the assessor evaluates.