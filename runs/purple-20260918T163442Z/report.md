# Purple-loop run report

- Run window start: 2026-09-18T16:29:44.957807+00:00
- Chains fired: **10/10** (score 1.0)
- Alerts fired: **28** (25 distinct rules)
- ATT&CK techniques hit: **16** (16 of them armed-technique hits; hit rate over armed techniques: 0.381)
- Coverage map: 102 armed / 126 total rules (lookback 168h)

## Detection-gain progression (committed run history)

Every row is a real committed purple-loop run -- the compounding
coverage story as the detection engineering landed, not a
projection.

| Run | Chains | Score | Rules armed | Armed hit rate |
|:--|:--|:--|:--|:--|
| purple-20260911T152518Z | 8/8 | 1.0 | 86 | 0.371 |
| purple-20260911T184340Z | 7/8 | 0.875 | 86 | 0.2 |
| purple-20260911T184744Z | 2/8 | 0.25 | 86 | 0.086 |
| purple-20260911T185056Z | 8/8 | 1.0 | 86 | 0.0 |
| purple-20260911T191054Z | 8/8 | 1.0 | 86 | 0.257 |
| purple-20260911T193228Z | 8/8 | 1.0 | 90 | 0.306 |
| purple-20260912T131438Z | 7/8 | 0.875 | 92 | 0.189 |
| purple-20260912T132254Z | 8/8 | 1.0 | 92 | 0.081 |
| purple-20260914T124904Z | 7/10 | 0.7 | 102 | 0.286 |
| purple-20260914T125948Z | 0/10 | 0.0 | 102 | 0.0 |
| purple-20260914T131433Z | 0/10 | 0.0 | 102 | 0.286 |
| purple-20260914T132209Z | 0/10 | 0.0 | 102 | 0.286 |
| purple-20260914T132947Z | 10/10 | 1.0 | 102 | 0.381 |
| (this run) | 10/10 | 1.0 | 102 | 0.381 |

## Chains

| Chain | Fired |
|:--|:--|
| ai_process_egress | YES |
| ai_verdict_block_sustained | YES |
| brute_force_success | YES |
| clickfix_dropper_execution | YES |
| credential_theft_exfil | YES |
| data_exfiltration | YES |
| defense_evasion_cleanup | YES |
| payload_callback | YES |
| persistence_activated | YES |
| privilege_escalation_chain | YES |

## Rules that fired

- Data Exfiltration Volume
- Download and Execute Pattern
- Encoded Command Execution
- Hidden File Creation in User Directories
- LaunchAgent Persistence Created
- Living-off-the-Land Binary Execution
- Log File Deletion
- Login from Unusual Geography
- Outbound Connection to Rare/C2 Port
- Privilege Escalation via Sudo
- Renamed System Binary (Masquerading)
- Reverse Shell Pattern Detected
- Script Interpreter from Unexpected Location
- Service Account Anomaly
- Suspicious Process from /tmp
- ai_process_egress
- ai_verdict_block_sustained
- brute_force_success
- clickfix_dropper_execution
- credential_theft_exfil
- data_exfiltration
- macOS Local Account Created (users differential)
- payload_callback
- persistence_activated
- privilege_escalation_chain

## Armed techniques NOT hit by this run

These chains/techniques did not participate in this run; they are
not failures -- they are the rest of the coverage map.

- T1003
- T1021
- T1041
- T1047
- T1053
- T1055
- T1074
- T1090
- T1098
- T1176
- T1213
- T1219
- T1486
- T1490
- T1505
- T1543
- T1546
- T1550
- T1553
- T1555
- T1560
- T1562
- T1567
- T1572
- T1574
- T1606
## TES-aligned scoring (SELF-SCORED)

Methodology: MITRE ATT&CK Evaluations Enterprise 2026 — self-scored,
NOT program participation. Detection-only run: PQI is not scored;
the TES line below reports DQI alone.

- Weighted DC (ACW, /3.0): **0.667** (raw 2.0)
- Detection Precision: unmeasured — no cases to measure consolidation against
- Detection Speed: unmeasured (at least one MTTD not derivable)
- DQI: unmeasured (a component above is unmeasured — honesty gate)
- IQI (reported separately): unmeasured — AP; CS_normalized

| Behavior | Chain | ACW | DC | Blocking (DC-3 elements) | MTTD min | IC |
|:--|:--|:--|:--|:--|:--|:--|
| T1027 | ai_process_egress | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1048 | ai_process_egress | 1.0 | DC-2 (2.0) | WHO | unmeasured | IC-2 |
| T1190 | ai_verdict_block_sustained | 1.0 | DC-2 (2.0) | WHERE, WHO | unmeasured | IC-2 |
| T1078 | brute_force_success | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1110 | brute_force_success | 1.0 | DC-2 (2.0) | WHO | unmeasured | IC-2 |
| T1059 | clickfix_dropper_execution | 0.75 | DC-2 (2.0) | WHERE, WHO | unmeasured | IC-2 |
| T1204.004 | clickfix_dropper_execution | 1.0 | DC-2 (2.0) | WHERE, WHO | unmeasured | IC-2 |
| T1048 | credential_theft_exfil | 0.75 | DC-2 (2.0) | WHO | unmeasured | IC-2 |
| T1552 | credential_theft_exfil | 1.0 | DC-2 (2.0) | WHO | unmeasured | IC-2 |
| T1048 | data_exfiltration | 1.0 | DC-2 (2.0) | WHO | unmeasured | IC-2 |
| T1059 | defense_evasion_cleanup | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1070 | defense_evasion_cleanup | 1.0 | DC-2 (2.0) | WHERE, WHO | unmeasured | IC-1 |
| T1036 | payload_callback | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1059 | payload_callback | 1.0 | DC-2 (2.0) | WHO | unmeasured | IC-2 |
| T1071 | payload_callback | 0.75 | DC-2 (2.0) | WHO | unmeasured | IC-2 |
| T1218 | persistence_activated | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1547 | persistence_activated | 1.0 | DC-2 (2.0) | WHERE, WHO | unmeasured | IC-2 |
| T1564 | persistence_activated | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1036 | privilege_escalation_chain | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1059 | privilege_escalation_chain | None | unmeasured (technique fired in the run but has no ACW weight in the config) | | | |
| T1548 | privilege_escalation_chain | 1.0 | DC-2 (2.0) | WHERE, WHO | unmeasured | IC-2 |
