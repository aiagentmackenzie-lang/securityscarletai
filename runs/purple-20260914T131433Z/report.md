# Purple-loop run report

- Run window start: 2026-09-14T13:09:26.725104+00:00
- Chains fired: **0/10** (score 0.0)
- Alerts fired: **17** (15 distinct rules)
- ATT&CK techniques hit: **12** (12 of them armed-technique hits; hit rate over armed techniques: 0.286)
- Coverage map: 102 armed / 123 total rules (lookback 168h)

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
| (this run) | 0/10 | 0.0 | 102 | 0.286 |

## Chains

| Chain | Fired |
|:--|:--|
| ai_process_egress | NO |
| ai_verdict_block_sustained | NO |
| brute_force_success | NO |
| clickfix_dropper_execution | NO |
| credential_theft_exfil | NO |
| data_exfiltration | NO |
| defense_evasion_cleanup | NO |
| payload_callback | NO |
| persistence_activated | NO |
| privilege_escalation_chain | NO |

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
- macOS Local Account Created (users differential)

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
- T1110
- T1176
- T1190
- T1204.004
- T1213
- T1219
- T1486
- T1490
- T1505
- T1543
- T1546
- T1550
- T1552
- T1553
- T1555
- T1560
- T1562
- T1567
- T1572
- T1574
- T1606

## Detection-engineering feedback (chains that did NOT fire)

Actionable, not aspirational: each item names the chain, the
correlation rule behind it, and where to look. Fix, re-run, and
the progression table above gains a row.

- **ai_process_egress**: inspect rule `ai_process_egress` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **ai_verdict_block_sustained**: inspect rule `ai_verdict_block_sustained` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **brute_force_success**: inspect rule `brute_force_success` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **clickfix_dropper_execution**: inspect rule `clickfix_dropper_execution` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **credential_theft_exfil**: inspect rule `credential_theft_exfil` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **data_exfiltration**: inspect rule `data_exfiltration` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **defense_evasion_cleanup**: inspect rule `defense_evasion_cleanup` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **payload_callback**: inspect rule `payload_callback` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **persistence_activated**: inspect rule `persistence_activated` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **privilege_escalation_chain**: inspect rule `privilege_escalation_chain` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
