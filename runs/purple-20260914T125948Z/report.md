# Purple-loop run report

- Run window start: 2026-09-14T12:55:21.446192+00:00
- Chains fired: **0/10** (score 0.0)
- Alerts fired: **0** (0 distinct rules)
- ATT&CK techniques hit: **0** (0 of them armed-technique hits; hit rate over armed techniques: 0.0)
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
| (this run) | 0/10 | 0.0 | 102 | 0.0 |

## Chains

| Chain | Fired |
|:--|:--|
| live-matrix-ai_process_egress | NO |
| live-matrix-ai_verdict_block_sustained | NO |
| live-matrix-brute_force_success | NO |
| live-matrix-clickfix_dropper_execution | NO |
| live-matrix-credential_theft_exfil | NO |
| live-matrix-data_exfiltration | NO |
| live-matrix-defense_evasion_cleanup | NO |
| live-matrix-payload_callback | NO |
| live-matrix-persistence_activated | NO |
| live-matrix-privilege_escalation_chain | NO |

## Rules that fired

- (none)

## Armed techniques NOT hit by this run

These chains/techniques did not participate in this run; they are
not failures -- they are the rest of the coverage map.

- T1003
- T1021
- T1027
- T1036
- T1041
- T1047
- T1048
- T1053
- T1055
- T1059
- T1070
- T1071
- T1074
- T1078
- T1090
- T1098
- T1110
- T1136
- T1176
- T1190
- T1204.004
- T1213
- T1218
- T1219
- T1486
- T1490
- T1505
- T1543
- T1546
- T1547
- T1548
- T1550
- T1552
- T1553
- T1555
- T1560
- T1562
- T1564
- T1567
- T1572
- T1574
- T1606

## Detection-engineering feedback (chains that did NOT fire)

Actionable, not aspirational: each item names the chain, the
correlation rule behind it, and where to look. Fix, re-run, and
the progression table above gains a row.

- **live-matrix-ai_process_egress**: inspect rule `ai_process_egress` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-ai_verdict_block_sustained**: inspect rule `ai_verdict_block_sustained` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-brute_force_success**: inspect rule `brute_force_success` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-clickfix_dropper_execution**: inspect rule `clickfix_dropper_execution` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-credential_theft_exfil**: inspect rule `credential_theft_exfil` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-data_exfiltration**: inspect rule `data_exfiltration` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-defense_evasion_cleanup**: inspect rule `defense_evasion_cleanup` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-payload_callback**: inspect rule `payload_callback` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-persistence_activated**: inspect rule `persistence_activated` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
- **live-matrix-privilege_escalation_chain**: inspect rule `privilege_escalation_chain` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
