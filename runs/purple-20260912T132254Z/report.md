# Purple-loop run report

- Run window start: 2026-09-12T13:19:00.844912+00:00
- Chains fired: **8/8** (score 1.0)
- Alerts fired: **2** (2 distinct rules)
- ATT&CK techniques hit: **3** (3 of them armed-technique hits; hit rate over armed techniques: 0.081)
- Coverage map: 92 armed / 112 total rules (lookback 168h)

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
| (this run) | 8/8 | 1.0 | 92 | 0.081 |

## Chains

| Chain | Fired |
|:--|:--|
| live-matrix-ai_verdict_block_sustained | YES |
| live-matrix-brute_force_success | YES |
| live-matrix-credential_theft_exfil | YES |
| live-matrix-data_exfiltration | YES |
| live-matrix-defense_evasion_cleanup | YES |
| live-matrix-payload_callback | YES |
| live-matrix-persistence_activated | YES |
| live-matrix-privilege_escalation_chain | YES |

## Rules that fired

- defense_evasion_cleanup
- payload_callback

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
- T1074
- T1078
- T1090
- T1098
- T1110
- T1176
- T1190
- T1213
- T1218
- T1486
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
- T1574
- T1606
