# Purple-loop run report

- Run window start: 2026-09-11T18:43:50.274596+00:00
- Chains fired: **2/8** (score 0.25)
- Alerts fired: **2** (2 distinct rules)
- ATT&CK techniques hit: **3** (3 of them armed-technique hits; hit rate over armed techniques: 0.086)
- Coverage map: 86 armed / 108 total rules (lookback 168h)

## Chains

| Chain | Fired |
|:--|:--|
| live-matrix-ai_verdict_block_sustained | NO |
| live-matrix-brute_force_success | NO |
| live-matrix-credential_theft_exfil | NO |
| live-matrix-data_exfiltration | NO |
| live-matrix-defense_evasion_cleanup | YES |
| live-matrix-payload_callback | YES |
| live-matrix-persistence_activated | NO |
| live-matrix-privilege_escalation_chain | NO |

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
- T1606
