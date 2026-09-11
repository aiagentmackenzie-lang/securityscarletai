# Purple-loop run report

- Run window start: 2026-09-11T18:39:46.789978+00:00
- Chains fired: **7/8** (score 0.875)
- Alerts fired: **9** (9 distinct rules)
- ATT&CK techniques hit: **7** (7 of them armed-technique hits; hit rate over armed techniques: 0.2)
- Coverage map: 86 armed / 108 total rules (lookback 168h)

## Chains

| Chain | Fired |
|:--|:--|
| live-matrix-ai_verdict_block_sustained | YES |
| live-matrix-brute_force_success | YES |
| live-matrix-credential_theft_exfil | YES |
| live-matrix-data_exfiltration | YES |
| live-matrix-defense_evasion_cleanup | YES |
| live-matrix-payload_callback | NO |
| live-matrix-persistence_activated | YES |
| live-matrix-privilege_escalation_chain | YES |

## Rules that fired

- Download and Execute Pattern
- Reverse Shell Pattern Detected
- Script Interpreter from Unexpected Location
- ai_verdict_block_sustained
- brute_force_success
- credential_theft_exfil
- data_exfiltration
- persistence_activated
- privilege_escalation_chain

## Armed techniques NOT hit by this run

These chains/techniques did not participate in this run; they are
not failures -- they are the rest of the coverage map.

- T1003
- T1021
- T1027
- T1036
- T1041
- T1047
- T1053
- T1055
- T1070
- T1071
- T1074
- T1078
- T1090
- T1098
- T1176
- T1218
- T1486
- T1505
- T1543
- T1546
- T1550
- T1553
- T1555
- T1560
- T1562
- T1564
- T1567
- T1606
