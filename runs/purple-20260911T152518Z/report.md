# Purple-loop run report

- Run window start: 2026-09-11T15:21:14.543088+00:00
- Chains fired: **8/8** (score 1.0)
- Alerts fired: **20** (18 distinct rules)
- ATT&CK techniques hit: **13** (13 of them armed-technique hits; hit rate over armed techniques: 0.371)
- Coverage map: 86 armed / 108 total rules (lookback 168h)

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

- Data Exfiltration Volume
- Download and Execute Pattern
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
- T1041
- T1047
- T1053
- T1055
- T1074
- T1090
- T1098
- T1176
- T1486
- T1505
- T1543
- T1546
- T1550
- T1553
- T1555
- T1560
- T1562
- T1567
- T1606
