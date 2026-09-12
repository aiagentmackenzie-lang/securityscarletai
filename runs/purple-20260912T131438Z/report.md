# Purple-loop run report

- Run window start: 2026-09-12T13:10:44.896057+00:00
- Chains fired: **7/8** (score 0.875)
- Alerts fired: **9** (9 distinct rules)
- ATT&CK techniques hit: **7** (7 of them armed-technique hits; hit rate over armed techniques: 0.189)
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
| (this run) | 7/8 | 0.875 | 92 | 0.189 |

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
- T1213
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
- T1574
- T1606

## Detection-engineering feedback (chains that did NOT fire)

Actionable, not aspirational: each item names the chain, the
correlation rule behind it, and where to look. Fix, re-run, and
the progression table above gains a row.

- **live-matrix-payload_callback**: inspect rule `payload_callback` -- chain produced no alert and no persisted match in the run window -- inspect the chain's detector SQL and the generator scenario for that host, fix, then re-run
