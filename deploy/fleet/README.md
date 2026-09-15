# SecurityScarletAI fleet kit (V0.5d; V0.6a cross-platform)

Everything needed to turn ONE machine into a fleet agent host: osquery
telemetry on the host, shipped raw to a SecurityScarletAI SIEM node, where
parsing, correlation, and detection stay server-side. V0.6a extends the kit
to Windows and adds the Linux auth shipper: the fleet spans macOS, Linux,
and Windows, and the brute-force chain fires on all three.

## Contents

| File | What it is |
|---|---|
| `bootstrap_fleet_host.sh` | The installer (Linux systemd + macOS launchd). Idempotent; fail-closed (unhealthy SIEM or bad token -> nothing installed). V0.6a: installs the PLATFORM-EXACT osquery config. |
| `bootstrap_fleet_host.ps1` | The WINDOWS installer (V0.6a). Same fail-closed contract (health gate + zero-write token probe first, exit codes 1/2/3/4/5). Shipper = SYSTEM scheduled task with restart-on-failure; token in an ACL-locked file (SYSTEM + Administrators only). |
| `osqueryd.conf.darwin.example` | macOS agent config (the ES-enabled schedule; derived 1:1 from `config/osquery.conf`). |
| `osqueryd.conf.linux.example` | Linux agent config (V0.6a): cross-platform tables only + Linux FIM path sets -- the old generic template's macOS-only queries (which ran empty on Linux) are gone. |
| `osqueryd.conf.windows.example` | Windows agent config (V0.6a): 12 verified entries incl. the evented streams (`windows_events` Security channel -> auth, `process_etw_events`, `powershell_events`, `ntfs_journal_events`) + `scheduled_tasks` / `services` / `registry` Run-keys persistence. Carries each evented table's exact required flags. |
| `fleet-shipper.service.example` | systemd unit (Linux). Token via root-only `/etc/scarletai/fleet.env` (0600), never in the unit file. |
| `com.scarletai.fleet-shipper.launchagent.plist.example` | launchd plist (macOS). launchd has no env-file mechanism, so the token lives in the plist -- the bootstrap chmods it 0600. |
| `scarletai-auth-shipper.service.example` + `.timer.example` | Linux auth shipper (V0.6a): sshd events (journalctl primary, `/var/log/auth.log` fallback) into the auth-vocabulary contract; 5-min timer; watermark dedup. Windows needs NO auth shipper -- `windows_events` 4624/4625 is parsed server-side into the same vocabulary. |
| `canary_playbook.sh` | Canary playbook (W1.5, deception-as-code): plants 0600 honeypot canary files (FIM-watched paths) and can emit one test `canary_file_access` event through the real ingest pipe -- expect a CRITICAL alert + auto-created case on the SIEM. Producer contract: `src/ingestion/deception.py`. |

## Quickstart

```bash
# 1. On the SIEM node (admin): enroll the host. The token is shown ONCE.
#    Pass the host's platform (V0.6a fleet inventory; default unknown).
#    The enrolled host_name MUST match the agent's osquery host identifier
#    (osquery.conf: "host_identifier": "hostname" -> the machine's hostname).
#    curl -X POST https://siem.example.com/api/v1/fleet/enroll \
#         -H "Authorization: Bearer $API_BEARER_TOKEN" \
#         -H "Content-Type: application/json" \
#         -d '{"host_name": "web-prod-01", "platform": "linux"}'
#
# 2. On the agent host:
SCARLETAI_FLEET_TOKEN="<plaintext token>" bash bootstrap_fleet_host.sh \
    --siem-url https://siem.example.com \
    --token "$SCARLETAI_FLEET_TOKEN"

# 3. Verify on the SIEM (within ~2 min of the first osquery differential):
#    GET /api/v1/fleet/hosts -> this host's last_seen_at updating
```

### Windows hosts (V0.6a)

```powershell
# 1. On the SIEM node: enroll with platform=windows (command above).

# 2. On the Windows host (elevated PowerShell):
#    osqueryd itself comes from the official MSI (registers the osqueryd
#    service; the bootstrap prints the command if it is missing):
#      winget install --id osquery.osquery
#    The shipper needs Python 3.8+ on PATH.
powershell -ExecutionPolicy Bypass -File bootstrap_fleet_host.ps1 `
    -SiemUrl https://siem.example.com -Token $SCARLETAI_FLEET_TOKEN

# 3. Restart osqueryd so the schedule loads, then start the shipper task:
Restart-Service osqueryd
Start-ScheduledTask -TaskName ScarletAIFleetShipper

# 4. Verify: GET /api/v1/fleet/hosts -> last_seen_at updating.
```

Windows prerequisites worth saying out loud (the schedule stays DORMANT
without them -- no telemetry, no fake rows, by design):
- **Windows Event Log**: `windows_events` needs the Security channel (set
  via `windows_event_channels` in the config) -- default on every Windows
  host, no action needed.
- **PowerShell script block logging**: `powershell_events` needs the
  Group Policy "Turn on PowerShell Script Block Logging" (Administrative
  Templates > Windows Components > PowerShell); without it the schedule
  entry returns nothing.
- **Task Scheduler**: the shipper task is registered SYSTEM at startup
  with restart-on-failure and NO execution time limit. The production-grade
  service-wrapper alternative is NSSM (not required).
- Honest limits: this kit has NOT been live-fired on a real Windows host
  yet (the macOS dev machine cannot) -- the parser, API, and config are
  CI-verified; the PowerShell script is syntax-reviewed but unverified on
  Windows until the first live-fire. Rotation = re-run the bootstrap.

### Linux auth telemetry (V0.6a)

The fleet shipper carries osquery telemetry; sshd auth failures live in
journald/auth.log, which osquery does not cover -- so the auth shipper runs
ALONGSIDE it (same 5-min cadence as the macOS launchd job):

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin scarletai-auth
sudo usermod -aG systemd-journal scarletai-auth   # journal read access
# (auth.log fallback instead: usermod -aG adm scarletai-auth)
sudo cp scarletai-auth-shipper.service.example /etc/systemd/system/scarletai-auth-shipper.service
sudo cp scarletai-auth-shipper.timer.example  /etc/systemd/system/scarletai-auth-shipper.timer
sudo sed -i 's|REPLACE_WITH_REPO|/opt/securityscarletai|; s|REPLACE_WITH_DATA_DIR|/var/lib/scarletai-fleet|; s|REPLACE_WITH_HOSTNAME|web-prod-01|' /etc/systemd/system/scarletai-auth-shipper.service
sudo systemctl daemon-reload && sudo systemctl enable --now scarletai-auth-shipper.timer
```
The shipper appends to the SAME `auth_events.log` the fleet shipper ships --
no second token, no second network path.

## What the bootstrap guarantees

- **Fail-closed install**: SIEM unreachable/unhealthy -> nothing installed;
  token rejected (401/403) -> nothing installed; osqueryd missing -> exact
  install commands printed, exit 2.
- **Zero-write auth probe**: the token is verified with a malformed line the
  server refuses to parse (`rejected_parse`), so the token proof persists no
  telemetry.
- **Token hygiene**: the token is never echoed, never on a command line
  (env var -> env file / 0600 plist), never in logs.
- **Rotation = re-run** the bootstrap with the new token (idempotent).
  **Revocation = SIEM-side**; the shipper exits FATAL on 401/403 and stays
  down rather than retrying a dead credential to health.
- Delivery semantics: at-least-once (checkpoint advances only on 2xx);
  at-most-once loss if the shipper dies between read and send -- the same
  documented bound as the local FileShipper.

## Honest scope notes

- https is enforced by default (`--allow-http` exists for trusted-LAN labs
  and shouts about it). The ingest endpoint should be TLS-fronted in any
  real fleet: deploy the SIEM node with the internet overlay
  (`docker-compose.prod.yml` + `deploy/Caddyfile`).
- osqueryd binary installation is distro-specific (Linux/macOS) and left
  to the operator (the bootstrap verifies presence and prints commands);
  on Windows the official MSI registers the osqueryd service.
- The FIM file-path sets are per-platform and work out of the box (Linux
  inotify, Windows NTFS USN journal). On macOS, EndpointSecurity FIM needs
  the root-daemon story in docs/PRODUCTION.md 1.3.
- Auth-failure telemetry on remote hosts: COVERED as of V0.6a (Linux auth
  shipper unit + timer; Windows via `windows_events` 4624/4625 server-side).
  sudo log events beyond sshd remain a documented future extension
  (extend SHIPPER_PATTERNS per source, never widen the SSH patterns).