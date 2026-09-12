# SecurityScarletAI fleet kit (V0.5d)

Everything needed to turn ONE machine into a fleet agent host: osquery
telemetry on the host, shipped raw to a SecurityScarletAI SIEM node, where
parsing, correlation, and detection stay server-side.

## Contents

| File | What it is |
|---|---|
| `bootstrap_fleet_host.sh` | The installer. Idempotent; fail-closed (unhealthy SIEM or bad token -> nothing installed). Linux systemd + macOS launchd. |
| `osqueryd.conf.example` | Agent-host osquery config. Derived 1:1 from the repo's `config/osquery.conf` (same query names = same parser mapping). Prune platform-specific queries per host OS. |
| `fleet-shipper.service.example` | systemd unit (Linux). Token via root-only `/etc/scarletai/fleet.env` (0600), never in the unit file. |
| `com.scarletai.fleet-shipper.launchagent.plist.example` | launchd plist (macOS). launchd has no env-file mechanism, so the token lives in the plist -- the bootstrap chmods it 0600. |

## Quickstart

```bash
# 1. On the SIEM node (admin): enroll the host. The token is shown ONCE.
#    The enrolled host_name MUST match the agent's osquery host identifier
#    (osquery.conf: "host_identifier": "hostname" -> the machine's hostname).
#    curl -X POST https://siem.example.com/api/v1/fleet/enroll \
#         -H "Authorization: Bearer $API_BEARER_TOKEN" \
#         -H "Content-Type: application/json" \
#         -d '{"host_name": "web-prod-01"}'

# 2. On the agent host:
SCARLETAI_FLEET_TOKEN="<plaintext token>" bash bootstrap_fleet_host.sh \
    --siem-url https://siem.example.com \
    --token "$SCARLETAI_FLEET_TOKEN"

# 3. Verify on the SIEM (within ~2 min of the first osquery differential):
#    GET /api/v1/fleet/hosts -> this host's last_seen_at updating
```

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
- osqueryd binary installation is distro-specific and left to the operator
  (the bootstrap verifies presence and prints commands).
- The FIM file-path sets in the template work out of the box on Linux
  (inotify). On macOS, EndpointSecurity FIM needs the root-daemon story in
  docs/PRODUCTION.md 1.3.
- Auth-failure telemetry on remote hosts is NOT collected by this kit (the
  local FileShipper's auth-shipper covers the SIEM's own host). A remote
  auth shipper is a future item, not a silent gap.