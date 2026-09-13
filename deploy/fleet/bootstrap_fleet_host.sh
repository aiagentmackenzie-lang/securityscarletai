#!/usr/bin/env bash
# SecurityScarletAI -- fleet host bootstrap (V0.5d "Small-Fleet Deployment").
#
# Installs and starts the fleet shipper on ONE agent host (Linux systemd or
# macOS launchd) after the SIEM admin enrolled the host:
#
#   1. on the SIEM node:  POST /api/v1/fleet/enroll  (admin; token shown ONCE)
#   2. on this agent host:  bootstrap_fleet_host.sh --siem-url ... --token ...
#
# Fail-closed by design:
#   - SIEM unreachable / unhealthy -> nothing is installed.
#   - Token rejected (401/403) -> nothing is installed.
#   - osqueryd missing -> exact install commands are printed, exit 2.
# The AUTH PROBE is zero-write: a malformed line is refused server-side
# (rejected_parse), so proving the token never persists telemetry.
#
# What this does NOT do (honest scope):
#   - it does NOT install the osqueryd binary (distro-specific; prints the
#     commands per OS instead)
#   - on macOS it does NOT install the osqueryd daemon itself (TCC / ES /
#     root-daemon story: docs/PRODUCTION.md 1.3) -- it installs the
#     shipper side + the osquery config file
#   - it does NOT touch the token after install (rotation = re-run with the
#     new token; revocation = SIEM-side, the shipper dies FATAL on 401/403)
#
# Usage:
#   bash bootstrap_fleet_host.sh \
#       --siem-url https://siem.example.com \
#       --token "$SCARLETAI_FLEET_TOKEN" \
#       [--os mac|linux] [--results-log PATH] [--install-dir PATH]
#       [--data-dir PATH] [--conf-path PATH] [--kit-dir PATH]
#       [--allow-http]
set -euo pipefail
umask 077

# ----------------------------------------------------------------- helpers --
log()  { echo "[bootstrap] $*"; }
fail() { echo "[bootstrap] FATAL: $*" >&2; exit 1; }
usage(){ echo "usage: bootstrap_fleet_host.sh --siem-url URL --token TOKEN [--os mac|linux] [--results-log PATH] [--install-dir PATH] [--data-dir PATH] [--conf-path PATH] [--kit-dir PATH] [--allow-http]" >&2; exit 2; }

TOKEN=""; SIEM_URL=""; OS=""; RESULTS_LOG=""; INSTALL_DIR=""; DATA_DIR=""
CONF_PATH=""; KIT_DIR="$(cd "$(dirname "$0")" && pwd)"; ALLOW_HTTP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --siem-url)    SIEM_URL="$2";   shift 2 ;;
        --token)       TOKEN="$2";      shift 2 ;;
        --os)          OS="$2";         shift 2 ;;
        --results-log) RESULTS_LOG="$2";shift 2 ;;
        --install-dir) INSTALL_DIR="$2";shift 2 ;;
        --data-dir)    DATA_DIR="$2";   shift 2 ;;
        --conf-path)   CONF_PATH="$2";  shift 2 ;;
        --kit-dir)     KIT_DIR="$2";    shift 2 ;;
        --allow-http)  ALLOW_HTTP=1;    shift ;;
        *) usage ;;
    esac
done
[ -n "$SIEM_URL" ] && [ -n "$TOKEN" ] || usage

# ---------------------------------------------------------------- validate
case "$SIEM_URL" in
    https://*) : ;;
    http://*)
        [ "$ALLOW_HTTP" = "1" ] || fail "plain http refused (the fleet token is a bearer credential). Use https, or pass --allow-http for a trusted LAN lab."
        log "WARNING: --allow-http: shipping telemetry + bearer token in PLAINTEXT on a trusted LAN. Lab use only."
        ;;
    *) fail "--siem-url must start with https:// (or http:// with --allow-http)" ;;
esac
case "$SIEM_URL" in */) SIEM_URL="${SIEM_URL%/}";; esac
[ -n "$OS" ] || OS="$(uname -s | grep -q Darwin && echo mac || echo linux)"
case "$OS" in
    mac)   [ -n "$RESULTS_LOG" ] || RESULTS_LOG="$HOME/Library/scarletai-fleet/osqueryd.results.log"
           [ -n "$INSTALL_DIR" ] || INSTALL_DIR="$HOME/.scarletai/lib"
           [ -n "$DATA_DIR" ]    || DATA_DIR="$HOME/.scarletai/data"
           [ -n "$CONF_PATH" ]   || CONF_PATH="$HOME/.scarletai/osquery.conf"
           ;;
    linux) [ -n "$RESULTS_LOG" ] || RESULTS_LOG="/var/log/osquery/osqueryd.results.log"
           [ -n "$INSTALL_DIR" ] || INSTALL_DIR="/usr/local/lib/scarletai"
           [ -n "$DATA_DIR" ]    || DATA_DIR="/var/lib/scarletai-fleet"
           [ -n "$CONF_PATH" ]   || CONF_PATH="/etc/osquery/osquery.conf"
           ;;
    *) fail "unsupported --os '$OS' (mac|linux)" ;;
esac

log "target: OS=$OS SIEM=$SIEM_URL"
[ -f "$KIT_DIR/fleet_shipper.py" ] || KIT_DIR="$(cd "$KIT_DIR/../.." && pwd)"
[ -f "$KIT_DIR/scripts/fleet_shipper.py" ] || fail "fleet_shipper.py not found in the kit (looked in $KIT_DIR/scripts/)"
# V0.6a platform-gated configs: each platform installs ONLY the tables that
# exist there (kills the empty-table waste of the old single generic config).
if [ "$OS" = "mac" ]; then
    CONF_EXAMPLE="osqueryd.conf.darwin.example"
else
    CONF_EXAMPLE="osqueryd.conf.linux.example"
fi
[ -f "$KIT_DIR/deploy/fleet/$CONF_EXAMPLE" ] || fail "$CONF_EXAMPLE not found next to this script (kit layout broken)"

# -------------------------------------------------------------- preflight
command -v python3 >/dev/null 2>&1 || fail "python3 is required by the shipper (stdlib-only; no venv needed). Install python3 first."

if ! command -v osqueryd >/dev/null 2>&1; then
    FOUND_OSQ=0
    for p in /usr/bin/osqueryd /usr/local/bin/osqueryd \
             /Library/osquery/osquery.app/Contents/MacOS/osqueryd \
             /opt/homebrew/bin/osqueryd; do
        [ -x "$p" ] && FOUND_OSQ=1 && break
    done
    [ "$FOUND_OSQ" = "1" ] || {
        echo "[bootstrap] FATAL: osqueryd is not installed. Install it first:" >&2
        echo "  Debian/Ubuntu: apt-get install -y osquery  (see osquery.io downloads)" >&2
        echo "  RHEL/Fedora:   dnf install -y osquery" >&2
        echo "  macOS:         brew install osquery  OR the LaunchDaemon story in" >&2
        echo "                 docs/PRODUCTION.md 1.3 (root daemon + FIM)" >&2
        exit 2
    }
fi

probe() {
    SCARLETAI_FLEET_TOKEN="$TOKEN" python3 - "$SIEM_URL" << 'PYEOF'
import json, os, sys, urllib.error, urllib.request

siem = sys.argv[1].rstrip("/")
token = os.environ["SCARLETAI_FLEET_TOKEN"]

# Health first: an unreachable or unhealthy SIEM must stop the bootstrap.
try:
    with urllib.request.urlopen(siem + "/api/v1/health", timeout=10) as r:
        body = json.loads(r.read().decode())
    if body.get("status") not in ("healthy", "degraded"):
        print("[bootstrap] FATAL: SIEM /health reports '%s'" % body.get("status"), file=sys.stderr)
        sys.exit(3)
except urllib.error.HTTPError as e:
    print("[bootstrap] FATAL: SIEM /health returned %s" % e.code, file=sys.stderr)
    sys.exit(3)
except Exception as e:
    print("[bootstrap] FATAL: SIEM unreachable (%s)" % e, file=sys.stderr)
    sys.exit(3)

# Auth probe: a malformed line is REFUSED server-side (rejected_parse), so
# this verifies the token WITHOUT persisting any telemetry. 202 + >=1
# rejected = token accepted; 401/403 = wrong/revoked token (fail loudly).
probe_body = json.dumps({"lines": ["scarletai-bootstrap auth probe (not an osquery line)"]}).encode()
req = urllib.request.Request(
    siem + "/api/v1/ingest/osquery",
    data=probe_body,
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        resp = json.loads(r.read().decode())
        if r.status == 202 and resp.get("rejected_parse", 0) >= 1:
            print("[bootstrap] probe: token ACCEPTED (202, %s rejected_parse; zero rows persisted)"
                  % resp.get("rejected_parse"))
            sys.exit(0)
        print("[bootstrap] FATAL: unexpected probe response %s: %s" % (r.status, resp), file=sys.stderr)
        sys.exit(4)
except urllib.error.HTTPError as e:
    if e.code in (401, 403):
        print("[bootstrap] FATAL: fleet token REJECTED (%s) -- enrollment missing, "
              "rotated, or revoked. Re-enroll the host on the SIEM and retry." % e.code, file=sys.stderr)
    else:
        print("[bootstrap] FATAL: probe failed with HTTP %s" % e.code, file=sys.stderr)
    sys.exit(4)
except Exception as e:
    print("[bootstrap] FATAL: probe failed (%s)" % e, file=sys.stderr)
    sys.exit(4)
PYEOF
}
probe
log "preflight ok: SIEM healthy, token verified (zero-write probe)"

# ------------------------------------------------------- install shipper
install_linux() {
    [ "$(id -u)" = "0" ] || fail "linux install needs root (re-run with sudo)"
    id scarletai-shipper >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin scarletai-shipper
    mkdir -p "$INSTALL_DIR" "$DATA_DIR" /etc/scarletai "$(dirname "$CONF_PATH")"
    cp "$KIT_DIR/scripts/fleet_shipper.py" "$INSTALL_DIR/fleet_shipper.py"
    chmod 0755 "$INSTALL_DIR/fleet_shipper.py" "$INSTALL_DIR" "$DATA_DIR"
    chown -R scarletai-shipper:scarletai-shipper "$INSTALL_DIR" "$DATA_DIR"
    cp "$KIT_DIR/deploy/fleet/$CONF_EXAMPLE" "$CONF_PATH"
    chmod 0644 "$CONF_PATH"
    # Env file: the token NEVER appears in the unit file or on the command line.
    { echo "SCARLETAI_FLEET_TOKEN=$TOKEN"; } > /etc/scarletai/fleet.env
    chmod 0600 /etc/scarletai/fleet.env
    sed -e "s|REPLACE_WITH_SIEM_URL|$SIEM_URL|g" \
        -e "s|REPLACE_WITH_RESULTS_LOG|$RESULTS_LOG|g" \
        "$KIT_DIR/deploy/fleet/fleet-shipper.service.example" \
        > /etc/systemd/system/fleet-shipper.service
    chmod 0644 /etc/systemd/system/fleet-shipper.service
    # The shipper (dedicated user) must be able to READ the osquery results
    # log. Verify rather than silently changing osquery's files.
    if [ -f "$RESULTS_LOG" ]; then
        su -s /bin/sh scarletai-shipper -c "test -r '$RESULTS_LOG'" 2>/dev/null || {
            echo "[bootstrap] FATAL: the shipper user cannot read $RESULTS_LOG" >&2
            echo "  fix with (example): touch '$RESULTS_LOG' && chgrp scarletai-shipper '$RESULTS_LOG' 'dir' && chmod g+rwx <log-dir>" >&2
            exit 5
        }
    else
        mkdir -p "$(dirname "$RESULTS_LOG")"
        chgrp scarletai-shipper "$(dirname "$RESULTS_LOG")" 2>/dev/null || true
        chmod g+rwx "$(dirname "$RESULTS_LOG")"
        touch "$RESULTS_LOG" && chgrp scarletai-shipper "$RESULTS_LOG" && chmod g+rw "$RESULTS_LOG"
    fi
    systemctl daemon-reload
    systemctl enable --now fleet-shipper.service
    sleep 1
    systemctl is-active --quiet fleet-shipper || { journalctl -u fleet-shipper -n 20 --no-pager >&2 || true; fail "fleet-shipper service failed to start (see journalctl -u fleet-shipper)"; }
    log "installed + started: systemd unit fleet-shipper (User=scarletai-shipper)"
}

install_mac() {
    PLIST_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$PLIST_DIR" "$(dirname "$RESULTS_LOG")" "$(dirname "$CONF_PATH")"
    cp "$KIT_DIR/scripts/fleet_shipper.py" "$INSTALL_DIR/fleet_shipper.py"
    cp "$KIT_DIR/deploy/fleet/$CONF_EXAMPLE" "$CONF_PATH"
    # launchd has no EnvironmentFile: the token goes into the plist, which
    # MUST be 0600 (world-readable plist = token disclosure).
    sed -e "s|REPLACE_WITH_INSTALL_DIR|$INSTALL_DIR|g" \
        -e "s|REPLACE_WITH_SIEM_URL|$SIEM_URL|g" \
        -e "s|REPLACE_WITH_RESULTS_LOG|$RESULTS_LOG|g" \
        -e "s|REPLACE_WITH_DATA_DIR|$DATA_DIR|g" \
        -e "s|REPLACE_WITH_FLEET_TOKEN|$TOKEN|g" \
        "$KIT_DIR/deploy/fleet/com.scarletai.fleet-shipper.launchagent.plist.example" \
        > "$PLIST_DIR/com.scarletai.fleet-shipper.plist"
    chmod 0600 "$PLIST_DIR/com.scarletai.fleet-shipper.plist"
    touch "$RESULTS_LOG"
    launchctl bootout "gui/$(id -u)/com.scarletai.fleet-shipper" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST_DIR/com.scarletai.fleet-shipper.plist"
    sleep 1
    launchctl print "gui/$(id -u)/com.scarletai.fleet-shipper" 2>/dev/null | grep -q "state" \
        || { echo "[bootstrap] FATAL: launchd agent not registered (see $DATA_DIR/fleet-shipper.err.log)" >&2; exit 5; }
    log "installed + started: launchd agent com.scarletai.fleet-shipper (plist 0600)"
}

case "$OS" in
    linux) install_linux ;;
    mac)   install_mac ;;
esac

log "osquery config:   $CONF_PATH (prune platform-specific queries per host OS)"
log "shipper install:  $INSTALL_DIR/fleet_shipper.py"
log "shipper checkpoint: $DATA_DIR (at-least-once delivery; advances only on 2xx)"
log "next: within ~2 min of the first osquery differential, check the SIEM:"
log "  GET /api/v1/fleet/hosts -> this host's last_seen_at is updating"
log "done."