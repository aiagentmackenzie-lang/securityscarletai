#!/usr/bin/env bash
# SecurityScarletAI -- canary playbook (Wave 1 W1.5, deception-as-code).
#
# Plants honeypot canary files on a fleet host and (optionally) emits one
# test canary event through the REAL ingest pipe, so the deception domain
# (rules/sigma/deception/ -> auto-case doctrine) is provable end to end:
#
#   1. PLANT (idempotent, safe to re-run): creates 0600 decoy files under
#      /var/opt/.canary/ (documented, FIM-watched paths -- osquery file
#      telemetry already covers them where file_events is scheduled; the
#      deception event stream is the escalation leg).
#   2. --emit-test-event: POSTs ONE canary_file_access event to the SIEM
#      through POST /api/v1/ingest (the same host-bound fleet transport
#      every kit component uses). Expect a CRITICAL alert + an auto-created
#      case on the SIEM within the rule evaluation window.
#
# Fail-closed by design:
#   - --emit-test-event without --siem-url/--token -> exit 2, nothing sent.
#   - SIEM unreachable/unhealthy or token refused -> nothing is sent.
#   - Plant never writes outside --canary-dir (default /var/opt/.canary).
#
# The event JSON mirrors the ONE producer contract
# (src/ingestion/deception.py: build_deception_event -> event_to_shipper_line)
# -- closed vocabulary, severity floor critical for canary kinds. Real
# steady-state producers (HONEYTRAP forwarder, EDR canary agents) emit the
# same shape; the SIEM-local deception shipper or /ingest ingests it.
#
# Usage:
#   bash canary_playbook.sh [--canary-dir PATH] [--emit-test-event]
#        --siem-url https://siem.example.com --token "$SCARLETAI_FLEET_TOKEN"
#        [--host-name "$(hostname)"] [--allow-http]
set -euo pipefail
umask 077

log()     { echo "[canary] $*"; }
fail()    { echo "[canary] FATAL: $*" >&2; exit 1; }
usage()   { echo "usage: canary_playbook.sh [--canary-dir PATH] [--emit-test-event] --siem-url URL --token TOKEN [--host-name NAME] [--allow-http]" >&2; exit 2; }

CANARY_DIR="/var/opt/.canary"
SIEM_URL=""; TOKEN=""; HOST_NAME="$(hostname 2>/dev/null || echo unknown-host)"
EMIT_TEST=0; ALLOW_HTTP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --canary-dir)     CANARY_DIR="$2"; shift 2 ;;
        --emit-test-event) EMIT_TEST=1;   shift ;;
        --siem-url)       SIEM_URL="$2";  shift 2 ;;
        --token)          TOKEN="$2";     shift 2 ;;
        --host-name)      HOST_NAME="$2"; shift 2 ;;
        --allow-http)     ALLOW_HTTP=1;   shift ;;
        *) usage ;;
    esac
done

# ------------------------------------------------------------------- plant --
# Two decoys: a secrets-file canary (T1083 file discovery bait) and a
# token canary (decoy credential; its USE is the T1552-shaped signal).
mkdir -p "$CANARY_DIR"

SECRETS_FILE="$CANARY_DIR/canary-secrets.txt"
if [ ! -f "$SECRETS_FILE" ]; then
    printf '%s\n' \
        "# DECOY FILE -- SecurityScarletAI canary (W1.5 deception doctrine)." \
        "# Nothing in production traffic should ever read this file." \
        "# Any access is a high-fidelity intrusion signal (critical)." \
        "# Decoy content below -- deliberately NOT a real credential shape" \
        "# (the repo's secret-scan gates must stay clean; the bait is the" \
        "# file name and its 'secrets' path, not a parseable key)." \
        "rotating-backup-credentials live in the vault; this copy is stale." \
        > "$SECRETS_FILE"
    log "planted: $SECRETS_FILE"
else
    log "already planted: $SECRETS_FILE"
fi

TOKEN_FILE="$CANARY_DIR/canary-token.key"
if [ ! -f "$TOKEN_FILE" ]; then
    printf '%s\n' \
        "CANARY-TOKEN-DECOY-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
        > "$TOKEN_FILE"
    log "planted: $TOKEN_FILE"
else
    log "already planted: $TOKEN_FILE"
fi
chmod 600 "$SECRETS_FILE" "$TOKEN_FILE" 2>/dev/null || true

log "watched paths (osquery FIM / HONEYTRAP forwarder -> deception events):"
log "  $SECRETS_FILE"
log "  $TOKEN_FILE"

# ------------------------------------------------------- emit-test-event ----
if [ "$EMIT_TEST" -eq 1 ]; then
    [ -n "$SIEM_URL" ] || usage
    [ -n "$TOKEN" ]    || usage
    case "$SIEM_URL" in
        http://*)
            [ "$ALLOW_HTTP" -eq 1 ] || fail "refusing plain http (use --allow-http to override)"
            ;;
    esac

    log "preflight: SIEM health + token (zero-write probe)"
    HEALTH_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$SIEM_URL/api/v1/health" || true)"
    [ "$HEALTH_CODE" = "200" ] || fail "SIEM /health not reachable (HTTP $HEALTH_CODE) -- nothing sent"
    PROBE_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$SIEM_URL/api/v1/ingest" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d '[{"host_name": "__probe__"}]' || true)"
    # 422 = token accepted, payload refused (zero-write: refused server-side).
    # 401/403 = token rejected -> fail closed, nothing is ever sent.
    case "$PROBE_CODE" in
        202|422) log "preflight ok: token verified (zero-write probe)" ;;
        401|403) fail "token rejected by the SIEM ($PROBE_CODE) -- nothing sent" ;;
        *)       fail "unexpected ingest probe response ($PROBE_CODE) -- nothing sent" ;;
    esac

    NOW="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))')"
    HOST_JSON="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$HOST_NAME")"
    EVENT="{\"@timestamp\": \"$NOW\", \"host_name\": $HOST_JSON, \"event_category\": \"deception\", \"event_type\": \"info\", \"event_action\": \"deception_canary_access\", \"source\": \"deception\", \"user_name\": null, \"severity\": \"critical\", \"raw_data\": {\"shipper\": \"deception\", \"component\": \"canary\", \"detail\": {\"path\": \"$SECRETS_FILE\", \"action\": \"read\", \"playbook\": \"canary_playbook.sh\"}}, \"enrichment\": {}}"
    CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$SIEM_URL/api/v1/ingest" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d "[$EVENT]" || true)"
    case "$CODE" in
        202) log "test event accepted (202) -- expect a CRITICAL deception alert + auto-created case on the SIEM" ;;
        *)   fail "ingest refused the test event ($CODE)" ;;
    esac
fi

log "done."