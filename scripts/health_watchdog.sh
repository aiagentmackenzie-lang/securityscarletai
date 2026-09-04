#!/usr/bin/env bash
# Local production health watchdog for SecurityScarletAI.
#
# Edge-triggered: alerts only on STATE CHANGE (ok → down, down → ok), so a
# flapping check does not spam. State is kept in data/backups/watchdog_state.
#
# Alerting: reads SLACK_WEBHOOK_URL from .env when present (Slack incoming
# webhook payload). If unset or the POST fails, the alert is appended to
# data/backups/watchdog.log — never silently dropped.
#
# Designed to run every 5 minutes from launchd (see
# deploy/watchdog.launchagent.plist.example).
set -uo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
STATE_DIR="$REPO_ROOT/data/backups"
STATE="$STATE_DIR/watchdog_state"
LOG="$STATE_DIR/watchdog.log"
mkdir -p "$STATE_DIR"

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/api/v1/health}"
DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:8501/_stcore/health}"

get_env() { sed -n "s/^$1=//p" "$REPO_ROOT/.env" 2>/dev/null | head -1; }

notify() {  # notify "subject" "detail"
    local subject="$1" detail="$2"
    local hook; hook="$(get_env SLACK_WEBHOOK_URL)"
    if [ -n "$hook" ]; then
        curl -s -m 10 -X POST -H 'Content-Type: application/json' \
            -d "{\"text\":\"[SecurityScarletAI] $subject — $detail\"}" \
            "$hook" >/dev/null 2>&1 || true
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') $subject: $detail" >> "$LOG"
}

# ── checks ──────────────────────────────────────────────────────
api_status="down"
health="$(curl -s -m 8 "$HEALTH_URL" 2>/dev/null || true)"
if echo "$health" | grep -q '"status":"healthy"'; then
    api_status="ok"
elif [ -n "$health" ]; then
    api_status="degraded"
fi

dash_status="down"
if [ "$(curl -s -m 8 -o /dev/null -w '%{http_code}' "$DASHBOARD_URL" 2>/dev/null)" = "200" ]; then
    dash_status="ok"
fi

prev=""; [ -f "$STATE" ] && prev="$(cat "$STATE")"
now="api=$api_status,dashboard=$dash_status"

[ "$now" = "$prev" ] && exit 0   # no state change → no alert
printf '%s' "$now" > "$STATE"

# ── state-change alerts ─────────────────────────────────────────
if [ "$prev" = "" ]; then
    notify "watchdog started" "$now"
    exit 0
fi

if echo "$now" | grep -q "api=ok" && ! echo "$prev" | grep -q "api=ok"; then
    notify "RECOVERED" "api back to $api_status (was $prev)"
fi
if [ "$api_status" != "ok" ]; then
    detail="health endpoint: $([ -n "$health" ] && echo "$health" | head -c 300 || echo 'unreachable')"
    notify "API $api_status" "$detail"
fi
if [ "$dash_status" != "ok" ]; then
    notify "dashboard $dash_status" "($DASHBOARD_URL)"
fi
exit 0