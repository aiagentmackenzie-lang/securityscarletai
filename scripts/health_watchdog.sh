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
STATE_DIR="${WATCHDOG_STATE_DIR:-$REPO_ROOT/data/backups}"
STATE="$STATE_DIR/watchdog_state"
LOG="$STATE_DIR/watchdog.log"
mkdir -p "$STATE_DIR"

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/api/v1/health}"
DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:8501/_stcore/health}"
DASHBOARD_PAGE_URL="${DASHBOARD_PAGE_URL:-http://127.0.0.1:8501/}"
DASHBOARD_CONTAINER="${DASHBOARD_CONTAINER:-scarletai-dashboard}"

# SS-043: JSON payload builder (jq/python3, never string interpolation).
# shellcheck source=watchdog_payload.sh
. "$REPO_ROOT/scripts/watchdog_payload.sh"

get_env() { sed -n "s/^$1=//p" "$REPO_ROOT/.env" 2>/dev/null | head -1; }

notify() {  # notify "subject" "detail"
    local subject="$1" detail="$2"
    local hook; hook="${SLACK_WEBHOOK_URL:-$(get_env SLACK_WEBHOOK_URL)}"
    if [ -n "$hook" ]; then
        local payload
        if payload="$(slack_payload "$subject" "$detail")"; then
            curl -s -m 10 -X POST -H 'Content-Type: application/json' \
                -d "$payload" \
                "$hook" >/dev/null 2>&1 || true
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') slack skipped (no JSON builder: jq/python3) — $subject: $detail" >> "$LOG"
        fi
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
    # SS-045: Streamlit answers 200 on /_stcore/health even when the script
    # raised at import (the 2026-09-23 dead-app class: "healthy" container,
    # exception page in the browser). A 200 from the server is not evidence
    # the APP works — inspect the rendered page and the container log too.
    body="$(curl -s -m 8 "$DASHBOARD_PAGE_URL" 2>/dev/null || true)"
    if printf '%s' "$body" | grep -qE 'Traceback \(most recent call last\)|StreamlitAPIException|ModuleNotFoundError'; then
        dash_status="app_error"
    elif [ -z "$body" ]; then
        dash_status="app_empty"
    elif [ -z "${WATCHDOG_SKIP_DOCKER:-}" ] && command -v docker >/dev/null 2>&1; then
        if docker logs --since 15m "$DASHBOARD_CONTAINER" 2>&1 | grep -q 'Traceback (most recent call last)'; then
            dash_status="app_error"
        fi
    fi
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
    notify "dashboard $dash_status" "($DASHBOARD_PAGE_URL — server $DASHBOARD_URL; app_error means the page rendered a traceback)"
fi
exit 0