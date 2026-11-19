#!/usr/bin/env bash
# Watchdog helpers — sourced by scripts/health_watchdog.sh.
#
# SS-043: the Slack body used to be assembled by string interpolation,
#   -d "{\"text\":\"[SecurityScarletAI] $subject — $detail\"}"
# which produces invalid JSON the moment `detail` contains a quote — i.e.
# exactly when the health endpoint reports `degraded` and the raw health JSON
# is embedded. Slack answered 400, `|| true` swallowed it, and the on-call
# alert existed only in the local log. Unstructured text must never be
# interpolated into JSON; the builder below asks a real JSON encoder.
#
# Design notes:
# - jq first (always present on macOS at /usr/bin/jq, and in launchd's PATH).
# - python3 second (host-mode installs; not guaranteed under launchd's PATH).
# - If neither exists the function FAILS LOUDLY (non-zero) instead of
#   emitting a payload that may be invalid: the caller logs the alert locally
#   and records that the webhook was skipped. Fail closed, never silently.

slack_payload() {  # slack_payload <subject> <detail> -> JSON on stdout
    local subject="$1" detail="$2"

    if command -v jq >/dev/null 2>&1; then
        jq -n --arg subject "$subject" --arg detail "$detail" \
            '{text: ("[SecurityScarletAI] " + $subject + " — " + $detail)}'
        return $?
    fi

    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json, sys
print(json.dumps({"text": "[SecurityScarletAI] " + sys.argv[1] + " — " + sys.argv[2]}))' \
            "$subject" "$detail"
        return $?
    fi

    return 1
}
