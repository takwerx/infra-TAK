#!/bin/bash
# Send Guard Dog alert via infra-TAK console (Email Relay). Usage: echo -e "$BODY" | send-alert-email.sh "Subject" "to@example.com"
# Replaces direct "mail" so all alerts use the same relay as the test email.
SUBJ="${1:-Guard Dog Alert}"
TO="${2:-}"
# No bail on an empty $TO. $2 is the address baked in at DEPLOY time; the console now
# resolves the real recipient from settings.json, so bailing here made a box deployed
# before an email was set stay silent forever after one was added.
#
# v10.1.48 W5: an empty $TO is fine, but the SEND must not be a silent no-op. This
# script used to discard the console's reply entirely (>/dev/null 2>&1), so an alert
# the console suppressed — or a console that never answered — looked identical to one
# that was delivered. Both outcomes now reach the journal via `logger`. The console
# journals its own side too; this is the caller's half of the same record.
CONSOLE_PORT="${CONSOLE_PORT:-5001}"
TMPF=$(mktemp)
trap 'rm -f "$TMPF"' EXIT
cat | python3 -c "
import json, sys
subj, to = sys.argv[1], sys.argv[2]
body = sys.stdin.read()
print(json.dumps({'subject': subj, 'body': body, 'to': to}))
" "$SUBJ" "$TO" > "$TMPF" 2>/dev/null || exit 1
# Console often runs with TLS on 5001; try HTTPS first (-k = allow self-signed), then HTTP
RESP="$(curl -s -k -X POST "https://127.0.0.1:${CONSOLE_PORT}/api/guarddog/send-alert-email" \
  -H "Content-Type: application/json" -d @"$TMPF" \
  --connect-timeout 5 --max-time 15 2>/dev/null)" || RESP=""
if [ -z "$RESP" ]; then
    RESP="$(curl -s -X POST "http://127.0.0.1:${CONSOLE_PORT}/api/guarddog/send-alert-email" \
      -H "Content-Type: application/json" -d @"$TMPF" \
      --connect-timeout 5 --max-time 15 2>/dev/null)" || RESP=""
fi

case "$RESP" in
    '') logger -t guarddog-alert -- \
            "NOT SENT (console unreachable on :${CONSOLE_PORT}): ${SUBJ}" 2>/dev/null ;;
    *'"suppressed": true'*|*'"suppressed":true'*)
        logger -t guarddog-alert -- \
            "SUPPRESSED by console (no recipient configured, or relay declined): ${SUBJ}" 2>/dev/null ;;
    *'"success": true'*|*'"success":true'*)
        logger -t guarddog-alert -- "sent: ${SUBJ}" 2>/dev/null ;;
    *)  logger -t guarddog-alert -- \
            "NOT SENT (console error): ${SUBJ} -- ${RESP}" 2>/dev/null ;;
esac
exit 0
