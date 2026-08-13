#!/bin/bash
# Send Guard Dog alert via infra-TAK console (Email Relay). Usage: echo -e "$BODY" | send-alert-email.sh "Subject" "to@example.com"
# Replaces direct "mail" so all alerts use the same relay as the test email.
SUBJ="${1:-Guard Dog Alert}"
TO="${2:-}"
# No bail on an empty $TO. $2 is the address baked in at DEPLOY time; the console now
# resolves the real recipient from settings.json, so bailing here made a box deployed
# before an email was set stay silent forever after one was added.
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
curl -s -k -X POST "https://127.0.0.1:${CONSOLE_PORT}/api/guarddog/send-alert-email" \
  -H "Content-Type: application/json" -d @"$TMPF" \
  --connect-timeout 5 --max-time 15 >/dev/null 2>&1 || \
curl -s -X POST "http://127.0.0.1:${CONSOLE_PORT}/api/guarddog/send-alert-email" \
  -H "Content-Type: application/json" -d @"$TMPF" \
  --connect-timeout 5 --max-time 15 >/dev/null 2>&1
