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
# v10.1.57 W2: capture the HTTP status ALONGSIDE the body. Until now an empty $RESP
# was reported as "console unreachable", and that single message covered two very
# different faults. In v10.1.48 a helper was inserted between
# @app.route('/api/guarddog/send-alert-email') and its handler, so the route bound to
# a function returning '' — which Flask renders as 200 with an EMPTY BODY. Every
# alert on every box was then logged as "console unreachable" while the console was
# answering in under a second. That wording is why the outage read as a networking
# problem for eight days. An empty body from a live console is a ROUTING bug, and the
# log has to say which of the two it is.
#
# Body and status are kept apart with -w so a body that happens to end in digits
# cannot be mistaken for the status.
_post() {  # $1 = scheme; sets RESP and CODE
    local _body_f _out
    _body_f="$(mktemp)" || return 1
    _out="$(curl -s -k -X POST "$1://127.0.0.1:${CONSOLE_PORT}/api/guarddog/send-alert-email" \
      -H "Content-Type: application/json" -d @"$TMPF" \
      -o "$_body_f" -w '%{http_code}' \
      --connect-timeout 5 --max-time 15 2>/dev/null)" || _out=""
    CODE="$_out"
    RESP="$(cat "$_body_f" 2>/dev/null)"
    rm -f "$_body_f"
}

# Console often runs with TLS on 5001; try HTTPS first (-k = allow self-signed), then HTTP.
# Retry on HTTP only when the HTTPS attempt got no response at all — a real HTTP status
# (even an error, even a 200 with an empty body) means the console answered, and repeating
# the POST could deliver the alert twice.
RESP=""; CODE=""
_post https
if [ -z "$CODE" ] || [ "$CODE" = "000" ]; then
    _post http
fi

case "$RESP" in
    '') _RC=3
        if [ -z "$CODE" ] || [ "$CODE" = "000" ]; then
            # No HTTP response at all: console down, wrong port, TLS refused.
            logger -t guarddog-alert -- \
                "NOT SENT (console unreachable on :${CONSOLE_PORT}): ${SUBJ}" 2>/dev/null
        else
            # The console answered and returned nothing. The endpoint is not bound to the
            # sender — see v10.1.57 W1. This is a code fault, not an environment fault.
            logger -t guarddog-alert -- \
                "NOT SENT (console returned HTTP ${CODE} with an EMPTY BODY on :${CONSOLE_PORT} -- alert endpoint is misrouted, this is a bug): ${SUBJ}" 2>/dev/null
        fi ;;
    *'"suppressed": true'*|*'"suppressed":true'*)
        logger -t guarddog-alert -- \
            "SUPPRESSED by console (no recipient configured, or relay declined): ${SUBJ}" 2>/dev/null ;;
    *'"success": true'*|*'"success":true'*)
        logger -t guarddog-alert -- "sent: ${SUBJ}" 2>/dev/null ;;
    *)  logger -t guarddog-alert -- \
            "NOT SENT (console error HTTP ${CODE}): ${SUBJ} -- ${RESP}" 2>/dev/null
        _RC=3 ;;
esac

# v10.1.58 W13: report DELIVERY STATUS to the caller.
#   0 = delivered, or deliberately suppressed (no recipient configured)
#   3 = NOT sent (console unreachable, misrouted, or an error)
#
# Until now this always exited 0, so a watcher had no way to know its alert had
# been dropped. Watchers gate themselves with an "alert once per episode" state
# file, and they write it whether or not the mail left the box — so an alert
# raised while the console was still starting CONSUMED the episode and was lost
# permanently, with no retry. Observed on test12 2026-09-02: the console was
# still running startup migrations 83s after a restart, the drift alert fired
# into that window, logged "console unreachable", and the once-gate closed
# behind it.
#
# This does NOT make alerting failure fatal to a watcher — that rule stands.
# Callers still run this without `set -e`; the code is advisory, and is used to
# decide whether the episode may be marked as reported.
exit ${_RC:-0}
