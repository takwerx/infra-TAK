#!/bin/bash
# Guard Dog: CloudTAK container health. On 3 consecutive failures: alert and restart containers.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
FAIL_FILE="$STATE_DIR/cloudtak.failcount"
COOLDOWN_FILE="$STATE_DIR/cloudtak_last_restart"
MAX_FAILS=3
COOLDOWN_SECS=900

mkdir -p "$STATE_DIR"

# Don't run during first 15 minutes after boot (avoid restarting during startup)
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt 900 ] && exit 0

# v10.1.44 (W3): resolve the stack dir via the shared lib — $HOME is EMPTY in a
# systemd unit, so the old "${HOME:-...}" default silently pointed at nothing on
# installs that do not match it and this watchdog exited 0 without ever watching.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true
CT_DIR="$(gd_find_stack_dir CloudTAK cloudtak-api-1)"
[ -z "$CT_DIR" ] && exit 0

# Health: cloudtak-api container running
STATUS=$(docker ps --filter name=cloudtak-api --format "{{.Status}}" 2>/dev/null || true)
if echo "$STATUS" | grep -q "Up"; then
  echo 0 > "$FAIL_FILE"
  exit 0
fi

# Failure
FAILS=$(( $(cat "$FAIL_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$FAILS" > "$FAIL_FILE"

if [ "$FAILS" -lt "$MAX_FAILS" ]; then
  exit 0
fi

# Cooldown
if [ -f "$COOLDOWN_FILE" ]; then
  LAST=$(cat "$COOLDOWN_FILE")
  NOW=$(date +%s)
  if [ $(( NOW - LAST )) -lt $COOLDOWN_SECS ]; then
    exit 0
  fi
fi

TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p /var/log/takguard
echo "$TS | restart | CloudTAK container not up — restarting" >> /var/log/takguard/restarts.log

SUBJ="Guard Dog: CloudTAK restarted on $SERVER_IDENTIFIER"
BODY="CloudTAK container was not running for $FAILS consecutive checks.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Action: Restarting CloudTAK containers (docker compose restart).

Check /var/log/takguard/restarts.log for history.
"
echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi

cd "$CT_DIR" && docker compose restart 2>&1
echo 0 > "$FAIL_FILE"
date +%s > "$COOLDOWN_FILE"
