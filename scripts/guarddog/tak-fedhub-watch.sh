#!/bin/bash
# Guard Dog: Federation Hub remote service monitor.
# Checks that federation-hub systemd service is active on the remote host,
# port 9100 is listening, and mongod is running. Alerts + auto-restart on 3 failures.
#
# Placeholders replaced at deploy time:
#   FEDHUB_HOST_PLACEHOLDER     → Fed Hub remote IP/hostname
#   SSH_KEY_PLACEHOLDER         → SSH key path
#   SSH_USER_PLACEHOLDER        → SSH user
#   ALERT_EMAIL_PLACEHOLDER     → Alert email (empty = no email)

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
FEDHUB_HOST="FEDHUB_HOST_PLACEHOLDER"
SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"

STATE_DIR="/var/lib/takguard"
FAIL_FILE="$STATE_DIR/fedhub.failcount"
COOLDOWN_FILE="$STATE_DIR/fedhub_last_restart"
ALERT_SENT_FILE="$STATE_DIR/fedhub_alert_sent"
MAX_FAILS=3
COOLDOWN_SECS=900

mkdir -p "$STATE_DIR"

UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt 900 ] && exit 0

[ -z "$FEDHUB_HOST" ] && exit 0

SSH_CMD="ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 ${SSH_USER}@${FEDHUB_HOST}"

HEALTHY=true
DETAILS=""

SVC_OUT=$($SSH_CMD 'systemctl is-active federation-hub 2>/dev/null' 2>/dev/null)
if [ "$SVC_OUT" != "active" ]; then
  HEALTHY=false
  DETAILS="federation-hub service: $SVC_OUT"
fi

PORT_OUT=$($SSH_CMD 'ss -ltn "sport = :9100" 2>/dev/null | grep -c LISTEN' 2>/dev/null)
if [ "${PORT_OUT:-0}" -lt 1 ]; then
  HEALTHY=false
  DETAILS="${DETAILS:+$DETAILS; }Port 9100 not listening"
fi

MONGO_OUT=$($SSH_CMD 'systemctl is-active mongod 2>/dev/null' 2>/dev/null)
if [ "$MONGO_OUT" != "active" ]; then
  HEALTHY=false
  DETAILS="${DETAILS:+$DETAILS; }mongod: $MONGO_OUT"
fi

if $HEALTHY; then
  echo 0 > "$FAIL_FILE"
  rm -f "$ALERT_SENT_FILE"
  exit 0
fi

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

# Try restart via SSH
RESTARTED=false
$SSH_CMD 'sudo systemctl restart mongod 2>/dev/null; sleep 2; sudo systemctl restart federation-hub 2>/dev/null' 2>/dev/null
sleep 8
SVC_AFTER=$($SSH_CMD 'systemctl is-active federation-hub 2>/dev/null' 2>/dev/null)
[ "$SVC_AFTER" = "active" ] && RESTARTED=true

echo 0 > "$FAIL_FILE"
date +%s > "$COOLDOWN_FILE"

if $RESTARTED; then
  RESTART_MSG="Guard Dog restarted federation-hub via SSH and service is now active."
  echo "$TS | restart | Federation Hub ($FEDHUB_HOST) was down, restarted successfully via SSH" >> /var/log/takguard/restarts.log
else
  RESTART_MSG="Guard Dog attempted remote restart but federation-hub is still not active. Manual intervention required."
  echo "$TS | restart | Federation Hub ($FEDHUB_HOST) restart FAILED" >> /var/log/takguard/restarts.log
fi

# Rate-limit alerts (once per hour)
if [ -f "$ALERT_SENT_FILE" ] && [ -z "$(find "$ALERT_SENT_FILE" -mmin +60 2>/dev/null)" ]; then
  exit 0
fi
touch "$ALERT_SENT_FILE"

SUBJ="Guard Dog: Federation Hub alert on $SERVER_IDENTIFIER"
BODY="Federation Hub ($FEDHUB_HOST) is not healthy.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Consecutive failures: $FAILS
Details: $DETAILS

$RESTART_MSG

Check from this host:
  ssh ${SSH_USER}@${FEDHUB_HOST} 'systemctl status federation-hub'
  ssh ${SSH_USER}@${FEDHUB_HOST} 'ss -ltn sport = :9100'
  ssh ${SSH_USER}@${FEDHUB_HOST} 'systemctl status mongod'
"

[ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi
