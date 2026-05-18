#!/bin/bash
# Guard Dog: Remote Database monitor.
# Works for two-server mode (SSH-managed DB on Server One) and
# external/managed DB mode (AWS RDS, Azure, etc. — TCP-only, no SSH).
#
# Placeholders replaced at deploy time:
#   DB_HOST_PLACEHOLDER        → Server One IP/hostname or managed DB endpoint
#   DB_PORT_PLACEHOLDER        → Database port (default 5432)
#   SSH_KEY_PLACEHOLDER        → SSH key path (empty for managed DB mode)
#   SSH_USER_PLACEHOLDER       → SSH user (empty for managed DB mode)
#   EXTERNAL_DB_PLACEHOLDER    → "true" for managed DB, "" for two-server
#   ALERT_EMAIL_PLACEHOLDER    → Alert email (empty = no email)

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
DB_HOST="DB_HOST_PLACEHOLDER"
DB_PORT="DB_PORT_PLACEHOLDER"
SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"
EXTERNAL_DB="EXTERNAL_DB_PLACEHOLDER"

ALERT_SENT_FILE="/var/lib/takguard/remotedb_alert_sent"
LAST_RESTART_FILE="/var/lib/takguard/last_restart_time"
FAIL_COUNT_FILE="/var/lib/takguard/remotedb_fail_count"

# Skip during boot grace period
if [ -f "$LAST_RESTART_FILE" ]; then
  LAST_RESTART=$(cat "$LAST_RESTART_FILE")
  CURRENT_TIME=$(date +%s)
  TIME_SINCE_RESTART=$((CURRENT_TIME - LAST_RESTART))
  if [ $TIME_SINCE_RESTART -lt 900 ]; then
    exit 0
  fi
fi

HEALTHY=true
DETAILS=""

# Check 1: TCP connectivity to DB port
if ! timeout 6 bash -c "</dev/tcp/$DB_HOST/$DB_PORT" >/dev/null 2>&1; then
  HEALTHY=false
  DETAILS="TCP port $DB_PORT on $DB_HOST is not reachable."
fi

# Check 2: SSH to Server One and verify PG cluster is up + cot database exists
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  SSH_OUT=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
    "${SSH_USER}@${DB_HOST}" \
    'pg_isready -q 2>/dev/null && sudo -u postgres psql -lqt 2>/dev/null | grep -q cot && echo REMOTE_PG_OK || echo REMOTE_PG_FAIL' \
    2>/dev/null)
  if [ "$SSH_OUT" != "REMOTE_PG_OK" ]; then
    HEALTHY=false
    DETAILS="${DETAILS:+$DETAILS }SSH health check failed: ${SSH_OUT:-no response}"
  fi
fi

if $HEALTHY; then
  rm -f "$ALERT_SENT_FILE" "$FAIL_COUNT_FILE"
  exit 0
fi

# Increment failure counter (alert after 3 consecutive failures)
FAIL_COUNT=0
[ -f "$FAIL_COUNT_FILE" ] && FAIL_COUNT=$(cat "$FAIL_COUNT_FILE")
FAIL_COUNT=$((FAIL_COUNT + 1))
echo "$FAIL_COUNT" > "$FAIL_COUNT_FILE"

if [ "$FAIL_COUNT" -lt 3 ]; then
  exit 0
fi

# Try to restart PostgreSQL on Server One via SSH
RESTARTED=false
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
    "${SSH_USER}@${DB_HOST}" \
    'sudo pg_ctlcluster 15 main restart 2>/dev/null || sudo systemctl restart postgresql 2>/dev/null' \
    2>/dev/null
  sleep 5
  SSH_OUT=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
    "${SSH_USER}@${DB_HOST}" 'pg_isready -q 2>/dev/null && echo RESTARTED_OK' 2>/dev/null)
  [ "$SSH_OUT" = "RESTARTED_OK" ] && RESTARTED=true
fi

# Rate-limit alerts (once per hour)
if [ -f "$ALERT_SENT_FILE" ] && [ -z "$(find "$ALERT_SENT_FILE" -mmin +60 2>/dev/null)" ]; then
  exit 0
fi

touch "$ALERT_SENT_FILE"
TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ "$EXTERNAL_DB" = "true" ]; then
  RESTART_MSG="This is a managed/external database (RDS, Azure, etc.). Guard Dog cannot restart it automatically. Contact your cloud provider or database administrator to investigate."
elif $RESTARTED; then
  RESTART_MSG="Guard Dog attempted a remote restart and PostgreSQL is now responding."
else
  RESTART_MSG="Guard Dog attempted a remote restart but PostgreSQL is still not responding. Manual intervention required."
fi

SUBJ="TAK Server Remote Database Alert on $SERVER_IDENTIFIER"
if [ "$EXTERNAL_DB" = "true" ]; then
BODY="The managed database endpoint ($DB_HOST:$DB_PORT) is not reachable from this TAK Server.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Consecutive failures: $FAIL_COUNT
Details: $DETAILS

$RESTART_MSG

Check from this server:
  timeout 5 bash -c '</dev/tcp/$DB_HOST/$DB_PORT' && echo OPEN || echo CLOSED
  pg_isready -h $DB_HOST -p $DB_PORT

Actions:
  - Check your cloud provider console for database status and maintenance windows
  - Verify security group / firewall rules allow traffic from this VM to $DB_HOST:$DB_PORT
  - Check for scheduled maintenance or failover events
"
else
BODY="The remote database server ($DB_HOST:$DB_PORT) is not healthy.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Consecutive failures: $FAIL_COUNT
Details: $DETAILS

$RESTART_MSG

Check from this server:
  timeout 5 bash -c '</dev/tcp/$DB_HOST/$DB_PORT' && echo OPEN || echo CLOSED

Check on Server One ($DB_HOST):
  pg_isready
  sudo pg_ctlcluster 15 main status
  sudo -u postgres psql -lqt
"
fi

[ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi
mkdir -p /var/log/takguard
if [ "$EXTERNAL_DB" = "true" ]; then
  echo "$(date): Managed DB ($DB_HOST) unreachable — no auto-restart (external provider)" >> /var/log/takguard/restarts.log
elif $RESTARTED; then
  echo "$(date): Remote DB ($DB_HOST) was down, restarted successfully via SSH" >> /var/log/takguard/restarts.log
else
  echo "$(date): Remote DB ($DB_HOST) is down, restart FAILED" >> /var/log/takguard/restarts.log
fi
