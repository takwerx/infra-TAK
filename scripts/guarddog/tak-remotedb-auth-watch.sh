#!/bin/bash
# Guard Dog: Remote Database Credential monitor (two-server mode).
# Validates that the martiuser password in CoreConfig.xml actually
# authenticates against PostgreSQL on Server One. On drift, auto-resyncs
# the password from Server One, patches CoreConfig.xml, restarts TAK Server,
# and sends an alert notification.
#
# Placeholders replaced at deploy time:
#   DB_HOST_PLACEHOLDER        → Server One IP/hostname
#   DB_PORT_PLACEHOLDER        → Database port (default 5432)
#   SSH_KEY_PLACEHOLDER        → SSH key path for Server One
#   SSH_USER_PLACEHOLDER       → SSH user for Server One
#   ALERT_EMAIL_PLACEHOLDER    → Alert email (empty = no email)

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
DB_HOST="DB_HOST_PLACEHOLDER"
DB_PORT="DB_PORT_PLACEHOLDER"
SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"

ALERT_SENT_FILE="/var/lib/takguard/remotedb_auth_alert_sent"
FAIL_COUNT_FILE="/var/lib/takguard/remotedb_auth_fail_count"
RESYNC_COOLDOWN_FILE="/var/lib/takguard/remotedb_auth_last_resync"

LAST_RESTART_FILE="/var/lib/takguard/last_restart_time"
if [ -f "$LAST_RESTART_FILE" ]; then
  LAST_RESTART=$(cat "$LAST_RESTART_FILE")
  CURRENT_TIME=$(date +%s)
  TIME_SINCE_RESTART=$((CURRENT_TIME - LAST_RESTART))
  if [ $TIME_SINCE_RESTART -lt 900 ]; then
    exit 0
  fi
fi

# Cooldown: don't resync more than once per 30 minutes
if [ -f "$RESYNC_COOLDOWN_FILE" ] && [ -z "$(find "$RESYNC_COOLDOWN_FILE" -mmin +30 2>/dev/null)" ]; then
  exit 0
fi

[ -z "$SSH_KEY" ] || [ ! -f "$SSH_KEY" ] && exit 0

CORE_CONFIG="/opt/tak/CoreConfig.xml"
CORE_CONFIG_CONTENT=$(sudo cat "$CORE_CONFIG" 2>/dev/null)
[ -z "$CORE_CONFIG_CONTENT" ] && exit 0

DB_PASSWORD=$(echo "$CORE_CONFIG_CONTENT" | grep -oP '<connection[^>]*url="jdbc:postgresql://[^"]+/cot"[^>]*password="\K[^"]*' | head -1)
if [ -z "$DB_PASSWORD" ]; then
  DB_PASSWORD=$(echo "$CORE_CONFIG_CONTENT" | grep -oP '<connection[^>]*username="martiuser"[^>]*password="\K[^"]*' | head -1)
fi
if [ -z "$DB_PASSWORD" ]; then
  DB_PASSWORD=$(echo "$CORE_CONFIG_CONTENT" | grep -oP 'password="\K[^"]*' | head -1)
fi
[ -z "$DB_PASSWORD" ] && exit 0

SSH_CMD="ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 ${SSH_USER}@${DB_HOST}"

# Test current password
AUTH_OUT=$($SSH_CMD \
  "PGPASSWORD='${DB_PASSWORD}' psql -h 127.0.0.1 -p ${DB_PORT} -U martiuser -d cot -tAc 'select 1' 2>/dev/null | tr -d '[:space:]'" \
  2>/dev/null)

if [ "$AUTH_OUT" = "1" ]; then
  rm -f "$ALERT_SENT_FILE" "$FAIL_COUNT_FILE"
  exit 0
fi

# Auth failed — resync immediately
FAIL_COUNT=0
[ -f "$FAIL_COUNT_FILE" ] && FAIL_COUNT=$(cat "$FAIL_COUNT_FILE")
FAIL_COUNT=$((FAIL_COUNT + 1))
echo "$FAIL_COUNT" > "$FAIL_COUNT_FILE"

# Fetch fresh password from Server One CoreConfig.example.xml / CoreConfig.xml
FRESH_PW=""
for PW_FILE in /opt/tak/CoreConfig.example.xml /opt/tak/CoreConfig.xml; do
  RAW=$($SSH_CMD "sudo cat $PW_FILE 2>/dev/null" 2>/dev/null)
  [ -z "$RAW" ] && continue
  FRESH_PW=$(echo "$RAW" | grep -oP '<connection[^>]*url="jdbc:postgresql://[^"]+/cot"[^>]*password="\K[^"]*' | head -1)
  [ -z "$FRESH_PW" ] && FRESH_PW=$(echo "$RAW" | grep -oP '<connection[^>]*username="martiuser"[^>]*password="\K[^"]*' | head -1)
  [ -n "$FRESH_PW" ] && break
done

RESYNCED=false
RESYNC_MSG="Could not fetch fresh password from Server One."

if [ -n "$FRESH_PW" ] && [ "$FRESH_PW" != "$DB_PASSWORD" ]; then
  # Verify the fresh password actually works
  VERIFY=$($SSH_CMD \
    "PGPASSWORD='${FRESH_PW}' psql -h 127.0.0.1 -p ${DB_PORT} -U martiuser -d cot -tAc 'select 1' 2>/dev/null | tr -d '[:space:]'" \
    2>/dev/null)

  if [ "$VERIFY" = "1" ]; then
    # Patch CoreConfig.xml with the fresh password
    sudo cp "$CORE_CONFIG" "${CORE_CONFIG}.pre-resync.bak" 2>/dev/null
    ESCAPED_PW=$(printf '%s\n' "$FRESH_PW" | sed 's/[&/\]/\\&/g')
    sudo sed -i "s|<connection\([^>]*\)password=\"[^\"]*\"|<connection\1password=\"${ESCAPED_PW}\"|g" "$CORE_CONFIG" 2>/dev/null

    if [ $? -eq 0 ]; then
      sudo systemctl restart takserver 2>/dev/null
      RESYNCED=true
      RESYNC_MSG="Auto-resynced: fetched fresh password from Server One, patched CoreConfig.xml, restarted TAK Server."
      rm -f "$FAIL_COUNT_FILE"
      touch "$RESYNC_COOLDOWN_FILE"
      date +%s > "$LAST_RESTART_FILE"
    else
      RESYNC_MSG="Failed to patch CoreConfig.xml with fresh password."
    fi
  else
    RESYNC_MSG="Fresh password from Server One also failed authentication. Manual intervention required."
  fi
elif [ -n "$FRESH_PW" ]; then
  RESYNC_MSG="Password on Server One matches CoreConfig.xml but auth still fails. Check pg_hba.conf or PostgreSQL status on Server One."
fi

# Always notify on resync. Rate-limit repeat alerts only if resync failed.
if ! $RESYNCED; then
  if [ -f "$ALERT_SENT_FILE" ] && [ -z "$(find "$ALERT_SENT_FILE" -mmin +60 2>/dev/null)" ]; then
    mkdir -p /var/log/takguard
    echo "$(date): DB credential drift — resync failed, alert suppressed (sent <1hr ago)" >> /var/log/takguard/restarts.log
    exit 0
  fi
fi

touch "$ALERT_SENT_FILE"
TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if $RESYNCED; then
  SUBJ="TAK Server DB Credential Auto-Resynced on $SERVER_IDENTIFIER"
  BODY="CREDENTIAL DRIFT DETECTED AND AUTO-FIXED.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Consecutive failures before fix: $FAIL_COUNT

$RESYNC_MSG

The martiuser password in CoreConfig.xml did not match PostgreSQL on
Server One ($DB_HOST:$DB_PORT). Guard Dog fetched the current password,
patched CoreConfig.xml, and restarted TAK Server.

No action required — TAK Server should be back online within 60 seconds.
A backup was saved to ${CORE_CONFIG}.pre-resync.bak.
"
else
  SUBJ="TAK Server DB Credential Alert on $SERVER_IDENTIFIER"
  BODY="CREDENTIAL DRIFT DETECTED — AUTO-RESYNC FAILED.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Consecutive failures: $FAIL_COUNT
Resync result: $RESYNC_MSG

The password in /opt/tak/CoreConfig.xml does not authenticate against
PostgreSQL on Server One ($DB_HOST:$DB_PORT).

This will cause TAK Server connection pool exhaustion (HikariPool errors)
and break CloudTAK registration.

FIX: Open infra-TAK → TAK Server → Sync DB Password.
Or manually get the correct password from Server One CoreConfig.example.xml
and update /opt/tak/CoreConfig.xml on this host.
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
if $RESYNCED; then
  echo "$(date): DB credential drift auto-resynced — fresh password from $DB_HOST, TAK Server restarted (failures: $FAIL_COUNT)" >> /var/log/takguard/restarts.log
else
  echo "$(date): DB credential drift detected — auto-resync FAILED on $DB_HOST:$DB_PORT (failures: $FAIL_COUNT) — $RESYNC_MSG" >> /var/log/takguard/restarts.log
fi
