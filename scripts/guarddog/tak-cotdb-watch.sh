#!/bin/bash
# Guard Dog: CoT / TAK Server database size monitor.
# Alerts when the CoT database grows too large. Retention deletes rows but PostgreSQL
# does not free disk until VACUUM runs; large row counts (e.g. 44M rows) can mean
# retention is running but disk is not reclaimed without VACUUM/REINDEX.
#
# Two-server mode: reads /opt/tak-guarddog/guarddog.conf and queries DB size on Server One via SSH.
# Placeholders replaced at deploy time (two-server): SSH_KEY_PLACEHOLDER, SSH_USER_PLACEHOLDER

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/cotdb_alert_sent"
# Alert when CoT DB size exceeds this (bytes). 25GB = 26843545600
SIZE_THRESHOLD_GB=25
SIZE_THRESHOLD=$((SIZE_THRESHOLD_GB * 1024 * 1024 * 1024))

# Optional: also alert at a higher critical level (e.g. 40GB)
CRITICAL_THRESHOLD_GB=40
CRITICAL_THRESHOLD=$((CRITICAL_THRESHOLD_GB * 1024 * 1024 * 1024))

# Check if two-server mode (remote DB)
GD_CONF="/opt/tak-guarddog/guarddog.conf"
TWO_SERVER=false
DB_HOST=""
SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"

if [ -f "$GD_CONF" ]; then
  TWO_SERVER=$(python3 -c "import json; d=json.load(open('$GD_CONF')); print('true' if d.get('two_server') else 'false')" 2>/dev/null || echo "false")
  DB_HOST=$(python3 -c "import json; d=json.load(open('$GD_CONF')); print(d.get('db_host',''))" 2>/dev/null || echo "")
fi

# Get size of 'cot' database (TAK Server CoT data). Use postgres user on DB host, or SSH to Server One in two-server mode.
COT_SIZE=0
if [ "$TWO_SERVER" = "true" ] && [ -n "$DB_HOST" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  COT_SIZE=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
    "${SSH_USER}@${DB_HOST}" \
    "sudo -u postgres psql -t -A -c \"SELECT COALESCE(pg_database_size('cot'), 0);\"" \
    2>/dev/null || echo "0")
elif command -v psql >/dev/null 2>&1; then
  COT_SIZE=$(sudo -u postgres psql -t -A -c "SELECT COALESCE(pg_database_size('cot'), 0);" 2>/dev/null || echo "0")
fi

# If cot doesn't exist or we couldn't connect, try sum of all non-template DBs (fallback)
if [ -z "$COT_SIZE" ] || [ "$COT_SIZE" = "" ]; then
  COT_SIZE=0
fi

# Ensure numeric
COT_SIZE=$((COT_SIZE + 0))

if [ "$COT_SIZE" -lt "$SIZE_THRESHOLD" ]; then
  rm -f "$ALERT_SENT_FILE"
  exit 0
fi

# Rate limit alerts (e.g. once per day unless critical)
if [ "$COT_SIZE" -lt "$CRITICAL_THRESHOLD" ]; then
  if [ -f "$ALERT_SENT_FILE" ] && [ -z "$(find "$ALERT_SENT_FILE" -mtime +1 2>/dev/null)" ]; then
    exit 0
  fi
fi

touch "$ALERT_SENT_FILE"
COT_GB=$((COT_SIZE / 1024 / 1024 / 1024))
TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
LEVEL="WARNING"
if [ "$COT_SIZE" -ge "$CRITICAL_THRESHOLD" ]; then
  LEVEL="CRITICAL"
fi

SUBJ="TAK Server CoT Database Size Alert ($LEVEL) on $SERVER_IDENTIFIER"
BODY="The TAK Server CoT (Cursor on Target) database is using ${COT_GB}GB of disk.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Database: cot
Size: ${COT_GB}GB (threshold: ${SIZE_THRESHOLD_GB}GB warning, ${CRITICAL_THRESHOLD_GB}GB critical)

Common causes:
- Data retention is set but PostgreSQL does not free disk when rows are deleted;
  you must run VACUUM (and optionally REINDEX) to reclaim space.
- Retention or tak-db-cleanup.service is not running or not deleting as expected.
- Federation or archiving is storing more data than intended.

Things to check:
1. Data Retention in TAK Server web UI (e.g. 1 day, run every hour).
2. Retention process: systemctl status takserver (look for retention).
3. If your install has it: systemctl status tak-db-cleanup.service
   and: sudo journalctl -u tak-db-cleanup.service -f (for deletion activity).
4. Reclaim disk after deletes (run as postgres on the database host):
   sudo -u postgres psql -d cot -c 'VACUUM ANALYZE;'
   (For large tables, VACUUM FULL can reclaim more space but locks tables.)
5. Row count: sudo -u postgres psql -d cot -t -c \"SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 5;\"
"

[ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi
mkdir -p /var/log/takguard
echo "$(date): CoT database size alert sent (${COT_GB}GB)" >> /var/log/takguard/restarts.log
