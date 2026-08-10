#!/bin/bash
# Guard Dog: CoT / TAK Server database size monitor.
# Alerts when the CoT database grows too large. Retention deletes rows but PostgreSQL
# does not free disk until VACUUM runs; large row counts (e.g. 44M rows) can mean
# retention is running but disk is not reclaimed without VACUUM/REINDEX.
#
# Two-server mode: reads /opt/tak-guarddog/guarddog.conf and queries DB size on Server One via SSH.
# Placeholders replaced at deploy time (two-server): SSH_KEY_PLACEHOLDER, SSH_USER_PLACEHOLDER
# v10.0.1: single-server local DB access goes through _gd-tak-lib.sh so a
# containerized DB (takserver-db) is queried via docker exec; native unchanged.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/cotdb_alert_sent"
# Alert when CoT DB size exceeds this (bytes). 25GB = 26843545600
SIZE_THRESHOLD_GB=25
SIZE_THRESHOLD=$((SIZE_THRESHOLD_GB * 1024 * 1024 * 1024))

# Optional: also alert at a higher critical level (e.g. 40GB)
CRITICAL_THRESHOLD_GB=40
CRITICAL_THRESHOLD=$((CRITICAL_THRESHOLD_GB * 1024 * 1024 * 1024))

# v10.1.29 (W8) — absolute GB thresholds alone cannot see the failure that
# actually strands a box. A 43 GB CoT database is fine on a 500 GB disk and fatal
# on a 96 GB one, and the box that filled on 2026-08-10 had been past CRITICAL
# for weeks with no free-space signal and no retention-stalled signal at all.
# Two extra conditions, each with its OWN latch so one firing can never suppress
# another (the single shared latch was itself part of why nothing reached the
# reporter).
FS_WARN_PCT=15          # free space on the DB data directory
FS_CRIT_PCT=8
RETENTION_STALE_FACTOR=2   # oldest row older than N x the configured TTL
FS_ALERT_FILE="/var/lib/takguard/cotdb_alert_sent.freespace"
RET_ALERT_FILE="/var/lib/takguard/cotdb_alert_sent.retention"

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
elif gd_psql_present; then
  COT_SIZE=$(gd_psql_scalar "SELECT COALESCE(pg_database_size('cot'), 0);" || echo "0")
fi

# If cot doesn't exist or we couldn't connect, try sum of all non-template DBs (fallback)
if [ -z "$COT_SIZE" ] || [ "$COT_SIZE" = "" ]; then
  COT_SIZE=0
fi

# Ensure numeric
COT_SIZE=$((COT_SIZE + 0))

# ===========================================================================
# v10.1.29 (W8) — shared helpers + the two conditions that actually predict a
# stranded box. Each condition owns its latch and is evaluated BEFORE the size
# check, which keeps its original early-exit.
# ===========================================================================
gd_ssh_db() {
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
    "${SSH_USER}@${DB_HOST}" "$1" 2>/dev/null
}

gd_remote_db() { [ "$TWO_SERVER" = "true" ] && [ -n "$DB_HOST" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; }

cotdb_scalar() {
  local sql="$1"; local db="${2:-}"
  if gd_remote_db; then
    gd_ssh_db "cd / && sudo -u postgres psql -t -A ${db:+-d $db} -c $(printf '%q' "$sql")"
  elif gd_psql_present; then
    gd_psql_scalar "$sql" "$db"
  fi
}

# Shell in the DB's own context: over SSH remotely, inside takserver-db in
# container mode, plain bash natively. `df` must measure where the DATA lives.
cotdb_shell() {
  if gd_remote_db; then gd_ssh_db "$1"; else gd_db_shell "$1" 2>/dev/null; fi
}

cotdb_numeric() { case "$1" in ''|*[!0-9]*) echo "" ;; *) echo "$1" ;; esac; }

send_cot_alert() {
  local subj="$1"; local body="$2"
  [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$body" | /opt/tak-guarddog/send-alert-email.sh "$subj" "ALERT_EMAIL_PLACEHOLDER"
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    local tmpf="/tmp/gd-sms-$$.txt"
    printf '%s' "$body" > "$tmpf"
    /opt/tak-guarddog/sms_send.sh "$subj" "$tmpf" 2>/dev/null || true
    rm -f "$tmpf"
  fi
  mkdir -p /var/log/takguard
}

# Fire at most once a day per condition (matches the size latch's cadence).
cot_latch_ready() { [ ! -f "$1" ] || [ -n "$(find "$1" -mtime +1 2>/dev/null)" ]; }

TS_NOW="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ── Condition A: free space on the DB data directory ──────────────────────
DATA_DIR=$(cotdb_scalar "SHOW data_directory;" | tr -d '[:space:]')
[ -z "$DATA_DIR" ] && DATA_DIR="/"
FS_LINE=$(cotdb_shell "df -P '$DATA_DIR' 2>/dev/null | tail -1")
FS_TOTAL=$(cotdb_numeric "$(echo "$FS_LINE" | awk '{print $2}')")
FS_AVAIL=$(cotdb_numeric "$(echo "$FS_LINE" | awk '{print $4}')")
if [ -n "$FS_TOTAL" ] && [ -n "$FS_AVAIL" ] && [ "$FS_TOTAL" -gt 0 ]; then
  FS_PCT=$(( FS_AVAIL * 100 / FS_TOTAL ))
  FS_AVAIL_GB=$(( FS_AVAIL / 1024 / 1024 ))
  if [ "$FS_PCT" -lt "$FS_WARN_PCT" ]; then
    FS_LEVEL="WARNING"
    [ "$FS_PCT" -lt "$FS_CRIT_PCT" ] && FS_LEVEL="CRITICAL"
    if cot_latch_ready "$FS_ALERT_FILE"; then
      touch "$FS_ALERT_FILE"
      send_cot_alert "TAK Server database disk space ($FS_LEVEL) on $SERVER_IDENTIFIER" \
"The filesystem holding the TAK Server database is running out of space.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS_NOW
Data directory: $DATA_DIR
Free: ${FS_AVAIL_GB}GB (${FS_PCT}% — warning below ${FS_WARN_PCT}%, critical below ${FS_CRIT_PCT}%)

Act on this BEFORE the disk fills. Once it is full:
 - VACUUM FULL and Online Compact CANNOT run — both need free space roughly
   equal to the largest table, so PostgreSQL fails with 'could not extend file'.
 - Updating the console needs ~1GB free and will refuse.

Open the console, go to Guard Dog -> Database maintenance (CoT), and press
Diagnose. It reports which case this box is in and highlights the button that
recovers it (Run Retention Now, Purge Old CoT, or Online Compact)."
      echo "$(date): CoT DB free-space alert sent (${FS_PCT}% free on ${DATA_DIR})" >> /var/log/takguard/restarts.log
    fi
  else
    rm -f "$FS_ALERT_FILE"
  fi
fi

# ── Condition B: retention stalled ────────────────────────────────────────
# The alert that would have reached the 2026-08-10 reporter WEEKS before the
# disk filled: retention configured at 1 day, yet 48.3M rows resident.
RETENTION_HOURS=24
if [ -f /opt/tak/CoreConfig.xml ]; then
  RH=$(python3 -c "
import xml.etree.ElementTree as ET, sys
try:
    t = ET.parse('/opt/tak/CoreConfig.xml')
    ns = {'m': 'http://bbn.com/marti/xml/config'}
    for repo in t.findall('.//m:repository', ns) + t.findall('.//repository'):
        rd = repo.get('retentionDays')
        if rd:
            h = int(float(rd) * 24)
            if h > 0:
                print(h)
                sys.exit(0)
except Exception:
    pass
print('')
" 2>/dev/null)
  [ -n "$RH" ] && [ "$RH" -gt 0 ] 2>/dev/null && RETENTION_HOURS=$RH
fi
OLDEST_SECS=$(cotdb_scalar "SET statement_timeout='20s'; SELECT COALESCE(EXTRACT(EPOCH FROM (now() - min(servertime)))::bigint, 0) FROM cot_router;" cot | tr -d '[:space:]')
OLDEST_SECS=$(cotdb_numeric "$OLDEST_SECS")
STALE_SECS=$(( RETENTION_HOURS * 3600 * RETENTION_STALE_FACTOR ))
if [ -n "$OLDEST_SECS" ] && [ "$OLDEST_SECS" -gt "$STALE_SECS" ]; then
  OLDEST_DAYS=$(( OLDEST_SECS / 86400 ))
  if cot_latch_ready "$RET_ALERT_FILE"; then
    touch "$RET_ALERT_FILE"
    send_cot_alert "TAK Server CoT retention is not deleting on $SERVER_IDENTIFIER" \
"TAK Server's CoT retention policy is not actually removing old data.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS_NOW
Configured retention: ${RETENTION_HOURS} hours
Oldest CoT row: ${OLDEST_DAYS} days old (alert fires past ${RETENTION_STALE_FACTOR}x the retention window)

The database is therefore growing from LIVE rows, not from reclaimable bloat —
VACUUM and Online Compact will free nothing here. Left alone this fills the disk.

Likely causes:
 - TAK Server's retention process is not running.
 - Guard Dog's takretentionguard.timer is not enabled (it was written but never
   enabled on consoles installed before v10.1.1).
 - The retention TTL is not actually set in TAK Server's Web Admin (:8443 ->
   Data Retention Policies).

Fix from the console: Guard Dog -> Database maintenance (CoT) -> Diagnose, then
Run Retention Now (it also re-arms the timer)."
    echo "$(date): CoT retention-stalled alert sent (oldest row ${OLDEST_DAYS}d, retention ${RETENTION_HOURS}h)" >> /var/log/takguard/restarts.log
  fi
else
  rm -f "$RET_ALERT_FILE"
fi

# ── Condition C: absolute database size (original behaviour, own latch) ────
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
