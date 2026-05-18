#!/bin/bash
# Guard Dog: CoT retention safety net.
# Kills long-running DELETE queries on cot_router that indicate TAK Server
# retention is stuck (overlapping runs, massive single-transaction deletes).
# Then runs batched deletes in small chunks so the table stays manageable.
#
# Intended to run every 15 minutes (systemd timer).
#
# Modes:
#   - Local: PostgreSQL on this host → sudo -u postgres psql -d cot
#   - Two-server: /opt/tak-guarddog/guarddog.conf has two_server=true → SSH to
#     Server One and run psql there.
#
# Placeholders replaced at deploy time:
#   DB_HOST_PLACEHOLDER        → Server One IP/hostname
#   SSH_KEY_PLACEHOLDER        → SSH private key path
#   SSH_USER_PLACEHOLDER       → SSH user
#   ALERT_EMAIL_PLACEHOLDER    → Alert email (empty = no email)

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
GUARDDOG_CONF="/opt/tak-guarddog/guarddog.conf"

SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"
DB_HOST="DB_HOST_PLACEHOLDER"

# Kill DELETE queries running longer than this (minutes)
KILL_THRESHOLD_MIN=30

# Batched delete: rows per chunk and sleep between chunks (seconds)
BATCH_SIZE=50000
BATCH_SLEEP=2

# Max batched-delete iterations per run (safety cap: 50k × 200 = 10M rows max)
MAX_BATCHES=200

# Parse guarddog.conf
TWO_SERVER_MODE=0
REMOTE_DB_HOST=""
if [ -f "$GUARDDOG_CONF" ]; then
  # v0.9.29 CRIT-07: replaced `eval "$(python3 ...)"` with newline-delimited
  # read so guarddog.conf values never reach a shell evaluator.
  {
    IFS= read -r TWO_SERVER_MODE
    IFS= read -r REMOTE_DB_HOST
  } < <(python3 - <<'PY'
import json, os
p = "/opt/tak-guarddog/guarddog.conf"
two = "0"; host = ""
if os.path.isfile(p):
    try:
        with open(p) as f:
            c = json.load(f)
        if c.get("two_server"):
            two = "1"
        host = str(c.get("db_host") or "")
    except Exception:
        pass
print(two)
print(host)
PY
  )
  TWO_SERVER_MODE="${TWO_SERVER_MODE:-0}"
fi

SSH_TARGET="${REMOTE_DB_HOST:-$DB_HOST}"

mkdir -p /var/log/takguard
LOG_FILE="/var/log/takguard/restarts.log"

log_line() {
  echo "$(date): $1" >> "$LOG_FILE"
}

# Run a query and return raw output (for scalars, use -t -A)
psql_scalar() {
  local sql="$1"
  if [ "$TWO_SERVER_MODE" = "1" ]; then
    [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ] && return 1
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
      "${SSH_USER}@${SSH_TARGET}" \
      "sudo -u postgres psql -d cot -t -A -c $(printf '%q' "$sql")" 2>/dev/null
  else
    sudo -u postgres psql -d cot -t -A -c "$sql" 2>/dev/null
  fi
}

# Run a command and return full output (for DELETE row count parsing)
psql_raw() {
  local sql="$1"
  if [ "$TWO_SERVER_MODE" = "1" ]; then
    [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ] && return 1
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
      "${SSH_USER}@${SSH_TARGET}" \
      "sudo -u postgres psql -d cot -c $(printf '%q' "$sql")" 2>/dev/null
  else
    sudo -u postgres psql -d cot -c "$sql" 2>/dev/null
  fi
}

# Pre-flight
if [ "$TWO_SERVER_MODE" = "1" ]; then
  if [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ]; then
    log_line "RETENTION-GUARD: two_server mode but SSH target/key unavailable, skipped"
    exit 1
  fi
fi

# ── Step 1: Find and kill stuck DELETE queries on cot_router ──
STUCK_PIDS=$(psql_scalar "SELECT pid FROM pg_stat_activity WHERE query ILIKE '%delete%cot_router%' AND state = 'active' AND now() - query_start > interval '${KILL_THRESHOLD_MIN} minutes';")

KILLED=0
if [ -n "$STUCK_PIDS" ]; then
  for pid in $STUCK_PIDS; do
    pid_clean=$(echo "$pid" | tr -d '[:space:]')
    [ -z "$pid_clean" ] && continue
    runtime=$(psql_scalar "SELECT EXTRACT(EPOCH FROM now() - query_start)::int FROM pg_stat_activity WHERE pid = ${pid_clean};")
    runtime_min=$(( (${runtime:-0} + 0) / 60 ))
    psql_raw "SELECT pg_terminate_backend(${pid_clean});" >/dev/null 2>&1
    log_line "RETENTION-GUARD: killed stuck DELETE pid ${pid_clean} (running ${runtime_min}min)"
    KILLED=$((KILLED + 1))
  done

  # Brief pause to let terminated backends release locks
  [ "$KILLED" -gt 0 ] && sleep 3

  if [ "$KILLED" -gt 0 ]; then
    TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    SUBJ="Guard Dog: killed ${KILLED} stuck CoT DELETE(s) on $SERVER_IDENTIFIER"
    BODY="Guard Dog Retention Guard detected ${KILLED} DELETE query/queries on cot_router
running longer than ${KILL_THRESHOLD_MIN} minutes and terminated them.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

Stuck retention DELETEs cause memory bloat, swap exhaustion, and high CPU.
Guard Dog will now run batched cleanup to remove expired rows safely.

If this keeps happening, increase TAK Server retention run frequency
(e.g. hourly instead of daily) in the Web Admin data retention settings.
"
    [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
  fi
fi

# ── Step 2: Check if TAK retention is running normally (short DELETE, under threshold) ──
ACTIVE_DELETES=$(psql_scalar "SELECT COUNT(*) FROM pg_stat_activity WHERE query ILIKE '%delete%cot_router%' AND state = 'active';")
ACTIVE_DELETES=$((${ACTIVE_DELETES:-0} + 0))

if [ "$ACTIVE_DELETES" -gt 0 ]; then
  log_line "RETENTION-GUARD: ${ACTIVE_DELETES} active DELETE(s) running (under ${KILL_THRESHOLD_MIN}min threshold), skipping batched cleanup"
  exit 0
fi

# ── Step 3: Determine retention hours from CoreConfig.xml ──
RETENTION_HOURS=24
if [ "$TWO_SERVER_MODE" = "0" ] && [ -f /opt/tak/CoreConfig.xml ]; then
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

# ── Step 4: Quick count of expired rows ──
EXPIRED_EST=$(psql_scalar "SELECT count_estimate('SELECT 1 FROM cot_router WHERE servertime < now() - interval ''${RETENTION_HOURS} hours''');" 2>/dev/null)
# count_estimate may not exist; fall back to real COUNT with a LIMIT-based estimate
if [ -z "$EXPIRED_EST" ] || [ "$EXPIRED_EST" = "" ]; then
  EXPIRED_EST=$(psql_scalar "SELECT COUNT(*) FROM (SELECT 1 FROM cot_router WHERE servertime < now() - interval '${RETENTION_HOURS} hours' LIMIT 100001) sub;")
fi
EXPIRED_EST=$((${EXPIRED_EST:-0} + 0))

if [ "$EXPIRED_EST" -lt 1000 ]; then
  log_line "RETENTION-GUARD: ~${EXPIRED_EST} expired rows (retention=${RETENTION_HOURS}h), nothing to do"
  exit 0
fi

log_line "RETENTION-GUARD: ~${EXPIRED_EST} expired rows (retention=${RETENTION_HOURS}h), starting batched delete (${BATCH_SIZE}/batch)"

# ── Step 5: Batched delete using ctid for reliable chunking ──
TOTAL_DELETED=0
BATCH_NUM=0
while [ "$BATCH_NUM" -lt "$MAX_BATCHES" ]; do
  # DELETE with subquery LIMIT; parse "DELETE NNNNN" from output
  DEL_OUT=$(psql_raw "DELETE FROM cot_router WHERE ctid IN (SELECT ctid FROM cot_router WHERE servertime < now() - interval '${RETENTION_HOURS} hours' LIMIT ${BATCH_SIZE});")
  ROW_COUNT=$(echo "$DEL_OUT" | grep -oP '(?<=DELETE )\d+' | head -1)
  ROW_COUNT=$((${ROW_COUNT:-0} + 0))

  TOTAL_DELETED=$((TOTAL_DELETED + ROW_COUNT))
  BATCH_NUM=$((BATCH_NUM + 1))

  # If we deleted fewer than BATCH_SIZE, we're done
  if [ "$ROW_COUNT" -lt "$BATCH_SIZE" ]; then
    break
  fi

  sleep "$BATCH_SLEEP"
done

log_line "RETENTION-GUARD: batched delete complete — removed ${TOTAL_DELETED} rows in ${BATCH_NUM} batches"

# Alert if we cleaned up a significant amount
if [ "$TOTAL_DELETED" -gt 100000 ]; then
  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  SUBJ="Guard Dog: cleaned ${TOTAL_DELETED} expired CoT rows on $SERVER_IDENTIFIER"
  BODY="Guard Dog Retention Guard ran batched cleanup on the CoT database.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Rows deleted: ${TOTAL_DELETED} (in ${BATCH_NUM} batches of up to ${BATCH_SIZE})
Retention: ${RETENTION_HOURS} hours

This prevents TAK Server's built-in retention from attempting a single
massive DELETE that can take hours and exhaust memory/swap.

If large cleanups keep happening, consider increasing TAK Server
retention run frequency (e.g. hourly) in the Web Admin settings.
"
  [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
fi

exit 0
