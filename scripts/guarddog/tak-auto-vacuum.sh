#!/bin/bash
# Guard Dog: CoT database auto-VACUUM when dead tuple count is high.
# Intended to run daily (systemd timer). Compares pg_stat_user_tables dead tuples
# to a threshold; runs VACUUM ANALYZE only when needed (routine autovacuum may lag
# after heavy retention deletes).
#
# Modes:
#   - Local: PostgreSQL on this host → sudo -u postgres psql -d cot
#   - Two-server: /opt/tak-guarddog/guarddog.conf has two_server=true → SSH to
#     Server One and run psql there (same as other remote Guard Dog scripts).
#
# Placeholders replaced at deploy time (same as tak-remotedb-watch.sh):
#   DB_HOST_PLACEHOLDER        → Server One IP/hostname (fallback if JSON omits db_host)
#   SSH_KEY_PLACEHOLDER        → SSH private key path for Server One
#   SSH_USER_PLACEHOLDER       → SSH user for Server One
#   ALERT_EMAIL_PLACEHOLDER    → Alert email (empty = no email)

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
GUARDDOG_CONF="/opt/tak-guarddog/guarddog.conf"

# SSH / host fallbacks (overridden by guarddog.conf db_host when two_server)
SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"
DB_HOST="DB_HOST_PLACEHOLDER"

# Sum of n_dead_tup across user tables must exceed this to trigger VACUUM ANALYZE
DEAD_TUP_THRESHOLD=1000000

# After VACUUM, if cot DB still exceeds this size, email recommending VACUUM FULL (bytes)
SIZE_THRESHOLD_GB=25
SIZE_THRESHOLD_BYTES=$((SIZE_THRESHOLD_GB * 1024 * 1024 * 1024))

DEAD_SQL="SELECT COALESCE(SUM(n_dead_tup),0)::bigint FROM pg_stat_user_tables;"
SIZE_SQL="SELECT COALESCE(pg_database_size('cot'), 0)::bigint;"

# Parse guarddog.conf (JSON): two_server, db_host, db_port
TWO_SERVER_MODE=0
REMOTE_DB_HOST=""
# db_port kept in sync with guarddog.conf (used by health checks elsewhere; psql over SSH is local on Server One)
REMOTE_DB_PORT="5432"
if [ -f "$GUARDDOG_CONF" ]; then
  # v0.9.29 CRIT-07: replaced `eval "$(python3 ...)"` with newline-delimited
  # read so guarddog.conf values never reach a shell evaluator.
  {
    IFS= read -r TWO_SERVER_MODE
    IFS= read -r REMOTE_DB_HOST
    IFS= read -r REMOTE_DB_PORT
  } < <(python3 - <<'PY'
import json, os
p = "/opt/tak-guarddog/guarddog.conf"
two = "0"
host = ""
port = "5432"
if os.path.isfile(p):
    try:
        with open(p) as f:
            c = json.load(f)
        if c.get("two_server"):
            two = "1"
        host = str(c.get("db_host") or "")
        if c.get("db_port") is not None:
            port = str(int(c.get("db_port")))
    except Exception:
        pass
print(two)
print(host)
print(port)
PY
  )
  TWO_SERVER_MODE="${TWO_SERVER_MODE:-0}"
  REMOTE_DB_PORT="${REMOTE_DB_PORT:-5432}"
fi

# Effective SSH target: JSON db_host first, then deployed placeholder
SSH_TARGET="${REMOTE_DB_HOST:-$DB_HOST}"

mkdir -p /var/log/takguard
LOG_FILE="/var/log/takguard/restarts.log"

log_line() {
  echo "$(date): $1" >> "$LOG_FILE"
}

# Run a query returning a single numeric row (trimmed)
psql_scalar() {
  local sql="$1"
  local out
  if [ "$TWO_SERVER_MODE" = "1" ]; then
    if [ -z "$SSH_TARGET" ]; then
      echo ""
      return 1
    fi
    if [ ! -f "$SSH_KEY" ]; then
      echo ""
      return 1
    fi
    out=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
      "${SSH_USER}@${SSH_TARGET}" \
      "sudo -u postgres psql -d cot -t -A -c $(printf '%q' "$sql")" 2>/dev/null) || return 1
  else
    out=$(sudo -u postgres psql -d cot -t -A -c "$sql" 2>/dev/null) || return 1
  fi
  # Trim whitespace
  echo "${out}" | tr -d '[:space:]'
}

# Run a non-query psql command (e.g. VACUUM)
psql_exec() {
  local sql="$1"
  if [ "$TWO_SERVER_MODE" = "1" ]; then
    if [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ]; then
      return 1
    fi
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
      "${SSH_USER}@${SSH_TARGET}" \
      "sudo -u postgres psql -d cot -c $(printf '%q' "$sql")" 2>/dev/null
  else
    sudo -u postgres psql -d cot -c "$sql" 2>/dev/null
  fi
}

# Two-server mode requires SSH to Server One
if [ "$TWO_SERVER_MODE" = "1" ]; then
  if [ -z "$SSH_TARGET" ]; then
    log_line "Auto-VACUUM: two_server mode but db_host is empty, skipped"
    exit 1
  fi
  if [ ! -f "$SSH_KEY" ]; then
    log_line "Auto-VACUUM: two_server mode but SSH key not found at ${SSH_KEY}, skipped"
    exit 1
  fi
fi

DEAD_RAW=$(psql_scalar "$DEAD_SQL")
if [ -z "$DEAD_RAW" ]; then
  if [ "$TWO_SERVER_MODE" = "1" ]; then
    log_line "Auto-VACUUM: could not read dead tuple count (SSH/psql failed), two_server=1 target=${SSH_USER}@${SSH_TARGET}, skipped"
  else
    log_line "Auto-VACUUM: could not read dead tuple count (local psql failed), two_server=0, skipped"
  fi
  exit 1
fi

# Ensure numeric
DEAD_COUNT=$((DEAD_RAW + 0))

if [ "$DEAD_COUNT" -gt "$DEAD_TUP_THRESHOLD" ]; then
  if ! psql_exec "VACUUM ANALYZE;"; then
    log_line "Auto-VACUUM: ${DEAD_COUNT} dead tuples found, VACUUM ANALYZE failed"
    exit 1
  fi
  log_line "Auto-VACUUM: ${DEAD_COUNT} dead tuples found, ran VACUUM ANALYZE"

  COT_BYTES_RAW=$(psql_scalar "$SIZE_SQL")
  COT_BYTES=$((COT_BYTES_RAW + 0))
  if [ "$COT_BYTES" -gt "$SIZE_THRESHOLD_BYTES" ]; then
    COT_GB=$((COT_BYTES / 1024 / 1024 / 1024))
    TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    SUBJ="TAK Server CoT post-VACUUM size (${COT_GB}GB) on $SERVER_IDENTIFIER - consider VACUUM FULL"
    BODY="Guard Dog ran VACUUM ANALYZE because dead tuples exceeded ${DEAD_TUP_THRESHOLD}.

After VACUUM ANALYZE, the CoT database is still about ${COT_GB}GB (threshold for this notice: ${SIZE_THRESHOLD_GB}GB).

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Database: cot

VACUUM ANALYZE updates statistics and reclaims space that autovacuum can return without an exclusive lock. If you still need to reclaim disk space from deleted rows (bloat), plan a maintenance window and consider:

  sudo -u postgres psql -d cot -c 'VACUUM FULL;'

VACUUM FULL locks tables and can take a long time on large databases; use only when necessary.

See also: CoT retention settings and tak-db-cleanup / retention jobs.
"
    [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
  fi
else
  log_line "Auto-VACUUM: ${DEAD_COUNT} dead tuples found, below threshold (1M), skipped"
fi

exit 0
