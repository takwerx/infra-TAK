#!/bin/bash
# Guard Dog: Online table repack for CoT database.
# Uses pg_repack to reclaim actual disk space without locking tables
# (unlike VACUUM FULL which requires exclusive lock / downtime).
#
# Intended to run weekly via systemd timer, after retention deletes have
# created bloat that VACUUM ANALYZE cannot reclaim.
#
# Modes:
#   - Local: PostgreSQL on this host
#   - Two-server: SSH to Server One (same pattern as tak-auto-vacuum.sh)
#
# Placeholders replaced at deploy time:
#   DB_HOST_PLACEHOLDER        → Server One IP/hostname
#   SSH_KEY_PLACEHOLDER        → SSH private key path
#   SSH_USER_PLACEHOLDER       → SSH user
#   ALERT_EMAIL_PLACEHOLDER    → Alert email

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
GUARDDOG_CONF="/opt/tak-guarddog/guarddog.conf"

SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"
DB_HOST="DB_HOST_PLACEHOLDER"

# Only repack if database exceeds this size (GB). Below this, bloat is negligible.
REPACK_THRESHOLD_GB=10
REPACK_THRESHOLD_BYTES=$((REPACK_THRESHOLD_GB * 1024 * 1024 * 1024))

SIZE_SQL="SELECT COALESCE(pg_database_size('cot'), 0)::bigint;"
# Top bloated tables by estimated dead/total ratio
BLOAT_SQL="SELECT relname FROM pg_stat_user_tables WHERE n_dead_tup > 10000 ORDER BY n_dead_tup DESC LIMIT 10;"

TWO_SERVER_MODE=0
REMOTE_DB_HOST=""
if [ -f "$GUARDDOG_CONF" ]; then
  # v0.9.29 CRIT-07: replaced `eval "$(python3 ...)"` with newline-delimited
  # read so guarddog.conf values never reach a shell evaluator. The python
  # process only emits two literal lines; we never re-parse them as shell.
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

psql_scalar() {
  local sql="$1"
  local out
  if [ "$TWO_SERVER_MODE" = "1" ]; then
    [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ] && return 1
    out=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
      "${SSH_USER}@${SSH_TARGET}" \
      "sudo -u postgres psql -d cot -t -A -c $(printf '%q' "$sql")" 2>/dev/null) || return 1
  else
    out=$(sudo -u postgres psql -d cot -t -A -c "$sql" 2>/dev/null) || return 1
  fi
  echo "${out}" | tr -d '[:space:]'
}

remote_cmd() {
  local cmd="$1"
  if [ "$TWO_SERVER_MODE" = "1" ]; then
    [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ] && return 1
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 \
      "${SSH_USER}@${SSH_TARGET}" "$cmd" 2>&1
  else
    # v0.9.29 CRIT-07: was `eval "$cmd"`. Replaced with `bash -c` so the
    # command is interpreted exactly once. All callers pass shell strings
    # that need a shell (pipes, &&, command substitution).
    bash -c "$cmd" 2>&1
  fi
}

# Pre-flight: check SSH connectivity for two-server mode
if [ "$TWO_SERVER_MODE" = "1" ]; then
  if [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ]; then
    log_line "DB-REPACK: two_server mode but SSH target/key unavailable, skipped"
    exit 1
  fi
fi

# Check database size — skip repack if below threshold
COT_SIZE_RAW=$(psql_scalar "$SIZE_SQL")
if [ -z "$COT_SIZE_RAW" ]; then
  log_line "DB-REPACK: could not read database size, skipped"
  exit 1
fi
COT_SIZE=$((COT_SIZE_RAW + 0))
COT_GB=$((COT_SIZE / 1024 / 1024 / 1024))

if [ "$COT_SIZE" -lt "$REPACK_THRESHOLD_BYTES" ]; then
  log_line "DB-REPACK: cot database is ${COT_GB}GB, below ${REPACK_THRESHOLD_GB}GB threshold, skipped"
  exit 0
fi

# Ensure pg_repack is installed (extension + CLI)
INSTALL_CHECK=$(remote_cmd "command -v pg_repack >/dev/null 2>&1 && echo 'ok' || echo 'missing'")
if [ "$INSTALL_CHECK" = "missing" ]; then
  log_line "DB-REPACK: pg_repack CLI not found, attempting install"
  PG_VER=$(remote_cmd "pg_config --version 2>/dev/null | grep -oP '\\d+' | head -1" || echo "")
  if [ -n "$PG_VER" ]; then
    remote_cmd "apt-get update -qq && apt-get install -y -qq postgresql-${PG_VER}-repack 2>&1" >/dev/null
  fi
  INSTALL_CHECK=$(remote_cmd "command -v pg_repack >/dev/null 2>&1 && echo 'ok' || echo 'missing'")
  if [ "$INSTALL_CHECK" = "missing" ]; then
    log_line "DB-REPACK: pg_repack could not be installed, skipped"
    exit 1
  fi
  log_line "DB-REPACK: pg_repack installed successfully"
fi

# Ensure extension is created in the database
remote_cmd "sudo -u postgres psql -d cot -c 'CREATE EXTENSION IF NOT EXISTS pg_repack;'" >/dev/null 2>&1

# Record size before repack
SIZE_BEFORE=$COT_GB

# Run pg_repack on the cot database
log_line "DB-REPACK: starting online repack of cot database (${SIZE_BEFORE}GB)"
REPACK_OUTPUT=$(remote_cmd "sudo -u postgres pg_repack -d cot --no-superuser-check --wait-timeout=30 2>&1")
REPACK_RC=$?

if [ $REPACK_RC -ne 0 ]; then
  log_line "DB-REPACK: pg_repack failed (rc=$REPACK_RC): $(echo "$REPACK_OUTPUT" | head -3)"

  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  SUBJ="Guard Dog: DB repack failed on $SERVER_IDENTIFIER"
  BODY="pg_repack failed on the CoT database.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Database size before: ${SIZE_BEFORE}GB
Exit code: $REPACK_RC
Output (first 10 lines):
$(echo "$REPACK_OUTPUT" | head -10)

The database may still have bloat. Consider running VACUUM FULL during a maintenance window.
"
  [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
  exit 1
fi

# Measure size after
COT_AFTER_RAW=$(psql_scalar "$SIZE_SQL")
COT_AFTER=$((COT_AFTER_RAW / 1024 / 1024 / 1024))
RECLAIMED=$((SIZE_BEFORE - COT_AFTER))

log_line "DB-REPACK: completed — before: ${SIZE_BEFORE}GB, after: ${COT_AFTER}GB, reclaimed: ~${RECLAIMED}GB"

# Alert with results if significant space was reclaimed or if still large
if [ "$COT_AFTER" -gt "$REPACK_THRESHOLD_GB" ] || [ "$RECLAIMED" -gt 2 ]; then
  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  SUBJ="Guard Dog: DB repack completed on $SERVER_IDENTIFIER (${SIZE_BEFORE}GB → ${COT_AFTER}GB)"
  BODY="Online database repack completed on the CoT database.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

Before: ${SIZE_BEFORE}GB
After:  ${COT_AFTER}GB
Reclaimed: ~${RECLAIMED}GB

pg_repack ran without exclusive locks; TAK Server remained online.
"
  [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
fi

exit 0
