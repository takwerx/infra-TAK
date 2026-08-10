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
#
# v10.0.1: single-server local mode dispatches through _gd-tak-lib.sh so a
# containerized DB (takserver-db) is queried/repacked via docker exec. The
# two-server SSH path and the native-local path are unchanged.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

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
    out=$(gd_psql_scalar "$sql" cot) || return 1
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
    # v10.0.1: gd_db_shell == `bash -c` on native, `docker exec <db> bash -c`
    # in container mode (for pg_repack install / pg_config inside the image).
    gd_db_shell "$cmd"
  fi
}

# Pre-flight: check SSH connectivity for two-server mode
if [ "$TWO_SERVER_MODE" = "1" ]; then
  if [ -z "$SSH_TARGET" ] || [ ! -f "$SSH_KEY" ]; then
    # v10.1.29 (W4b): a clean skip, not a failure — exit 0 so `systemctl --failed`
    # doesn't list this unit forever on a split box without a substituted key.
    # Mirrors the same decision already made in tak-retention-guard.sh (v10.1.4 WS5).
    log_line "DB-REPACK: two_server mode but SSH target/key unavailable, skipped (clean)"
    exit 0
  fi
fi

# Check database size — skip repack if below threshold
COT_SIZE_RAW=$(psql_scalar "$SIZE_SQL")
if [ -z "$COT_SIZE_RAW" ]; then
  # v10.1.29 (W4b): the DB simply isn't up yet — seen on container-TAK boxes right
  # after a reboot, where the weekly timer fired before takserver-db was accepting
  # connections and left the unit sitting `failed` until someone noticed. Not
  # reachable != broken; skip cleanly and let the next run do the work.
  log_line "DB-REPACK: could not read database size (database not reachable yet), skipped (clean)"
  exit 0
fi
COT_SIZE=$((COT_SIZE_RAW + 0))
COT_GB=$((COT_SIZE / 1024 / 1024 / 1024))

if [ "$COT_SIZE" -lt "$REPACK_THRESHOLD_BYTES" ]; then
  log_line "DB-REPACK: cot database is ${COT_GB}GB, below ${REPACK_THRESHOLD_GB}GB threshold, skipped"
  exit 0
fi

# ── pg_repack discovery / install (v10.1.29 W4a) ─────────────────────────────
# PATH IS NOT USABLE HERE. Debian exposes the PG client binaries on PATH via
# postgresql-common, but RHEL/PGDG installs them under /usr/pgsql-<v>/bin and
# does NOT add that to PATH — and this script runs from a systemd unit, whose
# default PATH is /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin, so the
# versioned dir is never on it. Measured on nuc (Rocky 9.8, 2026-08-10):
# `command -v pg_config` empty, real binary at /usr/pgsql-15/bin/pg_config.
# Consequences if we relied on PATH (both were live bugs):
#   1. PG_VER came back EMPTY, so the whole install block below was skipped and
#      the apt/dnf branch never executed on the one family it exists for.
#   2. Even after a successful install, `command -v pg_repack` would still miss,
#      and `sudo -u postgres pg_repack` would fail anyway because sudo discards
#      an exported PATH via secure_path. The path must be ABSOLUTE.
DB_ARCH=$(remote_cmd "uname -m 2>/dev/null" || echo "unknown")
# pg_config on PATH (Debian) -> versioned dir (RHEL) -> psql as last resort.
PG_VER=$(remote_cmd "{ pg_config --version 2>/dev/null \
  || /usr/pgsql-*/bin/pg_config --version 2>/dev/null \
  || psql --version 2>/dev/null; } | grep -oP '\\d+' | head -1" || echo "")

# Absolute path to the pg_repack CLI, or empty when it is not installed.
pg_repack_path() {
  remote_cmd "command -v pg_repack 2>/dev/null \
    || ls -1 /usr/pgsql-${PG_VER:-*}/bin/pg_repack /usr/lib/postgresql/${PG_VER:-*}/bin/pg_repack 2>/dev/null \
       | sort -V | tail -1"
}

PG_REPACK_BIN=$(pg_repack_path)
if [ -z "$PG_REPACK_BIN" ]; then
  log_line "DB-REPACK: pg_repack CLI not found, attempting install (pg=${PG_VER:-unknown}, arch=${DB_ARCH:-unknown})"
  if [ -n "$PG_VER" ]; then
    # MULTIPLATFORM: this was a bare `apt-get`, a hard failure on RHEL/Rocky.
    # Both the package manager AND the package name differ by family:
    #   Debian/Ubuntu : postgresql-<ver>-repack   (apt-get)
    #   RHEL/Rocky    : pg_repack_<ver>           (dnf, from PGDG — verified
    #                   present for rhel9 on BOTH x86_64 and aarch64)
    # The family is detected WHERE THE INSTALL RUNS — the remote box in
    # two-server mode, inside takserver-db in container mode — not from the
    # console's os_type, which describes a different machine in both of those.
    remote_cmd "if command -v apt-get >/dev/null 2>&1; then \
  apt-get update -qq && apt-get install -y -qq postgresql-${PG_VER}-repack 2>&1; \
elif command -v dnf >/dev/null 2>&1; then \
  dnf install -y -q pg_repack_${PG_VER} 2>&1; \
elif command -v yum >/dev/null 2>&1; then \
  yum install -y -q pg_repack_${PG_VER} 2>&1; \
else echo 'DB-REPACK: no supported package manager (apt-get/dnf/yum)'; fi" >/dev/null
    PG_REPACK_BIN=$(pg_repack_path)
    if [ -z "$PG_REPACK_BIN" ] && [ -n "$(remote_cmd 'command -v dnf 2>/dev/null')" ]; then
      # Known PGDG signature: a tty-less dnf run can die on an untrusted per-repo
      # keyring ("Bad GPG signature" even though the signature is fine) — and a
      # systemd oneshot is exactly that. Refresh metadata once and retry before
      # declaring the platform unsupported. GPG checking stays ON.
      log_line "DB-REPACK: dnf install did not yield pg_repack, refreshing repo metadata and retrying"
      remote_cmd "dnf clean all -q >/dev/null 2>&1; dnf -y -q makecache >/dev/null 2>&1; \
dnf install -y -q pg_repack_${PG_VER} 2>&1" >/dev/null
      PG_REPACK_BIN=$(pg_repack_path)
    fi
  fi
  if [ -z "$PG_REPACK_BIN" ]; then
    # Deliberately a FAILURE, not a clean skip (unlike the not-ready cases above):
    # the operator pressed Online Compact and must be told it cannot run here —
    # pg_repack has no package on every arch/PG combination — so they reach for
    # Purge Old CoT or Compact Database instead of waiting on a silent no-op.
    log_line "DB-REPACK: pg_repack is not available on this platform (arch=${DB_ARCH:-unknown}, pg=${PG_VER:-unknown}) — Online Compact cannot run here. Use Purge Old CoT to free space, or Compact Database during a maintenance window."
    exit 1
  fi
  log_line "DB-REPACK: pg_repack installed successfully (${PG_REPACK_BIN})"
fi

# Ensure extension is created in the database
if [ "$TWO_SERVER_MODE" = "1" ]; then
  remote_cmd "sudo -u postgres psql -d cot -c 'CREATE EXTENSION IF NOT EXISTS pg_repack;'" >/dev/null 2>&1
else
  # native-local → sudo -u postgres psql; container → docker exec -u postgres
  gd_psql_raw "CREATE EXTENSION IF NOT EXISTS pg_repack;" cot >/dev/null 2>&1
fi

# Record size before repack
SIZE_BEFORE=$COT_GB

# Run pg_repack on the cot database
log_line "DB-REPACK: starting online repack of cot database (${SIZE_BEFORE}GB)"
if [ "$TWO_SERVER_MODE" = "1" ]; then
  # Absolute path (see the PATH note above) — `sudo -u postgres` drops secure_path.
  REPACK_OUTPUT=$(remote_cmd "sudo -u postgres ${PG_REPACK_BIN} -d cot --no-superuser-check --wait-timeout=30 2>&1")
else
  # native-local → sudo -u postgres <abs path>; container → docker exec -u postgres
  REPACK_OUTPUT=$(gd_db_pg "$PG_REPACK_BIN" -d cot --no-superuser-check --wait-timeout=30)
fi
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
