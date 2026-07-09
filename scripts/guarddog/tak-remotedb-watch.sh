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
#
# v10.1.1 (F9 — NCTAK-2.0 field report, 4500+ false "not healthy" emails while
# the DB was verifiably fine):
#   - TCP reachability is the AUTHORITATIVE health signal. It ALONE gates the
#     "database not healthy / manual intervention" alert AND the remote restart.
#   - The SSH probe (pg_isready + sudo -u postgres psql) is a MANAGEMENT-CHANNEL
#     check only. When it fails but TCP is up, that is a monitoring/access issue,
#     NOT a DB outage: emit a distinct low-severity "management channel degraded"
#     note (naming the exact failing leg) and NEVER restart the database.
#   - Storm cap: identical failure state backs off hourly → daily after 24h;
#     resets the moment the state changes.
#   - sudo -n everywhere so a password prompt fails fast and is distinguishable.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
DB_HOST="DB_HOST_PLACEHOLDER"
DB_PORT="DB_PORT_PLACEHOLDER"
SSH_KEY="SSH_KEY_PLACEHOLDER"
SSH_USER="SSH_USER_PLACEHOLDER"
EXTERNAL_DB="EXTERNAL_DB_PLACEHOLDER"

ALERT_SENT_FILE="/var/lib/takguard/remotedb_alert_sent"            # db_down alert dedupe
DEGRADED_SENT_FILE="/var/lib/takguard/remotedb_mgmt_degraded_sent" # mgmt-degraded dedupe
LAST_RESTART_FILE="/var/lib/takguard/last_restart_time"
FAIL_COUNT_FILE="/var/lib/takguard/remotedb_fail_count"            # consecutive TCP-down count
STATE_FILE="/var/lib/takguard/remotedb_state"                     # last state (storm-cap reset)
STATE_SINCE_FILE="/var/lib/takguard/remotedb_state_since"         # epoch current state began
mkdir -p /var/lib/takguard /var/log/takguard

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/opt/tak-guarddog/known_hosts -o ConnectTimeout=10 -o BatchMode=yes)

# Skip during boot grace period
if [ -f "$LAST_RESTART_FILE" ]; then
  LAST_RESTART=$(cat "$LAST_RESTART_FILE")
  CURRENT_TIME=$(date +%s)
  if [ $((CURRENT_TIME - LAST_RESTART)) -lt 900 ]; then
    exit 0
  fi
fi

# ── Check 1: TCP connectivity — the authoritative "is the DB reachable" signal ──
TCP_OK=true
if ! timeout 6 bash -c "</dev/tcp/$DB_HOST/$DB_PORT" >/dev/null 2>&1; then
  TCP_OK=false
fi

# ── Check 2: SSH management probe (two-server only) — diagnostic, never gating a restart ──
# Distinguish the failing leg: ssh reachability vs pg_isready vs passwordless sudo.
SSH_MGMT_OK=true
SSH_DETAIL=""
if [ "$EXTERNAL_DB" != "true" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  PROBE=$(ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "${SSH_USER}@${DB_HOST}" \
    'PR=127; command -v pg_isready >/dev/null 2>&1 && { pg_isready -q; PR=$?; }; \
     sudo -n -u postgres psql -lqt >/dev/null 2>&1; SU=$?; echo "SSHOK PR=$PR SU=$SU"' 2>&1)
  if ! printf '%s' "$PROBE" | grep -q "SSHOK"; then
    SSH_MGMT_OK=false
    SSH_DETAIL="ssh connect/auth failed ($(printf '%s' "$PROBE" | head -1 | cut -c1-120))"
  else
    PR=$(printf '%s' "$PROBE" | sed -n 's/.*PR=\([0-9]*\).*/\1/p')
    SU=$(printf '%s' "$PROBE" | sed -n 's/.*SU=\([0-9]*\).*/\1/p')
    [ "$PR" = "127" ] && { SSH_MGMT_OK=false; SSH_DETAIL="pg_isready not found in PATH on Server One"; }
    [ "$PR" != "0" ] && [ "$PR" != "127" ] && { SSH_MGMT_OK=false; SSH_DETAIL="pg_isready rc=$PR"; }
    [ "$SU" != "0" ] && { SSH_MGMT_OK=false; SSH_DETAIL="${SSH_DETAIL:+$SSH_DETAIL; }sudo -n -u postgres psql rc=$SU (needs NOPASSWD sudo for the GD user)"; }
  fi
fi

# ── Determine state ──
if $TCP_OK && $SSH_MGMT_OK; then
  STATE="healthy"
elif ! $TCP_OK; then
  STATE="db_down"          # real outage: DB port unreachable
else
  STATE="mgmt_degraded"    # DB reachable, SSH management probe failing
fi

# Healthy → clear every state file and exit
if [ "$STATE" = "healthy" ]; then
  rm -f "$ALERT_SENT_FILE" "$DEGRADED_SENT_FILE" "$FAIL_COUNT_FILE" "$STATE_FILE" "$STATE_SINCE_FILE"
  exit 0
fi

# ── Storm cap: track state + first-seen; hourly under 24h, daily after ──
NOW=$(date +%s)
PREV_STATE=""; [ -f "$STATE_FILE" ] && PREV_STATE=$(cat "$STATE_FILE")
if [ "$STATE" != "$PREV_STATE" ]; then
  echo "$STATE" > "$STATE_FILE"
  echo "$NOW"   > "$STATE_SINCE_FILE"
  rm -f "$ALERT_SENT_FILE" "$DEGRADED_SENT_FILE" "$FAIL_COUNT_FILE"   # new state → alert promptly
fi
STATE_SINCE=$NOW; [ -f "$STATE_SINCE_FILE" ] && STATE_SINCE=$(cat "$STATE_SINCE_FILE")
DEDUPE_MIN=60
[ $((NOW - STATE_SINCE)) -ge 86400 ] && DEDUPE_MIN=1440
TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

send_alert() {  # $1=subject  $2=body  $3=dedupe_file
  if [ -f "$3" ] && [ -z "$(find "$3" -mmin +"$DEDUPE_MIN" 2>/dev/null)" ]; then return 0; fi
  touch "$3"
  [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$2" | /opt/tak-guarddog/send-alert-email.sh "$1" "ALERT_EMAIL_PLACEHOLDER"
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    TMPF="/tmp/gd-sms-$$.txt"; printf '%s' "$2" > "$TMPF"
    /opt/tak-guarddog/sms_send.sh "$1" "$TMPF" 2>/dev/null || true; rm -f "$TMPF"
  fi
}

# ── mgmt_degraded: DB is UP, only the SSH management probe fails ──────────────
# No restart. No "manual intervention". A distinct, low-severity, self-fixable note.
if [ "$STATE" = "mgmt_degraded" ]; then
  SUBJ="Guard Dog: remote DB management channel degraded on $SERVER_IDENTIFIER"
  BODY="Guard Dog's SSH management probe to Server One is failing, but the database itself is HEALTHY.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Database: REACHABLE — TCP $DB_HOST:$DB_PORT is open and TAK Server is using it normally.
Failing leg: $SSH_DETAIL

This is a MONITORING/ACCESS issue on Guard Dog's SSH health check — NOT a database
outage. No restart was attempted and none is needed.

Reproduce from this server:
  ssh ${SSH_USER}@${DB_HOST} 'pg_isready; sudo -n -u postgres psql -lqt'

Fix on Server One ($DB_HOST): ensure the Guard Dog SSH user ($SSH_USER) has
pg_isready in PATH and passwordless sudo for the postgres user, e.g.:
  $SSH_USER ALL=(postgres) NOPASSWD: /usr/bin/psql, /usr/bin/pg_isready

(This alert backs off to daily after 24h of the same state.)
"
  send_alert "$SUBJ" "$BODY" "$DEGRADED_SENT_FILE"
  echo "$(date): mgmt channel degraded (DB reachable) — $SSH_DETAIL — no restart" >> /var/log/takguard/restarts.log
  exit 0
fi

# ── db_down: TCP is actually unreachable — the real outage path ───────────────
FAIL_COUNT=0; [ -f "$FAIL_COUNT_FILE" ] && FAIL_COUNT=$(cat "$FAIL_COUNT_FILE")
FAIL_COUNT=$((FAIL_COUNT + 1)); echo "$FAIL_COUNT" > "$FAIL_COUNT_FILE"
[ "$FAIL_COUNT" -lt 3 ] && exit 0

# Restart authority is gated on TCP failure ONLY (we are here) — never on an SSH
# probe failure. Two-server only; a managed/external DB is never restarted.
RESTARTED=false
if [ "$EXTERNAL_DB" != "true" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "${SSH_USER}@${DB_HOST}" \
    'sudo -n pg_ctlcluster 15 main restart 2>/dev/null || sudo -n systemctl restart postgresql 2>/dev/null' 2>/dev/null
  sleep 5
  if timeout 6 bash -c "</dev/tcp/$DB_HOST/$DB_PORT" >/dev/null 2>&1; then
    RESTARTED=true
  fi
fi

if [ "$EXTERNAL_DB" = "true" ]; then
  RESTART_MSG="This is a managed/external database (RDS, Azure, etc.). Guard Dog cannot restart it automatically. Contact your cloud provider or database administrator to investigate."
elif $RESTARTED; then
  RESTART_MSG="Guard Dog attempted a remote restart and the database is now reachable again."
else
  RESTART_MSG="Guard Dog attempted a remote restart but the database is still unreachable. Manual intervention required."
fi

if [ "$EXTERNAL_DB" = "true" ]; then
  SUBJ="TAK Server Managed Database Alert on $SERVER_IDENTIFIER"
  BODY="The managed database endpoint ($DB_HOST:$DB_PORT) is not reachable from this TAK Server.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Consecutive failures: $FAIL_COUNT
Details: TCP port $DB_PORT on $DB_HOST is not reachable.

$RESTART_MSG

Check from this server:
  timeout 5 bash -c '</dev/tcp/$DB_HOST/$DB_PORT' && echo OPEN || echo CLOSED
  pg_isready -h $DB_HOST -p $DB_PORT

Actions:
  - Check your cloud provider console for database status and maintenance windows
  - Verify security group / firewall rules allow traffic from this VM to $DB_HOST:$DB_PORT
  - Check for scheduled maintenance or failover events

(This alert backs off to daily after 24h of the same state.)
"
else
  SUBJ="TAK Server Remote Database Alert on $SERVER_IDENTIFIER"
  BODY="The remote database server ($DB_HOST:$DB_PORT) is UNREACHABLE (TCP port closed).

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Consecutive failures: $FAIL_COUNT
Details: TCP port $DB_PORT on $DB_HOST is not reachable.

$RESTART_MSG

Check from this server:
  timeout 5 bash -c '</dev/tcp/$DB_HOST/$DB_PORT' && echo OPEN || echo CLOSED

Check on Server One ($DB_HOST):
  pg_isready
  sudo pg_ctlcluster 15 main status
  sudo -u postgres psql -lqt

(This alert backs off to daily after 24h of the same state.)
"
fi

send_alert "$SUBJ" "$BODY" "$ALERT_SENT_FILE"
if [ "$EXTERNAL_DB" = "true" ]; then
  echo "$(date): Managed DB ($DB_HOST) unreachable (TCP closed) — no auto-restart (external provider)" >> /var/log/takguard/restarts.log
elif $RESTARTED; then
  echo "$(date): Remote DB ($DB_HOST) TCP was down, restarted successfully via SSH" >> /var/log/takguard/restarts.log
else
  echo "$(date): Remote DB ($DB_HOST) TCP down, restart FAILED" >> /var/log/takguard/restarts.log
fi
