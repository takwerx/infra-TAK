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
#
# v10.2.10 (GH #99 — a split install restarted a HEALTHY production PostgreSQL five
# times, and logged "is down, restart FAILED" 1,540 times over two months, after the
# operator restricted the shared SSH key to rsync for their own backups):
#   - TCP failing from HERE is not proof the database is down. It is just as often this
#     node's own network (the field box had lost outbound connectivity on one of those
#     days). The restart now needs Server One ITSELF to say PostgreSQL is not responding
#     (pg_isready rc 2 over SSH). Cannot ask, or it says up / starting -> no restart.
#   - Daily cap: at most 3 database restarts per 24 h, like the 8089 check. Before this a
#     real outage that the restart could not fix was restarted on EVERY run, every 2 min.
#   - The probe's and the restart's real output are logged. "ssh connect/auth failed"
#     was also what a key restricted to a forced command produced — it connects fine,
#     it just runs something else — so the log said nothing about why.

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
DB_RESTART_COUNT_FILE="/var/lib/takguard/remotedb_restart_count_24h"
DB_RESTART_WINDOW_FILE="/var/lib/takguard/remotedb_restart_window"
MAX_DAILY_DB_RESTARTS=3
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
PR=""   # pg_isready rc ON Server One: 0 up, 1 rejecting (starting), 2 no response, 3 no attempt
if [ "$EXTERNAL_DB" != "true" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
  PROBE=$(ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "${SSH_USER}@${DB_HOST}" \
    'PR=127; command -v pg_isready >/dev/null 2>&1 && { pg_isready -q; PR=$?; }; \
     sudo -n -u postgres psql -lqt >/dev/null 2>&1; SU=$?; echo "SSHOK PR=$PR SU=$SU"' 2>&1)
  SSH_RC=$?
  if ! printf '%s' "$PROBE" | grep -q "SSHOK"; then
    SSH_MGMT_OK=false
    PROBE_OUT=$(printf '%s' "$PROBE" | tr '\n' ' ' | cut -c1-200)
    if [ "$SSH_RC" = "255" ]; then
      SSH_DETAIL="ssh connect/auth failed: ${PROBE_OUT:-no output}"
    else
      # ssh itself worked (255 is ssh's own error) but our command did not run — the
      # signature of a key restricted to a forced command on Server One.
      SSH_DETAIL="ssh connected but the probe did not run (rc $SSH_RC; is this key restricted to a forced command on Server One?): ${PROBE_OUT:-no output}"
    fi
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
  echo -e "$2" | /opt/tak-guarddog/send-alert-email.sh "$1" "ALERT_EMAIL_PLACEHOLDER"
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

# Restart authority: TCP is down from here (we are here) AND Server One itself says
# PostgreSQL is not responding. Anything less is "cannot determine", and an unknown
# state is never restarted. Two-server only; a managed/external DB is never restarted.
# OUTCOME: external | restarted | restart_failed | capped | unconfirmed
OUTCOME="unconfirmed"
WHY=""
RESTART_OUT=""
if [ "$EXTERNAL_DB" = "true" ]; then
  OUTCOME="external"
elif [ -z "$SSH_KEY" ] || [ ! -f "$SSH_KEY" ]; then
  WHY="Guard Dog has no SSH key for Server One, so it cannot check PostgreSQL there."
elif ! $SSH_MGMT_OK && [ -z "$PR" ]; then
  WHY="Guard Dog could not ask Server One: $SSH_DETAIL"
elif [ "$PR" = "0" ]; then
  WHY="Server One reports PostgreSQL is UP and accepting connections locally. The problem is the network path from this node to $DB_HOST:$DB_PORT (firewall, routing, or this node's own connectivity), not the database."
elif [ "$PR" = "1" ]; then
  WHY="Server One reports PostgreSQL is rejecting connections (starting up or in recovery). Guard Dog does not restart a database that is coming up."
elif [ "$PR" != "2" ]; then
  WHY="pg_isready on Server One could not tell (rc $PR)."
else
  # Confirmed down. Daily cap — 3 per 24 h, same as the TAK Server restarts.
  _window_start=$(cat "$DB_RESTART_WINDOW_FILE" 2>/dev/null || echo 0)
  if [ $((NOW - _window_start)) -ge 86400 ]; then
    echo "$NOW" > "$DB_RESTART_WINDOW_FILE"
    echo 0 > "$DB_RESTART_COUNT_FILE"
  fi
  _daily=$(cat "$DB_RESTART_COUNT_FILE" 2>/dev/null || echo 0)
  if [ "$_daily" -ge "$MAX_DAILY_DB_RESTARTS" ]; then
    OUTCOME="capped"
  else
    echo $((_daily + 1)) > "$DB_RESTART_COUNT_FILE"
    echo 0 > "$FAIL_COUNT_FILE"   # the next attempt needs 3 fresh consecutive failures
    RESTART_OUT=$(ssh -i "$SSH_KEY" "${SSH_OPTS[@]}" "${SSH_USER}@${DB_HOST}" \
      'sudo -n pg_ctlcluster 15 main restart 2>&1 || sudo -n systemctl restart postgresql 2>&1' 2>&1 \
      | tr '\n' ' ' | cut -c1-200)
    sleep 5
    if timeout 6 bash -c "</dev/tcp/$DB_HOST/$DB_PORT" >/dev/null 2>&1; then
      OUTCOME="restarted"
    else
      OUTCOME="restart_failed"
    fi
  fi
fi

case "$OUTCOME" in
  external)
    RESTART_MSG="This is a managed/external database (RDS, Azure, etc.). Guard Dog cannot restart it automatically. Contact your cloud provider or database administrator to investigate." ;;
  restarted)
    RESTART_MSG="Server One confirmed PostgreSQL was not responding. Guard Dog restarted it and the database is now reachable again." ;;
  restart_failed)
    RESTART_MSG="Server One confirmed PostgreSQL was not responding. Guard Dog attempted a remote restart but the database is still unreachable. Manual intervention required.
Restart output: ${RESTART_OUT:-none}" ;;
  capped)
    RESTART_MSG="Server One confirms PostgreSQL is not responding, but Guard Dog has already restarted it $MAX_DAILY_DB_RESTARTS times in the last 24 hours and will not try again. Manual intervention required." ;;
  *)
    RESTART_MSG="Guard Dog did NOT restart the database: it could not confirm from Server One that PostgreSQL is down.
$WHY" ;;
esac

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
case "$OUTCOME" in
  external)
    echo "$(date): Managed DB ($DB_HOST) unreachable (TCP closed) — no auto-restart (external provider)" ;;
  restarted)
    echo "$(date): Remote DB ($DB_HOST) TCP down, PostgreSQL confirmed down on Server One, restarted successfully via SSH" ;;
  restart_failed)
    echo "$(date): Remote DB ($DB_HOST) TCP down, PostgreSQL confirmed down on Server One, restart FAILED — ${RESTART_OUT:-no output}" ;;
  capped)
    echo "$(date): Remote DB ($DB_HOST) confirmed down but daily restart cap ($MAX_DAILY_DB_RESTARTS) reached — manual intervention required" ;;
  *)
    echo "$(date): Remote DB ($DB_HOST) TCP down — NOT restarted, state not confirmed on Server One: $WHY" ;;
esac >> /var/log/takguard/restarts.log
