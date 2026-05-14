#!/bin/bash

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
FAIL_FILE="$STATE_DIR/8089.failcount"
COOLDOWN_FILE="$STATE_DIR/last_restart"
REASON_FILE="$STATE_DIR/restart_reason"
LAST_RESTART_FILE="$STATE_DIR/last_restart_time"
RESTART_LOCK="$STATE_DIR/restart.lock"

PORT=8089
MAX_FAILS=5
COOLDOWN_SECS=900
MIN_UPTIME_SECS=900

mkdir -p "$STATE_DIR"

# Don't run during first 15 minutes after boot
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime)
if [ "$UPTIME_SECS" -lt "$MIN_UPTIME_SECS" ]; then
  exit 0
fi

# TAK takes ~5 min to fully start; restarting during startup orphans Java processes.
# Check actual service activation time (covers operator restart, systemd restart, Guard Dog restart).
STARTUP_GRACE=600
_tak_mono=$(systemctl show takserver --property=ActiveEnterTimestampMonotonic --value 2>/dev/null || echo "")
if [ -n "$_tak_mono" ] && [ "$_tak_mono" != "0" ]; then
  _tak_age=$(( UPTIME_SECS - _tak_mono / 1000000 ))
  [ "$_tak_age" -ge 0 ] && [ "$_tak_age" -lt "$STARTUP_GRACE" ] && exit 0
fi

# Check if we're in grace period (15 minutes after any restart)
if [ -f "$LAST_RESTART_FILE" ]; then
  LAST_RESTART=$(cat "$LAST_RESTART_FILE")
  CURRENT_TIME=$(date +%s)
  TIME_SINCE_RESTART=$((CURRENT_TIME - LAST_RESTART))
  if [ $TIME_SINCE_RESTART -lt 900 ]; then
    exit 0
  fi
fi

# Only run if takserver is active
systemctl is-active --quiet takserver || exit 0

# Check if another monitor is already restarting
if [ -f "$RESTART_LOCK" ]; then
  exit 0
fi

# ── Health check ──
# Signal: is port 8089 bound and listening?
# Port 8089 uses mutual TLS (auth="x509") — a raw TCP connect via nc -z
# reaches Netty, which immediately closes the connection on a non-TLS probe
# and logs SSL errors on every check. The ss LISTEN check is sufficient:
# if Netty is bound, the messaging process is accepting connections.
LISTEN_OK=false

LQ_LINE=$(ss -ltn "sport = :$PORT" | awk 'NR==2')
if echo "$LQ_LINE" | grep -q LISTEN; then
  LISTEN_OK=true
fi

# Healthy: port is listening
if $LISTEN_OK; then
  echo 0 > "$FAIL_FILE"
  exit 0
fi

# Increment fail counter
FAILS=0
[ -f "$FAIL_FILE" ] && FAILS=$(cat "$FAIL_FILE")
FAILS=$((FAILS+1))
echo "$FAILS" > "$FAIL_FILE"

# Need 3 consecutive failures
if [ "$FAILS" -lt "$MAX_FAILS" ]; then
  exit 0
fi

# Check cooldown period (15 minutes between restarts)
NOW=$(date +%s)
LAST=0
[ -f "$COOLDOWN_FILE" ] && LAST=$(cat "$COOLDOWN_FILE")
if [ $((NOW - LAST)) -lt "$COOLDOWN_SECS" ]; then
  exit 0
fi

# Daily restart cap — shared across all Guard Dog TAK scripts to prevent infinite loops
DAILY_COUNT_FILE="$STATE_DIR/tak_restart_count_24h"
DAILY_WINDOW_FILE="$STATE_DIR/tak_restart_window"
MAX_DAILY_RESTARTS=3
_window_start=$(cat "$DAILY_WINDOW_FILE" 2>/dev/null || echo 0)
if [ $((NOW - _window_start)) -ge 86400 ]; then
  echo "$NOW" > "$DAILY_WINDOW_FILE"
  echo 0 > "$DAILY_COUNT_FILE"
fi
_daily=$(cat "$DAILY_COUNT_FILE" 2>/dev/null || echo 0)
if [ "$_daily" -ge "$MAX_DAILY_RESTARTS" ]; then
  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  mkdir -p /var/log/takguard
  echo "$TS | SKIP | 8089 unhealthy but daily restart cap ($MAX_DAILY_RESTARTS) reached — manual intervention required" >> /var/log/takguard/restarts.log
  exit 0
fi

# Log and alert
logger -t takguard "8089 unhealthy for $FAILS checks; restarting takserver"

echo "$NOW" > "$COOLDOWN_FILE"
echo 0 > "$FAIL_FILE"
echo "guard dog_8089" > "$REASON_FILE"

# Detailed logging
LOGDIR="/var/log/takguard"
LOGFILE="$LOGDIR/restarts.log"
mkdir -p "$LOGDIR"

TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
LOAD="$(cut -d' ' -f1-3 /proc/loadavg)"
MEMFREE="$(free -h | awk '/Mem:/ {print $4}')"
MSGPID="$(ps -ef | grep takserver.war | grep messaging | grep -v grep | awk '{print $2}' | head -n1)"

DETAIL="listen=$LISTEN_OK"
echo "$TS | restart | 8089 unhealthy | $DETAIL | load=$LOAD | mem_free=$MEMFREE | msg_pid=${MSGPID:-na}" >> "$LOGFILE"

# Send alerts
SUBJ="TAK Guard Dog Restart on $SERVER_IDENTIFIER"
BODY="TAK Server was automatically restarted by the guard dog.

Server: $SERVER_IDENTIFIER
Reason: TCP 8089 unhealthy for $FAILS consecutive checks.
Time (UTC): $TS

System State:
- Load: $LOAD
- Free Memory: $MEMFREE
- Messaging PID before restart: ${MSGPID:-na}

This usually indicates:
- TAK Server messaging thread stuck or crashed
- Kernel accepting connections but TAK not processing them
- Network issues

Check /var/log/takguard/restarts.log for history.
"

[ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
[ -n "ALERT_SMS_PLACEHOLDER" ] && echo -e "$BODY" | mail -s "$SUBJ" "ALERT_SMS_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi

# Create restart lock
touch "$RESTART_LOCK"

# Record restart time for grace period
date +%s > "$LAST_RESTART_FILE"

# Increment daily restart counter
echo $((_daily + 1)) > "$DAILY_COUNT_FILE"

# Clean restart: stop → kill orphan Java processes → clear Ignite cache → start
systemctl stop takserver
sleep 2
pkill -9 -u tak 2>/dev/null || true
sleep 1
rm -rf /opt/tak/work
systemctl start takserver

# Wait 30 seconds then remove lock
sleep 30
rm -f "$RESTART_LOCK"
