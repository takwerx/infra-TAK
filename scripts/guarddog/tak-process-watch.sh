#!/bin/bash
# v10.0.1: container-aware via _gd-tak-lib.sh. On a container box the gate, the
# JVM pgrep checks, and the restart all target the takserver container; native
# (deb/rpm) behaviour is byte-identical.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true
type gd_stack_restore_standdown >/dev/null 2>&1 && gd_stack_restore_standdown tak-process-watch && exit 0

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/process_alert_sent"
FAIL_COUNT_FILE="/var/lib/takguard/process_fail_count"
LAST_RESTART_FILE="/var/lib/takguard/last_restart_time"
RESTART_LOCK="/var/lib/takguard/restart.lock"
MIN_UPTIME_SECS=900

# Don't run during first 15 minutes after boot (avoid restart loop on slow startup)
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime)
if [ "$UPTIME_SECS" -lt "$MIN_UPTIME_SECS" ]; then
  exit 0
fi

# TAK takes ~5 min to fully start; checking for missing processes during startup is invalid.
STARTUP_GRACE=600
_tak_started=$(gd_tak_started_monotonic)
if [ -n "$_tak_started" ]; then
  _tak_age=$(( UPTIME_SECS - _tak_started ))
  [ "$_tak_age" -ge 0 ] && [ "$_tak_age" -lt "$STARTUP_GRACE" ] && exit 0
fi

# Daily restart cap — shared across all Guard Dog TAK scripts to prevent infinite loops.
# 0 = a restart may run (count in $_daily), 1 = cap reached.
DAILY_COUNT_FILE="/var/lib/takguard/tak_restart_count_24h"
DAILY_WINDOW_FILE="/var/lib/takguard/tak_restart_window"
MAX_DAILY_RESTARTS=3
_daily_restart_ok() {
  local _now _window_start
  _now=$(date +%s)
  _window_start=$(cat "$DAILY_WINDOW_FILE" 2>/dev/null || echo 0)
  if [ $((_now - _window_start)) -ge 86400 ]; then
    echo "$_now" > "$DAILY_WINDOW_FILE"
    echo 0 > "$DAILY_COUNT_FILE"
  fi
  _daily=$(cat "$DAILY_COUNT_FILE" 2>/dev/null || echo 0)
  [ "$_daily" -lt "$MAX_DAILY_RESTARTS" ]
}

if ! gd_tak_running; then
  rm -f "$FAIL_COUNT_FILE"
  # ops #413 (GH #373): a FAILED unit is not an operator stop. Field (v10.3.3, Ubuntu
  # 22.04): the box rebooted after an OS patch, the boot start ran under heavy disk wait,
  # hit takserver.service's 300s TimeoutStartSec and was marked failed(timeout). Every
  # Guard Dog TAK watcher skipped a TAK that isn't active, so nothing ever started it
  # again and clients stayed off 8089 until someone noticed. `systemctl stop` leaves the
  # unit inactive, never failed, so an operator's stop is still left alone. Container
  # TAK runs with --restart=always and has no such state.
  if gd_is_container || ! systemctl is-failed --quiet takserver 2>/dev/null; then
    exit 0
  fi
  type gd_dbserver_standdown >/dev/null 2>&1 && gd_dbserver_standdown tak-process-watch && exit 0
  [ -f "$RESTART_LOCK" ] && exit 0
  if [ -f "$LAST_RESTART_FILE" ] && [ $(( $(date +%s) - $(cat "$LAST_RESTART_FILE") )) -lt 900 ]; then
    exit 0
  fi
  mkdir -p /var/log/takguard
  if ! _daily_restart_ok; then
    echo "$(date): TAK Server service failed to start — daily restart cap ($MAX_DAILY_RESTARTS) reached, skipping" >> /var/log/takguard/restarts.log
    exit 0
  fi
  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  _why=$(systemctl show takserver -p Result --value 2>/dev/null)
  echo "$TS | restart | TAK Server service failed to start (result=${_why:-unknown}) — starting it again" >> /var/log/takguard/restarts.log
  logger -t takguard "takserver.service failed (result=${_why:-unknown}); starting it again" 2>/dev/null
  SUBJ="TAK Server Start Failed on $SERVER_IDENTIFIER"
  BODY="TAK Server's service failed to start and was not running.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
systemd result: ${_why:-unknown}

Action taken: Guard Dog is starting TAK Server again (clean restart).
This often follows a reboot on a busy box, when the first start runs out of time.

Check: journalctl -b -u takserver --no-pager | tail -50
"
  echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    TMPF="$(mktemp /tmp/gd-sms.XXXXXX)"
    printf '%s' "$BODY" > "$TMPF"
    /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
    rm -f "$TMPF"
  fi
  touch "$RESTART_LOCK"
  date +%s > "$LAST_RESTART_FILE"
  echo $((_daily + 1)) > "$DAILY_COUNT_FILE"
  # Clean restart: stop, kill any JVM the timed-out start left behind, clear Ignite, start.
  gd_tak_restart
  sleep 30
  rm -f "$RESTART_LOCK"
  exit 0
fi

if [ -f "$LAST_RESTART_FILE" ]; then
  LAST_RESTART=$(cat "$LAST_RESTART_FILE")
  CURRENT_TIME=$(date +%s)
  TIME_SINCE_RESTART=$((CURRENT_TIME - LAST_RESTART))
  if [ $TIME_SINCE_RESTART -lt 900 ]; then
    exit 0
  fi
fi

MISSING_PROCESSES=()

if ! gd_tak_pgrep "spring.profiles.active=messaging"; then
  MISSING_PROCESSES+=("messaging")
fi

if ! gd_tak_pgrep "spring.profiles.active=api"; then
  MISSING_PROCESSES+=("api")
fi

if ! gd_tak_pgrep "spring.profiles.active=config"; then
  MISSING_PROCESSES+=("config")
fi

if ! gd_tak_pgrep "takserver-pm.jar"; then
  MISSING_PROCESSES+=("plugins")
fi

if ! gd_tak_pgrep "takserver-retention.jar"; then
  MISSING_PROCESSES+=("retention")
fi

if [ ${#MISSING_PROCESSES[@]} -gt 0 ]; then
  if [ -f "$FAIL_COUNT_FILE" ]; then
    FAIL_COUNT=$(cat "$FAIL_COUNT_FILE")
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    FAIL_COUNT=1
  fi
  echo "$FAIL_COUNT" > "$FAIL_COUNT_FILE"
  
  if [ "$FAIL_COUNT" -ge 3 ]; then
    if [ -f "$RESTART_LOCK" ]; then
      exit 0
    fi
    
    if [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find $ALERT_SENT_FILE -mmin +60 2>/dev/null)" ]; then
      touch "$ALERT_SENT_FILE"
      
      TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      MISSING_LIST=$(IFS=,; echo "${MISSING_PROCESSES[*]}")
      
      SUBJ="TAK Server Process Alert on $SERVER_IDENTIFIER"
      BODY="TAK Server processes are missing - RESTARTING.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

Service Status: Running (but incomplete)
Missing Processes: $MISSING_LIST
Consecutive failures: $FAIL_COUNT

Expected 5 processes:
- messaging (client connections)
- api (web interface)
- config (configuration)
- plugins (plugin manager)
- retention (data cleanup)

Action taken: Restarting TAK Server

Check logs after restart:
  tail -100 /opt/tak/logs/takserver-messaging.log
  tail -100 /opt/tak/logs/takserver-api.log
"

      echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
      if [ -f /opt/tak-guarddog/sms_send.sh ]; then
        TMPF="$(mktemp /tmp/gd-sms.XXXXXX)"
        printf '%s' "$BODY" > "$TMPF"
        /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
        rm -f "$TMPF"
      fi
      mkdir -p /var/log/takguard

      if ! _daily_restart_ok; then
        echo "$(date): TAK Server missing processes: $MISSING_LIST — daily restart cap ($MAX_DAILY_RESTARTS) reached, skipping" >> /var/log/takguard/restarts.log
        exit 0
      fi

      echo "$(date): TAK Server missing processes: $MISSING_LIST ($FAIL_COUNT failures) - restarting" >> /var/log/takguard/restarts.log
      
      touch "$RESTART_LOCK"
      date +%s > "$LAST_RESTART_FILE"
      echo $((_daily + 1)) > "$DAILY_COUNT_FILE"

      # Clean restart: native → stop, kill orphan Java (tak user), clear Ignite,
      # start; container → docker restart (handled by gd_tak_restart).
      gd_tak_restart

      sleep 30
      rm -f "$RESTART_LOCK"
      rm -f "$FAIL_COUNT_FILE"
    fi
  fi
else
  rm -f "$FAIL_COUNT_FILE"
  rm -f "$ALERT_SENT_FILE"
fi
