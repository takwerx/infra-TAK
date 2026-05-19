#!/bin/bash

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
LOGFILE="/opt/tak/logs/takserver-messaging.log"
STATEFILE="/var/run/tak_oom.state"
SERVICE="takserver"
MIN_UPTIME_SECS=900

# Don't run during first 15 minutes after boot (avoid acting on stale log or boot race)
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime)
if [ "$UPTIME_SECS" -lt "$MIN_UPTIME_SECS" ]; then
  exit 0
fi

# Don't act if TAK was started recently (OOM log entry may be stale from previous run)
STARTUP_GRACE=600
_tak_mono=$(systemctl show takserver --property=ActiveEnterTimestampMonotonic --value 2>/dev/null || echo "")
if [ -n "$_tak_mono" ] && [ "$_tak_mono" != "0" ]; then
  _tak_age=$(( UPTIME_SECS - _tak_mono / 1000000 ))
  [ "$_tak_age" -ge 0 ] && [ "$_tak_age" -lt "$STARTUP_GRACE" ] && exit 0
fi

# Check for OutOfMemoryError in logs
if grep -q "OutOfMemoryError: Java heap space" "$LOGFILE" 2>/dev/null; then
  # Only restart once until log clears
  if [ ! -f "$STATEFILE" ]; then
    touch "$STATEFILE"
    
    TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    LOAD="$(cut -d' ' -f1-3 /proc/loadavg)"
    MEMFREE="$(free -h | awk '/Mem:/ {print $4}')"
    
    mkdir -p /var/log/takguard
    echo "$TS | restart | OOM detected | load=$LOAD | mem_free=$MEMFREE" >> /var/log/takguard/restarts.log
    
    SUBJ="TAK OOM Restart on $SERVER_IDENTIFIER"
    BODY="TAK Server experienced Out of Memory error and was restarted.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Load: $LOAD
Free Memory: $MEMFREE

This usually indicates:
- Java heap exhaustion (not system RAM)
- Memory leak in application
- Too many concurrent connections
- Client reconnect loops causing object accumulation

Check /opt/tak/logs/takserver-messaging.log for details.
Consider reviewing Data Retention settings in TAK Server UI.
"

    [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    [ -n "ALERT_SMS_PLACEHOLDER" ] && echo -e "$BODY" | mail -s "$SUBJ" "ALERT_SMS_PLACEHOLDER"
    if [ -f /opt/tak-guarddog/sms_send.sh ]; then
      TMPF="/tmp/gd-sms-$$.txt"
      printf '%s' "$BODY" > "$TMPF"
      /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
      rm -f "$TMPF"
    fi

    # Daily restart cap — shared across all Guard Dog TAK scripts
    DAILY_COUNT_FILE="/var/lib/takguard/tak_restart_count_24h"
    DAILY_WINDOW_FILE="/var/lib/takguard/tak_restart_window"
    MAX_DAILY_RESTARTS=3
    _now=$(date +%s)
    _window_start=$(cat "$DAILY_WINDOW_FILE" 2>/dev/null || echo 0)
    if [ $((_now - _window_start)) -ge 86400 ]; then
      echo "$_now" > "$DAILY_WINDOW_FILE"
      echo 0 > "$DAILY_COUNT_FILE"
    fi
    _daily=$(cat "$DAILY_COUNT_FILE" 2>/dev/null || echo 0)
    if [ "$_daily" -ge "$MAX_DAILY_RESTARTS" ]; then
      echo "$TS | SKIP | OOM detected but daily restart cap ($MAX_DAILY_RESTARTS) reached — manual intervention required" >> /var/log/takguard/restarts.log
      exit 0
    fi
    echo $((_daily + 1)) > "$DAILY_COUNT_FILE"

    # Clean restart: stop → kill orphan Java processes → clear Ignite cache → rotate log → start
    systemctl stop $SERVICE
    sleep 2
    pkill -9 -u tak 2>/dev/null || true
    sleep 1
    rm -rf /opt/tak/work
    # Rotate the messaging log before restart so post-restart OOM check comes up clean.
    # TAK writes to a new file on startup; keep last 3 pre-OOM logs for forensics.
    mv /opt/tak/logs/takserver-messaging.log "/opt/tak/logs/takserver-messaging.log.pre-oom-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    ls -t /opt/tak/logs/takserver-messaging.log.pre-oom-* 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null || true
    systemctl start $SERVICE
  fi
else
  rm -f "$STATEFILE"
fi
