#!/bin/bash

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/disk_alert_sent"
ALERT_THRESHOLD=80
CRITICAL_THRESHOLD=90

ROOT_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
LOGS_USAGE=$(df /opt/tak/logs 2>/dev/null | awk 'NR==2 {print $5}' | sed 's/%//' || echo "0")

# Self-heal (v10.0.2): before alerting, reclaim dead Docker build cache if the root
# disk is getting tight. The reclaim script owns the authoritative threshold + 7-day
# keep-window and self-gates; this hourly hook just pokes it when disk is high so a box
# recovers WITHIN THE HOUR instead of waiting for the daily 04:30 timer. Riding this
# already-hourly monitor means the self-heal deploys on a plain pull+restart (no
# "Update Guard Dog" needed). Re-read usage after so the alert reflects post-reclaim state.
RECLAIM_TRIGGER_PCT=70
if [ -n "$ROOT_USAGE" ] && [ "$ROOT_USAGE" -ge "$RECLAIM_TRIGGER_PCT" ] && [ -x /opt/tak-guarddog/tak-buildcache-reclaim.sh ]; then
  /opt/tak-guarddog/tak-buildcache-reclaim.sh >/dev/null 2>&1
  ROOT_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
fi

NEED_ALERT=false
ALERT_MSG=""

if [ "$ROOT_USAGE" -ge "$CRITICAL_THRESHOLD" ]; then
  NEED_ALERT=true
  ALERT_MSG="${ALERT_MSG}CRITICAL: Root filesystem at ${ROOT_USAGE}%\n"
elif [ "$ROOT_USAGE" -ge "$ALERT_THRESHOLD" ]; then
  NEED_ALERT=true
  ALERT_MSG="${ALERT_MSG}WARNING: Root filesystem at ${ROOT_USAGE}%\n"
fi

if [ -n "$LOGS_USAGE" ] && [ "$LOGS_USAGE" -ge "$CRITICAL_THRESHOLD" ]; then
  NEED_ALERT=true
  ALERT_MSG="${ALERT_MSG}CRITICAL: TAK logs filesystem at ${LOGS_USAGE}%\n"
elif [ -n "$LOGS_USAGE" ] && [ "$LOGS_USAGE" -ge "$ALERT_THRESHOLD" ]; then
  NEED_ALERT=true
  ALERT_MSG="${ALERT_MSG}WARNING: TAK logs filesystem at ${LOGS_USAGE}%\n"
fi

if $NEED_ALERT; then
  if [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find $ALERT_SENT_FILE -mtime +1 2>/dev/null)" ]; then
    touch "$ALERT_SENT_FILE"
    
    TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    
    SUBJ="TAK Server Disk Space Alert on $SERVER_IDENTIFIER"
    BODY="TAK Server disk space is running low.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

${ALERT_MSG}

Disk Usage Details:
$(df -h /)
$(df -h /opt/tak/logs 2>/dev/null || true)

Action Required:
1. Review Data Retention settings in TAK Server web UI
2. Clean up old logs: /opt/tak/logs/
3. Consider increasing disk size if needed

Largest log files:
$(du -h /opt/tak/logs/*.log 2>/dev/null | sort -rh | head -5 || echo 'N/A')
"

    [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    if [ -f /opt/tak-guarddog/sms_send.sh ]; then
      TMPF="/tmp/gd-sms-$$.txt"
      printf '%s' "$BODY" > "$TMPF"
      /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
      rm -f "$TMPF"
    fi
  fi
else
  rm -f "$ALERT_SENT_FILE"
fi
