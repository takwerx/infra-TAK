#!/bin/bash
# v10.0.1: container-aware via _gd-tak-lib.sh. Native (deb/rpm) behaviour is
# byte-identical (the lib's native branch emits the same systemctl calls);
# container mode targets the takserver-db container.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/db_alert_sent"
LAST_RESTART_FILE="/var/lib/takguard/last_restart_time"

if [ -f "$LAST_RESTART_FILE" ]; then
  LAST_RESTART=$(cat "$LAST_RESTART_FILE")
  CURRENT_TIME=$(date +%s)
  TIME_SINCE_RESTART=$((CURRENT_TIME - LAST_RESTART))
  if [ $TIME_SINCE_RESTART -lt 900 ]; then
    exit 0
  fi
fi

if ! gd_db_running; then
  # v10.0.5: confirm a real outage before acting. A container-TAK stack restart
  # (e.g. the LE-cert self-heal / cert-renewal bouncing the TAK stack, or an operator
  # update) briefly downs the db container; a single 5-min check landing in that window
  # used to fire "PostgreSQL was down, restart FAILED" on a perfectly healthy DB. A
  # genuine outage persists across this short re-check; a restart window clears.
  sleep 8
  if gd_db_running; then
    exit 0
  fi
  if true; then  # DB-down already determined by gd_db_running (native svc or db container)
    if [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find $ALERT_SENT_FILE -mmin +60 2>/dev/null)" ]; then
      touch "$ALERT_SENT_FILE"
      
      TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      
      SUBJ="TAK Server Database Alert on $SERVER_IDENTIFIER"
      BODY="PostgreSQL service is not running.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

This will cause:
- TAK Server failure to start
- Data loss
- Service interruption

Check PostgreSQL status:
  systemctl status postgresql

Restart PostgreSQL:
  systemctl restart postgresql
"

      [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
      if [ -f /opt/tak-guarddog/sms_send.sh ]; then
        TMPF="/tmp/gd-sms-$$.txt"
        printf '%s' "$BODY" > "$TMPF"
        /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
        rm -f "$TMPF"
      fi
      gd_db_restart || true

      mkdir -p /var/log/takguard
      # A `docker restart` of the db container (and PostgreSQL's own startup) needs a
      # moment — judging immediately logged a false FAILED while PG was still booting.
      # Give it up to ~25s before deciding.
      _db_back=false
      for _i in 1 2 3 4 5; do
        if gd_db_running; then _db_back=true; break; fi
        sleep 5
      done
      if $_db_back; then
        echo "$(date): PostgreSQL was down, restarted successfully" >> /var/log/takguard/restarts.log
      else
        echo "$(date): PostgreSQL was down, restart FAILED" >> /var/log/takguard/restarts.log
      fi
    fi
  fi
else
  rm -f "$ALERT_SENT_FILE"
fi
