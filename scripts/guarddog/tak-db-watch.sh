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
      # The remedy has to be runnable on the machine the reader is looking at. On a split
      # deployment the database is on ANOTHER host, and telling someone to
      # `systemctl restart postgresql` here sends them chasing a fault on the wrong machine
      # (GH report, John Stefanini 2026-09-10). Name the host, and say plainly that nothing
      # was restarted from here.
      if gd_db_is_remote; then
        _DBH="$(gd_db_host)"
        BODY="TAK Server cannot reach its database.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Database host: $_DBH (port 5432) — a SEPARATE machine, not this one.

This will cause:
- TAK Server failure to start
- Service interruption

The database does NOT run on this host, so nothing was restarted from here and there is
nothing to restart here. Check the database machine:

  ssh $_DBH
  pg_lsclusters                 # or: systemctl status postgresql
  ss -ltn | grep 5432           # is it listening?

Also worth checking from this host, since this alert fires on reachability:
  network path / firewall between here and $_DBH on 5432
"
      else
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
      fi

      echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
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
        if gd_db_is_remote; then
          echo "$(date): remote database $(gd_db_host) was unreachable, now reachable again (nothing restarted from here)" >> /var/log/takguard/restarts.log
        else
          echo "$(date): PostgreSQL was down, restarted successfully" >> /var/log/takguard/restarts.log
        fi
      elif gd_db_is_remote; then
        # Not a failed restart — we never attempted one, and saying "restart FAILED" about a
        # machine we did not touch is the same wrong-machine confusion as the alert body.
        echo "$(date): remote database $(gd_db_host) still unreachable — no local restart attempted (database is on another host)" >> /var/log/takguard/restarts.log
      else
        echo "$(date): PostgreSQL was down, restart FAILED" >> /var/log/takguard/restarts.log
      fi
    fi
  fi
else
  rm -f "$ALERT_SENT_FILE"
fi
