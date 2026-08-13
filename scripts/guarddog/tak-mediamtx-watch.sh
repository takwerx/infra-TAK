#!/bin/bash
# Guard Dog: MediaMTX systemd service health. On 3 consecutive failures: alert and restart.
# v10.1.18: also watches mediamtx-webeditor.service — its crash-loop takes every
# stream.* route down (watch pages, share links, HLS proxy) and previously had
# ZERO alerting (test6 2026-08-03: editor crash-looped on a duplicate-endpoint
# mangle until the operator hit the dead page). A restart won't fix a code-level
# crash-loop, but the ALERT is the point; the email says where to look.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
FAIL_FILE="$STATE_DIR/mediamtx.failcount"
COOLDOWN_FILE="$STATE_DIR/mediamtx_last_restart"
ED_FAIL_FILE="$STATE_DIR/mediamtx_webeditor.failcount"
ED_COOLDOWN_FILE="$STATE_DIR/mediamtx_webeditor_last_alert"
MAX_FAILS=3
COOLDOWN_SECS=900

mkdir -p "$STATE_DIR"

# Don't run during first 15 minutes after boot (avoid restarting during startup)
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt 900 ] && exit 0

# --- Web editor (stream.* watch pages / share links / HLS proxy) ---
if systemctl list-unit-files mediamtx-webeditor.service 2>/dev/null | grep -q mediamtx-webeditor; then
  if systemctl is-active --quiet mediamtx-webeditor; then
    echo 0 > "$ED_FAIL_FILE"
  else
    ED_FAILS=$(( $(cat "$ED_FAIL_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$ED_FAILS" > "$ED_FAIL_FILE"
    ED_LAST=$(cat "$ED_COOLDOWN_FILE" 2>/dev/null || echo 0)
    NOW=$(date +%s)
    if [ "$ED_FAILS" -ge "$MAX_FAILS" ] && [ $(( NOW - ED_LAST )) -ge $COOLDOWN_SECS ]; then
      TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      ED_ERR=$(journalctl -u mediamtx-webeditor -n 12 --no-pager 2>/dev/null | grep -E 'Error|AssertionError|Traceback' | tail -3)
      mkdir -p /var/log/takguard
      echo "$TS | restart | MediaMTX web editor not active — alert + restart attempt" >> /var/log/takguard/restarts.log
      ED_SUBJ="Guard Dog: MediaMTX web editor DOWN on $SERVER_IDENTIFIER"
      ED_BODY="The MediaMTX web editor (stream.* watch pages, share links, HLS proxy) has not been running for $ED_FAILS consecutive checks.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Action: systemctl restart mediamtx-webeditor (attempted — a code-level crash-loop will NOT be fixed by this)

Last error lines:
$ED_ERR

Diagnose: journalctl -u mediamtx-webeditor -n 50
"
      echo -e "$ED_BODY" | /opt/tak-guarddog/send-alert-email.sh "$ED_SUBJ" "ALERT_EMAIL_PLACEHOLDER"
      if [ -f /opt/tak-guarddog/sms_send.sh ]; then
        ED_TMPF="/tmp/gd-sms-ed-$$.txt"
        printf '%s' "$ED_BODY" > "$ED_TMPF"
        /opt/tak-guarddog/sms_send.sh "$ED_SUBJ" "$ED_TMPF" 2>/dev/null || true
        rm -f "$ED_TMPF"
      fi
      systemctl restart mediamtx-webeditor 2>&1
      echo 0 > "$ED_FAIL_FILE"
      date +%s > "$ED_COOLDOWN_FILE"
    fi
  fi
fi

# Only run if MediaMTX is installed (systemd unit)
systemctl list-unit-files mediamtx.service >/dev/null 2>&1 || exit 0

# Health: systemctl is-active
if systemctl is-active --quiet mediamtx; then
  echo 0 > "$FAIL_FILE"
  exit 0
fi

# Failure
FAILS=$(( $(cat "$FAIL_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$FAILS" > "$FAIL_FILE"

if [ "$FAILS" -lt "$MAX_FAILS" ]; then
  exit 0
fi

# Cooldown
if [ -f "$COOLDOWN_FILE" ]; then
  LAST=$(cat "$COOLDOWN_FILE")
  NOW=$(date +%s)
  if [ $(( NOW - LAST )) -lt $COOLDOWN_SECS ]; then
    exit 0
  fi
fi

TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p /var/log/takguard
echo "$TS | restart | MediaMTX not active — restarting" >> /var/log/takguard/restarts.log

SUBJ="Guard Dog: MediaMTX restarted on $SERVER_IDENTIFIER"
BODY="MediaMTX was not running for $FAILS consecutive checks.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Action: systemctl restart mediamtx

Check /var/log/takguard/restarts.log for history.
"
echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi

# Re-apply read-access to Caddy's LE cert files before restart. Caddy renews certs
# every ~60 days by atomic-rename, which resets perms back to 0600 caddy:caddy and
# would leave MediaMTX (running as takwerx) unable to read them. Refreshing on every
# guarddog-triggered restart self-heals this without operator intervention.
CADDY_CERTS_BASE="/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
if [ -d "$CADDY_CERTS_BASE" ]; then
  usermod -aG caddy takwerx 2>/dev/null || true
  for d in /var/lib/caddy /var/lib/caddy/.local /var/lib/caddy/.local/share \
           /var/lib/caddy/.local/share/caddy /var/lib/caddy/.local/share/caddy/certificates \
           "$CADDY_CERTS_BASE"; do
    chmod g+rx "$d" 2>/dev/null || true
  done
  for d in "$CADDY_CERTS_BASE"/*/; do
    [ -d "$d" ] || continue
    chmod g+rx "$d" 2>/dev/null || true
    find "$d" -type f \( -name '*.crt' -o -name '*.key' \) -exec chmod g+r {} \; 2>/dev/null || true
  done
fi

systemctl restart mediamtx 2>&1
echo 0 > "$FAIL_FILE"
date +%s > "$COOLDOWN_FILE"
