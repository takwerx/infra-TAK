#!/bin/bash

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/network_alert_sent"
FAIL_COUNT_FILE="/var/lib/takguard/network_fail_count"

CLOUDFLARE_UP=false
GOOGLE_UP=false

if ping -c 2 -W 3 1.1.1.1 > /dev/null 2>&1; then
  CLOUDFLARE_UP=true
fi

if ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1; then
  GOOGLE_UP=true
fi

if [ "$CLOUDFLARE_UP" = false ] && [ "$GOOGLE_UP" = false ]; then
  if [ -f "$FAIL_COUNT_FILE" ]; then
    FAIL_COUNT=$(cat "$FAIL_COUNT_FILE")
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    FAIL_COUNT=1
  fi
  echo "$FAIL_COUNT" > "$FAIL_COUNT_FILE"
  
  if [ "$FAIL_COUNT" -ge 3 ]; then
    if [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find $ALERT_SENT_FILE -mmin +60 2>/dev/null)" ]; then
      touch "$ALERT_SENT_FILE"
      
      TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      
      SUBJ="TAK Server Network Alert on $SERVER_IDENTIFIER"
      BODY="Server cannot reach the internet.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

Tested:
- Cloudflare DNS (1.1.1.1): FAILED
- Google DNS (8.8.8.8): FAILED

Consecutive failures: $FAIL_COUNT

This may indicate:
- Network interface down
- ISP/VPS provider network issue
- Firewall blocking ICMP
- Routing problem

Check network status:
  ip addr show
  ip route show
  ping -c 3 1.1.1.1

TAK Server may still be functioning for local connections.
"

      echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
      if [ -f /opt/tak-guarddog/sms_send.sh ]; then
        TMPF="/tmp/gd-sms-$$.txt"
        printf '%s' "$BODY" > "$TMPF"
        /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
        rm -f "$TMPF"
      fi
      mkdir -p /var/log/takguard
      echo "$(date): Network connectivity lost (both Cloudflare and Google unreachable, $FAIL_COUNT failures)" >> /var/log/takguard/restarts.log
    fi
  fi
else
  rm -f "$FAIL_COUNT_FILE"
  rm -f "$ALERT_SENT_FILE"
fi
