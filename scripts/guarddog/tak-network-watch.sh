#!/bin/bash
# Network watcher: "can this box reach the internet at all?"
#
# ops #667 (GH #474): this used to be ping only. Boxes that block outbound ICMP
# (Azure does by default) have working DNS, TCP and HTTPS and still failed both pings
# every minute, so the box sent a false "cannot reach the internet" email every hour
# (one box counted 215072 failures, about 149 days). The console's own network monitor
# already falls back to TCP (v0.9.57); this script never did.
#
# Order: ICMP is the fast path. Only when BOTH pings fail do we try a TCP connect to
# 1.1.1.1:443 and 8.8.8.8:53. Any one of the four working means "online". Only when
# ICMP and TCP both fail is it counted as an outage.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/network_alert_sent"
FAIL_COUNT_FILE="/var/lib/takguard/network_fail_count"

# Same probe as gd_tcp_up() in _gd-tak-lib.sh, inlined so this watcher has no
# dependency on the lib (which reads TAK topology at source time). RHEL has no `nc` by
# default; the bash /dev/tcp builtin is identical on Ubuntu, RHEL and ARM64.
tcp_up() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

CLOUDFLARE_UP=false
GOOGLE_UP=false
CLOUDFLARE_TCP=skipped
GOOGLE_TCP=skipped

if ping -c 2 -W 3 1.1.1.1 > /dev/null 2>&1; then
  CLOUDFLARE_UP=true
fi

if ping -c 2 -W 3 8.8.8.8 > /dev/null 2>&1; then
  GOOGLE_UP=true
fi

# Both pings failed: ICMP may just be blocked. Ask over TCP before calling it an outage.
if [ "$CLOUDFLARE_UP" = false ] && [ "$GOOGLE_UP" = false ]; then
  if tcp_up 1.1.1.1 443; then
    CLOUDFLARE_TCP=ok
    CLOUDFLARE_UP=true
  else
    CLOUDFLARE_TCP=FAILED
  fi
  if tcp_up 8.8.8.8 53; then
    GOOGLE_TCP=ok
    GOOGLE_UP=true
  else
    GOOGLE_TCP=FAILED
  fi
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
- Cloudflare DNS (1.1.1.1): ping FAILED, TCP port 443 $CLOUDFLARE_TCP
- Google DNS (8.8.8.8): ping FAILED, TCP port 53 $GOOGLE_TCP

Consecutive failures: $FAIL_COUNT

This may indicate:
- Network interface down
- ISP/VPS provider network issue
- Firewall blocking all outbound traffic (both ping and TCP failed, so a ping block alone is not the cause)
- Routing problem

Check network status:
  ip addr show
  ip route show
  ping -c 3 1.1.1.1
  timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && echo tcp-ok

TAK Server may still be functioning for local connections.
"

      echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
      if [ -f /opt/tak-guarddog/sms_send.sh ]; then
        TMPF="$(mktemp /tmp/gd-sms.XXXXXX)"
        printf '%s' "$BODY" > "$TMPF"
        /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
        rm -f "$TMPF"
      fi
      mkdir -p /var/log/takguard
      echo "$(date): Network connectivity lost (Cloudflare and Google unreachable by ping and TCP, $FAIL_COUNT failures)" >> /var/log/takguard/restarts.log
    fi
  fi
else
  rm -f "$FAIL_COUNT_FILE"
  rm -f "$ALERT_SENT_FILE"
fi
