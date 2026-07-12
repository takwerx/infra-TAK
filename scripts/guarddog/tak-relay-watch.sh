#!/bin/bash
# Guard Dog — relay (connectivity anchor) health watch. v10.1.0 Leg 7.
#
# Once a box depends on a relay, the relay IS the ingress: if the tunnel is down,
# every no-VPN client loses the box, and a portable/CGNAT box has no other path.
#
# Primary signal = WireGuard handshake age on the anchor interface (wg0). A healthy
# relay always yields fresh handshakes (persistent-keepalive is 25s); latest-handshake
# older than ~3 min covers relay-VM-crash, public-IP change, Oracle termination,
# billing lapse, and cloud-firewall changes with one check. Runs every minute; alerts
# only on SUSTAINED downtime (3 consecutive stale checks) because most blips self-heal
# (WireGuard re-dials, Oracle auto-reboots on maintenance, a portable box briefly drops
# on a network hop). Auto-clears on recovery and sends a one-time recovery notice.
#
# No-ops silently when no relay is configured (no wg0.conf) — safe to install fleet-wide.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/relay_alert_sent"
FAIL_COUNT_FILE="/var/lib/takguard/relay_fail_count"
WG_IF="wg0"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
STALE_SECS=180
SUSTAINED_FAILS=3

# Not configured for a relay → nothing to watch.
[ -f "$WG_CONF" ] || exit 0
command -v wg >/dev/null 2>&1 || exit 0

mkdir -p /var/lib/takguard /var/log/takguard

ANCHOR_ENDPOINT=$(grep -im1 '^Endpoint' "$WG_CONF" 2>/dev/null | cut -d= -f2- | tr -d ' ')

HS_AGE=""
STATE="down"
DETAIL="interface ${WG_IF} is not up"
DUMP=$(wg show "$WG_IF" dump 2>/dev/null)
if [ -n "$DUMP" ]; then
  # dump: line 1 = interface; peer lines follow. Field 5 = latest-handshake epoch (0 = never).
  HS_EPOCH=$(echo "$DUMP" | sed -n '2p' | awk '{print $5}')
  case "$HS_EPOCH" in
    ''|*[!0-9]*) HS_EPOCH=0 ;;
  esac
  if [ "$HS_EPOCH" -gt 0 ]; then
    HS_AGE=$(( $(date +%s) - HS_EPOCH ))
    if [ "$HS_AGE" -le "$STALE_SECS" ]; then
      STATE="up"
      DETAIL="handshake ${HS_AGE}s ago"
    else
      DETAIL="last handshake ${HS_AGE}s ago (stale; threshold ${STALE_SECS}s)"
    fi
  else
    DETAIL="tunnel up but no handshake has ever completed"
  fi
fi

if [ "$STATE" = "up" ]; then
  # Recovered (or healthy). Auto-clear; send a one-time recovery notice if we had alerted.
  rm -f "$FAIL_COUNT_FILE"
  if [ -f "$ALERT_SENT_FILE" ]; then
    rm -f "$ALERT_SENT_FILE"
    TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    SUBJ="TAK Relay RECOVERED on $SERVER_IDENTIFIER"
    BODY="The relay tunnel is healthy again.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Relay endpoint: ${ANCHOR_ENDPOINT:-unknown}
Status: $DETAIL

No action needed. Clients can reach the box through the relay again.
"
    [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    if [ -f /opt/tak-guarddog/sms_send.sh ]; then
      TMPF="/tmp/gd-sms-$$.txt"
      printf '%s' "$BODY" > "$TMPF"
      /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
      rm -f "$TMPF"
    fi
    echo "$(date): Relay tunnel recovered ($DETAIL)" >> /var/log/takguard/restarts.log
  fi
  exit 0
fi

# Tunnel stale/down — count toward sustained.
if [ -f "$FAIL_COUNT_FILE" ]; then
  FAIL_COUNT=$(cat "$FAIL_COUNT_FILE")
  FAIL_COUNT=$((FAIL_COUNT + 1))
else
  FAIL_COUNT=1
fi
echo "$FAIL_COUNT" > "$FAIL_COUNT_FILE"

# Self-heal BEFORE alerting: exactly once per outage, at the sustained threshold,
# bounce the tunnel. Kernel WireGuard caches the peer's source address — after an
# uplink move (ethernet -> wifi) it can keep stamping the old source and never
# handshake again (field 2026-07-11: correct wifi route, dead tunnel until the
# cable returned). A wg-quick restart resets the socket and reconnects in ~2s;
# it also cures a wedged tunnel after relay-side restarts. Harmless if the real
# cause is elsewhere (relay down, no egress) — the alert below still fires on
# the next stale check.
# Re-fire every 5 checks (~5 min) during a sustained outage, not just once: a
# single bounce gets a single new NAT mapping, and carrier CGNATs can kill a
# mapping's return direction while the forward side stays alive (field-hit
# 2026-07-11 night: box initiations kept arriving at the relay on a mapping
# whose replies AT&T no longer delivered; only a fresh socket recovers).
if [ "$FAIL_COUNT" -ge "$SUSTAINED_FAILS" ] && [ $(( FAIL_COUNT % 5 )) -eq $(( SUSTAINED_FAILS % 5 )) ] && [ -f "/etc/wireguard/${WG_IF:-wg0}.conf" ]; then
  systemctl restart "wg-quick@${WG_IF:-wg0}" >/dev/null 2>&1 || true
  echo "$(date): Relay tunnel stale ${FAIL_COUNT} checks — self-heal: restarted wg-quick@${WG_IF:-wg0}" >> /var/log/takguard/restarts.log
fi

if [ "$FAIL_COUNT" -ge "$SUSTAINED_FAILS" ]; then
  if [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find $ALERT_SENT_FILE -mmin +60 2>/dev/null)" ]; then
    touch "$ALERT_SENT_FILE"

    TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    SUBJ="TAK Relay DOWN on $SERVER_IDENTIFIER"
    BODY="The relay tunnel has been down for ${FAIL_COUNT} consecutive checks (~${FAIL_COUNT} min).

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Relay endpoint: ${ANCHOR_ENDPOINT:-unknown}
Status: $DETAIL

While the relay is down, clients CANNOT reach this box through the relay address
(TAK, web UIs, enrollment). A portable/CGNAT box has no other inbound path.

Most likely causes, in order:
- Relay VM stopped/terminated (check the cloud console — Oracle Free Tier reclaims
  idle VMs on some account types; check billing/limits)
- Relay public IP changed (stop/start on the cloud side assigns a new one —
  reconfigure the relay card with the new IP)
- Cloud firewall / NSG changed (udp WireGuard port must be open)
- This box's own internet is down (other alerts would fire too)

WireGuard re-dials automatically — brief blips self-heal without this alert.
Check from this box:
  wg show ${WG_IF}
  systemctl status wg-quick@${WG_IF}
  ping -c 3 ${ANCHOR_ENDPOINT%%:*}

This alert repeats at most once per hour while the tunnel stays down, and a
recovery notice is sent when it comes back.
"

    [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    if [ -f /opt/tak-guarddog/sms_send.sh ]; then
      TMPF="/tmp/gd-sms-$$.txt"
      printf '%s' "$BODY" > "$TMPF"
      /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
      rm -f "$TMPF"
    fi
    echo "$(date): Relay tunnel down ($DETAIL, $FAIL_COUNT consecutive)" >> /var/log/takguard/restarts.log
  fi
fi
