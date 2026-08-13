#!/bin/bash
#
# Root CA and Intermediate CA certificate expiry monitor
# Notification milestones: 90, 75, 60, 45, 30 days, then daily until 0 (expired)

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
LOG="/var/log/takguard/restarts.log"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [ca-watch] $1" >> "$LOG" 2>/dev/null; }

check_cert() {
  local CERT_FILE="$1"
  local LABEL="$2"
  local STATE_FILE="$STATE_DIR/ca_alert_$(echo "$LABEL" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')"

  if [ ! -f "$CERT_FILE" ]; then
    return
  fi

  EXPIRY_RAW=$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
  if [ -z "$EXPIRY_RAW" ]; then
    log "ERROR: Could not read expiry from $CERT_FILE ($LABEL)"
    return
  fi

  EXPIRY_EPOCH=$(date -d "$EXPIRY_RAW" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY_RAW" +%s 2>/dev/null)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

  if [ "$DAYS_LEFT" -gt 90 ]; then
    rm -f "$STATE_FILE"
    return
  fi

  # Determine which milestone we're at
  # Daily when <= 30 days, otherwise only at 90, 75, 60, 45, 30
  SHOULD_ALERT=0
  LAST_ALERTED=-1

  if [ -f "$STATE_FILE" ]; then
    LAST_ALERTED=$(cat "$STATE_FILE" 2>/dev/null)
    LAST_ALERTED=${LAST_ALERTED:--1}
  fi

  if [ "$DAYS_LEFT" -le 30 ]; then
    # Daily alerts: fire if we haven't alerted for this day count yet
    if [ "$LAST_ALERTED" != "$DAYS_LEFT" ]; then
      SHOULD_ALERT=1
    fi
  else
    # Milestone alerts: 90, 75, 60, 45
    for MILESTONE in 90 75 60 45; do
      if [ "$DAYS_LEFT" -le "$MILESTONE" ] && [ "$LAST_ALERTED" -gt "$MILESTONE" -o "$LAST_ALERTED" -eq -1 ]; then
        SHOULD_ALERT=1
        break
      fi
    done
  fi

  if [ "$SHOULD_ALERT" -eq 0 ]; then
    return
  fi

  echo "$DAYS_LEFT" > "$STATE_FILE"

  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  EXPIRY_HUMAN=$(date -d "$EXPIRY_RAW" '+%Y-%m-%d' 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY_RAW" '+%Y-%m-%d' 2>/dev/null)

  if [ "$DAYS_LEFT" -le 0 ]; then
    URGENCY="EXPIRED"
  elif [ "$DAYS_LEFT" -le 30 ]; then
    URGENCY="CRITICAL"
  elif [ "$DAYS_LEFT" -le 60 ]; then
    URGENCY="WARNING"
  else
    URGENCY="NOTICE"
  fi

  if [ "$DAYS_LEFT" -le 0 ]; then
    SUBJ="[$URGENCY] TAK $LABEL HAS EXPIRED - $SERVER_IDENTIFIER"
    BODY="TAK Server $LABEL has expired.

The $LABEL expired on $EXPIRY_HUMAN.
All TAK connections using this certificate chain will fail.

Server: $SERVER_IDENTIFIER
Certificate: $CERT_FILE
Severity: $URGENCY

Action Required:
  Generate new certificates immediately and redeploy to all clients.
"
  elif [ "$DAYS_LEFT" -eq 1 ]; then
    SUBJ="[$URGENCY] TAK $LABEL expires TOMORROW - $SERVER_IDENTIFIER"
    BODY="You have 1 day until the TAK Server $LABEL expires.

Expiry date: $EXPIRY_HUMAN

Server: $SERVER_IDENTIFIER
Certificate: $CERT_FILE
Severity: $URGENCY

The $LABEL signs all TAK certificates in the chain.
When it expires, all TAK connections will fail.

Action Required:
  Generate new certificates and redeploy to all clients.
"
  else
    SUBJ="[$URGENCY] TAK $LABEL expires in $DAYS_LEFT days - $SERVER_IDENTIFIER"
    BODY="You have $DAYS_LEFT days until the TAK Server $LABEL expires.

Expiry date: $EXPIRY_HUMAN

Server: $SERVER_IDENTIFIER
Certificate: $CERT_FILE
Severity: $URGENCY

The $LABEL signs all TAK certificates in the chain.
When it expires, all TAK connections will fail.

Action Required:
  Generate new certificates and redeploy to all clients.
"
  fi

  log "$URGENCY: $LABEL expires in $DAYS_LEFT days ($EXPIRY_HUMAN)"

  echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    TMPF="/tmp/gd-sms-$$.txt"
    printf '%s' "$BODY" > "$TMPF"
    /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
    rm -f "$TMPF"
  fi
}

check_cert "/opt/tak/certs/files/root-ca.pem" "Root CA"
check_cert "/opt/tak/certs/files/ca.pem" "Intermediate CA"
