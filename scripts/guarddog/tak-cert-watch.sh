#!/bin/bash
# v10.0.1: container-aware via _gd-tak-lib.sh. The LE JKS lives at the same
# /opt/tak/certs/files path in both modes (bind-mounted), but a container box
# has no host keytool — gd_keytool runs it inside the takserver container.
# Native behaviour is byte-identical. (The cert-renewal timer is named
# takserver-cert-renewal.timer in BOTH modes, so the alert body is correct.)
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_SENT_FILE="/var/lib/takguard/cert_alert_sent"
CERT_PASS="CERT_PASS_PLACEHOLDER"

JKS="/opt/tak/certs/files/takserver-le.jks"
if [ -f "$JKS" ]; then
  TEMP_CERT="/tmp/takserver-le-temp.pem"
  # install_le_cert_on_8446() creates the LE JKS with alias = TAK hostname (e.g. takserver.example.com),
  # not the literal string "takserver". Wrong alias => empty export => bogus DAYS_LEFT and false alert emails.
  ALIAS=$(gd_keytool -list -keystore "$JKS" -storepass "$CERT_PASS" | awk -F', ' '/PrivateKeyEntry/ {print $1; exit}')
  if [ -z "$ALIAS" ]; then
    ALIAS="takserver"
  fi
  gd_keytool -exportcert -keystore "$JKS" -storepass "$CERT_PASS" -alias "$ALIAS" -rfc > "$TEMP_CERT" 2>/dev/null

  if [ -s "$TEMP_CERT" ] && openssl x509 -in "$TEMP_CERT" -noout -enddate >/dev/null 2>&1; then
    EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$TEMP_CERT" | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY_DATE" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    rm -f "$TEMP_CERT"

    if [ "$DAYS_LEFT" -le 25 ]; then
      if [ ! -f "$ALERT_SENT_FILE" ] || [ "$(find $ALERT_SENT_FILE -mtime +7 2>/dev/null)" ]; then
        touch "$ALERT_SENT_FILE"
        
        TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        
        SUBJ="TAK Server Certificate Expiring on $SERVER_IDENTIFIER"
        BODY="TAK Server Let's Encrypt certificate will expire soon.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Days Remaining: $DAYS_LEFT
Expires: $EXPIRY_DATE

Action Required:
1. Verify auto-renewal is working:
   systemctl status takserver-cert-renewal.timer

2. Manual renewal if needed:
   sudo /opt/tak/renew-letsencrypt.sh

If renewal fails, clients will be unable to connect after expiration.
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
  else
    rm -f "$TEMP_CERT"
  fi
fi
