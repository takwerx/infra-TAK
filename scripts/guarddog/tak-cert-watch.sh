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

        echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
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

# --- v10.1.68: a renewal that is FAILING is a pre-outage, not a warning -------
# Everything above watches the certificate's EXPIRY DATE, and only when the keystore
# exists. Two states therefore went completely unreported, and together they cost a
# box two days of silence followed by a total outage:
#
#   1. The keystore is MISSING. `if [ -f "$JKS" ]` skips the whole block, so the one
#      state in which TAK's API cannot start at all was the one state nobody was told
#      about. (A pre-v10.1.67 renewal script deleted the live keystore before a
#      keytool import that then failed, leaving exactly this.)
#   2. The renewal SERVICE is failing. The certificate stays valid for weeks, so the
#      expiry check stays quiet while renewal has actually been broken for days. The
#      damage only appears at the next restart, when TAK cannot load a keystore it can
#      no longer rebuild.
#
# Both are reported here with their own rate limits, and deliberately worded as
# "this becomes an outage later" rather than "a certificate expires later".

_CERT_MISSING_FLAG="/var/lib/takguard/cert_keystore_missing_alert"
_RENEWAL_FAIL_FLAG="/var/lib/takguard/cert_renewal_failed_alert"

if [ ! -f "$JKS" ] && [ -f /opt/tak/CoreConfig.xml ] && grep -q "takserver-le.jks" /opt/tak/CoreConfig.xml 2>/dev/null; then
  if [ ! -f "$_CERT_MISSING_FLAG" ] || [ "$(find "$_CERT_MISSING_FLAG" -mmin +360 2>/dev/null)" ]; then
    touch "$_CERT_MISSING_FLAG"
    SUBJ="TAK Server keystore MISSING on $SERVER_IDENTIFIER"
    BODY="TAK Server's Let's Encrypt keystore is missing.

Server: $SERVER_IDENTIFIER
Time (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
Missing file: $JKS

CoreConfig references this keystore for the 8446 connector, so TAK Server's API
cannot start without it. If TAK is still serving, it is running on a copy loaded
into memory before the file disappeared -- it will fail to start at the next
restart or reboot.

infra-TAK v10.1.67 and later rebuild this automatically at console startup. If you
are on an older release, update from the console; that is the fix."
    echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
  fi
else
  rm -f "$_CERT_MISSING_FLAG"
fi

if systemctl list-unit-files takserver-cert-renewal.service >/dev/null 2>&1; then
  _RENEW_RESULT=$(systemctl show takserver-cert-renewal.service -p Result --value 2>/dev/null)
  if [ -n "$_RENEW_RESULT" ] && [ "$_RENEW_RESULT" != "success" ]; then
    if [ ! -f "$_RENEWAL_FAIL_FLAG" ] || [ "$(find "$_RENEWAL_FAIL_FLAG" -mmin +1440 2>/dev/null)" ]; then
      touch "$_RENEWAL_FAIL_FLAG"
      SUBJ="TAK Server certificate renewal is FAILING on $SERVER_IDENTIFIER"
      BODY="The TAK Server certificate renewal job is failing.

Server: $SERVER_IDENTIFIER
Time (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
Last result: $_RENEW_RESULT

The certificate itself may still be valid, so nothing is broken yet. That is why
this is worth acting on now: a failing renewal is an outage that has not happened
yet, and it typically surfaces at the next restart rather than at expiry.

Check what it is failing on:
  systemctl status takserver-cert-renewal.service
  journalctl -u takserver-cert-renewal.service -n 50"
      echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
    fi
  else
    rm -f "$_RENEWAL_FAIL_FLAG"
  fi
fi
