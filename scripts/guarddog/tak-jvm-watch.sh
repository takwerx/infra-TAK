#!/bin/bash
# Guard Dog TAK Server JVM Monitor (v10.1.63 W4)
#
# Reads the JVM the TAK Server API process is ACTUALLY running on and alerts when it
# is not Java 17.
#
# Why this exists — field report, Tom Endress, 2026-09-09, three-day outage. He installed
# openjdk-21-jre-headless for an unrelated tool. update-alternatives was in auto mode, so
# JDK 21 won /usr/bin/java on priority. TAK kept running on its already-loaded JVM 17, and
# the box stayed perfectly healthy for FIVE DAYS. Then a routine reboot restarted TAK, it
# came up on 21, and every QR enrollment began failing:
#
#   POST /Marti/api/tls/signClient/v2 -> HTTP 500
#   java.lang.NoSuchMethodError: 'void sun.security.x509.X509CertInfo.set(String, Object)'
#
# TAK 5.7 reaches into JDK-internal sun.security.x509; JDK 21 dropped that generic setter.
# NOTHING ELSE in TAK touches that code path — 8089, federation, existing clients, CloudTAK
# and the whole map keep working. So no monitor fires, no service is down, and the only
# symptom is that NEW enrollments die: the one thing an admin does not exercise daily. Tom
# ran three days before a user called.
#
# This is the check that would have caught it on day one instead of day three.
#
# We read /proc/<pid>/exe, NOT `java -version`: the process may have been started with a
# different JVM than the one on today's PATH, and the running one is the only one that
# matters (memory tak57-jdk21-breaks-enrollment).
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
ALERT_SENT_FILE="$STATE_DIR/jvm_alert_sent"
STATUS_FILE="$STATE_DIR/jvm_status"
mkdir -p "$STATE_DIR" 2>/dev/null

# Container TAK carries its own JVM inside the image — the host's alternatives cannot
# move it, so there is nothing to watch and a false alert would be worse than silence.
if gd_is_container 2>/dev/null; then
  echo "container=1" > "$STATUS_FILE" 2>/dev/null
  exit 0
fi

# The API process is the one that signs enrollment certs, and it is identified by its OWN
# JVM flag. Do NOT match on 'takserver-api': TAK's launcher is a shell script, so that
# pattern resolves to /usr/bin/dash rather than the JVM (measured on test6 and test12,
# 2026-09-10). Reading `dash -version` finds no "17" and would have emailed a WRONG-JVM
# alert from every healthy box in the fleet. No loose fallback for the same reason —
# matching the wrong process is worse than reporting unknown.
PID=$(pgrep -f -- '-Dspring.profiles.active=api' 2>/dev/null | head -1)
if [ -z "$PID" ]; then
  # TAK is not running — that is the process monitor's job to alert on, not ours.
  echo "running=0" > "$STATUS_FILE" 2>/dev/null
  exit 0
fi

JVM_EXE=$(readlink -f "/proc/$PID/exe" 2>/dev/null)
if [ -z "$JVM_EXE" ] || [ ! -f "$JVM_EXE" ]; then
  # Unreadable /proc entry (non-root console user vs a root-owned JVM) — report unknown
  # rather than guessing. An unknown must never become a false "wrong JVM" alert.
  echo "unknown=1" > "$STATUS_FILE" 2>/dev/null
  exit 0
fi

# We found the PID with `pgrep -f`, which matches on ARGV, and argv is attacker-chosen:
# any local user can run `exec -a takserver-api /tmp/evil`. This script runs as ROOT from
# systemd, so executing that binary to read its version would be a local privilege
# escalation introduced by the check itself. Run it only if it is a root-owned, non-
# group/world-writable file under a system prefix. Anything else is UNKNOWN, never an
# alert — a false red here pages someone about an outage that is not happening.
case "$JVM_EXE" in
  /usr/lib/jvm/*|/usr/lib64/jvm/*|/usr/local/lib/jvm/*|/usr/bin/*|/usr/local/bin/*|/opt/*) ;;
  *) echo "untrusted_exe=$JVM_EXE" > "$STATUS_FILE" 2>/dev/null; exit 0 ;;
esac
_OWNER=$(stat -c %u "$JVM_EXE" 2>/dev/null)
_PERM=$(stat -c %a "$JVM_EXE" 2>/dev/null)
if [ "$_OWNER" != "0" ] || [ -z "$_PERM" ] || [ $((0$_PERM & 022)) -ne 0 ]; then
  echo "untrusted_exe=$JVM_EXE owner=$_OWNER perm=$_PERM" > "$STATUS_FILE" 2>/dev/null
  exit 0
fi

JVM_VER=$("$JVM_EXE" -version 2>&1 | head -1)
printf 'pid=%s\nexe=%s\nversion=%s\n' "$PID" "$JVM_EXE" "$JVM_VER" > "$STATUS_FILE" 2>/dev/null

case "$JVM_VER" in
  *'version "17.'*|*'version "17"'*)
    rm -f "$ALERT_SENT_FILE"
    exit 0 ;;
esac

# Wrong JVM. Re-alert at most once a day — this is a standing condition, not an event,
# and it stays broken until someone acts.
if [ -f "$ALERT_SENT_FILE" ] && [ -z "$(find "$ALERT_SENT_FILE" -mmin +1440 2>/dev/null)" ]; then
  exit 0
fi
touch "$ALERT_SENT_FILE"

TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
SUBJ="TAK Server is running on the WRONG JVM on $SERVER_IDENTIFIER"
BODY="TAK Server is running on a JVM other than Java 17. New client enrollments are
failing RIGHT NOW, and nothing else will look wrong.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
TAK API PID: $PID
JVM in use: $JVM_EXE
Reported as: $JVM_VER

What breaks:
  POST /Marti/api/tls/signClient/v2 returns HTTP 500
  java.lang.NoSuchMethodError: sun.security.x509.X509CertInfo.set(String, Object)

TAK 5.7 reaches into a JDK-internal class that Java 21 changed. Existing clients, port
8089, federation, CloudTAK and the map are all UNAFFECTED — which is exactly why this can
run for days unnoticed. Only NEW enrollments fail.

How this usually happens: something installed a newer JDK (often as a dependency of an
unrelated tool) and update-alternatives moved /usr/bin/java to it on priority. TAK then
picks it up at its next restart, which can be days later.

Action Required:
1. Restart the infra-TAK console — it re-applies the JDK 17 pin automatically:
     sudo systemctl restart takwerx-console
2. Confirm the pin took:
     readlink -f /usr/bin/java
     systemctl cat takserver | grep JAVA_HOME
3. Restart TAK Server so it picks up Java 17:
     sudo systemctl restart takserver
4. Verify enrollment works again by enrolling one client.
"

echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi
exit 0
