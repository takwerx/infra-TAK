#!/bin/bash
# Guard Dog TAK Session Visibility Watch — v10.1.46 (W2)
#
# Detects clients that are CONNECTED BUT NOT ACCOUNTED FOR, and emails the
# operator. It never kills a socket and never restarts anything.
#
# WHY THIS EXISTS
# ---------------
# On 2026-08-21 a production public-safety deployment (~800 users) ran for an
# unknown length of time with clients showing `__ANON__` instead of channels
# after a reboot. Radios were green. Nothing logged it, nothing alerted, no card
# showed it. It surfaced only because an operator happened to open the client
# dashboard. That invisibility — not the fault itself — is what made the
# incident expensive.
#
# Two symptoms, both read-only checks:
#   1. SOCKET WITHOUT SUBSCRIPTION — an external peer is established on 8089 but
#      the api JVM lists fewer subscriptions than there are such peers. That is
#      the 10.1.44 pre-API race: traffic flows, the client is invisible forever.
#   2. GROUPLESS SUBSCRIPTION — a subscription whose only group is __ANON__.
#      That is the null-user/LDAP-down case: connected, authenticated to nothing,
#      routed nothing.
#
# WHY IT ONLY DETECTS
# -------------------
# The kill path lives in tak-post-start.sh, bounded to boot. A watcher that
# disconnects live clients on a wrong predicate is how you drop healthy users at
# 3am. Detection must prove the predicate in the field for at least one release
# before anything here is allowed to act. DO NOT ADD `ss -K` TO THIS SCRIPT.
#
# NON-ROOT-COMMANDS: ss, openssl, curl (logged for the v10.0.5 sudoers allowlist).

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
LOGDIR="/var/log/takguard"
LOGFILE="$LOGDIR/session.log"
FAIL_FILE="$STATE_DIR/session.failcount"
COOLDOWN_FILE="$STATE_DIR/session.last_alert"

PORT=8089
API_URL="https://127.0.0.1:8443/Marti/api/subscriptions/all?page=1&limit=1000"
ADMIN_P12="/opt/tak/certs/files/admin.p12"
# The cert password is read at RUNTIME from guarddog.conf (mode 600), never baked
# into this file at deploy time. Every script under /opt/tak-guarddog is written
# 0755, so a substituted cert-password placeholder would put the TAK admin cert
# password in a world-readable file. guarddog.conf already carries it for
# tak-metrics-collector.py.
# (Deliberately no cert-password placeholder token anywhere in this script — the
# deploy substitution is a blind string replace and would rewrite even a comment.)
GD_CONF="/opt/tak-guarddog/guarddog.conf"
# Shared with tak-metrics-collector.py — reuse its extraction when it is present
# rather than re-decrypting the p12 every five minutes.
SHARED_PEM="/opt/tak-guarddog/_marti_admin.pem"
SHARED_KEY="/opt/tak-guarddog/_marti_admin.key"
OWN_PEM="/opt/tak-guarddog/_sessionwatch.pem"
OWN_KEY="/opt/tak-guarddog/_sessionwatch.key"

# ── Fleet constants (no per-box tuning, no operator overrides) ──
MIN_UPTIME_SECS=1200     # 20 min — matches the timer's OnBootSec
STARTUP_GRACE=600        # TAK needs ~5-7 min to finish starting
CONSEC_REQUIRED=3        # 3 consecutive runs (15 min) before anyone is emailed
COOLDOWN_SECS=3600       # one alert per hour at most

# Our own containers and the console's loopback Marti calls are NOT EUDs; they
# are excluded from the socket count so they can never manufacture an alert.
# (Same nets the client gate permits — see tak-client-gate.sh.)
LOCAL_PEER_RE='^(127\.|::1|172\.(1[6-9]|2[0-9]|3[01])\.)'

mkdir -p "$STATE_DIR" "$LOGDIR" 2>/dev/null

_log()  { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') | $1" >> "$LOGFILE"; }
_quiet_exit() { echo 0 > "$FAIL_FILE"; exit 0; }

_cleanup() { rm -f "$OWN_PEM" "$OWN_KEY"; }
trap _cleanup EXIT

# ── Preconditions: never evaluate a box that is still coming up ──
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt "$MIN_UPTIME_SECS" ] && exit 0

_tak_mono=$(systemctl show takserver --property=ActiveEnterTimestampMonotonic --value 2>/dev/null || echo "")
if [ -n "$_tak_mono" ] && [ "$_tak_mono" != "0" ]; then
  _tak_age=$(( UPTIME_SECS - _tak_mono / 1000000 ))
  [ "$_tak_age" -ge 0 ] && [ "$_tak_age" -lt "$STARTUP_GRACE" ] && exit 0
fi

command -v ss >/dev/null 2>&1 || exit 0
command -v python3 >/dev/null 2>&1 || exit 0
ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN || exit 0

# ── 1. External established peers on 8089 ──
EXTERNAL=$(ss -tn state established "( sport = :$PORT )" 2>/dev/null \
  | tail -n +2 | awk '{print $4}' | sed 's/:[0-9]*$//' \
  | grep -Ev "$LOCAL_PEER_RE" | grep -c . || true)
EXTERNAL=${EXTERNAL:-0}

# ── 2. Subscriptions the api JVM knows about ──
_admin_cert() {
  if [ -s "$SHARED_PEM" ] && [ -s "$SHARED_KEY" ]; then
    PEM="$SHARED_PEM"; KEY="$SHARED_KEY"; return 0
  fi
  [ -f "$ADMIN_P12" ] || return 1
  local _p
  _p=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("tak_cert_pass") or "")
except Exception: print("")' "$GD_CONF" 2>/dev/null)
  [ -z "$_p" ] && _p="atakatak"          # TAK's default when no password is set
  # umask BEFORE the redirect: the private key must never exist, even for an
  # instant, at the default 0644. chmod after the fact is a window, not a fix.
  local _um; _um=$(umask); umask 077
  # env: not pass: — an argv password is world-readable in /proc/PID/cmdline for
  # the life of the process. TAK emits RC2-40-CBC, so OpenSSL 3 needs -legacy.
  GD_CERT_PASS="$_p" openssl pkcs12 -in "$ADMIN_P12" -passin env:GD_CERT_PASS -clcerts -nokeys -legacy 2>/dev/null > "$OWN_PEM"
  GD_CERT_PASS="$_p" openssl pkcs12 -in "$ADMIN_P12" -passin env:GD_CERT_PASS -nocerts -nodes  -legacy 2>/dev/null > "$OWN_KEY"
  umask "$_um"
  [ -s "$OWN_PEM" ] && [ -s "$OWN_KEY" ] || return 1
  PEM="$OWN_PEM"; KEY="$OWN_KEY"; return 0
}

_admin_cert || { _log "SKIP | no usable admin cert — cannot query subscriptions"; exit 0; }

SUBS_JSON=$(curl -sk --max-time 15 --cert "$PEM" --key "$KEY" "$API_URL" 2>/dev/null)
# NOTE: this API is PAGINATED and `page` is 1-INDEXED — page=0 returns zero rows.
# If the paginated form yields nothing, retry unparameterized before concluding
# anything: an empty result must never be read as "every client vanished".
if [ -z "$SUBS_JSON" ] || ! echo "$SUBS_JSON" | grep -q '"data"'; then
  SUBS_JSON=$(curl -sk --max-time 15 --cert "$PEM" --key "$KEY" \
    "https://127.0.0.1:8443/Marti/api/subscriptions/all" 2>/dev/null)
fi
if [ -z "$SUBS_JSON" ] || ! echo "$SUBS_JSON" | grep -q '"data"'; then
  _log "SKIP | subscriptions API returned no usable data — not evaluating"
  exit 0
fi

# Parse: total subscriptions, and how many resolve to no real channel.
# SCHEMA TOLERANCE IS DELIBERATE. The exact key carrying groups is not pinned in
# any TAK doc we have, so any record where no group-ish field is found counts as
# UNKNOWN, never as groupless — an alert must never rest on a guessed schema.
# The observed key set is logged once so the next release can pin it.
read -r SUBS GROUPLESS UNKNOWN KEYS <<EOF
$(printf '%s' "$SUBS_JSON" | python3 -c '
import json, sys
try:
    rows = json.load(sys.stdin).get("data") or []
except Exception:
    print("ERR 0 0 -"); sys.exit(0)
if not isinstance(rows, list):
    print("ERR 0 0 -"); sys.exit(0)
groupless = unknown = 0
keys = set()
for r in rows:
    if not isinstance(r, dict):
        unknown += 1; continue
    keys.update(r.keys())
    vals = []
    found = False
    for k, v in r.items():
        if "group" not in k.lower():
            continue
        found = True
        if isinstance(v, list):
            vals += [str(x) for x in v]
        elif isinstance(v, str):
            vals += [p for p in v.replace(",", " ").split() if p]
    if not found:
        unknown += 1; continue
    real = [x for x in vals if x and "__ANON__" not in x]
    if not real:
        groupless += 1
print(len(rows), groupless, unknown, ",".join(sorted(keys)) or "-")
' 2>/dev/null)
EOF
[ -z "$SUBS" ] && SUBS=ERR
if [ "$SUBS" = "ERR" ]; then
  _log "SKIP | could not parse subscriptions payload"
  exit 0
fi

# Record the schema once so a future release can stop guessing at the group key.
if [ ! -f "$STATE_DIR/session.schema" ] && [ "$KEYS" != "-" ]; then
  echo "$KEYS" > "$STATE_DIR/session.schema"
  _log "INFO | subscription record keys: $KEYS"
fi

INVISIBLE=$(( EXTERNAL - SUBS ))
[ "$INVISIBLE" -lt 0 ] && INVISIBLE=0

_log "CHECK | external_sockets=$EXTERNAL subscriptions=$SUBS groupless=$GROUPLESS unknown_schema=$UNKNOWN invisible=$INVISIBLE"

# ── 3. Verdict ──
if [ "$INVISIBLE" -eq 0 ] && [ "$GROUPLESS" -eq 0 ]; then
  _quiet_exit
fi

FAILS=0
[ -f "$FAIL_FILE" ] && FAILS=$(cat "$FAIL_FILE" 2>/dev/null || echo 0)
FAILS=$((FAILS + 1))
echo "$FAILS" > "$FAIL_FILE"
[ "$FAILS" -lt "$CONSEC_REQUIRED" ] && exit 0

NOW=$(date +%s)
LAST=0
[ -f "$COOLDOWN_FILE" ] && LAST=$(cat "$COOLDOWN_FILE" 2>/dev/null || echo 0)
if [ $((NOW - LAST)) -lt "$COOLDOWN_SECS" ]; then
  exit 0
fi
echo "$NOW" > "$COOLDOWN_FILE"

TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
SUBJ="TAK client visibility alert on $SERVER_IDENTIFIER"
BODY="TAK Server has connected clients that it cannot fully account for.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Sustained for: $FAILS consecutive checks (~$((FAILS * 5)) minutes)

What was measured:
- External clients connected on TCP $PORT : $EXTERNAL
- Subscriptions the TAK API reports      : $SUBS
- Connected but INVISIBLE to the API     : $INVISIBLE
- Subscriptions with no channel (__ANON__): $GROUPLESS

What this means:
- INVISIBLE clients are connected and passing traffic, but do not appear in the
  8446 client dashboard and never will. They connected while TAK's api JVM was
  still starting. They do not self-correct.
- __ANON__ subscriptions are connected and authenticated to nothing: no channels,
  so TAK routes them nothing. This is the signature of clients that connected
  while LDAP was unavailable.

Both usually follow a reboot. Nothing has been disconnected — this is a report.

To clear it: restart TAK Server from the console (TAK Server -> Restart). Affected
clients reconnect into a ready server on their own and reappear with their real
channels. If it recurs on every boot, check that the boot client gate is engaging:
  journalctl -t takguard-boot -b | grep 'client gate'

History: $LOGFILE
"

echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi

_log "ALERT | external=$EXTERNAL subs=$SUBS invisible=$INVISIBLE groupless=$GROUPLESS fails=$FAILS"
logger -t takguard "client visibility: $INVISIBLE invisible, $GROUPLESS groupless subscription(s)"
echo 0 > "$FAIL_FILE"
exit 0
