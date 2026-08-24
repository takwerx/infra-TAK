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
#   3. CONNECTION STORM (v10.1.47 W2) — one DEVICE holding hundreds or thousands
#      of concurrent connections. Field report 2026-08-24: ~3000 TLS connections
#      from a single EUD running a beta WinTAK tracker. Nothing detected it.
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

# ── W2 connection-storm thresholds (v10.1.47) ──
# Provenance, stated plainly because it is not symmetrical: the FLOOR is ours and
# measured; the CEILING is a single field report.
#   Floor  - Guard Dog's metrics collector has recorded conn_count on :8089 every
#            30s since v0.9.47. Pulled 2026-08-24: 80,663 samples over 7 days on
#            four boxes. Fleet-wide ceiling 9 TOTAL concurrent connections per box.
#            Per real device, measured from the subscriptions API: 1.
#   Ceiling- one operator field report of ~3000 connections from one device.
# The two ends are three orders of magnitude apart, so any threshold in the wide
# middle cannot fire on a healthy device and cannot miss that storm. These are NOT
# tuned against a storm we instrumented; nobody should read them as precise.
STORM_UID_SUBS=50        # one non-empty clientUid holding >= this many subscriptions
STORM_IP_SOCKETS=100     # one external peer IP holding >= this many sockets on 8089
STORM_IP_RATIO=25        # ...AND that many sockets per distinct uid behind that IP.
                         # A NAT'd agency is 3000 sockets / 400 uids = 7.5 and must
                         # never alert; one storming device is 3000 / 1 = 3000.

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
# Collected once, used twice: the total (invisible-client check) and the per-IP
# breakdown (storm check). Peer IPs are taken from the socket table rather than
# from the subscriptions API on purpose — a storming client can hold sockets that
# never became subscriptions, and that is precisely the case worth seeing.
PEER_IPS=$(ss -tn state established "( sport = :$PORT )" 2>/dev/null \
  | tail -n +2 | awk '{print $4}' | sed 's/:[0-9]*$//' \
  | grep -Ev "$LOCAL_PEER_RE" || true)
EXTERNAL=$(printf '%s\n' "$PEER_IPS" | grep -c . || true)
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

# Parse the subscription payload: channel health (W2 of 10.1.46) plus the
# per-device connection counts (W2 of 10.1.47).
#
# SCHEMA IS NOW PINNED (v10.1.47 W4). 10.1.46 shipped a schema-TOLERANT parser
# because the key carrying groups was not pinned in any TAK doc we had; it
# happened to be correct by stringifying whatever it found. Live data from the
# fleet settled it:
#   groups = [ {name, direction, created, type, bitpos, active}, ... ]
# so read g["name"]. Each channel appears TWICE (direction IN and OUT), which is
# why names are de-duplicated before deciding a subscription is groupless.
# The UNKNOWN counter is kept: a record that does not match the pinned shape is
# counted as unknown, never as groupless. An alert must never rest on a guess.
#
# Two traps the live data confirmed, both of which a naive counter walks into:
#   - clientUid is EMPTY on most subscriptions (9 of 10 on test12: admin, feeds,
#     container connections). Counting empty uids buckets unrelated rows together
#     and alerts on a healthy box on day one. Empty uids are excluded outright.
#   - username is NOT device identity. admin legitimately holds 6 subscriptions,
#     and one cert used across ATAK/WinTAK/iTAK/TAK Aware is expected and normal.
#     Never key the storm check on username.
read -r SUBS GROUPLESS UNKNOWN TOPUID TOPUIDN TOPCLIENT TOPVER TOPIP TOPIPSOCK TOPIPUIDS KEYS <<EOF
$(printf '%s' "$SUBS_JSON" | PEER_IPS="$PEER_IPS" python3 -c '
import json, os, sys, collections
def out(*a): print(" ".join(str(x) for x in a))
try:
    rows = json.load(sys.stdin).get("data") or []
except Exception:
    out("ERR",0,0,"-",0,"-","-","-",0,0,"-"); sys.exit(0)
if not isinstance(rows, list):
    out("ERR",0,0,"-",0,"-","-","-",0,0,"-"); sys.exit(0)

groupless = unknown = 0
keys = set()
uid_subs = collections.Counter()        # non-empty clientUid -> subscriptions
ip_uids  = collections.defaultdict(set) # peer ip -> distinct non-empty uids
uid_meta = {}                           # uid -> (takClient, takVersion)

for r in rows:
    if not isinstance(r, dict):
        unknown += 1; continue
    keys.update(r.keys())

    g = r.get("groups")
    if isinstance(g, list):
        names = {x.get("name") for x in g
                 if isinstance(x, dict) and isinstance(x.get("name"), str)}
        if not names and g:
            unknown += 1          # a list, but not the pinned shape
        elif not [n for n in names if "__ANON__" not in n]:
            groupless += 1
    else:
        unknown += 1              # not the pinned shape at all

    uid = (r.get("clientUid") or "").strip()
    if uid:                       # empty uid is never device identity
        uid_subs[uid] += 1
        ip = (r.get("ipAddress") or "").strip()
        if ip:
            ip_uids[ip].add(uid)
        if uid not in uid_meta:
            uid_meta[uid] = ((r.get("takClient") or "-").replace(" ", "_") or "-",
                             (r.get("takVersion") or "-").split()[0] or "-")

top_uid, top_n = ("-", 0)
if uid_subs:
    top_uid, top_n = uid_subs.most_common(1)[0]
tc, tv = uid_meta.get(top_uid, ("-", "-"))

# Socket counts come from ss (passed in), uid distinctness from the API above.
sock = collections.Counter()
for line in (os.environ.get("PEER_IPS") or "").split():
    if line.strip():
        sock[line.strip()] += 1
top_ip, top_sock, top_ipuids = ("-", 0, 0)
if sock:
    top_ip, top_sock = sock.most_common(1)[0]
    top_ipuids = len(ip_uids.get(top_ip, ()))

out(len(rows), groupless, unknown,
    top_uid[:64] or "-", top_n, tc[:24] or "-", tv[:24] or "-",
    top_ip, top_sock, top_ipuids,
    ",".join(sorted(keys)) or "-")
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

# ── W2 (v10.1.47): connection storms ──
# Two independent predicates. The uid one is the primary signal — it is device
# identity straight from TAK. The IP one is the backstop for a client storming
# without ever registering subscriptions, and it is ratio-qualified so a NAT'd
# agency behind one public address can never look like one storming device.
STORM_UID=0
STORM_IP=0
[ "${TOPUIDN:-0}" -ge "$STORM_UID_SUBS" ] && STORM_UID=1
if [ "${TOPIPSOCK:-0}" -ge "$STORM_IP_SOCKETS" ]; then
  _d=${TOPIPUIDS:-0}; [ "$_d" -lt 1 ] && _d=1
  [ $(( TOPIPSOCK / _d )) -ge "$STORM_IP_RATIO" ] && STORM_IP=1
fi

_log "CHECK | external_sockets=$EXTERNAL subscriptions=$SUBS groupless=$GROUPLESS unknown_schema=$UNKNOWN invisible=$INVISIBLE top_uid=$TOPUID/$TOPUIDN top_ip=$TOPIP/$TOPIPSOCK sockets/$TOPIPUIDS uids storm_uid=$STORM_UID storm_ip=$STORM_IP"

# ── 3. Verdict ──
if [ "$INVISIBLE" -eq 0 ] && [ "$GROUPLESS" -eq 0 ] \
   && [ "$STORM_UID" -eq 0 ] && [ "$STORM_IP" -eq 0 ]; then
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

# v10.1.47 W3: the remedy is per-symptom. 10.1.46 told every reader to restart
# TAK Server. That is right for an INVISIBLE client and wrong for an account that
# has no channel assigned — no number of restarts gives an account a channel, and
# pointing a customer at the wrong remedy costs them a reboot and their trust.
# It is also wrong for a storm, where the correct action is to look at the client.
SUBJ="TAK client visibility alert on $SERVER_IDENTIFIER"
if [ "$STORM_UID" -eq 1 ] || [ "$STORM_IP" -eq 1 ]; then
  if [ "$INVISIBLE" -eq 0 ] && [ "$GROUPLESS" -eq 0 ]; then
    SUBJ="TAK connection storm on $SERVER_IDENTIFIER"
  else
    SUBJ="TAK client visibility alert + connection storm on $SERVER_IDENTIFIER"
  fi
fi

FINDINGS=""
ACTIONS=""

if [ "$INVISIBLE" -gt 0 ]; then
  FINDINGS="$FINDINGS
- INVISIBLE clients: $INVISIBLE
  Connected on TCP $PORT and passing traffic, but absent from the 8446 client
  dashboard and they never will appear. They connected while TAK's api JVM was
  still starting. They do not self-correct.
  (external clients connected: $EXTERNAL / subscriptions the API reports: $SUBS)"
  ACTIONS="$ACTIONS
- For the INVISIBLE clients: restart TAK Server from the console
  (TAK Server -> Restart). They reconnect into a ready server on their own and
  reappear with their real channels. If this recurs on every boot, check the boot
  client gate is engaging:  journalctl -t takguard-boot -b | grep 'client gate'"
fi

if [ "$GROUPLESS" -gt 0 ]; then
  FINDINGS="$FINDINGS
- Subscriptions with no channel (__ANON__): $GROUPLESS
  Connected and authenticated, but holding no channel, so TAK routes them
  nothing."
  ACTIONS="$ACTIONS
- For the __ANON__ subscriptions: there are two different causes and they need
  different fixes.
    * If they appeared after a reboot, they connected while LDAP was still
      unavailable. Restarting TAK Server clears those.
    * If they persist after a restart, or the same account keeps coming back
      __ANON__, the ACCOUNT HAS NO CHANNEL ASSIGNED. Restarting will not fix it.
      Assign the user a channel (TAK Portal -> the user -> channels), then have
      them reconnect."
fi

if [ "$STORM_UID" -eq 1 ]; then
  FINDINGS="$FINDINGS
- CONNECTION STORM from one device: $TOPUIDN concurrent connections
  Device (clientUid): $TOPUID
  Client / version  : $TOPCLIENT $TOPVER
  A healthy device holds 1. The alert threshold is $STORM_UID_SUBS."
fi

if [ "$STORM_IP" -eq 1 ]; then
  FINDINGS="$FINDINGS
- CONNECTION STORM from one address: $TOPIPSOCK sockets from $TOPIP
  Distinct devices behind that address: $TOPIPUIDS
  A site with many devices spreads its connections across them; this address is
  concentrating them on very few, which is what a misbehaving client looks like."
fi

if [ "$STORM_UID" -eq 1 ] || [ "$STORM_IP" -eq 1 ]; then
  ACTIONS="$ACTIONS
- For the CONNECTION STORM: nothing has been disconnected, deliberately. Dropping
  thousands of sockets on a wrong guess is worse than the storm. Identify the
  device above and check its client build - storms so far have come from
  pre-release clients, and the fix is on the client side. A single cert used
  across ATAK / WinTAK / iTAK / TAK Aware at once is NORMAL and is not this:
  those are separate devices with separate uids."
fi

BODY="TAK Server has connected clients that it cannot fully account for.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Sustained for: $FAILS consecutive checks (~$((FAILS * 5)) minutes)

WHAT WAS FOUND
$FINDINGS

WHAT TO DO
$ACTIONS

Nothing has been disconnected or restarted - this is a report.

History: $LOGFILE
"

echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi

_log "ALERT | external=$EXTERNAL subs=$SUBS invisible=$INVISIBLE groupless=$GROUPLESS storm_uid=$STORM_UID($TOPUID/$TOPUIDN) storm_ip=$STORM_IP($TOPIP/$TOPIPSOCK) fails=$FAILS"
logger -t takguard "client visibility: $INVISIBLE invisible, $GROUPLESS groupless, storm_uid=$STORM_UID storm_ip=$STORM_IP"
echo 0 > "$FAIL_FILE"
exit 0
