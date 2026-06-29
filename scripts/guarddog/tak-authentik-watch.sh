#!/bin/bash
# Guard Dog: Authentik health monitor.
# Checks both HTTP (server) and LDAP (outpost) independently.
# - HTTP failure × 3 → full down + up -d (stronger than restart)
# - LDAP failure × 3 → targeted LDAP recreate (doesn't nuke the whole stack)
# - 10-min boot grace period, 15-min cooldown between restarts.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
FAIL_HTTP="$STATE_DIR/authentik.failcount"
FAIL_LDAP="$STATE_DIR/authentik_ldap.failcount"
COOLDOWN_HTTP="$STATE_DIR/authentik_last_restart"
COOLDOWN_LDAP="$STATE_DIR/authentik_ldap_last_restart"
MAX_FAILS=3
COOLDOWN_SECS=900

mkdir -p "$STATE_DIR"

UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt 600 ] && exit 0

AK_DIR=""
for _d in "${HOME:-/home/takwerx}/authentik"; do
  [ -f "$_d/docker-compose.yml" ] && AK_DIR="$_d" && break
done
[ -z "$AK_DIR" ] && exit 0

_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
_log() {
  mkdir -p /var/log/takguard
  echo "$(_ts) | authentik-watch | $1" >> /var/log/takguard/restarts.log
}

_alert() {
  local subj="$1" body="$2"
  [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$body" | /opt/tak-guarddog/send-alert-email.sh "$subj" "ALERT_EMAIL_PLACEHOLDER" 2>/dev/null
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    local tmpf="/tmp/gd-sms-$$.txt"
    printf '%s' "$body" > "$tmpf"
    /opt/tak-guarddog/sms_send.sh "$subj" "$tmpf" 2>/dev/null || true
    rm -f "$tmpf"
  fi
}

_cooldown_ok() {
  local cf="$1"
  [ ! -f "$cf" ] && return 0
  local last now
  last=$(cat "$cf")
  now=$(date +%s)
  [ $(( now - last )) -ge $COOLDOWN_SECS ]
}

# Portable TCP liveness probe. RHEL ships NO `nc` by default, so the old
# `nc -z 127.0.0.1 389` exited 127 every check on Rocky — a false "LDAP down" that
# drove an endless 15-min LDAP-recreate loop while the outpost was perfectly healthy
# (and each recreate flapped TAK's LDAP bind). bash /dev/tcp is a builtin, identical
# on Ubuntu / RHEL / ARM. Usage: _tcp_up 127.0.0.1 389
_tcp_up() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# ── HTTP health check (Authentik server) ──
ak_http_ok() {
  local url code
  for url in \
    "http://127.0.0.1:9090/-/health/live/" \
    "http://127.0.0.1:9090/"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null || echo "000")
    case "$code" in
      200|204|301|302) return 0 ;;
    esac
  done
  AK_LAST_CODE="$code"
  return 1
}

HTTP_OK=0
if ak_http_ok; then
  HTTP_OK=1
else
  sleep 3
  ak_http_ok && HTTP_OK=1
fi

if [ "$HTTP_OK" -eq 1 ]; then
  echo 0 > "$FAIL_HTTP"
else
  CODE="${AK_LAST_CODE:-000}"
  FAILS=$(( $(cat "$FAIL_HTTP" 2>/dev/null || echo 0) + 1 ))
  echo "$FAILS" > "$FAIL_HTTP"

  if [ "$FAILS" -ge "$MAX_FAILS" ] && _cooldown_ok "$COOLDOWN_HTTP"; then
    _log "restart | Authentik HTTP unhealthy ($CODE) for $FAILS checks — full restart"
    SUBJ="Guard Dog: Authentik restarted on $SERVER_IDENTIFIER"
    BODY="Authentik server failed HTTP health check (HTTP $CODE) for $FAILS consecutive checks.

Server: $SERVER_IDENTIFIER
Time (UTC): $(_ts)
Action: Full restart (docker compose down + up -d).
"
    _alert "$SUBJ" "$BODY"
    cd "$AK_DIR" && docker compose down --timeout 30 2>&1 && docker compose up -d 2>&1
    echo 0 > "$FAIL_HTTP"
    echo 0 > "$FAIL_LDAP"
    date +%s > "$COOLDOWN_HTTP"
    date +%s > "$COOLDOWN_LDAP"
    exit 0
  fi
fi

# ── LDAP health check (outpost on port 389) ──
# Only check LDAP if HTTP is OK (no point if the whole stack is down)
if [ "$HTTP_OK" -eq 1 ]; then
  LDAP_OK=0

  if _tcp_up 127.0.0.1 389; then
    LDAP_OK=1
  else
    sleep 3
    _tcp_up 127.0.0.1 389 && LDAP_OK=1
  fi

  if [ "$LDAP_OK" -eq 1 ]; then
    echo 0 > "$FAIL_LDAP"
  else
    LDAP_FAILS=$(( $(cat "$FAIL_LDAP" 2>/dev/null || echo 0) + 1 ))
    echo "$LDAP_FAILS" > "$FAIL_LDAP"

    if [ "$LDAP_FAILS" -ge "$MAX_FAILS" ] && _cooldown_ok "$COOLDOWN_LDAP"; then
      _log "restart | LDAP outpost down for $LDAP_FAILS checks — recreating LDAP container"
      SUBJ="Guard Dog: Authentik LDAP restarted on $SERVER_IDENTIFIER"
      BODY="Authentik LDAP outpost (port 389) failed health check for $LDAP_FAILS consecutive checks.
Authentik server HTTP is healthy — only the LDAP container is being restarted.

Server: $SERVER_IDENTIFIER
Time (UTC): $(_ts)
Action: Force-recreating LDAP container only (docker compose up -d --force-recreate ldap).
"
      _alert "$SUBJ" "$BODY"
      cd "$AK_DIR" && docker compose up -d --force-recreate ldap 2>&1
      echo 0 > "$FAIL_LDAP"
      date +%s > "$COOLDOWN_LDAP"
    fi
  fi
fi
