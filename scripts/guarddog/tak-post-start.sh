#!/bin/bash
# Guard Dog Post-Start Orchestrator
# Runs as a separate systemd oneshot after takserver.service.
#
# Waits for TAK Server to be fully listening on 8089, then starts
# every service in order:
#   1. Authentik (LDAP + SSO) — waits for healthy
#   2. TAK Portal
#   3. CloudTAK
#   4. Node-RED
#   5. MediaMTX
#
# Each service is given time to stabilize before the next one starts.
# Only starts services that are actually installed; skips the rest.
# Companion to tak-boot-sequencer.sh which stops these before TAK starts.

MAX_WAIT_TAK=900
MAX_WAIT_AK=300
INTERVAL=10

_log() {
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') post-start: $1"
  logger -t takguard-boot "$1" 2>/dev/null
}

# ── 1. Wait for TAK Server to be listening on 8089 ──
_log "Waiting for TAK Server port 8089..."
_t=0
_msg_restarted=0
while [ $_t -lt $MAX_WAIT_TAK ]; do
  if ss -ltn "sport = :8089" 2>/dev/null | grep -q LISTEN; then
    _log "TAK Server 8089 ready (${_t}s)"
    break
  fi

  if [ $_t -ge 120 ] && [ $_msg_restarted -eq 0 ] && [ $((_t % 60)) -eq 0 ]; then
    if grep -q "Started TAK Server config Microservice" /opt/tak/logs/takserver-config.log 2>/dev/null; then
      if ! pgrep -f "spring.profiles.active=messaging" >/dev/null 2>&1; then
        _log "Config ready but messaging crashed — restarting messaging"
        service takserver-messaging start 2>/dev/null
        _msg_restarted=1
      fi
    fi
  fi

  sleep $INTERVAL
  _t=$((_t + INTERVAL))
done
if [ $_t -ge $MAX_WAIT_TAK ]; then
  _log "TAK Server 8089 not ready after ${MAX_WAIT_TAK}s — starting remaining services anyway"
fi

# ── 2. Start Authentik ──
AK_DIR=""
for _d in "${HOME:-/home/takwerx}/authentik"; do
  [ -f "$_d/docker-compose.yml" ] && AK_DIR="$_d" && break
done

if [ -n "$AK_DIR" ]; then
  cd "$AK_DIR"

  # Stagger: start PostgreSQL first and wait for it to accept connections
  _log "Starting Authentik PostgreSQL..."
  docker compose up -d postgresql 2>/dev/null
  _pg_t=0
  while [ $_pg_t -lt 60 ]; do
    if docker compose exec -T postgresql pg_isready -U authentik 2>/dev/null; then
      _log "PostgreSQL ready (${_pg_t}s)"
      break
    fi
    sleep 2
    _pg_t=$((_pg_t + 2))
  done
  [ $_pg_t -ge 60 ] && _log "PostgreSQL not ready after 60s, starting server anyway"

  # Start remaining services (compose depends_on handles ordering)
  _log "Starting Authentik server and worker..."
  docker compose up -d 2>/dev/null

  _t=0
  while [ $_t -lt $MAX_WAIT_AK ]; do
    _status=$(docker ps --filter name=authentik-server --format '{{.Status}}' 2>/dev/null || echo "")
    if echo "$_status" | grep -q "healthy"; then
      _log "Authentik server healthy (${_t}s)"
      break
    fi
    sleep $INTERVAL
    _t=$((_t + INTERVAL))
  done
  [ $_t -ge $MAX_WAIT_AK ] && _log "Authentik server not healthy after ${MAX_WAIT_AK}s, continuing"

  # Verify LDAP outpost is responding (already started by compose up -d above)
  _log "Checking LDAP outpost (port 389)..."
  _t=0
  _MAX_LDAP=120
  while [ $_t -lt $_MAX_LDAP ]; do
    if nc -z 127.0.0.1 389 2>/dev/null; then
      _log "LDAP outpost ready (${_t}s)"
      break
    fi
    sleep $INTERVAL
    _t=$((_t + INTERVAL))
  done
  if [ $_t -ge $_MAX_LDAP ]; then
    _log "LDAP not responding after ${_MAX_LDAP}s — force-recreating LDAP container"
    cd "$AK_DIR" && docker compose up -d --force-recreate ldap 2>/dev/null
    sleep 30
    if nc -z 127.0.0.1 389 2>/dev/null; then
      _log "LDAP outpost recovered after recreate"
    else
      _log "LDAP still not responding — Guard Dog will monitor"
    fi
  fi
else
  _log "Authentik not installed, skipping"
fi

# ── 3. Start TAK Portal ──
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^tak-portal$'; then
  _log "Starting TAK Portal..."
  docker start tak-portal 2>/dev/null
  sleep 10
  _log "TAK Portal started"
else
  _log "TAK Portal not found, skipping"
fi

# ── 4. Start CloudTAK ──
# Stagger Docker starts to avoid iptables churn that disrupts TAK Server connections
CT_DIR=""
for _d in "${HOME:-/home/takwerx}/CloudTAK"; do
  [ -f "$_d/docker-compose.yml" ] && CT_DIR="$_d" && break
done

if [ -n "$CT_DIR" ]; then
  _log "Starting CloudTAK (30s stagger to protect TAK connections)..."
  sleep 30
  cd "$CT_DIR" && docker compose up -d 2>/dev/null
  sleep 15
  _log "CloudTAK started"
else
  _log "CloudTAK not installed, skipping"
fi

# ── 5. Start Node-RED ──
NR_DIR=""
for _d in "${HOME:-/home/takwerx}/node-red"; do
  [ -f "$_d/docker-compose.yml" ] && NR_DIR="$_d" && break
done

if [ -n "$NR_DIR" ]; then
  _log "Starting Node-RED (30s stagger to protect TAK connections)..."
  sleep 30
  cd "$NR_DIR" && docker compose up -d 2>/dev/null
  sleep 15
  _log "Node-RED started"
else
  _log "Node-RED not installed, skipping"
fi

# ── 6. Start MediaMTX ──
# MediaMTX is systemd-native (no Docker iptables impact), shorter stagger is fine
if systemctl list-unit-files mediamtx.service &>/dev/null; then
  _log "Starting MediaMTX..."
  sleep 10
  systemctl start mediamtx 2>/dev/null
  sleep 5
  if systemctl is-active --quiet mediamtx 2>/dev/null; then
    _log "MediaMTX running"
  else
    _log "MediaMTX failed to start (Guard Dog will retry later)"
  fi
else
  _log "MediaMTX not installed, skipping"
fi

_log "Boot sequence complete — all services started"
exit 0
