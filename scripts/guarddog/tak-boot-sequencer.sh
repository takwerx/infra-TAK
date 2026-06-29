#!/bin/bash
# Guard Dog Boot Sequencer (Pre-Start)
# ExecStartPre for takserver.service.
#
# 1. Stops all non-essential services (Docker containers + MediaMTX) so TAK
#    Server gets full CPU during its heavy 5-7 minute initialization.
# 2. Waits for PostgreSQL to accept connections.
# 3. Exits → TAK Server starts with full CPU.
#
# Services stopped: Authentik, TAK Portal, CloudTAK, Node-RED, MediaMTX.
# Caddy (reverse proxy) is left running — it's lightweight and harmless.
#
# The companion tak-post-start.sh brings services back up in order
# once TAK is listening on 8089.

MAX_WAIT=120
INTERVAL=5

_log() {
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') boot-sequencer: $1"
  logger -t takguard-boot "$1" 2>/dev/null
}

# Portable TCP probe — RHEL ships no `nc`, so `nc -z host port` exits 127 there.
# bash /dev/tcp is a builtin, identical on Ubuntu / RHEL / ARM.
_tcp_up() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# ── 1. Stop Docker containers so TAK gets full CPU (boot only) ──
# On a real boot, uptime is under a few minutes — stop everything so TAK
# gets full CPU during its heavy 5-7 minute initialization.
# On a manual restart (uptime > 10 min), the containers are already running
# fine and should not be disturbed.
_uptime_sec=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo 9999)
if [ "$_uptime_sec" -lt 600 ]; then
  _log "Boot detected (uptime ${_uptime_sec}s) — stopping Docker containers and MediaMTX to give TAK Server full CPU..."

  for _d in "${HOME:-/home/takwerx}/authentik"; do
    if [ -f "$_d/docker-compose.yml" ]; then
      cd "$_d" && docker compose stop -t 10 2>/dev/null && _log "Authentik containers stopped"
      break
    fi
  done

  docker stop tak-portal 2>/dev/null && _log "TAK Portal stopped"

  for _d in "${HOME:-/home/takwerx}/CloudTAK"; do
    if [ -f "$_d/docker-compose.yml" ]; then
      cd "$_d" && docker compose stop -t 10 2>/dev/null && _log "CloudTAK stopped"
      break
    fi
  done

  for _d in "${HOME:-/home/takwerx}/node-red"; do
    if [ -f "$_d/docker-compose.yml" ]; then
      cd "$_d" && docker compose stop -t 10 2>/dev/null && _log "Node-RED stopped"
      break
    fi
  done

  if systemctl list-unit-files mediamtx.service &>/dev/null && systemctl is-active --quiet mediamtx 2>/dev/null; then
    systemctl stop mediamtx 2>/dev/null && _log "MediaMTX stopped"
  fi
else
  _log "Runtime restart (uptime ${_uptime_sec}s) — skipping container shutdown"
fi

# ── 2. Wait for PostgreSQL ──
_REMOTE_DB=""
if id -u postgres &>/dev/null; then
  # Local PostgreSQL — readiness probe via a TCP connect to the loopback
  # listener (bash builtin /dev/tcp). Universal across distros: needs no
  # sudo/sudoers and no psql on PATH, so it works for the unprivileged 'tak'
  # service user everywhere. The old `sudo -u postgres psql` failed on RHEL —
  # the .rpm ships no sudoers entry for tak (the .deb does) — so the probe
  # never succeeded, the loop burned the full MAX_WAIT, and systemd killed
  # start-pre at TimeoutStartSec → takserver.service failed (timeout).
  # Mirrors the remote-DB branch below, which already uses a pure TCP check.
  _log "Waiting for local PostgreSQL (127.0.0.1:5432)..."
  _t=0
  while [ $_t -lt $MAX_WAIT ]; do
    if (echo > /dev/tcp/127.0.0.1/5432) >/dev/null 2>&1; then
      _log "PostgreSQL ready (${_t}s)"
      break
    fi
    sleep $INTERVAL
    _t=$((_t + INTERVAL))
  done
  [ $_t -ge $MAX_WAIT ] && _log "PostgreSQL not ready after ${MAX_WAIT}s, proceeding anyway"
else
  # No local postgres user — two-server setup, check remote DB via TCP
  if [ -f /opt/tak-guarddog/guarddog.conf ]; then
    _REMOTE_DB=$(grep '^REMOTE_DB_HOST=' /opt/tak-guarddog/guarddog.conf 2>/dev/null | cut -d= -f2 | tr -d '"' | tr -d "'")
  fi
  if [ -z "$_REMOTE_DB" ] && [ -f /opt/tak/CoreConfig.xml ]; then
    _REMOTE_DB=$(grep -oP 'jdbc:postgresql://\K[^:/"]+' /opt/tak/CoreConfig.xml 2>/dev/null | head -1)
    [ "$_REMOTE_DB" = "127.0.0.1" ] || [ "$_REMOTE_DB" = "localhost" ] && _REMOTE_DB=""
  fi
  if [ -n "$_REMOTE_DB" ]; then
    _log "Waiting for remote PostgreSQL ($_REMOTE_DB:5432)..."
    _t=0
    while [ $_t -lt $MAX_WAIT ]; do
      if _tcp_up "$_REMOTE_DB" 5432; then
        _log "Remote PostgreSQL ($_REMOTE_DB) ready (${_t}s)"
        break
      fi
      sleep $INTERVAL
      _t=$((_t + INTERVAL))
    done
    [ $_t -ge $MAX_WAIT ] && _log "Remote PostgreSQL not ready after ${MAX_WAIT}s, proceeding anyway"
  else
    _log "No local PostgreSQL and no remote DB configured — skipping wait"
  fi
fi

_log "Pre-start complete — TAK Server may start with full CPU"
exit 0
