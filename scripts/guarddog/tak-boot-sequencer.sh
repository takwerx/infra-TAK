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

# v10.1.44 (W2): source the shared lib for gd_find_stack_dir() — $HOME is
# EMPTY in a systemd unit, so the old "${HOME:-/home/takwerx}/<stack>" globs
# silently missed /root-era installs and this script stopped NOTHING.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

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
  # ── 0. Hold the client port shut until TAK can actually account for clients ──
  # v10.1.46 (W1). TAK opens 8089 from the messaging JVM but serves the client
  # dashboard and /Marti/api/* from the api JVM, which finishes 5.5-30s LATER.
  # Anything that connects in that gap works but is invisible to the api JVM
  # forever. tak-post-start.sh releases the gate the instant 8443 answers; a
  # trap there, an independent takclientgate.timer backstop at OnBootSec=15min,
  # and a console-startup sweep all release it independently — and the rules are
  # runtime-only on both families, so a reboot clears them regardless. The gate
  # script fails OPEN on every error — a box that cannot gate simply behaves like
  # 10.1.44, where the post-start sweeper still recycles the racers.
  # This runs as ExecStartPre, so the gate is up before TAK's first listener.
  # ── HELD FOR 10.1.47 — DO NOT RE-ENABLE WITHOUT READING THIS ──────────────
  # The gate is NOT inserted in 10.1.46. It works on Debian (proven three times on
  # test6/test8, including with a live EUD and the backstop test) but NOT on RHEL:
  #
  #   06:06:41  boot-sequencer: client gate ENGAGED on 8089 (firewalld)
  #   06:06:48  docker starts
  #   06:06:50  console startup hardening runs firewall-cmd
  #   06:08:xx  post-start: client gate not engaged — nothing to release
  #
  # firewalld runtime rich rules do not survive boot on a box where Docker and the
  # console's own hardening both touch the firewall seconds later — the same class
  # of failure that killed the ufw-chain approach on Debian (see tak-client-gate.sh
  # header). infra-TAK is multiplatform by hard requirement: a gate that only works
  # on Ubuntu does not land.
  #
  # 10.1.47 unifies both families on the RAW table (already proven on Debian), which
  # is untouched by ufw reloads and should likewise be untouched by firewalld ones.
  # That needs verifying as root on a RHEL box first — it could not be verified from
  # the dev Mac because the broker (correctly) allows neither `iptables` nor an
  # arbitrary `systemd-run` unit.
  #
  # Everything else stays installed on purpose: tak-client-gate.sh, takclientgate.timer
  # and the console-startup sweep all still run, so any stray gate left by a box that
  # ran a 10.1.46 dev build gets cleaned up rather than stranded.
  #
  # To re-enable: restore the single line below AND land the raw-table unification.
  #   GATE_LOG_PREFIX="boot-sequencer" /opt/tak-guarddog/tak-client-gate.sh insert || true

  _log "Boot detected (uptime ${_uptime_sec}s) — stopping Docker containers and MediaMTX to give TAK Server full CPU..."

  _ak_d="$(gd_find_stack_dir authentik authentik-server-1)"
  if [ -n "$_ak_d" ]; then
    cd "$_ak_d" && docker compose stop -t 10 2>/dev/null && _log "Authentik containers stopped"
  else
    # Last resort: stop by container name so `restart: unless-stopped` cannot
    # race TAK's start even when no compose dir is discoverable.
    docker stop -t 10 authentik-server-1 authentik-worker-1 authentik-ldap-1 2>/dev/null \
      && _log "Authentik containers stopped (by name — no compose dir found)"
  fi

  docker stop tak-portal 2>/dev/null && _log "TAK Portal stopped"

  _ct_d="$(gd_find_stack_dir CloudTAK cloudtak-api-1)"
  if [ -n "$_ct_d" ]; then
    cd "$_ct_d" && docker compose stop -t 10 2>/dev/null && _log "CloudTAK stopped"
  fi

  _nr_d="$(gd_find_stack_dir node-red nodered)"
  if [ -n "$_nr_d" ]; then
    cd "$_nr_d" && docker compose stop -t 10 2>/dev/null && _log "Node-RED stopped"
  else
    # Node-RED's feeds connect the instant 8089 opens. If it is not stopped here,
    # `restart: unless-stopped` starts it alongside TAK and every feed binds with
    # no LDAP behind it. Stop it by name rather than let that happen.
    docker stop -t 10 nodered 2>/dev/null \
      && _log "Node-RED stopped (by name — no compose dir found)"
  fi

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
