#!/bin/bash
# Guard Dog Post-Start Orchestrator
# Runs as a separate systemd oneshot after takserver.service.
#
# Starts every service in order:
#   1. Authentik (LDAP + SSO) — waits for the LDAP outpost on 389
#   2. (wait for TAK Server 8089)
#   3. TAK Portal
#   4. CloudTAK
#   5. Node-RED
#   6. MediaMTX
#
# Each service is given time to stabilize before the next one starts.
# Only starts services that are actually installed; skips the rest.
# Companion to tak-boot-sequencer.sh which stops these before TAK starts.
#
# v10.1.44 (W1) — AUTHENTIK STARTS BEFORE THE 8089 WAIT, NOT AFTER. This order is
# load-bearing; do not "tidy" it back.
#
# Until 10.1.44 this script waited for TAK's 8089 to LISTEN and only THEN started
# Authentik. Since tak-boot-sequencer.sh stops Authentik before TAK starts, that
# left a window — measured 42s (test6), 61-62s (test6/test12) — in which TAK was
# accepting client connections with LDAP down. An EUD reconnecting inside it got a
# subscription with a NULL USER:
#
#   Added Subscription: id=tls:3 source=<eud>
#   ERROR DistributedSubscriptionManager - found subscription with null user!
#   ERROR DistributedPersistentGroupManager - LDAP connection has been closed
#
# The subscription is never removed, the TCP socket stays ESTABLISHED forever, and
# ATAK shows a healthy green connection — while TAK routes the client nothing and
# it appears in no channel. It never self-heals: the client sees a good socket and
# never reconnects. Reproduced live on test6 2026-08-22; field-reported on a
# production public-safety deployment 2026-08-21.
#
# TAK takes 110-170s to open 8089; Authentik reaches a live LDAP outpost in ~40-60s.
# Starting Authentik first therefore has LDAP up well before TAK can accept anyone,
# and costs nothing at the tail: the heavy consumers (CloudTAK, Node-RED, MediaMTX)
# still start after 8089, which is what the boot sequencer's CPU-headroom design was
# actually protecting.
#
# RESIDUAL RACE (not closed here): if TAK ever opens 8089 before Authentik's LDAP is
# up — a warm restart, an unusually slow Authentik — the window reopens. Closing it
# for good needs a hard gate (hold TAK's client ports until 389 answers) plus reaping
# null-user subscriptions so a client that slips through reconnects instead of
# camping on a dead socket. Both are tracked for 10.1.45.

# v10.0.1: container-aware via _gd-tak-lib.sh. The 8089 wait and service
# orchestration are host-level and unchanged; only the "messaging crashed"
# fallback restart targets the takserver container in container mode.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

MAX_WAIT_TAK=900
MAX_WAIT_AK=300
INTERVAL=10

_log() {
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') post-start: $1"
  logger -t takguard-boot "$1" 2>/dev/null
}

# ── 1. Start Authentik FIRST — TAK cannot authenticate anyone without LDAP ──
# v10.1.44 (W2): $HOME is EMPTY in a systemd unit — never resolve the stack
# dir from it alone. gd_find_stack_dir() asks the container itself first.
AK_DIR="$(gd_find_stack_dir authentik authentik-server-1)"

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
    if gd_tcp_up 127.0.0.1 389; then
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
    if gd_tcp_up 127.0.0.1 389; then
      _log "LDAP outpost recovered after recreate"
    else
      _log "LDAP still not responding — Guard Dog will monitor"
    fi
  fi
else
  _log "Authentik not installed, skipping"
fi

# ── 2. Wait for TAK Server to be listening on 8089 ──
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
      if ! gd_tak_pgrep "spring.profiles.active=messaging"; then
        _log "Config ready but messaging crashed — restarting messaging"
        if gd_is_container; then
          # All JVMs share one container — restart it to recover messaging.
          gd_tak_restart
        else
          service takserver-messaging start 2>/dev/null
        fi
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

# ── 3. Recycle sessions that connected before TAK's API was ready ──
#
# v10.1.44 (W4). TAK opens 8089 from the *messaging* JVM, but the dashboard and
# every /Marti/api/* view are served by the *api* JVM, which finishes starting
# LATER. Measured on test6 across every boot on record (Jun 4 - Aug 22): the gap
# between "Netty started on 8089" and "Started TAK Server api Microservice" runs
# 5.5s to 23.6s. It is inherent to TAK, not something infra-TAK introduced.
#
# A client that connects inside that gap gets a working session — messaging routes
# it, traffic flows both ways, groups resolve correctly — but the api JVM never
# learns about the subscription, so the client is INVISIBLE in the 8446 client
# dashboard and in /Marti/api/subscriptions/all. It never self-corrects, because
# nothing is actually wrong from the client's side.
#
# Proven on test6 2026-08-22: an ATAK client connecting 10s after 8089 opened
# (4.3s before the api microservice finished) passed traffic continuously but did
# not appear in the dashboard. Killing its socket made ATAK reconnect on its own
# within a minute, and it appeared immediately with its correct channels.
#
# This is what the operator of a large deployment sees as "a lot of missing users"
# after a reboot: hundreds of EUDs all reconnect the instant 8089 opens, so a large
# share of them land inside the window every time.
#
# Fix: once the api JVM is genuinely up, recycle exactly the sockets that were
# already connected when it came up. Those are precisely the ones that raced it.
# Each client reconnects itself into a fully-ready server. Cost is one reconnect
# for the affected clients; doing nothing leaves them invisible until someone
# notices and toggles them by hand.
#
# Deliberately NOT a firewall gate on 8089: a bug in that locks every EUD out of a
# public-safety server with no safe failure mode. The worst case here is a spurious
# reconnect.
#
# SAFETY: `ss -K` with no filter destroys EVERY socket on the box, including SSH.
# Every kill below is filtered to one exact peer address+port AND sport = :8089.
# Never add an unfiltered `ss -K` to this script.
_api_ready=0
_t=0
_MAX_API=300
_log "Waiting for TAK Server API microservice (8443)..."
while [ $_t -lt $_MAX_API ]; do
  if gd_tcp_up 127.0.0.1 8443; then
    _api_ready=1
    _log "TAK API responding on 8443 (${_t}s)"
    break
  fi
  sleep $INTERVAL
  _t=$((_t + INTERVAL))
done

if [ $_api_ready -eq 0 ]; then
  _log "TAK API not up after ${_MAX_API}s — skipping session recycle (fail safe: change nothing)"
elif ! command -v ss >/dev/null 2>&1; then
  _log "ss not available — skipping session recycle"
else
  # Snapshot the peers already connected at the moment the API came up. Anything
  # connecting after this point talks to a ready server and is left alone.
  _early=$(ss -tn state established "( sport = :8089 )" 2>/dev/null | tail -n +2 | awk '{print $4}' | grep -E '^[0-9a-fA-F:.]+:[0-9]+$')
  _n=$(printf '%s\n' "$_early" | grep -c . || true)
  if [ "${_n:-0}" -eq 0 ]; then
    _log "No clients connected before the API was ready — nothing to recycle"
  else
    # Let anything that CAN still register do so before we judge it.
    sleep 20
    _killed=0
    for _peer in $_early; do
      _ip="${_peer%:*}"
      _port="${_peer##*:}"
      [ -z "$_ip" ] && continue
      [ -z "$_port" ] && continue
      # Still connected? (it may have gone away during the settle)
      if ! ss -tn state established "( sport = :8089 )" "dst $_ip and dport = $_port" 2>/dev/null | tail -n +2 | grep -q .; then
        continue
      fi
      if ss -K state established "( sport = :8089 )" "dst $_ip and dport = $_port" >/dev/null 2>&1; then
        _killed=$((_killed + 1))
        _log "Recycled pre-API session $_peer (client will reconnect itself)"
      else
        _log "Could not recycle $_peer (kernel may lack INET_DIAG_DESTROY) — leaving it"
      fi
    done
    _log "Session recycle complete — $_killed of $_n pre-API session(s) recycled"
  fi
fi

# ── 4. Start TAK Portal ──
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^tak-portal$'; then
  _log "Starting TAK Portal..."
  docker start tak-portal 2>/dev/null
  sleep 10
  _log "TAK Portal started"
else
  _log "TAK Portal not found, skipping"
fi

# ── 5. Start CloudTAK ──
# Stagger Docker starts to avoid iptables churn that disrupts TAK Server connections
# v10.1.44 (W2): $HOME is EMPTY in a systemd unit — never resolve the stack
# dir from it alone. gd_find_stack_dir() asks the container itself first.
CT_DIR="$(gd_find_stack_dir CloudTAK cloudtak-api-1)"

if [ -n "$CT_DIR" ]; then
  _log "Starting CloudTAK (30s stagger to protect TAK connections)..."
  sleep 30
  cd "$CT_DIR" && docker compose up -d 2>/dev/null
  sleep 15
  _log "CloudTAK started"
else
  _log "CloudTAK not installed, skipping"
fi

# ── 6. Start Node-RED ──
# v10.1.44 (W2): $HOME is EMPTY in a systemd unit — never resolve the stack
# dir from it alone. gd_find_stack_dir() asks the container itself first.
NR_DIR="$(gd_find_stack_dir node-red nodered)"

if [ -n "$NR_DIR" ]; then
  _log "Starting Node-RED (30s stagger to protect TAK connections)..."
  sleep 30
  cd "$NR_DIR" && docker compose up -d 2>/dev/null
  sleep 15
  _log "Node-RED started"
else
  _log "Node-RED not installed, skipping"
fi

# ── 7. Start MediaMTX ──
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
