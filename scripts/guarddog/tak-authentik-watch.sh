#!/bin/bash
# Guard Dog: Authentik health monitor.
# Checks both HTTP (server) and LDAP (outpost) independently.
# - HTTP failure × 3 → restart server+worker; a second escalation within 6h → full down + up -d
# - HTTP failure while the host is CPU-starved → hold and alert, do not restart (GH #111)
# - LDAP failure × 3 → targeted LDAP recreate (doesn't nuke the whole stack)
# - LDAP flow herd that does not drain (8 of the last 10 min busy) → same restart as HTTP (ops #38),
#   held while it is clearly falling from its peak (ops #64)
# - 10-min boot grace period; HTTP cooldown 15 min, doubling per restart in the last 6h (max 2h).

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
FAIL_HTTP="$STATE_DIR/authentik.failcount"
FAIL_LDAP="$STATE_DIR/authentik_ldap.failcount"
COOLDOWN_HTTP="$STATE_DIR/authentik_last_restart"
COOLDOWN_LDAP="$STATE_DIR/authentik_ldap_last_restart"
RESTART_HIST="$STATE_DIR/authentik_restart_history"
HOLD_SINCE="$STATE_DIR/authentik_hold_since"
HOLD_ALERTED="$STATE_DIR/authentik_hold_alerted"
MAX_FAILS=3
COOLDOWN_SECS=900
COOLDOWN_MAX_SECS=7200
HISTORY_WINDOW_SECS=21600
HOLD_MAX_SECS=7200
HOLD_ALERT_EVERY_SECS=3600
PROBE_MAX_SECS=30

mkdir -p "$STATE_DIR"

UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt 600 ] && exit 0

# v10.1.44 (W3): resolve the stack dir via the shared lib — $HOME is EMPTY in a
# systemd unit, so the old "${HOME:-...}" default silently pointed at nothing on
# installs that do not match it and this watchdog exited 0 without ever watching.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true
AK_DIR="$(gd_find_stack_dir authentik authentik-server-1)"
[ -z "$AK_DIR" ] && exit 0

_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
_log() {
  mkdir -p /var/log/takguard
  echo "$(_ts) | authentik-watch | $1" >> /var/log/takguard/restarts.log
}

_alert() {
  local subj="$1" body="$2"
  echo -e "$body" | /opt/tak-guarddog/send-alert-email.sh "$subj" "ALERT_EMAIL_PLACEHOLDER" 2>/dev/null
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    local tmpf="/tmp/gd-sms-$$.txt"
    printf '%s' "$body" > "$tmpf"
    /opt/tak-guarddog/sms_send.sh "$subj" "$tmpf" 2>/dev/null || true
    rm -f "$tmpf"
  fi
}

_cooldown_ok() {
  local cf="$1" secs="${2:-$COOLDOWN_SECS}"
  [ ! -f "$cf" ] && return 0
  local last now
  last=$(cat "$cf")
  now=$(date +%s)
  [ $(( now - last )) -ge "$secs" ]
}

# ── Restart backoff (GH #111) ────────────────────────────────────────────────
# A fixed 15-min cooldown turned a CPU-starved host into a restart every ~20 min, all
# night: each cold start burns ~1.5 cores for 2 min and drops the LDAP outpost's cache,
# so the restart deepened the overload it was reacting to. Restarts in the last 6h now
# double the cooldown: 15 → 30 → 60 → 120 min.
_recent_restarts() {
  local cutoff=$(( $(date +%s) - HISTORY_WINDOW_SECS ))
  [ -f "$RESTART_HIST" ] || { echo 0; return; }
  awk -v c="$cutoff" '$1+0 >= c' "$RESTART_HIST" 2>/dev/null | wc -l | tr -d ' '
}

_backoff_secs() {
  local n="$1" s=$COOLDOWN_SECS
  while [ "$n" -gt 0 ] && [ "$s" -lt "$COOLDOWN_MAX_SECS" ]; do s=$((s * 2)); n=$((n - 1)); done
  [ "$s" -gt "$COOLDOWN_MAX_SECS" ] && s=$COOLDOWN_MAX_SECS
  echo "$s"
}

_record_restart() {
  local now cutoff
  now=$(date +%s); cutoff=$(( now - HISTORY_WINDOW_SECS ))
  { awk -v c="$cutoff" '$1+0 >= c' "$RESTART_HIST" 2>/dev/null; echo "$now"; } > "$RESTART_HIST.tmp" \
    && mv -f "$RESTART_HIST.tmp" "$RESTART_HIST"
}

# ── Host CPU starvation (GH #111) ────────────────────────────────────────────
# A slow Authentik on a starved host is not a dead Authentik, and restarting it only
# adds load (field: load ~50 on 8 vCPUs, cpu pressure 83%; test6 2026-10-02 recovered
# by itself once restarts stopped). PSI is the precise signal; RHEL 9 ships it disabled
# by default, so fall back to the 1-min load average per CPU there.
_cpu_saturated() {
  local some ncpu load
  some=$(awk '/^some/ { for (i = 2; i <= NF; i++) if ($i ~ /^avg60=/) { sub("avg60=", "", $i); print int($i) } }' \
         /proc/pressure/cpu 2>/dev/null)
  if [ -n "$some" ]; then
    CPU_DESC="CPU pressure ${some}% (avg60)"
    [ "$some" -ge 50 ]
    return
  fi
  ncpu=$(nproc 2>/dev/null || echo 1)
  load=$(awk '{ print int($1) }' /proc/loadavg 2>/dev/null || echo 0)
  CPU_DESC="load average ${load} on ${ncpu} CPUs"
  [ "$load" -ge $(( ncpu * 3 )) ]
}

# top, not ps: ps %CPU is the average since each process started, not what it is doing now.
_top_cpu() {
  if command -v top >/dev/null 2>&1; then top -b -n 1 -o %CPU 2>/dev/null | head -n 17
  else ps -eo pcpu,comm --sort=-pcpu 2>/dev/null | head -n 8; fi
}

# A targeted restart only helps when what server+worker depend on is up; otherwise the
# full down+up is the right tool, as it was before.
_ak_deps_running() {
  local svcs
  svcs=$(cd "$AK_DIR" && timeout 60 docker compose ps --status running --services 2>/dev/null)
  printf '%s\n' "$svcs" | grep -qx postgresql && printf '%s\n' "$svcs" | grep -qx redis
}

# Portable TCP liveness probe. RHEL ships NO `nc` by default, so the old
# `nc -z 127.0.0.1 389` exited 127 every check on Rocky — a false "LDAP down" that
# drove an endless 15-min LDAP-recreate loop while the outpost was perfectly healthy
# (and each recreate flapped TAK's LDAP bind). bash /dev/tcp is a builtin, identical
# on Ubuntu / RHEL / ARM. Usage: _tcp_up 127.0.0.1 389
_tcp_up() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# ── Authentik compose mutex (v10.1.55 W3) ────────────────────────────────────
# The console ALSO runs `docker compose` against this same project — from its
# max-requests autotune, its SMTP recreate, its stack self-heal and several other
# paths. This script runs every 60 seconds. On test12 (2026-08-31) the console
# force-recreated server+worker while this script was inside its down+up, waiting
# for the server to go healthy:
#
#   00:16:10  Container authentik-server-1 Waiting
#   00:16:29  [ak-mr-autotune] recreating server+worker to apply new values...
#   00:16:35  dependency failed to start: container authentik-server-1 exited (0)
#
# The aborted down+up left authentik-postgresql-1 `created` and never started, and
# Authentik never came back until someone started it by hand. flock(1) here pairs
# with fcntl.flock in app.py's _authentik_compose_lock() — same file, same semantics.
# Skipping a tick is free: this script runs again in 60 seconds.
# ONE fixed path, matching app.py's _AK_COMPOSE_LOCK_PATH exactly. Do NOT make this
# conditional. The first cut said `/var/lock` when that directory existed, falling back
# to /tmp otherwise — which silently disabled the whole mutex: /var/lock is root-owned
# 0755, so THIS script (root, via systemd) took /var/lock while the console (takwerx,
# non-root on every current box) got EACCES and used /tmp. Two files, no exclusion, no
# error anywhere. flock is advisory and keyed on the inode: the only thing that matters
# is that both sides open the same path. /tmp is 1777 on Debian and RHEL alike.
_AK_LOCK="/tmp/takwerx-authentik-compose.lock"
_AK_LOCK_WAIT=180

# Run a compose operation under the shared lock. Usage: _ak_compose_locked <tag> <args...>
# Returns non-zero WITHOUT running anything if the lock cannot be taken in time.
_ak_compose_locked() {
  _tag="$1"; shift
  if ! command -v flock >/dev/null 2>&1; then
    # util-linux is present on Debian and RHEL alike, so this should not happen —
    # but degrade to today's behaviour rather than stop managing Authentik.
    _log "compose-lock | flock unavailable — running $_tag UNLOCKED"
    docker compose "$@" 2>&1
    return $?
  fi
  ( umask 000; : >> "$_AK_LOCK" ) 2>/dev/null || true
  chmod 666 "$_AK_LOCK" 2>/dev/null || true
  exec 9>>"$_AK_LOCK" || { _log "compose-lock | cannot open $_AK_LOCK — running $_tag UNLOCKED"; docker compose "$@" 2>&1; return $?; }
  if ! flock -w "$_AK_LOCK_WAIT" 9; then
    _log "compose-lock | NOT acquired after ${_AK_LOCK_WAIT}s — skipping $_tag (console is mid-compose; next tick retries)"
    exec 9>&-
    return 1
  fi
  docker compose "$@" 2>&1
  _rc=$?
  flock -u 9 2>/dev/null || true
  exec 9>&-
  return $_rc
}

# v10.1.64 W3 (GH #64): after ANY cold start of the LDAP outpost, verify it can actually
# RESOLVE GROUPS — do not declare success on the container coming up.
#
# v10.1.55 fixed the BOOT path this way and the reporter confirmed it with measurements.
# What was left undone is exactly here: both of this watcher's recreate paths bring the
# outpost up cold, with no provider tree, and then judge it by a TCP/port health check. The
# entire point of #64 is that binds succeed while group searches fail — so that check cannot
# tell a working outpost from a broken one, and TAK clients end up connected-but-invisible
# while everything reports green.
#
# gd_ldap_groups_ok is tri-state ON PURPOSE: 0 = resolving, 1 = proven broken
# ("Operations error"), 2 = cannot determine (no ldapsearch, unreadable .env). A 2 must
# NEVER be reported as broken; we say so and move on.
_ak_verify_ldap_groups() {
  local _what="$1" _t=0 _rc=2
  # The outpost legitimately needs time to receive its provider tree — the boot path
  # measured 17s on a real box, so poll rather than asking once and calling it broken.
  while [ $_t -lt 90 ]; do
    gd_ldap_groups_ok "$AK_DIR"; _rc=$?
    [ "$_rc" -eq 0 ] && { _log "$_what | LDAP outpost resolving groups (${_t}s)"; return 0; }
    [ "$_rc" -eq 2 ] && { _log "$_what | cannot verify group resolution (no ldapsearch or unreadable .env) — NOT treating as broken"; return 2; }
    sleep 10; _t=$((_t + 10))
  done
  _log "$_what | *** LDAP outpost is UP but cannot resolve groups after ${_t}s"
  return 1
}

# Full restart under a SINGLE lock hold. A lock taken per-command would release
# between the `down` and the `up`, and the console slipping in at that instant is
# the worst possible moment — it is the window that left postgresql created and
# never started. Down and up are one critical section, not two.
_ak_compose_restart_locked() {
  if ! command -v flock >/dev/null 2>&1; then
    _log "compose-lock | flock unavailable — running full restart UNLOCKED"
    docker compose down --timeout 30 2>&1 && docker compose up -d 2>&1
    return $?
  fi
  ( umask 000; : >> "$_AK_LOCK" ) 2>/dev/null || true
  chmod 666 "$_AK_LOCK" 2>/dev/null || true
  exec 9>>"$_AK_LOCK" || { _log "compose-lock | cannot open $_AK_LOCK — full restart UNLOCKED"; docker compose down --timeout 30 2>&1 && docker compose up -d 2>&1; return $?; }
  if ! flock -w "$_AK_LOCK_WAIT" 9; then
    _log "compose-lock | NOT acquired after ${_AK_LOCK_WAIT}s — skipping full restart (console is mid-compose; next tick retries)"
    exec 9>&-
    return 1
  fi
  docker compose down --timeout 30 2>&1 && docker compose up -d 2>&1
  _rc=$?
  flock -u 9 2>/dev/null || true
  exec 9>&-
  return $_rc
}

# Postgres, Redis and the LDAP outpost were healthy through the whole field loop;
# tearing them down added load and reset the outpost every time. The first restart
# in 6h touches only server+worker; another one within 6h escalates to the full
# down+up, which is what this watchdog always did. Sets ACTION and MODE.
_ak_pick_restart_mode() {
  if [ "$RECENT" -eq 0 ] && _ak_deps_running; then
    ACTION="Restart of server and worker only (docker compose restart server worker)"
    MODE="server-worker"
  else
    ACTION="Full restart (docker compose down + up -d)"
    MODE="full"
  fi
}

# Run the restart picked above, then the bookkeeping every restart shares (the 6h
# history the backoff reads, the cooldown stamps, the fail counters).
_ak_restart() {
  if [ "$MODE" = "server-worker" ]; then
    cd "$AK_DIR" && _ak_compose_locked "server-worker-restart" restart -t 30 server worker
    # The outpost reconnects to the restarted server by itself; if it still cannot
    # resolve groups, restart it too (the order the LDAP alert below recommends).
    _ak_verify_ldap_groups "server-worker-restart"
    if [ $? -eq 1 ]; then
      cd "$AK_DIR" && _ak_compose_locked "ldap-restart" restart ldap
      _ak_verify_ldap_groups "ldap-restart" || true
    fi
  else
    # v10.1.55 (W3): down+up is ONE critical section — see _ak_compose_restart_locked.
    cd "$AK_DIR" && _ak_compose_restart_locked
    # v10.1.64 W3 (GH #64): a full stack restart starts the outpost COLD too — same blind spot.
    _ak_verify_ldap_groups "stack-restart" || true
  fi
  _record_restart
  echo 0 > "$FAIL_HTTP"
  echo 0 > "$FAIL_LDAP"
  date +%s > "$COOLDOWN_HTTP"
  date +%s > "$COOLDOWN_LDAP"
}

# ── LDAP flow herd (ops #38) ─────────────────────────────────────────────────
# The outpost (bind_mode: cached) keeps a bind in its cache until the LDAP flow's
# session expires (hours=1, AK_LDAP_SESSION_DURATION). Then EVERY bind that arrives
# before a new flow finishes runs the full ldap-authentication-flow itself; the
# outpost does not wait for the one already running. TAK Server binds about 3 times a
# second on a busy box, so each expiry is a burst of 25–200 flows that drains in a
# minute or two. When Authentik is already slow it does not drain: slower flows mean
# more binds miss the cache, which means more flows. test8, 2026-10-12: flow median
# 0.5 s → 28 s, 750 flows per 10 min, health check 7 s, and nothing here noticed —
# HTTP answered inside 30 s and port 389 stayed open. A server+worker restart cleared
# it. Healthy boxes show 1–2 busy minutes an hour; the stuck herd shows every minute.
#
# ops #64: a herd that is DRAINING must be left alone. test12, 2026-10-16: an expiry
# that met a 2,200-request Node-RED poll ran 149/237/225/192 flows a minute, then fell
# 96, 40, 58, 15, 14 on its own; 8 busy minutes tripped the restart at the tail, and the
# restart itself cost a 90 s LDAP group outage and a second herd (178/215/130). So the
# rule also looks at the trend: if the last HERD_TAIL_MIN complete minutes together ran
# no more flows than the peak minute alone (their average is a third of the peak or
# less), the backlog is clearing and we hold. The hold ends by itself: once the peak
# slides out of the window, a herd still running at the lower rate is judged against
# its own level and restarted, so a draining verdict buys at most HERD_WINDOW_MIN.
HERD_WINDOW_MIN=10
HERD_PER_MIN=10
HERD_BUSY_MIN=8
HERD_TAIL_MIN=3

# Prints "BUSY PEAK TAIL": how many of the last HERD_WINDOW_MIN minutes ran >= HERD_PER_MIN
# LDAP flows, the busiest minute's count, and the total over the last HERD_TAIL_MIN
# complete minutes (the current, partial minute is left out; a minute with no flows
# counts as 0). Minutes are placed by age from now (UTC, as Authentik logs), so a
# window across midnight still lines up.
_ldap_flow_herd_stats() {
  local now_hm
  now_hm=$(date -u +%H:%M)
  timeout 30 docker logs authentik-server-1 --since "${HERD_WINDOW_MIN}m" 2>&1 \
    | grep 'flows/executor/ldap-authentication-flow' \
    | grep -oE '"timestamp": ?"[0-9-]{10}T[0-9]{2}:[0-9]{2}' \
    | sed -E 's/.*T//' | sort | uniq -c \
    | awk -v n="$HERD_PER_MIN" -v tail="$HERD_TAIL_MIN" -v now="$now_hm" '
        BEGIN { split(now, t, ":"); now_m = t[1] * 60 + t[2] }
        {
          split($2, t, ":"); age = (now_m - (t[1] * 60 + t[2]) + 1440) % 1440
          if ($1 >= n) b++
          if ($1 > peak) peak = $1
          if (age >= 1 && age <= tail) s += $1
        }
        END { print b + 0, peak + 0, s + 0 }'
}

# ── HTTP health check (Authentik server) ──
# GH #111: --max-time bounds each probe. Without it a starved server held a probe open
# for 100–200 s, so slow and down looked the same and one tick could run for minutes.
# AK_LAST_RC 7 = connection refused (nothing listening), the one case that is "down"
# however busy the host is.
ak_http_ok() {
  local url out code rc
  for url in \
    "http://127.0.0.1:9090/-/health/live/" \
    "http://127.0.0.1:9090/"; do
    out=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" --connect-timeout 5 \
          --max-time "$PROBE_MAX_SECS" "$url" 2>/dev/null)
    rc=$?
    code="${out%% *}"; [ -z "$code" ] && code="000"
    case "$code" in
      200|204|301|302) return 0 ;;
    esac
  done
  AK_LAST_CODE="$code"
  AK_LAST_RC="$rc"
  AK_LAST_SECS="${out#* }"
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
  if [ -f "$HOLD_SINCE" ]; then
    _log "hold | Authentik HTTP healthy again — recovered without a restart"
    rm -f "$HOLD_SINCE" "$HOLD_ALERTED"
  fi
else
  CODE="${AK_LAST_CODE:-000}"
  case "${AK_LAST_RC:-0}" in
    7)  PROBE_DESC="HTTP $CODE, connection refused" ;;
    28) PROBE_DESC="HTTP $CODE, no answer within ${PROBE_MAX_SECS}s" ;;
    *)  PROBE_DESC="HTTP $CODE in ${AK_LAST_SECS:-?}s" ;;
  esac
  FAILS=$(( $(cat "$FAIL_HTTP" 2>/dev/null || echo 0) + 1 ))
  echo "$FAILS" > "$FAIL_HTTP"

  RECENT=$(_recent_restarts)
  HTTP_COOLDOWN=$(_backoff_secs "$RECENT")

  if [ "$FAILS" -ge "$MAX_FAILS" ] && _cooldown_ok "$COOLDOWN_HTTP" "$HTTP_COOLDOWN"; then
    NOW=$(date +%s)
    HOLD_START=$(cat "$HOLD_SINCE" 2>/dev/null)
    case "$HOLD_START" in ''|*[!0-9]*) HOLD_START="$NOW" ;; esac
    HELD_FOR=$(( NOW - HOLD_START ))

    # GH #111: on a CPU-starved host, a server that is still listening is slow, not dead.
    # Hold and say so instead of restarting. Capped at 2h so a genuinely wedged server on a
    # busy box is still restarted eventually (and the backoff above still applies then).
    if [ "${AK_LAST_RC:-0}" != "7" ] && _cpu_saturated && [ "$HELD_FOR" -lt "$HOLD_MAX_SECS" ]; then
      [ -f "$HOLD_SINCE" ] || echo "$NOW" > "$HOLD_SINCE"
      _log "hold | Authentik HTTP unhealthy ($PROBE_DESC) for $FAILS checks, but host is CPU-starved ($CPU_DESC) — NOT restarting (held ${HELD_FOR}s)"
      if _cooldown_ok "$HOLD_ALERTED" "$HOLD_ALERT_EVERY_SECS"; then
        _alert "Guard Dog: Authentik slow, host CPU overloaded on $SERVER_IDENTIFIER" \
"Authentik is answering too slowly ($PROBE_DESC) for $FAILS consecutive checks.

Server: $SERVER_IDENTIFIER
Time (UTC): $(_ts)
Host: $CPU_DESC

Guard Dog is NOT restarting Authentik: the host is short of CPU, and a restart adds
about 1.5 cores of load for 2 minutes and resets the LDAP outpost, which makes it worse.
Find what is using the CPU. Top processes right now:

$(_top_cpu)

If the host is still overloaded after 2 hours, Guard Dog will restart Authentik anyway.
"
        date +%s > "$HOLD_ALERTED"
      fi
    else
      [ "$HELD_FOR" -ge "$HOLD_MAX_SECS" ] && _log "hold | held ${HELD_FOR}s with the host still starved — restarting anyway"
      rm -f "$HOLD_SINCE" "$HOLD_ALERTED"

      _ak_pick_restart_mode
      NEXT_COOLDOWN=$(_backoff_secs $(( RECENT + 1 )))
      _log "restart | Authentik HTTP unhealthy ($PROBE_DESC) for $FAILS checks — $MODE restart (restart $(( RECENT + 1 )) in 6h; next allowed after $(( NEXT_COOLDOWN / 60 )) min)"
      SUBJ="Guard Dog: Authentik restarted on $SERVER_IDENTIFIER"
      BODY="Authentik server failed HTTP health check ($PROBE_DESC) for $FAILS consecutive checks.

Server: $SERVER_IDENTIFIER
Time (UTC): $(_ts)
Action: $ACTION.
Restarts in the last 6 hours, including this one: $(( RECENT + 1 )). Next restart allowed after $(( NEXT_COOLDOWN / 60 )) minutes.
"
      _alert "$SUBJ" "$BODY"
      _ak_restart
      exit 0
    fi
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
      cd "$AK_DIR" && _ak_compose_locked "ldap-recreate" up -d --force-recreate ldap   # v10.1.55 W3
      # v10.1.64 W3 (GH #64): the recreate alert above reads as "we fixed it". Verify that
      # before leaving it standing — a recreated outpost that still cannot resolve groups is
      # the exact silent failure this issue is about, and it must be said out loud.
      _ak_verify_ldap_groups "ldap-recreate"
      case $? in
        1) _alert "Guard Dog: Authentik LDAP restarted but CANNOT RESOLVE GROUPS on $SERVER_IDENTIFIER" \
"The LDAP outpost was recreated and is accepting connections, but it still cannot resolve groups.

Server: $SERVER_IDENTIFIER
Time (UTC): $(_ts)

WHAT THIS MEANS: TAK Server routes strictly by channel. Clients will connect, stay connected,
and transmit to NOBODY — while the server, the containers and the client all report healthy.
A fast way to see it: the TAK Client Dashboard shows a higher total client count than the
number of rows it lists.

This does NOT self-correct on its own timetable and the earlier 'LDAP restarted' message
should not be read as a fix.

Try, in order:
  docker restart authentik-server-1   # republishes the provider tree
  docker restart authentik-ldap-1     # then the outpost picks it up
  systemctl restart takserver         # TAK holds a long-lived directory context and will
                                      # not re-establish on its own
" ;;
      esac
      echo 0 > "$FAIL_LDAP"
      date +%s > "$COOLDOWN_LDAP"
    fi
  fi
fi

# ── LDAP flow herd check (ops #38) ──
# Only while HTTP and port 389 are OK: an unhealthy server is the HTTP check's to restart,
# a closed port the LDAP check's (which may have just recreated the outpost). Shares that
# check's cooldown and 6h backoff, so the two triggers can never stack restarts. There
# is no CPU-starvation hold here (GH #111): the herd IS Authentik's own load, and a
# server+worker restart does not touch the outpost's bind cache.
if [ "$HTTP_OK" -eq 1 ] && [ "${LDAP_OK:-0}" -eq 1 ]; then
  RECENT=$(_recent_restarts)
  HTTP_COOLDOWN=$(_backoff_secs "$RECENT")
  if _cooldown_ok "$COOLDOWN_HTTP" "$HTTP_COOLDOWN"; then
    read -r BUSY PEAK TAIL <<EOF
$(_ldap_flow_herd_stats)
EOF
    if [ "${BUSY:-0}" -ge "$HERD_BUSY_MIN" ] && [ "${TAIL:-0}" -le "${PEAK:-0}" ]; then
      _log "hold | LDAP flow herd draining (${BUSY} of the last ${HERD_WINDOW_MIN} min ran >= ${HERD_PER_MIN} LDAP flows, but the last ${HERD_TAIL_MIN} min ran ${TAIL} vs a peak of ${PEAK}/min) — NOT restarting"
    elif [ "${BUSY:-0}" -ge "$HERD_BUSY_MIN" ]; then
      _ak_pick_restart_mode
      NEXT_COOLDOWN=$(_backoff_secs $(( RECENT + 1 )))
      _log "restart | LDAP flow herd not draining (${BUSY} of the last ${HERD_WINDOW_MIN} min ran >= ${HERD_PER_MIN} LDAP flows; the last ${HERD_TAIL_MIN} min ran ${TAIL} vs a peak of ${PEAK}/min) — $MODE restart (restart $(( RECENT + 1 )) in 6h; next allowed after $(( NEXT_COOLDOWN / 60 )) min)"
      _alert "Guard Dog: Authentik LDAP logins backed up, restarted on $SERVER_IDENTIFIER" \
"Authentik's LDAP login flow has been running non-stop: ${BUSY} of the last ${HERD_WINDOW_MIN} minutes each ran ${HERD_PER_MIN} or more LDAP flows (a healthy box runs a short burst about once an hour).

Server: $SERVER_IDENTIFIER
Time (UTC): $(_ts)

This happens when the LDAP outpost's login cache expires while Authentik is slow: every TAK Server lookup then runs the full login flow, each one makes Authentik slower, and the backlog never clears. TAK logins and channel lookups slow down with it. The health check still passes, so nothing else catches it.

Action: $ACTION.
Restarts in the last 6 hours, including this one: $(( RECENT + 1 )). Next restart allowed after $(( NEXT_COOLDOWN / 60 )) minutes.
"
      _ak_restart
      exit 0
    fi
  fi
fi
