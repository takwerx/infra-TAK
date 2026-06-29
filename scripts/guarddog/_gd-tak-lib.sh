#!/bin/bash
# Guard Dog shared TAK/DB dispatch library (v10.0.1).
#
# Sourced by the TAK- and DB-touching watch scripts so ONE script per monitor
# works on both native (.deb / .rpm) TAK and containerized TAK. The native
# branch emits the EXACT command the script used before this library existed —
# so on a deb box behaviour is byte-identical. All container behaviour is gated
# on guarddog.conf "tak_mode":"container" (written only by _tak_is_container()
# at deploy time).
#
# Container facts (validated on aws-arm, 2026-06-18):
#   - TAK JVM + keytool live in the "takserver" container; the host shares the
#     container PID view so `pgrep` sees the JVMs, but the lifecycle is docker.
#   - PostgreSQL lives in "takserver-db"; `docker exec -u postgres takserver-db
#     psql` is the peer-auth equivalent of native `sudo -u postgres psql`.
#   - /opt/tak is symlinked to the bundle, so file reads (logs, certs, JKS,
#     CoreConfig) work unchanged in BOTH modes.
#
# NON-ROOT-COMMANDS: docker (logged for the v10.0.5 sudoers allowlist).

GD_CONF_FILE="${GD_CONF_FILE:-/opt/tak-guarddog/guarddog.conf}"

# Read tak_mode / container names from guarddog.conf (JSON). Defaults keep the
# native path identical when the keys are absent (every existing deb box).
GD_TAK_MODE="native"
GD_TAK_CONTAINER="takserver"
GD_DB_CONTAINER="takserver-db"
if [ -f "$GD_CONF_FILE" ]; then
  # Newline-delimited read (no shell eval of conf values — matches the CRIT-07
  # hardening used elsewhere in the Guard Dog scripts).
  {
    IFS= read -r _gd_mode
    IFS= read -r _gd_takc
    IFS= read -r _gd_dbc
  } < <(python3 - "$GD_CONF_FILE" <<'PY'
import json, os, sys
p = sys.argv[1]
mode = "native"; takc = "takserver"; dbc = "takserver-db"
if os.path.isfile(p):
    try:
        with open(p) as f:
            c = json.load(f)
        if c.get("tak_mode") == "container":
            mode = "container"
        takc = str(c.get("tak_container") or takc)
        dbc = str(c.get("db_container") or dbc)
    except Exception:
        pass
print(mode); print(takc); print(dbc)
PY
  )
  GD_TAK_MODE="${_gd_mode:-native}"
  GD_TAK_CONTAINER="${_gd_takc:-takserver}"
  GD_DB_CONTAINER="${_gd_dbc:-takserver-db}"
fi

# True (0) when TAK runs as a container on this box.
gd_is_container() { [ "$GD_TAK_MODE" = "container" ]; }

# Portable TCP liveness probe. RHEL ships NO `nc` by default, so the old
# `nc -z host port` exited 127 on every call there — a false "port down" that drove
# an endless LDAP-recreate loop on Rocky. bash /dev/tcp is a builtin, identical on
# Ubuntu / RHEL / ARM. Usage: gd_tcp_up 127.0.0.1 389  -> rc 0 if accepting connects.
gd_tcp_up() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# --- PostgreSQL access (local single-server only; two-server scripts keep their
# own SSH path and never call these) -----------------------------------------
# gd_psql_scalar "<sql>" [db]   -> -t -A scalar, stdout, rc passthrough
gd_psql_scalar() {
  local sql="$1"; local db="${2:-}"
  if gd_is_container; then
    if [ -n "$db" ]; then
      docker exec -u postgres "$GD_DB_CONTAINER" psql -d "$db" -t -A -c "$sql" 2>/dev/null
    else
      docker exec -u postgres "$GD_DB_CONTAINER" psql -t -A -c "$sql" 2>/dev/null
    fi
  else
    if [ -n "$db" ]; then
      sudo -u postgres psql -d "$db" -t -A -c "$sql" 2>/dev/null
    else
      sudo -u postgres psql -t -A -c "$sql" 2>/dev/null
    fi
  fi
}

# gd_psql_raw "<sql>" [db]      -> full psql output (e.g. for "DELETE NNN" parse)
gd_psql_raw() {
  local sql="$1"; local db="${2:-}"
  if gd_is_container; then
    if [ -n "$db" ]; then
      docker exec -u postgres "$GD_DB_CONTAINER" psql -d "$db" -c "$sql" 2>/dev/null
    else
      docker exec -u postgres "$GD_DB_CONTAINER" psql -c "$sql" 2>/dev/null
    fi
  else
    if [ -n "$db" ]; then
      sudo -u postgres psql -d "$db" -c "$sql" 2>/dev/null
    else
      sudo -u postgres psql -c "$sql" 2>/dev/null
    fi
  fi
}

# gd_psql_present  -> 0 if a local psql path is usable in the current mode
gd_psql_present() {
  if gd_is_container; then
    docker inspect -f '{{.State.Running}}' "$GD_DB_CONTAINER" 2>/dev/null | grep -q true
  else
    command -v psql >/dev/null 2>&1
  fi
}

# gd_db_running    -> 0 if the database is up (native service OR db container)
gd_db_running() {
  if gd_is_container; then
    [ "$(docker inspect -f '{{.State.Running}}' "$GD_DB_CONTAINER" 2>/dev/null)" = "true" ]
  else
    systemctl is-active --quiet postgresql 2>/dev/null || systemctl is-active --quiet postgresql-15 2>/dev/null
  fi
}

# gd_db_restart    -> bring the database back (native restart OR docker restart)
gd_db_restart() {
  if gd_is_container; then
    docker restart "$GD_DB_CONTAINER" >/dev/null 2>&1
  else
    systemctl restart postgresql 2>/dev/null || systemctl restart postgresql-15 2>/dev/null
  fi
}

# --- TAK Server lifecycle / process inspection ------------------------------
# gd_tak_running   -> 0 if TAK Server is up (native unit OR takserver container)
gd_tak_running() {
  if gd_is_container; then
    [ "$(docker inspect -f '{{.State.Running}}' "$GD_TAK_CONTAINER" 2>/dev/null)" = "true" ]
  else
    systemctl is-active --quiet takserver 2>/dev/null
  fi
}

# gd_tak_pgrep "<pattern>"  -> 0 if a JVM matching pattern is alive
gd_tak_pgrep() {
  local pat="$1"
  if gd_is_container; then
    docker exec "$GD_TAK_CONTAINER" pgrep -f "$pat" >/dev/null 2>&1
  else
    pgrep -f "$pat" >/dev/null 2>&1
  fi
}

# gd_tak_restart   -> clean restart of TAK Server.
#   native    : stop -> kill orphan java (tak user) -> clear Ignite -> start
#   container : docker restart (entrypoint re-launches the JVMs; the work/
#               Ignite dir is inside the container's TAK tree and is recreated)
gd_tak_restart() {
  if gd_is_container; then
    docker restart "$GD_TAK_CONTAINER" >/dev/null 2>&1
  else
    systemctl stop takserver
    sleep 2
    pkill -9 -u tak 2>/dev/null || true
    sleep 1
    rm -rf /opt/tak/work
    systemctl start takserver
  fi
}

# gd_tak_stop / gd_tak_start  -> granular lifecycle for callers that must run
# steps BETWEEN stop and start (tak-oom-watch rotates the messaging log mid-
# restart so the post-restart OOM check comes up clean).
gd_tak_stop() {
  if gd_is_container; then
    docker stop "$GD_TAK_CONTAINER" >/dev/null 2>&1
  else
    systemctl stop takserver
  fi
}
gd_tak_start() {
  if gd_is_container; then
    docker start "$GD_TAK_CONTAINER" >/dev/null 2>&1
  else
    systemctl start takserver
  fi
}

# gd_tak_started_monotonic  -> seconds-since-boot when TAK last entered active,
# or empty when unknown. Native reads systemd; container reads the container's
# StartedAt against /proc/uptime so the startup-grace logic still works.
gd_tak_started_monotonic() {
  if gd_is_container; then
    local started_epoch now_epoch uptime_sec
    started_epoch=$(docker inspect -f '{{.State.StartedAt}}' "$GD_TAK_CONTAINER" 2>/dev/null)
    [ -z "$started_epoch" ] && { echo ""; return; }
    started_epoch=$(date -d "$started_epoch" +%s 2>/dev/null)
    [ -z "$started_epoch" ] && { echo ""; return; }
    now_epoch=$(date +%s)
    uptime_sec=$(awk '{print int($1)}' /proc/uptime)
    # Convert to the same "monotonic since boot" frame the native script uses.
    echo $(( uptime_sec - (now_epoch - started_epoch) ))
  else
    local mono
    mono=$(systemctl show takserver --property=ActiveEnterTimestampMonotonic --value 2>/dev/null)
    [ -n "$mono" ] && [ "$mono" != "0" ] && echo $(( mono / 1000000 )) || echo ""
  fi
}

# gd_db_shell "<cmd>"  -> run an arbitrary shell command in the DB host context
# as root (used by tak-db-repack for pg_repack install / pg_config). native →
# bash -c on the host; container → root shell inside the db container.
gd_db_shell() {
  local cmd="$1"
  if gd_is_container; then
    docker exec "$GD_DB_CONTAINER" bash -c "$cmd" 2>&1
  else
    bash -c "$cmd" 2>&1
  fi
}

# gd_db_pg <argv...>   -> run a binary as the postgres OS user in the DB context
# (used by tak-db-repack to invoke pg_repack). native → sudo -u postgres …;
# container → docker exec -u postgres … (no sudo needed inside the image).
gd_db_pg() {
  if gd_is_container; then
    docker exec -u postgres "$GD_DB_CONTAINER" "$@" 2>&1
  else
    sudo -u postgres "$@" 2>&1
  fi
}

# gd_keytool [args...]  -> run keytool in the right context (host vs container).
# In container mode the JKS path is identical (bind-mounted /opt/tak), so the
# same args work; output goes to the caller's stdout.
gd_keytool() {
  if gd_is_container; then
    docker exec "$GD_TAK_CONTAINER" keytool "$@" 2>/dev/null
  else
    keytool "$@" 2>/dev/null
  fi
}
