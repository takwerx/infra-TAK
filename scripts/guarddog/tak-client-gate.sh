#!/bin/bash
# Guard Dog TAK Client Port Gate — v10.1.46 (W1)
#
# Holds TCP 8089 (TAK's EUD client port) closed to external clients for the
# short boot window in which TAK is *listening* but not yet *ready*, and opens
# it the moment TAK's api JVM answers on 8443.
#
# WHY THIS EXISTS
# ---------------
# TAK opens 8089 from the MESSAGING JVM. The 8446 client dashboard and every
# /Marti/api/* view are served by the API JVM, which finishes LATER — measured
# 5.5s-23.6s on test6 across every boot on record, 30.0s on test12. A client
# that connects inside that gap gets a working session (traffic flows both
# ways, groups resolve) that the api JVM never learns about: permanently
# invisible in the dashboard, never self-correcting. On a deployment with
# hundreds of radios, every reboot puts a large share of them in that state.
# 10.1.44 (W4) recycles those sessions ~30s later — hundreds of unnecessary
# reconnects on every boot, plus 30s of a wrong client list. This closes the
# window instead of cleaning up after it.
#
# THIS SCRIPT CAN LOCK EVERY EUD OUT OF A LIVE PUBLIC-SAFETY SERVER.
# The safety design is the point, not a footnote:
#
#   1. BOOT ONLY.      insert refuses when uptime >= MAX_BOOT_UPTIME. A runtime
#                      `systemctl restart takserver` never gates.
#   2. TRAP RELEASE.   tak-post-start.sh runs `trap ... EXIT` so every exit path
#                      — success, timeout, crash, kill — releases.
#   3. BACKSTOP.       takclientgate.timer (OnBootSec=15min) releases
#                      unconditionally, depending on nothing else having run.
#   4. FAIL OPEN.      No backend, an unrecognised backend, or a failed insert
#                      => log loudly, gate NOTHING, continue. A box that cannot
#                      gate behaves exactly like 10.1.44 (the W4 sweeper still
#                      catches the race). Never fail closed.
#   5. STALE SWEEP.    `sweep` (called from console startup) removes a gate that
#                      outlived its boot — the ufw case, where rules persist.
#   6. IDEMPOTENT.     release is safe with no gate present, and safe to repeat.
#
# Verbs: release | sweep | insert | status      (release is defined FIRST on
# purpose: the gate must be provably removable before it is ever inserted.)
#
# NON-ROOT-COMMANDS: ufw, firewall-cmd (logged for the v10.0.5 sudoers allowlist).

PORT=8089
STATE_DIR="/var/lib/takguard"
STATE_FILE="$STATE_DIR/client-gate.state"
MAX_BOOT_UPTIME=600      # matches tak-boot-sequencer.sh's boot branch
STALE_AFTER=900          # a gate older than the 15-min backstop is stale

# Sources that must keep reaching 8089 through the gate: the console's own
# loopback Marti calls, and CloudTAK / Node-RED / TAK Portal on the Docker
# bridge. (The boot sequencer stops those containers anyway, so this is belt
# and braces — but a gate that can break a container feed is not one we ship.)
PERMIT_NETS="127.0.0.0/8 172.16.0.0/12"

_log() {
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${GATE_LOG_PREFIX:-client-gate}: $1"
  logger -t takguard-boot "${GATE_LOG_PREFIX:+${GATE_LOG_PREFIX}: }$1" 2>/dev/null
}

# Mirror of app.py _fw_backend(): family-native tool wins when both exist, so a
# box converges on one backend deterministically. dnf => rhel, else debian.
_backend() {
  local have_ufw=1 have_fwd=1 family=debian
  command -v ufw >/dev/null 2>&1 && have_ufw=0
  command -v firewall-cmd >/dev/null 2>&1 && have_fwd=0
  command -v dnf >/dev/null 2>&1 && family=rhel
  if [ "$family" = "rhel" ]; then
    [ $have_fwd -eq 0 ] && { echo firewalld; return; }
    [ $have_ufw -eq 0 ] && { echo ufw; return; }
  else
    [ $have_ufw -eq 0 ] && { echo ufw; return; }
    [ $have_fwd -eq 0 ] && { echo firewalld; return; }
  fi
  echo ""
}

# firewalld rich rules. RUNTIME ONLY — never --permanent, so a reboot inherently
# clears the gate even if every other safety net fails.
_fwd_drop_rule()   { echo "rule family=\"$1\" port port=\"$PORT\" protocol=\"tcp\" drop"; }
_fwd_permit_rule() { echo "rule priority=\"-10\" family=\"ipv4\" source address=\"$1\" port port=\"$PORT\" protocol=\"tcp\" accept"; }

# A rule added to an INACTIVE firewall is not enforced, so gating there would be
# a lie; and it would leave cruft behind if release ever failed. Treat "backend
# present but not running" as no backend at all — fail open.
_ufw_active() { ufw status 2>/dev/null | head -1 | grep -q "Status: active"; }
_fwd_active() { [ "$(firewall-cmd --state 2>/dev/null)" = "running" ]; }

# Does OUR exact drop rule exist right now?
_ufw_has_drop()   { ufw status 2>/dev/null | grep -qE "^${PORT}(/tcp)?[[:space:]]+DENY"; }
# Does a permit for $1 on this port already exist? (an operator's rule we must never delete)
_ufw_has_permit() { ufw status 2>/dev/null | tr -s " " | grep -qF "$PORT/tcp ALLOW IN $1"; }

# ─────────────────────────── RELEASE ───────────────────────────
# Idempotent, backend-agnostic, and correct with no state file — the backstop
# timer calls this on a box where post-start may never have run.
_release() {
  local removed=0 be
  be="$(_backend)"

  # The DROP rules are the dangerous ones: remove them unconditionally on BOTH
  # backends, regardless of what the state file says or whether it exists.
  if command -v firewall-cmd >/dev/null 2>&1; then
    for _fam in ipv4 ipv6; do
      if firewall-cmd --query-rich-rule="$(_fwd_drop_rule $_fam)" >/dev/null 2>&1; then
        firewall-cmd --remove-rich-rule="$(_fwd_drop_rule $_fam)" >/dev/null 2>&1 && removed=$((removed + 1))
      fi
    done
  fi
  if command -v ufw >/dev/null 2>&1; then
    # ufw has no --query; delete is a no-op ("Could not delete non-existent rule")
    # when the rule is absent, so this is safe to call blind.
    # Bounded: a delete that reports success without removing the rule must not
    # spin forever inside the backstop. 10 is far above any real duplicate count.
    local _guard=0
    while _ufw_has_drop && [ "$_guard" -lt 10 ]; do
      _guard=$((_guard + 1))
      ufw delete deny proto tcp to any port "$PORT" >/dev/null 2>&1 || break
      removed=$((removed + 1))
    done
    if _ufw_has_drop; then
      _log "WARNING: a DENY rule on $PORT survived release — inspect: ufw status | grep $PORT"
    fi
  fi

  # PERMIT rules are removed only when the state file proves WE inserted them —
  # never guess at ownership of a rule an operator may have set themselves.
  if [ -f "$STATE_FILE" ]; then
    while IFS= read -r _line; do
      case "$_line" in
        permit_ufw=*)
          command -v ufw >/dev/null 2>&1 && \
            ufw delete allow from "${_line#permit_ufw=}" to any port "$PORT" proto tcp >/dev/null 2>&1
          ;;
        permit_fwd=*)
          command -v firewall-cmd >/dev/null 2>&1 && \
            firewall-cmd --remove-rich-rule="$(_fwd_permit_rule "${_line#permit_fwd=}")" >/dev/null 2>&1
          ;;
      esac
    done < "$STATE_FILE"
    rm -f "$STATE_FILE"
  fi

  if [ "$removed" -gt 0 ]; then
    _log "client gate RELEASED on $PORT (${be:-none}, $removed rule(s) removed)"
  else
    _log "client gate not engaged on $PORT — nothing to release"
  fi
  return 0
}

# ─────────────────────────── SWEEP ─────────────────────────────
# Console-startup hygiene. A gate must never outlive its boot: firewalld rich
# rules are runtime-only and die with the reboot, but UFW RULES PERSIST ACROSS
# REBOOT — a box that lost power mid-gate would come back with 8089 denied.
#
# It must NOT release a gate that is legitimately engaged: the console restarts
# during boot too, well before TAK's api JVM is up, and an unconditional sweep
# would defeat W1 on every single boot. So: release only when the gate belongs
# to a previous boot, or has outlived the 15-min backstop window.
_sweep() {
  local _boot_now _boot_state _at _age _now
  [ -f "$STATE_FILE" ] || { _release_if_orphan_rule; return 0; }
  _boot_now="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
  _boot_state="$(grep '^boot_id=' "$STATE_FILE" 2>/dev/null | cut -d= -f2-)"
  _at="$(grep '^engaged_at=' "$STATE_FILE" 2>/dev/null | cut -d= -f2-)"
  _now="$(date +%s)"
  _age=$(( _now - ${_at:-0} ))
  if [ "$_boot_state" != "$_boot_now" ]; then
    _log "stale client gate from a previous boot — releasing"
    _release
  elif [ "${_at:-0}" -gt 0 ] && [ "$_age" -ge "$STALE_AFTER" ]; then
    _log "client gate engaged ${_age}s ago (past the ${STALE_AFTER}s backstop) — releasing"
    _release
  fi
  return 0
}

# No state file but a drop rule present (state lost, gate left behind): that is
# unambiguously orphaned — nothing legitimate engages a gate without writing state.
_release_if_orphan_rule() {
  local orphan=0
  command -v ufw >/dev/null 2>&1 && _ufw_has_drop && orphan=1
  command -v firewall-cmd >/dev/null 2>&1 && \
    firewall-cmd --query-rich-rule="$(_fwd_drop_rule ipv4)" >/dev/null 2>&1 && orphan=1
  if [ "$orphan" -eq 1 ]; then
    _log "orphaned client gate on $PORT with no state file — releasing"
    _release
  fi
  return 0
}

# ─────────────────────────── INSERT ────────────────────────────
_insert() {
  local _up be rc=0
  _up=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo 9999)
  if [ "$_up" -ge "$MAX_BOOT_UPTIME" ]; then
    _log "client gate SKIPPED (uptime ${_up}s — runtime restart, not a boot)"
    return 0
  fi

  if [ -f "$STATE_FILE" ] && \
     [ "$(grep '^boot_id=' "$STATE_FILE" 2>/dev/null | cut -d= -f2-)" = "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]; then
    # Already engaged this boot (TAK restarted twice during startup). Re-inserting
    # is harmless but would reset engaged_at, moving the staleness deadline out.
    _log "client gate already engaged this boot — leaving it as is"
    return 0
  fi

  be="$(_backend)"
  if [ -z "$be" ]; then
    _log "client gate SKIPPED (no firewall backend) — continuing ungated"
    return 0
  fi
  if { [ "$be" = "ufw" ] && ! _ufw_active; } || { [ "$be" = "firewalld" ] && ! _fwd_active; }; then
    _log "client gate SKIPPED ($be present but not running) — continuing ungated"
    return 0
  fi

  mkdir -p "$STATE_DIR" 2>/dev/null
  local _tmp="$STATE_FILE.tmp.$$"
  : > "$_tmp"

  if [ "$be" = "ufw" ]; then
    # NOTE THE ASYMMETRY: ufw rules PERSIST across reboot. That is exactly why
    # the backstop timer and the console-startup sweep exist.
    # Insert order matters — each `insert 1` pushes the previous down, so the
    # deny goes in FIRST and ends up last of the three.
    if ! ufw insert 1 deny proto tcp to any port "$PORT" >/dev/null 2>&1; then
      _log "client gate FAILED to insert (ufw) — continuing ungated"
      rm -f "$_tmp"; return 0
    fi
    for _net in $PERMIT_NETS; do
      # Never delete a rule we did not create: an operator's own permit is left
      # exactly as found, and only a permit WE add is recorded for removal.
      _ufw_has_permit "$_net" && continue
      if ufw insert 1 allow from "$_net" to any port "$PORT" proto tcp >/dev/null 2>&1; then
        echo "permit_ufw=$_net" >> "$_tmp"
      fi
    done
  elif [ "$be" = "firewalld" ]; then
    for _net in $PERMIT_NETS; do
      case "$_net" in *:*) continue;; esac
      firewall-cmd --query-rich-rule="$(_fwd_permit_rule "$_net")" >/dev/null 2>&1 && continue
      if firewall-cmd --add-rich-rule="$(_fwd_permit_rule "$_net")" >/dev/null 2>&1; then
        echo "permit_fwd=$_net" >> "$_tmp"
      fi
    done
    if ! firewall-cmd --add-rich-rule="$(_fwd_drop_rule ipv4)" >/dev/null 2>&1; then
      _log "client gate FAILED to insert (firewalld) — continuing ungated"
      # Roll back the permits we just added so the box is left untouched.
      while IFS= read -r _l; do
        [ -n "$_l" ] && firewall-cmd --remove-rich-rule="$(_fwd_permit_rule "${_l#permit_fwd=}")" >/dev/null 2>&1
      done < "$_tmp"
      rm -f "$_tmp"; return 0
    fi
    # IPv6 is best-effort: a v6-disabled box rejects it, and a v4-only gate is
    # still strictly better than none.
    firewall-cmd --add-rich-rule="$(_fwd_drop_rule ipv6)" >/dev/null 2>&1 || \
      _log "client gate: ipv6 drop rule not applied (v6 may be disabled) — v4 gate active"
  else
    _log "client gate SKIPPED (unrecognised backend '$be') — continuing ungated"
    rm -f "$_tmp"; return 0
  fi

  {
    echo "backend=$be"
    echo "engaged_at=$(date +%s)"
    echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
    cat "$_tmp"
  } > "$STATE_FILE" 2>/dev/null
  chmod 600 "$STATE_FILE" 2>/dev/null
  rm -f "$_tmp"
  _log "client gate ENGAGED on $PORT ($be)"
  return $rc
}

# ─────────────────────────── STATUS ────────────────────────────
_status() {
  local be; be="$(_backend)"
  echo "backend: ${be:-none}"
  if [ -f "$STATE_FILE" ]; then
    echo "state file:"; sed 's/^/  /' "$STATE_FILE"
  else
    echo "state file: (none)"
  fi
  if command -v ufw >/dev/null 2>&1; then
    echo "ufw rules for $PORT:"; ufw status 2>/dev/null | grep -E "(^|[[:space:]])$PORT" | sed 's/^/  /'
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewalld rich rules for $PORT:"; firewall-cmd --list-rich-rules 2>/dev/null | grep "$PORT" | sed 's/^/  /'
  fi
}

case "${1:-}" in
  release) _release ;;
  sweep)   _sweep ;;
  insert)  _insert ;;
  status)  _status ;;
  *) echo "usage: $0 {release|sweep|insert|status}" >&2; exit 2 ;;
esac
exit 0
