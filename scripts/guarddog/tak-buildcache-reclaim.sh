#!/bin/bash
# Guard Dog: Docker BuildKit build-cache reclaim (disk-capacity hygiene).
#
# Boxes that rebuild images repeatedly (CloudTAK API rebuilds on every plugin
# install/rebuild, plus Authentik / TAK Portal / MediaMTX image work) accumulate
# tens-to-hundreds of GB of dead BuildKit build cache under the Docker/containerd
# data root. On large dev disks this just looks like high usage; on a customer's
# small root disk it silently fills to 100% and Postgres/apps can no longer write
# — which then masquerades as a database or log-retention problem.
#
# This healer prunes build cache OLDER than 7 days (keeps recent cache so the next
# plugin rebuild stays fast) when the root disk is above RECLAIM_THRESHOLD_PCT, and
# escalates to reclaiming ALL unused cache once the disk is critically full
# (>= EMERGENCY_PCT) — a rebuild burst fills the disk with <7-day cache the routine
# window cannot touch. It NEVER touches images, containers, or volumes (no `-a`, no
# `system prune`), so running containers are unaffected.
#
# Fleet-uniform thresholds (no per-box knobs). Runs on a systemd timer (hourly, so it
# can rescue a disk that fills between runs — a no-op below RECLAIM_THRESHOLD_PCT).
# Off switch: create /opt/tak-guarddog/buildcache_reclaim_off to disable.
# Cross-platform: docker + df + awk + logger only — identical on Ubuntu, RHEL, ARM64.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
LOG_DIR="/var/log/takguard"
mkdir -p "$STATE_DIR" "$LOG_DIR" 2>/dev/null
LAST_FILE="$LOG_DIR/buildcache_reclaim_last.txt"   # human-readable, read by the Guard Dog UI card
LOG="$STATE_DIR/buildcache_reclaim.log"

log_line() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1" >> "$LOG" 2>/dev/null; }

# Fleet-uniform constants (same on every box — no operator override preserved)
CACHE_CAP_GB=20            # size cap: keep total BuildKit cache under this, ALWAYS
                           # (disk-size-agnostic — see the size-cap tier below).
RECLAIM_THRESHOLD_PCT=70   # routine: reclaim cache OLDER than KEEP_WINDOW at/above this
KEEP_WINDOW="168h"         # keep build cache newer than 7 days (routine band)
EMERGENCY_PCT=85           # at/above this, reclaim ALL unused cache (drop the age
                           # filter): a burst of rebuilds fills the disk with <7-day
                           # cache the routine window-limited prune cannot touch
                           # (it would reclaim ~0 and the disk stays red/full).

# Off switch
if [ -f /opt/tak-guarddog/buildcache_reclaim_off ]; then
  log_line "disabled (buildcache_reclaim_off present) — skipping"
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') (disabled)" > "$LAST_FILE" 2>/dev/null
  exit 0
fi

# Docker must be present and responsive
if ! command -v docker >/dev/null 2>&1; then
  log_line "docker not found — nothing to do"
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  log_line "docker not responding — skipping (no prune)"
  exit 0
fi

# Root-disk usage percent (integer)
disk_pct=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
[ -z "$disk_pct" ] && disk_pct=$(df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')   # POSIX fallback
disk_pct=${disk_pct:-0}

# Parse the reclaimed size from a `docker builder prune` summary. Docker 29.x /
# containerd snapshotter prints "Total:\t52.4GB"; older Docker prints "Total
# reclaimed space: 52.4GB". Match either by grabbing the size token off "Total".
parse_reclaimed() { echo "$1" | grep -iE '^Total' | grep -oiE '[0-9.]+ ?[KMGTP]?i?B' | tail -1; }

# ── Tier 0: size cap — disk-size-AGNOSTIC, runs EVERY time ────────────────────
# The %-of-disk tiers below never fire on a large disk: 70% of a 500G disk is
# ~350G of runway, so hundreds of GB of BuildKit cache accrue while the disk sits
# at ~40% and the healer sleeps every night (field: a 502G box reached 177G cache
# at 44%). Cap total build cache at CACHE_CAP_GB regardless of disk %. NEVER
# touches images/containers/volumes. Docker 28+ renamed `--keep-storage` →
# `--max-used-space`; detect which this daemon supports (both take "20GB").
if docker builder prune --help 2>&1 | grep -q -- '--max-used-space'; then
  CAP_FLAG="--max-used-space=${CACHE_CAP_GB}GB"
else
  CAP_FLAG="--keep-storage=${CACHE_CAP_GB}GB"
fi
RAW_CAP=$(docker builder prune -f $CAP_FLAG 2>>"$LOG")
CAP_RECLAIMED=$(parse_reclaimed "$RAW_CAP"); [ -z "$CAP_RECLAIMED" ] && CAP_RECLAIMED="0B"
log_line "size-cap: reclaimed ${CAP_RECLAIMED} (cap ${CACHE_CAP_GB}GB, ${CAP_FLAG%%=*}); disk ${disk_pct}%"
logger -t takguard-buildcache "size-cap reclaimed ${CAP_RECLAIMED} (cap ${CACHE_CAP_GB}GB); disk ${disk_pct}%"
SUMMARY="size-cap reclaimed ${CAP_RECLAIMED} (cap ${CACHE_CAP_GB}GB)"

# ── Tier 1/2: disk-% backstop (the emergency-full case) ───────────────────────
# The size cap holds steady-state; these catch a disk driven critically full
# between runs (e.g. a rebuild burst of <7-day cache under the cap, plus other
# growth). Both modes NEVER touch images/containers/volumes.
#   routine   (70–84%): prune cache OLDER than KEEP_WINDOW.
#   emergency ( >=85% ): prune ALL unused cache (no age filter) — disk critically full.
if [ "$disk_pct" -lt "$RECLAIM_THRESHOLD_PCT" ]; then
  log_line "root disk ${disk_pct}% — below ${RECLAIM_THRESHOLD_PCT}% threshold; size-cap only"
else
  if [ "$disk_pct" -ge "$EMERGENCY_PCT" ]; then
    MODE="emergency: all unused cache (disk ${disk_pct}% >= ${EMERGENCY_PCT}%)"
    RAW=$(docker builder prune -f 2>>"$LOG")
  else
    MODE="routine: cache older than ${KEEP_WINDOW}"
    RAW=$(docker builder prune -f --filter "until=${KEEP_WINDOW}" 2>>"$LOG")
  fi
  RECLAIMED=$(parse_reclaimed "$RAW"); [ -z "$RECLAIMED" ] && RECLAIMED="0B"
  disk_after=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
  [ -z "$disk_after" ] && disk_after=$(df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
  disk_after=${disk_after:-$disk_pct}
  log_line "RECLAIMED ${RECLAIMED} [${MODE}]; root disk ${disk_pct}% -> ${disk_after}%"
  logger -t takguard-buildcache "Reclaimed ${RECLAIMED} Docker build cache [${MODE}]; disk ${disk_pct}%->${disk_after}%"
  SUMMARY="${SUMMARY}; ${MODE} reclaimed ${RECLAIMED}, disk ${disk_pct}%->${disk_after}%"
fi

echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${SUMMARY}" > "$LAST_FILE" 2>/dev/null
exit 0
