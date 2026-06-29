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

if [ "$disk_pct" -lt "$RECLAIM_THRESHOLD_PCT" ]; then
  log_line "root disk ${disk_pct}% — below ${RECLAIM_THRESHOLD_PCT}% threshold, keeping all cache (skip)"
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${disk_pct}% disk — below threshold, no prune" > "$LAST_FILE" 2>/dev/null
  exit 0
fi

# Two-tier reclaim. Both modes NEVER touch images/containers/volumes (no `-a`, no
# `system prune`), so running containers are unaffected.
#   routine   (70–84%): prune cache OLDER than KEEP_WINDOW — keeps recent cache so
#                       the next plugin rebuild stays fast.
#   emergency ( >=85% ): prune ALL unused cache (no age filter) — the disk is
#                       critically full and the young cache is the bloat; keeping it
#                       fast is moot if Postgres/apps can't write.
if [ "$disk_pct" -ge "$EMERGENCY_PCT" ]; then
  MODE="emergency: all unused cache (disk ${disk_pct}% >= ${EMERGENCY_PCT}%)"
  RAW=$(docker builder prune -f 2>>"$LOG")
else
  MODE="routine: cache older than ${KEEP_WINDOW}"
  RAW=$(docker builder prune -f --filter "until=${KEEP_WINDOW}" 2>>"$LOG")
fi
# Parse the reclaimed size from the summary line. Docker 29.x / containerd
# snapshotter prints "Total:\t52.4GB"; older Docker prints "Total reclaimed
# space: 52.4GB". Match either by grabbing the size token off any "Total" line.
RECLAIMED=$(echo "$RAW" | grep -iE '^Total' | grep -oiE '[0-9.]+ ?[KMGTP]?i?B' | tail -1)
[ -z "$RECLAIMED" ] && RECLAIMED="0B"

disk_after=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
[ -z "$disk_after" ] && disk_after=$(df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
disk_after=${disk_after:-$disk_pct}

log_line "RECLAIMED ${RECLAIMED} [${MODE}]; root disk ${disk_pct}% -> ${disk_after}%"
logger -t takguard-buildcache "Reclaimed ${RECLAIMED} Docker build cache [${MODE}]; disk ${disk_pct}%->${disk_after}%"
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') reclaimed ${RECLAIMED} [${MODE}], disk ${disk_pct}%->${disk_after}%" > "$LAST_FILE" 2>/dev/null
exit 0
