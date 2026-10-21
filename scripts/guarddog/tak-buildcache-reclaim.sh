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
# escalates once the disk reaches FULL_RECLAIM_PCT — the same 80% at which
# tak-disk-watch.sh raises its warning. There it reclaims ALL unused build cache,
# removes images no container references (running or stopped), and trims the
# system journal. It NEVER touches containers, volumes, or an image a container
# uses, so running services are unaffected.
#
# GH #165: before, the 80–84% band only pruned cache older than 7 days. A box sat at
# 81% with 16 GB of young cache, 13 GB of image tags left behind by upgrades and a
# 3.9 GB journal; every hourly run "succeeded" with 0B reclaimed and the alert never
# cleared. The warning level is now also the level at which everything safe goes.
#
# It also caps journald at JOURNAL_MAX on every run (a drop-in, converged if absent
# or different) — no box shipped with a cap, so the journal grew without bound.
#
# Fleet-uniform thresholds (no per-box knobs). Runs on a systemd timer (hourly, so it
# can rescue a disk that fills between runs — a no-op below RECLAIM_THRESHOLD_PCT).
# Off switch: create /opt/tak-guarddog/buildcache_reclaim_off to disable.
# Cross-platform: docker + df + awk + logger + journalctl only — identical on
# Ubuntu, RHEL, ARM64.

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
FULL_RECLAIM_PCT=80        # at/above this, reclaim ALL unused cache (drop the age
                           # filter), unused images and journal: a burst of rebuilds
                           # fills the disk with <7-day cache the routine window-
                           # limited prune cannot touch (it would reclaim ~0 and the
                           # disk stays red). MUST equal ALERT_THRESHOLD in
                           # tak-disk-watch.sh — reclaiming only above the warning
                           # leaves a band where the alert can never clear (GH #165).
JOURNAL_MAX="500M"         # journald SystemMaxUse. Above the ~200M the reporter
                           # used, to keep more sshd/sudo history for audit (C3).
JOURNAL_DROPIN="/etc/systemd/journald.conf.d/takwerx-size.conf"
UPDATE_LOCK="/var/lib/takwerx-console/update-now.lock"   # written by Update Now; 20-min TTL

# Root-disk usage percent (integer)
root_pct() {
  local p
  p=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
  [ -z "$p" ] && p=$(df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')   # POSIX fallback
  echo "${p:-0}"
}

# ── journald size cap — every run, on every box, Docker or not ───────────────
# Fleet constant: always converge to JOURNAL_MAX (no operator value preserved).
# A restart is how journald picks up a drop-in; it then holds the cap itself, and
# the vacuum trims what was already on disk before the cap existed.
if command -v journalctl >/dev/null 2>&1; then
  want_conf=$(printf '[Journal]\nSystemMaxUse=%s' "$JOURNAL_MAX")
  if [ "$(cat "$JOURNAL_DROPIN" 2>/dev/null)" != "$want_conf" ]; then
    if mkdir -p "$(dirname "$JOURNAL_DROPIN")" 2>/dev/null && printf '%s\n' "$want_conf" > "$JOURNAL_DROPIN" 2>/dev/null; then
      systemctl restart systemd-journald >/dev/null 2>&1
      journalctl --vacuum-size="$JOURNAL_MAX" >/dev/null 2>&1
      log_line "journald: capped at SystemMaxUse=${JOURNAL_MAX} ($JOURNAL_DROPIN)"
      logger -t takguard-buildcache "journald capped at SystemMaxUse=${JOURNAL_MAX}"
    else
      log_line "journald: could not write $JOURNAL_DROPIN — cap not applied"
    fi
  fi
fi

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

disk_pct=$(root_pct)

# Parse the reclaimed size from a `docker builder prune` / `docker image prune`
# summary. Docker 29.x / containerd snapshotter prints "Total:\t52.4GB"; older
# Docker prints "Total reclaimed space: 52.4GB". Match either by grabbing the size
# token off "Total".
parse_reclaimed() { echo "$1" | grep -iE '^Total' | grep -oiE '[0-9.]+ ?[KMGTP]?i?B' | tail -1; }

# Is an install or update pulling/building images right now? Between a pull and the
# `compose up` that starts it — or across a `compose down && up` — a wanted image
# has no container yet and would look unused. Skip the image prune then; the next
# hourly run picks it up. Prints the reason when busy.
images_in_flight() {
  if [ -f "$UPDATE_LOCK" ] && [ -n "$(find "$UPDATE_LOCK" -mmin -20 2>/dev/null)" ]; then
    echo "console update in progress"; return 0
  fi
  if pgrep -f 'docker(-| )compose|docker( image)? (pull|load|import)|docker( buildx)? build|buildctl' >/dev/null 2>&1; then
    echo "docker compose/pull/build running"; return 0
  fi
  return 1
}

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

# ── Tier 1/2: disk-% backstop ─────────────────────────────────────────────────
# The size cap holds steady-state; these catch a disk driven full between runs
# (e.g. a rebuild burst of <7-day cache under the cap, upgrade leftovers, journal).
# None of it touches containers, volumes, or an image a container uses.
#   routine (70–79%): prune cache OLDER than KEEP_WINDOW.
#   full    ( >=80%): prune ALL unused cache (no age filter), images no container
#                     references, and vacuum the journal to JOURNAL_MAX.
if [ "$disk_pct" -lt "$RECLAIM_THRESHOLD_PCT" ]; then
  log_line "root disk ${disk_pct}% — below ${RECLAIM_THRESHOLD_PCT}% threshold; size-cap only"
else
  if [ "$disk_pct" -ge "$FULL_RECLAIM_PCT" ]; then
    MODE="full: all unused cache (disk ${disk_pct}% >= ${FULL_RECLAIM_PCT}%)"
    RAW=$(docker builder prune -af 2>>"$LOG")
  else
    MODE="routine: cache older than ${KEEP_WINDOW}"
    RAW=$(docker builder prune -f --filter "until=${KEEP_WINDOW}" 2>>"$LOG")
  fi
  RECLAIMED=$(parse_reclaimed "$RAW"); [ -z "$RECLAIMED" ] && RECLAIMED="0B"
  log_line "RECLAIMED ${RECLAIMED} [${MODE}]"
  SUMMARY="${SUMMARY}; ${MODE} reclaimed ${RECLAIMED}"

  if [ "$disk_pct" -ge "$FULL_RECLAIM_PCT" ]; then
    # Unused images: `-a` = every image no container (running OR stopped) references —
    # the old tags upgrades leave behind. Never volumes, never `system prune`.
    if busy=$(images_in_flight); then
      log_line "image prune skipped: ${busy}"
      SUMMARY="${SUMMARY}; image prune skipped (${busy})"
    else
      RAW_IMG=$(docker image prune -af 2>>"$LOG")
      IMG_RECLAIMED=$(parse_reclaimed "$RAW_IMG"); [ -z "$IMG_RECLAIMED" ] && IMG_RECLAIMED="0B"
      log_line "RECLAIMED ${IMG_RECLAIMED} unused images"
      SUMMARY="${SUMMARY}; unused images reclaimed ${IMG_RECLAIMED}"
    fi
    if command -v journalctl >/dev/null 2>&1; then
      J_FREED=$(journalctl --vacuum-size="$JOURNAL_MAX" 2>&1 | grep -oE 'freed [0-9.]+[KMGT]?B?' | tail -1)
      log_line "journal vacuum to ${JOURNAL_MAX}: ${J_FREED:-nothing to free}"
      SUMMARY="${SUMMARY}; journal ${J_FREED:-already under ${JOURNAL_MAX}}"
    fi
  fi

  disk_after=$(root_pct)
  log_line "root disk ${disk_pct}% -> ${disk_after}%"
  SUMMARY="${SUMMARY}, disk ${disk_pct}%->${disk_after}%"
  logger -t takguard-buildcache "${SUMMARY#*; }"
fi

echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') ${SUMMARY}" > "$LAST_FILE" 2>/dev/null
exit 0
