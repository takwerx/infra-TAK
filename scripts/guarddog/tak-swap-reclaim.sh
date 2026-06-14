#!/bin/bash
# Guard Dog: swap hygiene — reclaim STALE swap after a memory-pressure event.
#
# Linux does not proactively swap pages back in, so after a transient spike (e.g.
# a heavy Authentik autovacuum / large DELETE reclaim) the swapfile can stay pinned
# ~full long after RAM has recovered, leaving no swap headroom for the next spike.
#
# This healer reclaims swap (swapoff -a && swapon -a) ONLY when it is SAFE:
#   - swap is at least SWAP_FULL_PCT full, AND
#   - MemAvailable is large enough to absorb the swapped-in pages with margin
#     (MemAvailable >= swap_used * 1.3).
# If swap is full but RAM is NOT available (genuine, ongoing pressure), it does
# NOT reclaim — running swapoff under real pressure could OOM the box. Instead it
# sends a one-shot alert until the condition clears.
#
# Fleet-uniform thresholds (no per-box knobs). Runs on a systemd timer.
# Placeholders replaced at deploy time:  ALERT_EMAIL_PLACEHOLDER

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
mkdir -p "$STATE_DIR" 2>/dev/null
LAST_FILE="$STATE_DIR/swap_reclaim_last"
LOG="$STATE_DIR/swap_reclaim.log"
PRESSURE_ALERT_SENT="$STATE_DIR/swap_pressure_alert_sent"

log_line() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1" >> "$LOG" 2>/dev/null; }

# Fleet-uniform thresholds
SWAP_FULL_PCT=90            # only act when swap is at least this full
RAM_SAFETY_NUM=13          # require MemAvailable >= swap_used * (13/10) to reclaim safely
RAM_SAFETY_DEN=10

# /proc/meminfo values are in kB
swap_total=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
swap_free=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
mem_avail=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)

echo "$(date +%s)" > "$LAST_FILE" 2>/dev/null

# No swap configured → nothing to do
if [ -z "$swap_total" ] || [ "$swap_total" -eq 0 ]; then
  log_line "no swap configured — nothing to do"
  exit 0
fi

swap_used=$(( swap_total - swap_free ))
swap_pct=$(( 100 * swap_used / swap_total ))

if [ "$swap_pct" -lt "$SWAP_FULL_PCT" ]; then
  log_line "swap ${swap_pct}% used — below ${SWAP_FULL_PCT}%, nothing to do"
  rm -f "$PRESSURE_ALERT_SENT" 2>/dev/null
  exit 0
fi

# swap is nearly full — is it SAFE to reclaim? (enough free RAM to absorb it)
need_ram=$(( swap_used * RAM_SAFETY_NUM / RAM_SAFETY_DEN ))
if [ "$mem_avail" -ge "$need_ram" ]; then
  # Safe: stale swap left over from a past spike. Reclaim it.
  if swapoff -a 2>>"$LOG" && swapon -a 2>>"$LOG"; then
    new_free=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
    log_line "RECLAIMED: swap was ${swap_pct}% full (${swap_used}kB), MemAvailable ${mem_avail}kB >= need ${need_ram}kB → swapoff/swapon OK (SwapFree now ${new_free}kB)"
    rm -f "$PRESSURE_ALERT_SENT" 2>/dev/null
  else
    # swapoff failed (kernel refused — usually means it could not move pages safely);
    # make sure swap is back on and leave it alone.
    swapon -a 2>>"$LOG"
    log_line "WARN: swapoff/swapon failed at swap ${swap_pct}% full — restored swapon, left swap in place"
  fi
  exit 0
fi

# swap full AND RAM not available → genuine memory pressure. Do NOT reclaim. Alert once.
log_line "PRESSURE: swap ${swap_pct}% full but MemAvailable ${mem_avail}kB < need ${need_ram}kB — NOT reclaiming (would risk OOM); alerting"
if [ ! -f "$PRESSURE_ALERT_SENT" ]; then
  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  swap_used_mb=$(( swap_used / 1024 ))
  mem_avail_mb=$(( mem_avail / 1024 ))
  SUBJ="Memory pressure on $SERVER_IDENTIFIER - swap ${swap_pct}% full, low free RAM"
  BODY="Guard Dog detected sustained memory pressure on $SERVER_IDENTIFIER.

Swap is ${swap_pct}% full (${swap_used_mb} MB used) and MemAvailable is only ${mem_avail_mb} MB - not
enough to safely reclaim swap, so Guard Dog did NOT run swapoff (that could OOM the box under real pressure).

Server: $SERVER_IDENTIFIER
Time (UTC): $TS

This usually means a process is using a lot of memory. Check:
  free -h
  ps -eo pmem,rss,comm --sort=-rss | head

Guard Dog will automatically reclaim the swap once RAM frees up. This alert is sent once until the
condition clears.
"
  [ -n "ALERT_EMAIL_PLACEHOLDER" ] && echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
  touch "$PRESSURE_ALERT_SENT" 2>/dev/null
fi
exit 0
