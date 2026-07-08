#!/bin/bash
# infra-TAK Setup AP auto-trigger watcher — v10.1.0 Leg 6b.
#
# Runs every ~30s (systemd timer). Decides whether the box should be broadcasting
# its own setup wifi, based ONLY on "can this box reach the internet right now":
#
#   - Uplink OK  → ensure the setup AP is DOWN (box is online; nothing to do).
#   - No uplink  → after a grace window, bring the setup AP UP so an operator can
#                  join locally and provision a network.
#
# Trigger rule (operator-specified 2026-07-08):
#   * On ETHERNET with a working internet path → NEVER broadcast.
#   * Fresh boot with no uplink → broadcast IMMEDIATELY (short ~45s connect window
#     only, to let a known wifi associate first).
#   * Loses uplink while running → ~90s grace (ride out a blip / wifi roam) then
#     broadcast.
# When a real uplink returns while the AP is up, the AP is torn down and the
# client radio restored (tak-setup-ap.sh stop).
#
# Disabled entirely if the operator turned auto-AP off (setup-ap.conf: AUTO=0).
set -u

STATE_DIR="/var/lib/takguard"
CONF="$STATE_DIR/setup-ap.conf"
ACTIVE_FLAG="$STATE_DIR/setup-ap.active"
NOUP_SINCE="$STATE_DIR/setup-ap.nouplink-since"
BOOT_GRACE=45          # seconds after boot to let a known wifi connect
RUN_GRACE=90           # seconds of sustained no-uplink while running before AP
ENGINE="/opt/tak-guarddog/tak-setup-ap.sh"

# Parse by assignment, never `source` (operator-typed values — same injection
# guard as the engine).
conf_get(){ grep -m1 "^$1=" "$CONF" 2>/dev/null | cut -d= -f2-; }
[ -x "$ENGINE" ] || exit 0
[ "$(conf_get SETUP_AP_AUTO)" = "0" ] && exit 0
# Do NOT auto-broadcast until an operator-set (or previously auto-generated +
# persisted) PSK exists — never stand up an AP with no real key (finding B).
_ap_pass="$(conf_get SETUP_AP_PASS)"
[ "${#_ap_pass}" -ge 8 ] || exit 0

now(){ date +%s; }

# Working internet path? Try a couple of fast TCP checks (no ICMP dependency —
# many networks filter ping). Any success = uplink OK.
uplink_ok(){
    for hp in 1.1.1.1:443 8.8.8.8:443 9.9.9.9:443; do
        h="${hp%:*}"; p="${hp#*:}"
        if timeout 3 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then
            exec 3>&- 3<&- 2>/dev/null; return 0
        fi
    done
    return 1
}

# Is a wired interface carrying an internet path? (ethernet-with-internet = never AP)
# uplink_ok already covers "can we reach the internet by ANY means", so we just
# use it — an ethernet uplink makes uplink_ok true and suppresses the AP.

AP_UP(){ [ -f "$ACTIVE_FLAG" ]; }

if uplink_ok; then
    rm -f "$NOUP_SINCE"
    if AP_UP; then
        "$ENGINE" stop >/dev/null 2>&1
    fi
    exit 0
fi

# No uplink.
if AP_UP; then
    exit 0                         # already broadcasting; wait for uplink to return
fi

# Pick the grace window: boot vs runtime.
UPTIME_S=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 9999)
if [ "$UPTIME_S" -le "$BOOT_GRACE" ]; then
    exit 0                         # still inside the boot connect window
fi

# Track how long we've had no uplink.
if [ ! -f "$NOUP_SINCE" ]; then
    now > "$NOUP_SINCE"
    exit 0
fi
SINCE=$(cat "$NOUP_SINCE" 2>/dev/null || echo 0)
ELAPSED=$(( $(now) - SINCE ))

# Fresh-boot-with-no-wifi ⇒ immediate (we're just past BOOT_GRACE, no client
# connected). Runtime drop ⇒ require RUN_GRACE of sustained no-uplink.
if [ "$UPTIME_S" -le $(( BOOT_GRACE + 60 )) ] || [ "$ELAPSED" -ge "$RUN_GRACE" ]; then
    "$ENGINE" start >/dev/null 2>&1
fi
