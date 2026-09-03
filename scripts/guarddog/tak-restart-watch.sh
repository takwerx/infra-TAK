#!/bin/bash
# v10.1.57 W4: classify the PREVIOUS boot and say why the box went down.
#
# Guard Dog had no restart detection at all. A customer box (helpnow/trytak.org) was
# power-cycled TEN times by its hosting provider between 2026-07-06 and 2026-09-02 --
# including one unclean stop that kept it down 2h21m -- and the console had nothing to
# say about it. The operator concluded it was a certificate he had changed, and lost
# days. The signal was sitting in the journal the whole time, free.
#
# PORTABILITY IS THE WHOLE TRICK. qemu-ga is a KVM/QEMU detail: `nuc` is bare metal
# and has no guest agent, `aws-arm` is Nitro. So classification is SIGNATURE-ADDITIVE,
# never signature-dependent -- the absence of a qemu-ga line means "not a QEMU host",
# never "no verdict". EXTERNAL and UNCLEAN are the platform-neutral buckets and must
# work with no guest agent present. Everything used here (journalctl, systemd) is
# family-neutral: no apt/dnf, no firewall change, no arch-specific binary.
#
# Runs ONCE at boot from takrestartwatch.service (Type=oneshot). Idempotent by boot id.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATEDIR="/var/lib/takguard"
HISTORY="$STATEDIR/restart-history.jsonl"
LASTFILE="$STATEDIR/restart-watch.last"
MAX_HISTORY=50

mkdir -p "$STATEDIR" 2>/dev/null || true

BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '-')"
[ -z "$BOOT_ID" ] && exit 0

# Already classified this boot: nothing to do. Keeps a unit re-run (or a console
# restart that re-triggers it) from double-recording or double-alerting.
[ "$(cat "$LASTFILE" 2>/dev/null)" = "$BOOT_ID" ] && exit 0

# A box with volatile journald has no previous boot to read. That is not a fault and
# must not be reported as one.
if ! journalctl --list-boots --no-pager >/dev/null 2>&1 \
   || [ "$(journalctl --list-boots --no-pager 2>/dev/null | wc -l)" -lt 2 ]; then
    echo "$BOOT_ID" > "$LASTFILE"
    logger -t guarddog-restart -- "no previous boot in the journal (volatile storage or first boot) — nothing to classify" 2>/dev/null
    exit 0
fi

# --- gather evidence -----------------------------------------------------------------
# NOT a fixed tail of the whole boot. The shutdown sequence is as long as the box has
# units to stop: on `nuc` the decisive `systemd-logind: System is rebooting.` line sits
# 880 lines from the end of an 871,737-line boot, and a 600-line tail classified a
# deliberate reboot as EXTERNAL -- which would have alerted on every planned restart.
# journald indexes by syslog identifier, so ask it for the two streams that actually
# decide this. Both are small and cheap regardless of how big the boot was.
LOGIND="$(journalctl -b -1 --no-pager -t systemd-logind 2>/dev/null)"
QEMUGA="$(journalctl -b -1 --no-pager -t qemu-ga 2>/dev/null)"
KERN="$(journalctl -b -1 --no-pager -k 2>/dev/null | tail -n 300)"
TAILN="$(journalctl -b -1 --no-pager -o short-iso -n 200 2>/dev/null)"
[ -z "$TAILN" ] && { echo "$BOOT_ID" > "$LASTFILE"; exit 0; }

# --- times, for the downtime figure -------------------------------------------------
# -n 1 asks journald for the last record directly instead of piping a whole boot to tail.
_prev_end="$(journalctl -b -1 --no-pager -o short-iso -n 1 2>/dev/null | awk '{print $1}')"
_cur_start="$(journalctl -b 0 --no-pager -o short-iso 2>/dev/null | head -n1 | awk '{print $1}')"
DOWN_SECS=""
if [ -n "$_prev_end" ] && [ -n "$_cur_start" ]; then
    _a="$(date -d "$_prev_end" +%s 2>/dev/null)"
    _b="$(date -d "$_cur_start" +%s 2>/dev/null)"
    [ -n "$_a" ] && [ -n "$_b" ] && [ "$_b" -ge "$_a" ] && DOWN_SECS=$((_b - _a))
fi
_human_down="unknown"
if [ -n "$DOWN_SECS" ]; then
    if   [ "$DOWN_SECS" -lt 120 ];  then _human_down="${DOWN_SECS}s"
    elif [ "$DOWN_SECS" -lt 7200 ]; then _human_down="$((DOWN_SECS / 60)) min"
    else _human_down="$((DOWN_SECS / 3600))h $(((DOWN_SECS % 3600) / 60))m"; fi
fi

# --- classify -----------------------------------------------------------------------
# Order matters: the most specific cause wins. Each test is a POSITIVE signature, so a
# platform that cannot emit one simply falls through to the next.
VERDICT=""; EVIDENCE=""
_grab() { printf '%s\n' "$2" | grep -iE "$1" | tail -n1 | cut -c1-240; }

if _e="$(_grab 'kernel panic|Oops: [0-9]|BUG: unable to handle' "$KERN")" && [ -n "$_e" ]; then
    VERDICT="PANIC";               EVIDENCE="$_e"
elif _e="$(_grab 'Out of memory: Killed process|oom-kill:' "$KERN")" && [ -n "$_e" ]; then
    VERDICT="OOM";                 EVIDENCE="$_e"
elif _e="$(_grab 'guest-shutdown called' "$QEMUGA")" && [ -n "$_e" ]; then
    VERDICT="HYPERVISOR_POWEROFF"; EVIDENCE="$_e"
elif _e="$(_grab 'hypervisor initiated shutdown' "$LOGIND")" && [ -n "$_e" ]; then
    VERDICT="HYPERVISOR_POWEROFF"; EVIDENCE="$_e"
elif _e="$(_grab 'System is (powering down|rebooting)|The system will (power off|reboot)' "$LOGIND")" && [ -n "$_e" ]; then
    # Something ON the box asked: an operator's `reboot`, or a script/unattended-upgrade.
    # Deliberate either way -- this is the one verdict that does NOT alert. Checked AFTER
    # the hypervisor tests, because a hypervisor shutdown ALSO produces a logind line
    # (helpnow: "System is powering down (hypervisor initiated shutdown)") and the more
    # specific cause must win.
    VERDICT="OPERATOR";            EVIDENCE="$_e"
elif _e="$(_grab 'Reached target (System Power Off|Power-Off|Reboot|System Reboot)|systemd-shutdown.*(Powering off|Rebooting)' "$TAILN")" && [ -n "$_e" ]; then
    # A clean shutdown that logind never announced: ACPI button, IPMI, a cloud console.
    # The platform-neutral sibling of HYPERVISOR_POWEROFF -- this is the bucket that
    # covers bare metal and non-QEMU hypervisors, which have no guest agent to ask.
    VERDICT="EXTERNAL";            EVIDENCE="$_e"
else
    # No shutdown records at all: the journal simply stops mid-write. Power loss, a
    # hard reset, or the VM being destroyed under us.
    VERDICT="UNCLEAN"
    EVIDENCE="$(printf '%s\n' "$TAILN" | tail -n1 | cut -c1-240)"
fi

TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# --- record -------------------------------------------------------------------------
_json_escape() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$(printf '%s' "$1" | tr -d '"\\')"; }
{
  printf '{"boot_id":%s,"classified_at":%s,"verdict":%s,"prev_boot_ended":%s,"booted_at":%s,"down_seconds":%s,"evidence":%s}\n' \
    "$(_json_escape "$BOOT_ID")" "$(_json_escape "$TS")" "$(_json_escape "$VERDICT")" \
    "$(_json_escape "${_prev_end:-unknown}")" "$(_json_escape "${_cur_start:-unknown}")" \
    "${DOWN_SECS:-null}" "$(_json_escape "$EVIDENCE")"
} >> "$HISTORY" 2>/dev/null

# Keep the file bounded — this is a breadcrumb trail, not a log.
if [ "$(wc -l < "$HISTORY" 2>/dev/null || echo 0)" -gt "$MAX_HISTORY" ]; then
    tail -n "$MAX_HISTORY" "$HISTORY" > "$HISTORY.tmp" 2>/dev/null && mv "$HISTORY.tmp" "$HISTORY"
fi
echo "$BOOT_ID" > "$LASTFILE"
logger -t guarddog-restart -- "previous boot classified: $VERDICT (down ${_human_down})" 2>/dev/null

# --- alert --------------------------------------------------------------------------
# OPERATOR is silent: a deliberate reboot is not an incident. Everything else is.
[ "$VERDICT" = "OPERATOR" ] && exit 0

case "$VERDICT" in
  HYPERVISOR_POWEROFF)
    _what="Your hosting provider or virtualization platform powered this VM off."
    _why="This did not come from anything running on the server. The guest agent received a shutdown command from the host. If you did not request it, open a ticket with your hosting provider and quote the timestamps below." ;;
  EXTERNAL)
    _what="The server was shut down cleanly by something outside the operating system."
    _why="No process on the box asked for this — it came from a power button, a management controller (IPMI/iDRAC), or a cloud console." ;;
  UNCLEAN)
    _what="The server stopped WITHOUT shutting down — power loss, a hard reset, or the VM being destroyed."
    _why="The system journal ends mid-write with no shutdown records. Data written in the final seconds may be lost. If this repeats, it is a hardware or hosting-platform fault, not a software one." ;;
  PANIC)
    _what="The Linux kernel panicked."
    _why="This is an operating-system or hardware fault. The evidence line below is the panic message." ;;
  OOM)
    _what="The kernel ran out of memory and started killing processes before the box went down."
    _why="Check what is oversized on this box — TAK JVM heaps, Authentik workers, or Postgres shared_buffers." ;;
  *)
    _what="The server restarted for a reason Guard Dog could not classify."
    _why="The evidence line below is the last thing in the previous boot's journal." ;;
esac

# The console serves the alert relay on :5001. This unit runs at boot, so it can easily
# beat the console up and log "console unreachable" for the one alert that most needed to
# be delivered. Wait for it -- bounded, and we still send on timeout so a wedged console
# costs us the email but never the journal record.
CONSOLE_PORT="${CONSOLE_PORT:-5001}"
for _i in $(seq 1 30); do
    if curl -s -k -o /dev/null --connect-timeout 2 --max-time 4 \
         "https://127.0.0.1:${CONSOLE_PORT}/login" 2>/dev/null \
       || curl -s -o /dev/null --connect-timeout 2 --max-time 4 \
         "http://127.0.0.1:${CONSOLE_PORT}/login" 2>/dev/null; then
        break
    fi
    sleep 4
done

SUBJ="Unexpected restart ($VERDICT) on $SERVER_IDENTIFIER"
BODY="$_what

Server:        $SERVER_IDENTIFIER
Verdict:       $VERDICT
Went down:     ${_prev_end:-unknown}
Came back:     ${_cur_start:-unknown}
Down for:      $_human_down
Detected (UTC): $TS

$_why

Evidence from the previous boot's journal:
  $EVIDENCE

Guard Dog records the last $MAX_HISTORY restarts in $HISTORY, and the console's
Guard Dog page shows them with their causes.
"

echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    TMPF="/tmp/gd-restart-sms-$$.txt"
    printf '%s' "$BODY" > "$TMPF"
    /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
    rm -f "$TMPF"
fi
exit 0
