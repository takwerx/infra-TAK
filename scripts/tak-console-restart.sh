#!/bin/bash
# infra-TAK console daily restart with idle gate — v0.9.44-alpha.
#
# A wedged gunicorn worker keeps port 5001 in LISTEN while serving nothing, so
# systemd reports takwerx-console "active (running)" and never recovers it
# (test6 + test8, 2026-06-03: 5-7 day-old workers hung; front door + backdoor
# both dead while Authentik stayed up). Nothing restarted the console on a
# schedule. This oneshot, fired daily at 04:00 by takconsolerestart.timer,
# bounces the console so a wedged worker can never sit dead for days and pulled
# code actually goes live.
#
# Idle gate: ask the console whether a deploy/update is in flight before
# bouncing it. If it answers "not safe" we defer to the next cycle. If it does
# NOT answer within the timeout it is almost certainly wedged -- which is
# EXACTLY when a restart is wanted -- so we proceed.
#
# CANONICAL SOURCE is the _CONSOLE_RESTART_SCRIPT constant in app.py, which is
# what gets written to /usr/local/sbin/tak-console-restart.sh on each console
# boot by _ensure_console_restart_timer(). This file is the committed copy for
# operator visibility -- keep the two in sync.
set -u
TAG=tak-console-restart
log() { logger -t "$TAG" -- "$*" 2>/dev/null; echo "$(date -u +%FT%TZ) [$TAG] $*"; }

PORT="$(grep -oP '"console_port"[[:space:]]*:[[:space:]]*"?\K[0-9]+' /root/infra-TAK/.config/settings.json 2>/dev/null | head -1)"
[ -n "${PORT:-}" ] || PORT=5001

SAFE="$(curl -ks -m 5 "https://127.0.0.1:${PORT}/api/console/restart-safe" 2>/dev/null || true)"

if [ -z "$SAFE" ]; then
    log "console did not respond within 5s on :${PORT} (likely wedged) -- restarting"
elif printf '%s' "$SAFE" | grep -q '"safe"[: ]*true'; then
    log "console idle -- restarting to recover workers / load pulled code"
else
    REASON="$(printf '%s' "$SAFE" | grep -oP '"reason"[[:space:]]*:[[:space:]]*"\K[^"]*' | head -1)"
    log "deferred -- console busy (${REASON:-operation in progress}); next cycle will retry"
    exit 0
fi

if systemctl restart takwerx-console.service; then
    log "restart issued OK"
else
    log "restart FAILED rc=$?"
fi
exit 0
