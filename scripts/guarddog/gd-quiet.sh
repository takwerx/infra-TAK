#!/bin/bash
# Guard Dog quiet window (ops #228): hold alert email/SMS while planned work runs.
#
#   gd-quiet.sh on <minutes> <reason...>   open (or replace) a window, 1-240 minutes
#   gd-quiet.sh off                        close it now
#   gd-quiet.sh status                     print the window, if any
#
# Guard Dog keeps watching and restarting during the window; only DELIVERY is held.
# Held alerts are not dropped blind: when the window closes the console re-runs Guard
# Dog's checks and sends one email if anything is still failing (app.py,
# _gd_quiet_review_once). A run that dies leaves a window that simply expires.
#
# Root only. The marker lives in Guard Dog's root-owned state dir for the same reason
# as the Authentik update marker (#167): anyone who can write it can mute Guard Dog.
# Keep MAX_MIN and the path in step with app.py GD_QUIET_MAX_S / GD_QUIET_MARKER.
MARKER="/var/lib/takguard/quiet_window"
MAX_MIN=240

_log() {
  mkdir -p /var/log/takguard
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') | quiet-window | $1" >> /var/log/takguard/restarts.log
  logger -t guarddog-quiet -- "$1" 2>/dev/null
}

if [ "$(id -u)" -ne 0 ]; then
  echo "gd-quiet.sh: must run as root (sudo)" >&2
  exit 1
fi

case "${1:-status}" in
  on)
    MIN="${2:-}"
    case "$MIN" in ''|*[!0-9]*) echo "usage: gd-quiet.sh on <minutes 1-$MAX_MIN> <reason>" >&2; exit 2 ;; esac
    if [ "$MIN" -lt 1 ] || [ "$MIN" -gt "$MAX_MIN" ]; then
      echo "gd-quiet.sh: minutes must be 1-$MAX_MIN" >&2; exit 2
    fi
    shift 2
    # One line, printable, bounded: the reason is shown in the console and in the
    # close-out email, so control characters and newlines are stripped here.
    REASON="$(printf '%s' "$*" | tr -cd '[:print:]' | cut -c1-120)"
    [ -n "$REASON" ] || REASON="planned work"
    NOW=$(date +%s)
    END=$(( NOW + MIN * 60 ))
    mkdir -p "$(dirname "$MARKER")"
    TMP="$(mktemp "${MARKER}.XXXXXX")" || exit 1
    printf '%s %s %s\n' "$NOW" "$END" "$REASON" > "$TMP"
    chmod 0644 "$TMP"
    mv -f "$TMP" "$MARKER"
    _log "on for ${MIN} min (until $(date -u -d "@$END" '+%H:%M:%SZ' 2>/dev/null || echo "$END")): $REASON"
    echo "Guard Dog quiet window on for ${MIN} min: $REASON"
    ;;
  off)
    if [ -f "$MARKER" ]; then
      rm -f "$MARKER"
      _log "off"
    fi
    echo "Guard Dog quiet window off"
    ;;
  status)
    if [ ! -f "$MARKER" ]; then
      echo "no quiet window"; exit 0
    fi
    read -r START END REASON < "$MARKER"
    NOW=$(date +%s)
    case "$START$END" in *[!0-9]*|'') echo "quiet window marker unreadable (ignored)"; exit 0 ;; esac
    if [ "$END" -le "$NOW" ]; then
      echo "quiet window expired $(( (NOW - END) / 60 )) min ago: $REASON"
    elif [ $(( END - START )) -gt $(( MAX_MIN * 60 )) ]; then
      echo "quiet window longer than $MAX_MIN min (ignored): $REASON"
    else
      echo "quiet window on, $(( (END - NOW + 59) / 60 )) min left: $REASON"
    fi
    ;;
  *)
    echo "usage: gd-quiet.sh on <minutes> <reason> | off | status" >&2
    exit 2
    ;;
esac
