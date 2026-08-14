#!/bin/bash
# Guard Dog: alert when an ArcGIS feed's UPSTREAM SOURCE stops publishing.
#
# v10.1.34, operator-requested. Found live 2026-08-14: the CA Power Outages service
# (all of Northern California, PG&E) stopped publishing at 2026-08-11 20:00:2xZ on all
# three of its layers within ten seconds of each other - the publisher's pipeline died.
# test12 kept serving those 273 outage polygons for ~46 HOURS as if current, with every
# log line 200 OK, the mission full, the console green and Guard Dog silent. The
# operator only noticed because a phone would not sync.
#
# For a public-safety tool that is the dangerous failure: not missing data, but
# confidently WRONG data. Restored outages still drawn on the map two days later.
#
# The detection is free. Every ArcGIS layer publishes editingInfo.dataLastEditDate in
# its own metadata (<serviceUrl>/<layerId>?f=json, no auth), which is when the SOURCE
# was last edited - independent of whether our poll succeeded.
#
# IMPORTANT: a static feed is NOT automatically a dead feed. We check the source's own
# edit timestamp; we deliberately do NOT infer staleness from our own zero-churn,
# because a genuinely quiet feed (no new fires, no outages) is legitimate and would
# generate false alarms every night.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_EMAIL="ALERT_EMAIL_PLACEHOLDER"
STATE_FILE="/var/lib/takguard/feedsource_notified"
LOG_FILE="/var/log/takguard/feedsource.log"
CURL_TIMEOUT=20

# SELF-CALIBRATING, not a fixed threshold. First live run (test12, 2026-08-14) proved
# why: a single 6h rule correctly passed CA AIR INTEL and POWER-OUTAGES, but flagged
# "NWS Response Zones" as STALE at 217h - and that layer is an NWS administrative
# BOUNDARY set which is redrawn every few months. It was perfectly healthy. A watcher
# that emails about healthy feeds gets muted, and then it is worthless precisely when
# it matters.
#
# So we learn each layer's own cadence instead (deterministic auto-tune - same logic on
# every box, no operator knob, per the fleet-uniform rules). We remember the largest gap
# we have ever OBSERVED between edits for that layer, and alert only when the current
# silence is well past it. A fire feed that normally updates hourly alerts within hours;
# a boundary layer that normally updates monthly does not alert until it is months late.
STALE_FLOOR_H=6          # never alert sooner than this, however chatty the feed
STALE_GAP_MULTIPLE=3     # ... or sooner than 3x the largest gap ever seen for it
STALE_UNKNOWN_H=720      # no cadence learned yet (30d) - catches a feed dead since install
BASELINE_FILE="/var/lib/takguard/feedsource_baseline"

NR_CTX="/var/lib/docker/volumes/node-red_node_red_data/_data/context/global/global.json"

log_msg() { mkdir -p /var/log/takguard 2>/dev/null; echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $*" >> "$LOG_FILE" 2>/dev/null; }

# Nothing to do if Node-RED never stored any feed config.
[ -f "$NR_CTX" ] || { log_msg "no Node-RED global context - skipping"; exit 0; }

# Emit "<configName>\t<serviceUrl>\t<layerId>" per ArcGIS feed. python3 is present on
# every supported platform (the console itself runs on it).
FEEDS=$(python3 - "$NR_CTX" <<'PY' 2>/dev/null
import json, sys
try:
    j = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
cfgs = j.get('arcgis_configs') or []
cfgs = list(cfgs.values()) if isinstance(cfgs, dict) else cfgs
for c in cfgs:
    if not isinstance(c, dict):
        continue
    src = c.get('source') or {}
    url = (src.get('serviceUrl') or '').rstrip('/')
    if not url:
        continue
    layer = src.get('layerId')
    if layer is None:
        layers = src.get('layers') or []
        layer = (layers[0] or {}).get('layerId') if layers else 0
    name = c.get('configName') or 'unnamed'
    print('%s\t%s\t%s' % (name, url, layer if layer is not None else 0))
PY
)

[ -z "$FEEDS" ] && { log_msg "no ArcGIS feeds configured - nothing to watch"; exit 0; }

NOW_EPOCH=$(date -u +%s)
STALE=""
SIG=""

while IFS=$'\t' read -r NAME URL LAYER; do
  [ -z "$URL" ] && continue
  # Cache-bust: ArcGIS Online serves layer metadata through its CDN too, and a cached
  # copy would report a stale-looking timestamp long after the publisher recovered.
  META=$(curl -sS -f --max-time "$CURL_TIMEOUT" \
    -H "User-Agent: infra-TAK" \
    "${URL}/${LAYER}?f=json&_ts=${NOW_EPOCH}" 2>/dev/null)
  if [ -z "$META" ]; then
    log_msg "$NAME: could not reach ${URL}/${LAYER} - not treating unreachable as stale"
    continue
  fi
  # dataLastEditDate is epoch MILLISECONDS.
  LAST_MS=$(echo "$META" | grep -o '"dataLastEditDate":[[:space:]]*[0-9]*' | head -1 | grep -o '[0-9]*$')
  if [ -z "$LAST_MS" ]; then
    log_msg "$NAME: layer publishes no dataLastEditDate - cannot assess staleness"
    continue
  fi
  LAST_EPOCH=$((LAST_MS / 1000))
  AGE_H=$(( (NOW_EPOCH - LAST_EPOCH) / 3600 ))
  # Learn this layer's cadence and get back the threshold to judge it by.
  THRESH_H=$(python3 - "$BASELINE_FILE" "$NAME" "$LAST_EPOCH" "$STALE_FLOOR_H" "$STALE_GAP_MULTIPLE" "$STALE_UNKNOWN_H" <<'PYB' 2>/dev/null
import os, sys
path, name, last_s, floor_h, mult, unknown_h = sys.argv[1:7]
last = int(last_s); floor_h = int(floor_h); mult = int(mult); unknown_h = int(unknown_h)
rows = {}
if os.path.exists(path):
    for line in open(path):
        parts = line.rstrip("\n").split("|")
        if len(parts) == 3:
            rows[parts[0]] = (int(parts[1]), int(parts[2]))
prev_edit, max_gap = rows.get(name, (0, 0))
if prev_edit and last > prev_edit:
    max_gap = max(max_gap, last - prev_edit)   # observed a real publication interval
rows[name] = (max(last, prev_edit), max_gap)
tmp = path + ".tmp"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(tmp, "w") as f:
    for k, (e, g) in rows.items():
        f.write("%s|%d|%d\n" % (k, e, g))
os.replace(tmp, path)
# No cadence learned yet -> only a very long silence is evidence of death.
print(unknown_h if max_gap == 0 else max(floor_h, (max_gap * mult) // 3600))
PYB
)
  THRESH_H=${THRESH_H:-$STALE_UNKNOWN_H}
  if [ "$AGE_H" -ge "$THRESH_H" ]; then
    LAST_ISO=$(date -u -d "@${LAST_EPOCH}" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || date -u -r "${LAST_EPOCH}" '+%Y-%m-%d %H:%M UTC' 2>/dev/null)
    STALE="${STALE}  - ${NAME}: source last updated ${LAST_ISO} (${AGE_H}h ago, expected within ${THRESH_H}h)\n      ${URL}/${LAYER}\n"
    # Signature keyed on the feed and the day it went stale, so a feed that stays dead
    # re-alerts daily rather than every run.
    SIG="${SIG}${NAME}:$((LAST_EPOCH / 86400));"
    log_msg "$NAME: STALE - source last edit ${AGE_H}h ago (learned threshold ${THRESH_H}h)"
  else
    log_msg "$NAME: ok - source last edit ${AGE_H}h ago (threshold ${THRESH_H}h)"
  fi
done <<< "$FEEDS"

[ -z "$STALE" ] && exit 0

SHOULD_SEND=false
if [ ! -f "$STATE_FILE" ]; then
  SHOULD_SEND=true
elif [ -n "$(find "$STATE_FILE" -mtime +1 2>/dev/null)" ]; then
  SHOULD_SEND=true
else
  old_sig=$(cat "$STATE_FILE" 2>/dev/null)
  [ "$old_sig" != "$SIG" ] && SHOULD_SEND=true
fi
[ "$SHOULD_SEND" = false ] && log_msg "stale feeds but already notified (same set); next email in 24h or when the set changes"

if $SHOULD_SEND; then
  mkdir -p /var/lib/takguard 2>/dev/null
  printf '%s' "$SIG" > "$STATE_FILE"
  SUBJ="infra-TAK: map feed source has stopped publishing on $SERVER_IDENTIFIER"
  BODY="A map feed's UPSTREAM SOURCE has stopped publishing on $SERVER_IDENTIFIER ($(date -u '+%Y-%m-%d %H:%M UTC')).

The feed itself is healthy and is still serving its last known data. That data is now
stale, and anyone looking at the map has no way to tell.

$(printf '%b' "$STALE")
This is a fault at the data publisher, not on this server. There is nothing to restart.
Contact whoever publishes the service, or expect the map to keep showing old data until
they resume.

Thresholds are learned per feed from how often that source normally publishes.
"

  if echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "$ALERT_EMAIL" 2>/dev/null; then
    log_msg "stale-feed email handed to console (recipient resolved from settings)"
  else
    log_msg "stale-feed email FAILED (console/relay unreachable - check the Guard Dog page)"
  fi
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    TMPF="/tmp/gd-feedsource-$$.txt"
    printf '%s' "$BODY" > "$TMPF"
    /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
    rm -f "$TMPF"
  fi
fi
