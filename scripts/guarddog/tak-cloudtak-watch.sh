#!/bin/bash
# Guard Dog: CloudTAK container health. On 3 consecutive failures: alert and restart containers.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
FAIL_FILE="$STATE_DIR/cloudtak.failcount"
COOLDOWN_FILE="$STATE_DIR/cloudtak_last_restart"
MAX_FAILS=3
COOLDOWN_SECS=900

mkdir -p "$STATE_DIR"

# v10.1.55 (W6): this script had no logger of its own — each guard defines one, and
# the shared lib does not. Same shape and same destination as tak-authentik-watch.sh
# so the drift lines land in the one log operators already read.
_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
_log() {
  mkdir -p /var/log/takguard
  echo "$(_ts) | cloudtak-watch | $1" >> /var/log/takguard/restarts.log
}

# Don't run during first 15 minutes after boot (avoid restarting during startup)
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt 900 ] && exit 0

# v10.1.44 (W3): resolve the stack dir via the shared lib — $HOME is EMPTY in a
# systemd unit, so the old "${HOME:-...}" default silently pointed at nothing on
# installs that do not match it and this watchdog exited 0 without ever watching.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true
CT_DIR="$(gd_find_stack_dir CloudTAK cloudtak-api-1)"
[ -z "$CT_DIR" ] && exit 0

# Health: cloudtak-api container running
STATUS=$(docker ps --filter name=cloudtak-api --format "{{.Status}}" 2>/dev/null || true)
if echo "$STATUS" | grep -q "Up"; then
  echo 0 > "$FAIL_FILE"
  exit 0
fi

# Failure
FAILS=$(( $(cat "$FAIL_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$FAILS" > "$FAIL_FILE"

if [ "$FAILS" -lt "$MAX_FAILS" ]; then
  exit 0
fi

# Cooldown
if [ -f "$COOLDOWN_FILE" ]; then
  LAST=$(cat "$COOLDOWN_FILE")
  NOW=$(date +%s)
  if [ $(( NOW - LAST )) -lt $COOLDOWN_SECS ]; then
    exit 0
  fi
fi

TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p /var/log/takguard
echo "$TS | restart | CloudTAK container not up — restarting" >> /var/log/takguard/restarts.log

# ── CloudTAK media patch drift (v10.1.55 W6) ─────────────────────────────────
# infra-TAK is NOT a stock CloudTAK deploy for video. The console writes an HLS
# profile into cloudtak-media's /mediamtx.yml (and a reaper + SRT fix into its JS)
# with `sed -i` INSIDE THE RUNNING CONTAINER — none of it is in the image. So any
# recreate reverts it: a manual `docker compose up --build --no-cache`, a restart
# policy, an OOM recreate. The console re-heals after every path IT drives (deploy,
# update, force-recreate — all tagged v0.9.48), but nothing watched the cases it
# does not drive, and those patches then stayed gone until the next console restart.
#
# Why it matters: stock MediaMTX is 7 segments x 1s ~= 7s before a playable playlist,
# and CloudTAK's VideoPlayer retry budget is 1+2+4 ~= 7s. The player gives up exactly
# at that boundary and the user gets a black screen on a stream that is perfectly
# healthy (ffplay and the Video Wall play it fine). Our profile warms in ~1.5s.
# This is the mechanism behind the recurring field report "I get it working... I
# update... it fails" — reported again 2026-08-31 with the cause misattributed to an
# hls.js patch bump. See [[infratak-cloudtak-media-patches]].
#
# Detection only, plus a nudge. Re-applying is the console's job — it owns the apply
# script and the remote/split-box cases; duplicating that sed here would be a second
# writer of the same file.
if docker inspect cloudtak-media-1 >/dev/null 2>&1; then
  _hls_ok=1
  for _k in "^hlsVariant: mpegts" "^hlsSegmentCount: 3" "^hlsSegmentDuration: 500ms" "^hlsPartDuration: 200ms"; do
    docker exec cloudtak-media-1 grep -q "$_k" /mediamtx.yml 2>/dev/null || _hls_ok=0
  done
  _DRIFT_STATE="$STATE_DIR/cloudtak_media_drift"
  if [ "$_hls_ok" -eq 0 ]; then
    _log "drift | cloudtak-media HLS profile MISSING — container was recreated outside the console; CoT video will black-screen until reconverged"
    # Alert once per drift episode, not every minute.
    if [ ! -f "$_DRIFT_STATE" ]; then
      date +%s > "$_DRIFT_STATE"
      SUBJ_D="Guard Dog: CloudTAK video config drift on $SERVER_IDENTIFIER"
      BODY_D="cloudtak-media lost infra-TAK's HLS profile (/mediamtx.yml).

This happens when the container is recreated by something the console did not drive
(a manual docker compose --build, a restart policy, an OOM recreate). Stock MediaMTX
takes ~7s to produce a playable playlist, which loses to CloudTAK's ~7s player retry
budget, so CoT video shows a black screen while the stream itself is fine.

Server: $SERVER_IDENTIFIER
Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')
Fix: restart the infra-TAK console (systemctl restart takwerx-console) — its
converger re-applies the profile. A CloudTAK rebuild is NOT required and will not help.

Verify: docker exec cloudtak-media-1 grep -E '^hls' /mediamtx.yml
"
      echo -e "$BODY_D" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ_D" "ALERT_EMAIL_PLACEHOLDER" 2>/dev/null || true
    fi
  else
    [ -f "$_DRIFT_STATE" ] && { _log "drift | cloudtak-media HLS profile restored"; rm -f "$_DRIFT_STATE"; }
  fi
fi

SUBJ="Guard Dog: CloudTAK restarted on $SERVER_IDENTIFIER"
BODY="CloudTAK container was not running for $FAILS consecutive checks.

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Action: Restarting CloudTAK containers (docker compose restart).

Check /var/log/takguard/restarts.log for history.
"
echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi

cd "$CT_DIR" && docker compose restart 2>&1
echo 0 > "$FAIL_FILE"
date +%s > "$COOLDOWN_FILE"
