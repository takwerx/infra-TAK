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
type gd_stack_restore_standdown >/dev/null 2>&1 && gd_stack_restore_standdown tak-cloudtak-watch && exit 0
CT_DIR="$(gd_find_stack_dir CloudTAK cloudtak-api-1)"
[ -z "$CT_DIR" ] && exit 0

# NOTE (v10.1.55 W6): the media-patch drift check below runs BEFORE the health check
# on purpose. The health path exits 0 as soon as cloudtak-api is Up, so anything placed
# after it only runs when CloudTAK is already failing — which is precisely NOT the case
# we are looking for. The drift we care about is a perfectly healthy CloudTAK whose
# media container silently lost infra-TAK's HLS profile. Caught in test on test12
# 2026-08-31: the first cut sat after the early exit and never fired.
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
# Detection here, repair in the console (ops #197). Re-applying is the console's job — it
# owns the apply script, the override and the recreate; duplicating them here would be a
# second writer of the same files. So on the second check this asks the console to repair
# (POST /api/guarddog/cloudtak-repair) and only alarms when it can't.
#
# ops #197: the second signal. TAK Portal's marketplace recreates CloudTAK with its own
# `-f docker-compose.yml -f docker-compose.marketplace.yml`, which skips infra-TAK's
# docker-compose.override.yml (explicit -f flags ignore COMPOSE_FILE). Every container that
# run made carries compose's config_files label WITHOUT the override: stock media-infra and
# postgis images, no console CA in the api — and, for media, no HLS profile. A running
# container of the CloudTAK project without the override in that label is drift.
# ops #216: only for the services the override configures (api, events, media, postgis).
# TAK Portal runs Print and the uDash sidecar from their own docker-compose.plugin-<id>.yml in
# the same project; they never carry the override, and counting them was drift that no repair
# could clear (three repairs an hour, then the alarm). Same rule as the console's check.
_ct_no_override=""
if [ -f "$CT_DIR/docker-compose.override.yml" ]; then
  _ct_proj="$(docker inspect cloudtak-api-1 --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null)"
  _ct_ov_svcs="$(awk '/^services:/{s=1;next} s&&/^[^ \t#]/{exit} s&&/^  [A-Za-z0-9][A-Za-z0-9_.-]*:[ \t]*$/{sub(/^  /,"");sub(/:.*/,"");print}' \
    "$CT_DIR/docker-compose.override.yml" 2>/dev/null | tr '\n' ' ')"
  if [ -n "$_ct_proj" ]; then
    while IFS='|' read -r _n _f _s; do
      [ -n "$_f" ] || continue
      if [ -n "$_ct_ov_svcs" ]; then
        case " $_ct_ov_svcs " in *" $_s "*) ;; *) continue ;; esac
      fi
      case ",$_f," in
        *,docker-compose.override.yml,*|*/docker-compose.override.yml,*) ;;
        *) _ct_no_override="$_ct_no_override $_n" ;;
      esac
    done <<EOF
$(docker ps --filter "label=com.docker.compose.project=$_ct_proj" --format '{{.Names}}|{{.Label "com.docker.compose.project.config_files"}}|{{.Label "com.docker.compose.service"}}' 2>/dev/null)
EOF
  fi
fi

# ops #197: ask the console to repair. Sets _rep_state (ok|repairing|waiting|rate_limited|
# failed|unreachable) and _rep_detail. HTTPS first (self-signed, -k), HTTP only when HTTPS
# got no answer at all — same rule as send-alert-email.sh.
_ct_request_repair() {
  local _o="" _sch
  for _sch in https http; do
    _o="$(curl -s -k -X POST "$_sch://127.0.0.1:${CONSOLE_PORT:-5001}/api/guarddog/cloudtak-repair" \
      --connect-timeout 5 --max-time 90 2>/dev/null)" && [ -n "$_o" ] && break
    _o=""
  done
  _rep_state=unreachable; _rep_detail="console did not answer on :${CONSOLE_PORT:-5001}"
  [ -n "$_o" ] || return 0
  _rep_state="$(printf '%s' "$_o" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(str(d.get("state") or "failed").split()[0])' 2>/dev/null || echo failed)"
  _rep_detail="$(printf '%s' "$_o" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(str(d.get("detail") or d.get("error") or "").split())[:300])' 2>/dev/null)"
}

_hls_ok=na
if docker inspect cloudtak-media-1 >/dev/null 2>&1; then
  # ops #161: read the file ONCE, then grep it here. This used to run
  # `docker exec ... grep -q` per key, so a failed exec looked exactly like a missing
  # key. Seen on ops1 2026-10-21: the patch job's apt run restarted Docker, exec
  # failed for ~45s, and two checks in a row reported MISSING on a profile that was
  # never gone (a plain restart keeps it). A read we could not make is UNKNOWN: log
  # it and leave the drift state alone, so it neither starts nor clears an episode.
  _hls_cfg="$(docker exec cloudtak-media-1 cat /mediamtx.yml 2>/dev/null)"
  _hls_rc=$?
  if [ "$_hls_rc" -ne 0 ] || [ -z "$_hls_cfg" ]; then
    _hls_ok=unknown
  else
    _hls_ok=1
    for _k in "^hlsVariant: mpegts" "^hlsSegmentCount: 3" "^hlsSegmentDuration: 500ms" "^hlsPartDuration: 200ms"; do
      printf '%s\n' "$_hls_cfg" | grep -q "$_k" || _hls_ok=0
    done
  fi
fi
_ct_found=""
[ "$_hls_ok" = 0 ] && _ct_found="cloudtak-media HLS profile missing"
[ -n "$_ct_no_override" ] && _ct_found="${_ct_found:+$_ct_found; }created without infra-TAK's compose override:$_ct_no_override"
if [ "$_hls_ok" != na ] || [ -n "$_ct_found" ]; then
  _DRIFT_STATE="$STATE_DIR/cloudtak_media_drift"
  _DRIFT_PENDING="$STATE_DIR/cloudtak_media_drift_pending"
  if [ -z "$_ct_found" ] && [ "$_hls_ok" = unknown ]; then
    _log "drift | cloudtak-media HLS profile UNKNOWN — could not read /mediamtx.yml (docker exec rc=$_hls_rc); not counted as missing"
  elif [ -n "$_ct_found" ]; then
    [ "$_hls_ok" = 0 ] && _log "drift | cloudtak-media HLS profile MISSING — container was recreated outside the console; CoT video will black-screen until reconverged"
    [ -n "$_ct_no_override" ] && _log "drift | created without infra-TAK's compose override (image pins, console CA):$_ct_no_override"
    # v10.1.57 W12: TWO-STRIKE. Do not alert on first sight.
    #
    # The console recreates CloudTAK itself during post-update security hardening and
    # re-heals the media patch immediately afterwards. On test12 2026-09-02 that ran:
    #   19:39:36  "CloudTAK recreated with hardened port bindings"   (console)
    #   19:39:41  docker recreates cloudtak-media-1                  (profile wiped)
    #   19:39:42  "cloudtak-media healed (HLS=mpegts/alwaysRemux)"   (console, +1s)
    #   19:39:43  ALERT EMAIL SENT                                   (+1s, already fixed)
    # The operator was emailed about damage the console had caused AND repaired one
    # second earlier, and told to fix it by restarting the console — the very action
    # that triggered the recreate. An alert that fires inside a self-heal window is
    # noise, and noise is how a real alert gets ignored later.
    #
    # Real drift (a manual --build, a restart policy, an OOM recreate) is NOT repaired
    # by anything and persists until the next console restart, i.e. for hours. Costing
    # it one extra check interval loses nothing; suppressing the self-healed case
    # is the entire point.
    if [ ! -f "$_DRIFT_PENDING" ]; then
      date +%s > "$_DRIFT_PENDING"
      _log "drift | first detection — deferring alert one interval to let the console's converger finish"
    elif [ ! -f "$_DRIFT_STATE" ]; then
      # ops #197: second check — ask the console to repair before alarming. repairing /
      # waiting / ok hold the alarm back (the console is on it, the stack is still being
      # changed, or it has already cleared). The alarm goes out when the console says the
      # repair failed or hit its hourly limit, cannot be reached, or the episode has gone
      # 30 min without being fixed.
      _ct_request_repair
      _ct_age=$(( $(date +%s) - $(cat "$_DRIFT_PENDING" 2>/dev/null || date +%s) ))
      _ct_alarm=1
      case "$_rep_state" in
        repairing|waiting|ok)
          if [ "$_ct_age" -lt 1800 ]; then
            _ct_alarm=0
            _log "drift | auto-repair: $_rep_state — $_rep_detail"
          else
            _rep_detail="not fixed after $(( _ct_age / 60 )) min (console: $_rep_state — $_rep_detail)"
          fi ;;
      esac
    fi
    if [ -f "$_DRIFT_PENDING" ] && [ ! -f "$_DRIFT_STATE" ] && [ "${_ct_alarm:-0}" = 1 ]; then
      _log "drift | auto-repair did not fix it ($_rep_state: $_rep_detail) — sending the alert"
      if [ "$_hls_ok" = 0 ]; then
        SUBJ_D="Guard Dog: CloudTAK video config drift on $SERVER_IDENTIFIER"
      else
        SUBJ_D="Guard Dog: CloudTAK settings drift on $SERVER_IDENTIFIER"
      fi
      BODY_D="CloudTAK is running without infra-TAK's settings, and Guard Dog could not put
them back by itself.

Found: $_ct_found
Automatic repair: $_rep_state — $_rep_detail

infra-TAK re-applies its CloudTAK settings after every recreate it drives, and Guard Dog
repairs a recreate it did not drive (a TAK Portal marketplace plugin install, a manual
docker compose run) by itself. This alert means that repair did not happen or did not
work.

Impact: without infra-TAK's compose override CloudTAK runs upstream's media and postgis
images and the api does not trust the console's certificate. Without the HLS profile,
stock MediaMTX takes ~7s to produce a playable playlist, which loses to CloudTAK's ~7s
player retry budget, so CoT video shows a black screen while the stream itself is fine.

Server: $SERVER_IDENTIFIER
Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')

Check it yourself:
  docker exec cloudtak-media-1 grep -E '^hls' /mediamtx.yml
  (expect hlsVariant: mpegts, hlsSegmentCount: 3, hlsSegmentDuration: 500ms)

To fix: restart the infra-TAK console (systemctl restart takwerx-console) — it rewrites
the override, recreates CloudTAK with it and re-applies the profile. A CloudTAK rebuild
is NOT required and will not help.
"
      # v10.1.58 W13: close the once-per-episode gate ONLY on successful delivery.
      #
      # This used to write $_DRIFT_STATE BEFORE sending, so the episode was marked
      # reported whether or not the mail left the box. Measured on test12
      # 2026-09-02: after a console restart the console took 318s to answer, the
      # drift alert fired 83s into that window, logged "console unreachable" — and
      # the gate had already closed, so it was attempted once and lost forever.
      # A watcher that runs every minute had all the retries it needed and used none.
      #
      # Leaving $_DRIFT_PENDING in place means the next run re-enters this branch
      # and tries again, so the alert survives a console that is merely busy.
      if echo -e "$BODY_D" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ_D" "ALERT_EMAIL_PLACEHOLDER" 2>/dev/null; then
        date +%s > "$_DRIFT_STATE"
      else
        _log "drift | alert NOT delivered (console unreachable?) — episode left open, will retry next check"
      fi
    fi
  else
    if [ -f "$_DRIFT_PENDING" ] && [ ! -f "$_DRIFT_STATE" ]; then
      _log "drift | CloudTAK settings and HLS profile back before the alert threshold — repaired or self-healed, not reported"
    fi
    [ -f "$_DRIFT_STATE" ] && _log "drift | CloudTAK settings and HLS profile restored"
    rm -f "$_DRIFT_STATE" "$_DRIFT_PENDING"
  fi
fi

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
