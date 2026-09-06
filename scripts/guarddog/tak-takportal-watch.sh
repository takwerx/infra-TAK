#!/bin/bash
# Guard Dog: TAK Portal health. On 3 consecutive failures: alert and recover.
#
# v10.1.59: TAK Portal is a Docker Compose PROJECT (web + worker + Postgres ...), not one
# container. Health is the WEB service only — resolved by its compose service label, never
# `docker ps --filter name=tak-portal`, which is a SUBSTRING match that `tak-portal-worker`
# satisfies while the web UI is down. Recovery is `docker compose up -d` in the project
# directory, which also brings back a missing worker/Postgres; `docker start tak-portal`
# would start the web container alone. Volumes are never touched.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
STATE_DIR="/var/lib/takguard"
FAIL_FILE="$STATE_DIR/takportal.failcount"
COOLDOWN_FILE="$STATE_DIR/takportal_last_restart"
MAX_FAILS=3
COOLDOWN_SECS=900
WEB_SERVICE="tak-portal"   # upstream's SERVICE_NAME in ./takportal

mkdir -p "$STATE_DIR"

# Don't run during first 15 minutes after boot (avoid restarting during startup)
UPTIME_SECS=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
[ "$UPTIME_SECS" -lt 900 ] && exit 0

# Only check if TAK Portal is installed
# v10.1.44 (W3): resolve the stack dir via the shared lib — $HOME is EMPTY in a
# systemd unit, so the old "${HOME:-...}" default silently pointed at nothing on
# installs that do not match it and this watchdog exited 0 without ever watching.
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true
PORTAL_DIR="$(gd_find_stack_dir TAK-Portal tak-portal)"
[ -z "$PORTAL_DIR" ] && exit 0

# Compose project name: COMPOSE_PROJECT_NAME from the project .env, else the directory
# basename the way Compose normalizes it (TAK-Portal -> tak-portal).
PROJECT="$(grep -m1 '^COMPOSE_PROJECT_NAME=' "$PORTAL_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '"'"'")"
if [ -z "$PROJECT" ]; then
  PROJECT="$(basename "$PORTAL_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-' | sed 's/^[_-]*//')"
fi

# Health: EVERY service in the project is running — web, worker, Postgres (v10.1.60 W3).
# Upstream's main runs on Postgres now, and a dead Postgres or worker leaves the web
# container "running" while the portal serves its stack-down page — the web-only check
# (v10.1.59) stayed green through exactly that. Services come from the compose file
# itself (so an upstream rename or a new service is picked up without a script change);
# each is resolved by its compose labels, one-off `run` containers excluded. Falls back to
# the web-only check when compose cannot read the project (pre-compose checkout, no .env).
DOWN=""
SERVICES="$(cd "$PORTAL_DIR" 2>/dev/null && docker compose config --services 2>/dev/null | tr -d '\r')"
if [ -n "$SERVICES" ]; then
  for SVC in $SERVICES; do
    ST="$(docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" \
                      --filter "label=com.docker.compose.service=${SVC}" \
                      --filter "label=com.docker.compose.oneoff=False" \
                      --format '{{.State}}' 2>/dev/null | head -1)"
    [ "$ST" = "running" ] || DOWN="${DOWN}${SVC}(${ST:-missing}) "
  done
  WEB_STATE="running"; case " $DOWN" in *" ${WEB_SERVICE}("*) WEB_STATE="down";; esac
else
  # Pre-compose / unreadable project: the WEB service's container, exact match — never a
  # substring (`name=tak-portal` also matches tak-portal-worker while the web UI is down).
  WEB_STATE="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" \
                         --filter "label=com.docker.compose.service=${WEB_SERVICE}" \
                         --format '{{.State}}' 2>/dev/null | head -1)"
  if [ -z "$WEB_STATE" ]; then
    WEB_STATE="$(docker ps --filter 'name=^tak-portal$' --format '{{.State}}' 2>/dev/null | head -1)"
  fi
  [ "$WEB_STATE" = "running" ] || DOWN="${WEB_SERVICE}(${WEB_STATE:-missing}) "
fi
if [ -z "$DOWN" ]; then
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

# Recover the WHOLE project. `up -d` starts whatever is missing (web, worker, Postgres)
# and leaves running services and every volume alone.
ACTION="docker compose up -d (in $PORTAL_DIR)"
if [ -f "$PORTAL_DIR/docker-compose.yml" ] && (cd "$PORTAL_DIR" && docker compose up -d >>/var/log/takguard/restarts.log 2>&1); then
  RESULT="ok"
else
  ACTION="docker start tak-portal (compose unavailable — web container only)"
  if docker start tak-portal >>/var/log/takguard/restarts.log 2>&1; then RESULT="ok"; else RESULT="FAILED"; fi
fi
echo "$TS | restart | TAK Portal service(s) not running: ${DOWN}— recovered via ${ACTION}: ${RESULT}" >> /var/log/takguard/restarts.log

SUBJ="Guard Dog: TAK Portal restarted on $SERVER_IDENTIFIER"
BODY="TAK Portal service(s) not running for $FAILS consecutive checks: ${DOWN}

Server: $SERVER_IDENTIFIER
Time (UTC): $TS
Action: ${ACTION} — ${RESULT}

Check /var/log/takguard/restarts.log for history.
"
echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "ALERT_EMAIL_PLACEHOLDER"
if [ -f /opt/tak-guarddog/sms_send.sh ]; then
  TMPF="/tmp/gd-sms-$$.txt"
  printf '%s' "$BODY" > "$TMPF"
  /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
  rm -f "$TMPF"
fi

echo 0 > "$FAIL_FILE"
date +%s > "$COOLDOWN_FILE"
