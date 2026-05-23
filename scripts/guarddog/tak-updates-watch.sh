#!/bin/bash
# Guard Dog: check for available updates (infra-TAK, Authentik, MediaMTX, CloudTAK, TAK Portal) and email once per change.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_EMAIL="ALERT_EMAIL_PLACEHOLDER"
CONSOLE_VERSION="CONSOLE_VERSION_PLACEHOLDER"
STATE_FILE="/var/lib/takguard/updates_notified"
LOG_FILE="/var/log/takguard/updates.log"
CURL_TIMEOUT=15

log_msg() { mkdir -p /var/log/takguard 2>/dev/null; echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $*" >> "$LOG_FILE" 2>/dev/null; }

# Skip only when empty or not a real address (no @). Deploy replaces ALERT_EMAIL_PLACEHOLDER globally, so we must not compare to that literal.
if [ -z "$ALERT_EMAIL" ] || ! echo "$ALERT_EMAIL" | grep -q '@'; then
  log_msg "Alert email not configured; skipping. Set email in Guard Dog → Notifications and click Update Guard Dog."
  exit 0
fi

# Fetch latest tag from GitHub (repo = org/repo). Strips version/ and v prefix.
latest_tag() {
  local repo="$1"
  raw=$(curl -sS -f --max-time "$CURL_TIMEOUT" \
    -H "Accept: application/vnd.github.v3+json" -H "User-Agent: infra-TAK" \
    "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null | \
    grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
  echo "$raw" | sed 's/^version\///' | sed 's/^v//'
}

# For infra-TAK we use tags API (no releases/latest)
latest_infratak() {
  curl -sS -f --max-time "$CURL_TIMEOUT" \
    -H "Accept: application/vnd.github.v3+json" -H "User-Agent: infra-TAK" \
    "https://api.github.com/repos/takwerx/infra-TAK/tags?per_page=5" 2>/dev/null | \
    grep -o '"name":[[:space:]]*"v[^"]*"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/'
}

# Return 0 if update available (cur < latest). If we don't know cur, don't report (avoid false "update" when already current).
need_update() {
  local cur="$1" latest="$2"
  [ -z "$latest" ] && return 1
  [ -z "$cur" ] && return 1
  max=$(printf '%s\n%s\n' "${cur}" "${latest}" | sort -V 2>/dev/null | tail -1)
  [ "$max" = "$latest" ] && [ "$cur" != "$latest" ] && return 0
  return 1
}

UPDATES=""
SIG=""

# infra-TAK (skip if placeholders not replaced; never report update when current equals latest)
latest_console=$(latest_infratak)
cur_console="$CONSOLE_VERSION"
if [ "$cur_console" != "CONSOLE_VERSION_PLACEHOLDER" ] && [ -n "$cur_console" ] && [ -n "$latest_console" ] && [ "$cur_console" != "$latest_console" ] && need_update "$cur_console" "$latest_console"; then
  UPDATES="${UPDATES}  - infra-TAK: current ${cur_console:-unknown}, latest ${latest_console}\n"
  SIG="${SIG}infratak:${latest_console};"
fi

# Authentik (only if installed) — read version from docker-compose.yml (same as dashboard), then .env
cur_ak=""
if [ -f "$HOME/authentik/docker-compose.yml" ]; then
  cur_ak=$(grep -oE 'AUTHENTIK_TAG:-[^}[:space:]]+' "$HOME/authentik/docker-compose.yml" 2>/dev/null | head -1 | sed 's/AUTHENTIK_TAG:-//' | sed 's/^v//')
fi
[ -z "$cur_ak" ] && [ -f "$HOME/authentik/.env" ] && cur_ak=$(grep -E '^AUTHENTIK_TAG=' "$HOME/authentik/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' | sed 's/^v//')
if [ -f "$HOME/authentik/docker-compose.yml" ] || [ -f "$HOME/authentik/.env" ]; then
  latest_ak=$(latest_tag "goauthentik/authentik")
  if need_update "$cur_ak" "$latest_ak"; then
    UPDATES="${UPDATES}  - Authentik: current ${cur_ak:-unknown}, latest ${latest_ak}\n"
    SIG="${SIG}authentik:${latest_ak};"
  fi
fi

# MediaMTX binary (only if present)
if [ -x "/usr/local/bin/mediamtx" ]; then
  cur_mtx=$(/usr/local/bin/mediamtx -version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/^v//')
  [ -z "$cur_mtx" ] && cur_mtx=$(strings /usr/local/bin/mediamtx 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
  latest_mtx=$(latest_tag "bluenviron/mediamtx")
  if need_update "$cur_mtx" "$latest_mtx"; then
    UPDATES="${UPDATES}  - MediaMTX (binary): current ${cur_mtx:-unknown}, latest ${latest_mtx}\n"
    SIG="${SIG}mediamtx:${latest_mtx};"
  fi
fi

# MediaMTX web editor (takwerx/mediamtx-installer; only if installed)
if [ -f "/opt/mediamtx-webeditor/mediamtx_config_editor.py" ]; then
  cur_ed=$(grep -oE 'CURRENT_VERSION = "[^"]+"' /opt/mediamtx-webeditor/mediamtx_config_editor.py 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/' | sed 's/^v//')
  latest_ed=$(latest_tag "takwerx/mediamtx-installer")
  if need_update "$cur_ed" "$latest_ed"; then
    UPDATES="${UPDATES}  - MediaMTX (web editor): current ${cur_ed:-unknown}, latest ${latest_ed}\n"
    SIG="${SIG}mediamtx_editor:${latest_ed};"
  fi
fi

# CloudTAK (only if installed)
if [ -f "$HOME/CloudTAK/api/package.json" ]; then
  cur_ct=$(grep -o '"version":[[:space:]]*"[^"]*"' "$HOME/CloudTAK/api/package.json" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
  latest_ct=$(latest_tag "dfpc-coe/CloudTAK")
  if need_update "$cur_ct" "$latest_ct"; then
    UPDATES="${UPDATES}  - CloudTAK: current ${cur_ct:-unknown}, latest ${latest_ct}\n"
    SIG="${SIG}cloudtak:${latest_ct};"
  fi
fi

# CloudTAK plugins — compare local HEAD vs remote HEAD (no release tags; use git ls-remote)
if [ -d "$HOME/CloudTAK/api/web/plugins" ]; then
  for plugin_dir in "$HOME/CloudTAK/api/web/plugins"/*/; do
    [ -d "$plugin_dir/.git" ] || continue
    plugin_name=$(basename "$plugin_dir")
    local_sha=$(git -C "$plugin_dir" rev-parse HEAD 2>/dev/null)
    remote_sha=$(git -C "$plugin_dir" ls-remote origin HEAD 2>/dev/null | awk '{print $1}')
    if [ -n "$local_sha" ] && [ -n "$remote_sha" ] && [ "$local_sha" != "$remote_sha" ]; then
      UPDATES="${UPDATES}  - CloudTAK plugin ($plugin_name): update available (${local_sha:0:7} → ${remote_sha:0:7})\n"
      SIG="${SIG}ctplugin_${plugin_name}:${remote_sha:0:8};"
    fi
  done
fi

# TAK Portal (current from package.json, latest from container logs [update-check] — same as console)
if [ -f "$HOME/TAK-Portal/package.json" ]; then
  cur_portal=$(grep -o '"version":[[:space:]]*"[^"]*"' "$HOME/TAK-Portal/package.json" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
  latest_portal=""
  if docker ps --filter name=tak-portal -q 2>/dev/null | grep -q .; then
    latest_portal=$(docker logs tak-portal --tail 200 2>/dev/null | grep '\[update-check\]' | tail -1 | sed -n 's/.*latest=\([^[:space:]]*\).*/\1/p')
  fi
  if [ -n "$latest_portal" ] && need_update "$cur_portal" "$latest_portal"; then
    UPDATES="${UPDATES}  - TAK Portal: current ${cur_portal:-unknown}, latest ${latest_portal}\n"
    SIG="${SIG}takportal:${latest_portal};"
  fi
fi

[ -z "$UPDATES" ] && { log_msg "No updates available"; exit 0; }

# Only send if we haven't sent for this exact set of updates, or last send was >1 day ago
mkdir -p /var/lib/takguard
SHOULD_SEND=false
if [ ! -f "$STATE_FILE" ]; then
  SHOULD_SEND=true
elif [ -n "$(find "$STATE_FILE" -mtime +1 2>/dev/null)" ]; then
  SHOULD_SEND=true
else
  old_sig=$(cat "$STATE_FILE" 2>/dev/null)
  [ "$old_sig" != "$SIG" ] && SHOULD_SEND=true
fi
[ "$SHOULD_SEND" = false ] && log_msg "Updates available but already notified (same set); next email in 24h or when set changes"

if $SHOULD_SEND; then
  printf '%s' "$SIG" > "$STATE_FILE"
  TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  SUBJ="infra-TAK: Updates available on $SERVER_IDENTIFIER"
  BODY="Updates available on $SERVER_IDENTIFIER ($(date -u '+%Y-%m-%d %H:%M UTC')):

$(printf '%b' "$UPDATES")
"

  if [ -n "$ALERT_EMAIL" ]; then
    if echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "$ALERT_EMAIL" 2>/dev/null; then
      log_msg "Updates email sent to $ALERT_EMAIL"
    else
      log_msg "Updates email FAILED to $ALERT_EMAIL (console/relay unreachable or check Guard Dog page)"
    fi
  else
    log_msg "Updates available but ALERT_EMAIL not set — save email in Guard Dog → Notifications and Update Guard Dog"
  fi
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    TMPF="/tmp/gd-updates-$$.txt"
    printf '%s' "$BODY" > "$TMPF"
    /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
    rm -f "$TMPF"
  fi
fi
