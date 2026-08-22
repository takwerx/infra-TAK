#!/bin/bash
# Guard Dog: check for available updates (infra-TAK, Authentik, MediaMTX, CloudTAK, TAK Portal) and email once per change.

SERVER_IDENTIFIER=$(cat /opt/tak-guarddog/server_identifier 2>/dev/null || echo "$(hostname)")
ALERT_EMAIL="ALERT_EMAIL_PLACEHOLDER"
CONSOLE_VERSION="CONSOLE_VERSION_PLACEHOLDER"
# v10.1.40: this box's update channel and the Authentik release its CONSOLE will actually
# offer. Without these the watcher compared against upstream latest while the console was
# gated to the vetted release, so main-channel users were emailed about an Authentik update
# that the Update button then correctly refused to install.
UPDATE_CHANNEL="UPDATE_CHANNEL_PLACEHOLDER"
AK_VETTED_RELEASE="AK_VETTED_PLACEHOLDER"
STATE_FILE="/var/lib/takguard/updates_notified"
LOG_FILE="/var/log/takguard/updates.log"
CURL_TIMEOUT=15

# v10.1.44 (W3): resolve stack dirs via the shared lib. These were bare "$HOME/..."
# with NO fallback at all — and $HOME is EMPTY in a systemd unit, so every probe below
# read a path like "/authentik/.env", found nothing, and reported no current version.
# The console's update badge reads "no update found" as "up to date".
source /opt/tak-guarddog/_gd-tak-lib.sh 2>/dev/null || true
AK_DIR="$(gd_find_stack_dir authentik authentik-server-1)"
CT_DIR="$(gd_find_stack_dir CloudTAK cloudtak-api-1)"
PORTAL_DIR="$(gd_find_stack_dir TAK-Portal tak-portal)"

log_msg() { mkdir -p /var/log/takguard 2>/dev/null; echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') $*" >> "$LOG_FILE" 2>/dev/null; }

# v10.1.40: "was this value ever substituted?" — WITHOUT writing a full *_PLACEHOLDER
# token, because the deploy-time .replace() rewrites every occurrence including the one
# inside the test itself. That is not hypothetical: the infra-TAK console check below
# used to compare cur_console against the CONSOLE_VERSION token itself, which substitution
# turned into [ "$cur_console" != "<the actual version>" ] — always false. The console
# update check therefore NEVER fired on any box (updates.log showed zero "infra-TAK:"
# lines fleet-wide). Matching on the suffix alone is safe: no replace target is a bare
# "_PLACEHOLDER".
unsubstituted() { case "$1" in *_PLACEHOLDER) return 0 ;; *) return 1 ;; esac; }

# v10.1.30: do NOT gate on the baked address. The console resolves the recipient from
# settings.json at send time, so a box deployed before an email was configured still
# alerts once one is saved - no "click Update Guard Dog" step.

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
if ! unsubstituted "$cur_console" && [ -n "$cur_console" ] && [ -n "$latest_console" ] && [ "$cur_console" != "$latest_console" ] && need_update "$cur_console" "$latest_console"; then
  UPDATES="${UPDATES}  - infra-TAK: current ${cur_console:-unknown}, latest ${latest_console}\n"
  SIG="${SIG}infratak:${latest_console};"
fi

# Authentik (only if installed).
# v10.1.40 — .env is read FIRST, on purpose. Docker Compose resolves ${AUTHENTIK_TAG:-default}
# by letting .env WIN over the compose default, so reading compose first reported the wrong
# running version on any box carrying an .env pin. Same precedence bug v10.1.39 fixed on the
# console side (COPIX field report); it was still live here.
cur_ak=""
[ -f "$AK_DIR/.env" ] && cur_ak=$(grep -E '^AUTHENTIK_TAG=' "$AK_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' | sed 's/^v//')
if [ -z "$cur_ak" ] && [ -f "$AK_DIR/docker-compose.yml" ]; then
  cur_ak=$(grep -oE 'AUTHENTIK_TAG:-[^}[:space:]]+' "$AK_DIR/docker-compose.yml" 2>/dev/null | head -1 | sed 's/AUTHENTIK_TAG:-//' | sed 's/^v//')
fi
if [ -f "$AK_DIR/docker-compose.yml" ] || [ -f "$AK_DIR/.env" ]; then
  # Compare against what the CONSOLE will offer, never against upstream latest.
  # main -> AUTHENTIK_VETTED_RELEASE (the fleet-validation gate); dev -> upstream latest,
  # falling back to the baked vetted value when GitHub is unreachable. Mirrors
  # _get_authentik_target_release() in app.py — if that logic changes, change it here too.
  if [ "$UPDATE_CHANNEL" = "dev" ]; then
    target_ak=$(latest_tag "goauthentik/authentik")
    [ -z "$target_ak" ] && target_ak="$AK_VETTED_RELEASE"
  else
    target_ak="$AK_VETTED_RELEASE"
  fi
  if unsubstituted "$target_ak" || [ -z "$target_ak" ]; then
    log_msg "authentik: no usable target (channel=$UPDATE_CHANNEL) - skipping"
  elif need_update "$cur_ak" "$target_ak"; then
    UPDATES="${UPDATES}  - Authentik: current ${cur_ak:-unknown}, latest ${target_ak}\n"
    SIG="${SIG}authentik:${target_ak};"
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
if [ -f "$CT_DIR/api/package.json" ]; then
  cur_ct=$(grep -o '"version":[[:space:]]*"[^"]*"' "$CT_DIR/api/package.json" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
  latest_ct=$(latest_tag "dfpc-coe/CloudTAK")
  if need_update "$cur_ct" "$latest_ct"; then
    UPDATES="${UPDATES}  - CloudTAK: current ${cur_ct:-unknown}, latest ${latest_ct}\n"
    SIG="${SIG}cloudtak:${latest_ct};"
  fi
fi

# CloudTAK plugins — compare local HEAD vs remote HEAD (no release tags; use git ls-remote)
if [ -d "$CT_DIR/api/web/plugins" ]; then
  for plugin_dir in "$CT_DIR/api/web/plugins"/*/; do
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
if [ -f "$PORTAL_DIR/package.json" ]; then
  cur_portal=$(grep -o '"version":[[:space:]]*"[^"]*"' "$PORTAL_DIR/package.json" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
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

  if echo -e "$BODY" | /opt/tak-guarddog/send-alert-email.sh "$SUBJ" "$ALERT_EMAIL" 2>/dev/null; then
    log_msg "Updates email handed to console (recipient resolved from settings)"
  else
    log_msg "Updates email FAILED (console/relay unreachable - check the Guard Dog page)"
  fi
  if [ -f /opt/tak-guarddog/sms_send.sh ]; then
    TMPF="/tmp/gd-updates-$$.txt"
    printf '%s' "$BODY" > "$TMPF"
    /opt/tak-guarddog/sms_send.sh "$SUBJ" "$TMPF" 2>/dev/null || true
    rm -f "$TMPF"
  fi
fi
