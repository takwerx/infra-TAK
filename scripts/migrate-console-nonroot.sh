#!/bin/bash
##############################################################################
# infra-TAK — existing-box console non-root migrator  (v10.0.5)
#
# Flips an EXISTING root console to the unprivileged `takwerx` user. The heavy
# lifting (provision takwerx, relocate the repo to /opt/infratak, rewrite the
# systemd unit to User=takwerx / HOME=/home/takwerx) is done by the born-non-root
# path in start.sh (TAKWERX_NONROOT=1) — start.sh rsyncs the current install
# INCLUDING .config, so the admin password carries over. This wrapper adds the
# migration-specific safety + reporting that a fresh install doesn't need:
#   * pre-flight (root, console present, disk space)
#   * back up the current unit + record the old install dir (rollback path)
#   * run the born-non-root flip
#   * post-check the console comes up non-root
#   * REPORT module dirs that still live under /root or the old home (the broker
#     reads/writes them as root, but the broker PATH_ALLOW must include their
#     prefix for ENFORCE mode — see notes). This wrapper does NOT relocate module
#     dirs or rewrite docker bind-mounts: that is the risky, operator-supervised
#     remainder (live containers + mounts).
#
# DRY-RUN by default. Pass --apply to actually migrate.
#   sudo scripts/migrate-console-nonroot.sh            # show the plan
#   sudo scripts/migrate-console-nonroot.sh --apply    # do it
##############################################################################
set -o pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

APPLY=0; AUTO_ROLLBACK=0
for _a in "$@"; do
    case "$_a" in
        --apply)         APPLY=1 ;;
        --auto-rollback) AUTO_ROLLBACK=1 ;;   # used by the in-console button: a
                                              # failed flip restores the root unit
                                              # so the operator is never locked out
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT=/etc/systemd/system/takwerx-console.service
NONROOT_INSTALL=/opt/infratak
# Status breadcrumb the in-console "Switch to non-root" button polls. running ->
# done -> the console answers as takwerx; failed:<reason> -> rolled back to root.
STATUS_FILE=/var/lib/infratak-nonroot-migrate.status
# 0600 (umask 077): the breadcrumb is only ever read by the root console (the
# rollback case) or short-circuited by the live uid on the non-root console, so a
# local user can neither read nor pre-poison it.
_status() { ( umask 077; echo "$1" > "$STATUS_FILE" ) 2>/dev/null || true; }

say()  { echo -e "$@"; }
step() { echo -e "${CYAN}▸ $*${NC}"; }

# Auto-rollback (button path only): restore the backed-up root unit + restart, then
# PROVE the root console actually answered — the whole point of this flag is "never
# locked out", so we don't claim a clean rollback we didn't verify. Returns 0 if the
# root console is back (HTTP 200), 1 otherwise (operator needs SSH; old install is
# intact since start.sh rsyncs, never moves).
_rollback() {
    say "${YELLOW}↩ Auto-rollback: restoring the root console unit…${NC}"
    [ -f "${UNIT}.pre-nonroot.bak" ] && cp -a "${UNIT}.pre-nonroot.bak" "$UNIT" 2>/dev/null
    systemctl daemon-reload 2>/dev/null
    systemctl restart takwerx-console 2>/dev/null
    local rp rc i
    rp=$(grep -oE 'console_port"[: ]+[0-9]+' "$CUR_DIR/.config/settings.json" 2>/dev/null | grep -oE '[0-9]+' | head -1)
    [ -z "$rp" ] && rp=5001
    rc=000
    for i in $(seq 1 12); do
        rc=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:$rp/login" 2>/dev/null)
        [ "$rc" != "000" ] && break; sleep 4
    done
    if [ "$rc" = "200" ]; then
        say "${GREEN}  ✓ Root console restored (HTTP $rc).${NC}"; return 0
    fi
    say "${RED}  ✗ Rollback restart did not answer (HTTP $rc) — SSH recovery needed.${NC}"; return 1
}

# --- pre-flight -------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    say "${RED}ERROR: run as root (sudo).${NC}"; exit 1
fi
if [ ! -f "$UNIT" ]; then
    say "${RED}ERROR: no takwerx-console.service — nothing to migrate. Use start.sh for a fresh install.${NC}"; exit 1
fi

CUR_DIR=$(grep -E '^WorkingDirectory=' "$UNIT" | cut -d= -f2- | tr -d ' ')
CUR_USER=$(grep -E '^User=' "$UNIT" | cut -d= -f2- | tr -d ' ')
CUR_HOME=$(grep -E '^Environment=HOME=' "$UNIT" | head -1 | cut -d= -f3- | tr -d ' ')
[ -z "$CUR_USER" ] && CUR_USER="root"

say ""
say "${BOLD}infra-TAK console non-root migration${NC}"
say "  current install : ${CUR_DIR:-<unknown>}"
say "  current user    : $CUR_USER"
say "  current HOME     : ${CUR_HOME:-/root}"
say "  target install  : $NONROOT_INSTALL"
say "  target user     : takwerx  (HOME=/home/takwerx)"
say ""

if [ "$CUR_USER" = "takwerx" ] && [ "$CUR_DIR" = "$NONROOT_INSTALL" ]; then
    say "${GREEN}✓ Already migrated (console runs as takwerx from $NONROOT_INSTALL). Nothing to do.${NC}"
    exit 0
fi

# --- module-dir survey (report only) ---------------------------------------
step "Module directories that will remain in place (NOT relocated by this tool)"
FOUND_MODS=0
_seen_bases=" "
for base in /root "${CUR_HOME:-/root}" "$(getent passwd "${SUDO_USER:-}" 2>/dev/null | cut -d: -f6)"; do
    [ -z "$base" ] && continue
    case "$_seen_bases" in *" $base "*) continue;; esac   # dedup bases
    _seen_bases="$_seen_bases$base "
    for m in authentik CloudTAK TAK-Portal webodm mediamtx-webeditor; do
        if [ -d "$base/$m" ]; then
            say "    $base/$m"
            FOUND_MODS=1
        fi
    done
done
if [ "$FOUND_MODS" = "1" ]; then
    say "${YELLOW}  ⚠ These stay where they are. The root broker can still read/write them"
    say "    (it runs as root), but for ENFORCE mode their prefix must be in the broker"
    say "    PATH_ALLOW, and docker bind-mounts keep referencing the old paths. Relocating"
    say "    them + rewriting mounts is a separate operator-supervised step.${NC}"
else
    say "    (none found — console-only box, clean migration)"
fi
say ""

# --- plan / apply -----------------------------------------------------------
if [ "$APPLY" != "1" ]; then
    step "DRY-RUN — would now:"
    say "    1. back up $UNIT  ->  ${UNIT}.pre-nonroot.bak"
    say "    2. record old install dir for rollback: $CUR_DIR"
    say "    3. run:  TAKWERX_NONROOT=1 bash $SCRIPT_DIR/start.sh"
    say "       (provisions takwerx, rsyncs $CUR_DIR -> $NONROOT_INSTALL incl .config,"
    say "        rebuilds the venv there, rewrites the unit User=takwerx, restarts)"
    say "    4. verify the console returns 200 as takwerx"
    say ""
    say "${BOLD}Re-run with --apply to perform the migration.${NC}"
    exit 0
fi

# --- APPLY ------------------------------------------------------------------
_status running
step "Backing up current unit"
cp -a "$UNIT" "${UNIT}.pre-nonroot.bak"
echo "$CUR_DIR" > /etc/takwerx-console.prenonroot-dir
say "  ✓ ${UNIT}.pre-nonroot.bak  (rollback: restore it + systemctl daemon-reload + restart)"

step "Running born-non-root flip (start.sh TAKWERX_NONROOT=1)"
# TERM=dumb + </dev/null: this runs headless (systemd-run, no TTY). start.sh now
# guards its `clear` on [ -t 1 ], but keep these as defense-in-depth so any other
# terminal/stdin-dependent step degrades instead of hanging or aborting.
if ! TERM=dumb TAKWERX_NONROOT=1 bash "$SCRIPT_DIR/start.sh" </dev/null; then
    say "${RED}✗ start.sh non-root flip failed. The backup unit is at ${UNIT}.pre-nonroot.bak.${NC}"
    if [ "$AUTO_ROLLBACK" = "1" ]; then
        if _rollback; then _status "failed:start.sh flip failed — rolled back to the root console";
        else _status "failed-rollback:start.sh flip failed AND rollback unverified — recover via SSH (old install at $CUR_DIR)"; fi
    else
        _status "failed:start.sh flip failed"
    fi
    exit 1
fi

step "Post-check"
sleep 5
NEW_USER=$(systemctl show takwerx-console -p User --value)
NEW_DIR=$(systemctl show takwerx-console -p WorkingDirectory --value)
PORT=$(grep -oE 'console_port"[: ]+[0-9]+' "$NONROOT_INSTALL/.config/settings.json" 2>/dev/null | grep -oE '[0-9]+' | head -1)
[ -z "$PORT" ] && PORT=5001
CODE=000
for i in $(seq 1 12); do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:$PORT/login")
    [ "$CODE" != "000" ] && break; sleep 4
done
say "  user=$NEW_USER  dir=$NEW_DIR  login_http=$CODE"
if [ "$NEW_USER" = "takwerx" ] && [ "$NEW_DIR" = "$NONROOT_INSTALL" ] && [ "$CODE" = "200" ]; then
    _status done
    say "${GREEN}${BOLD}✓ Migration complete — console runs as takwerx from $NONROOT_INSTALL.${NC}"
    say "  Old install left at: $CUR_DIR  (remove once you've confirmed everything works)"
else
    say "${RED}✗ Post-check failed (expected takwerx @ $NONROOT_INSTALL, login 200)."
    say "  Roll back: cp ${UNIT}.pre-nonroot.bak $UNIT && systemctl daemon-reload && systemctl restart takwerx-console${NC}"
    if [ "$AUTO_ROLLBACK" = "1" ]; then
        if _rollback; then _status "failed:post-check failed (user=$NEW_USER http=$CODE) — rolled back to the root console";
        else _status "failed-rollback:post-check failed AND rollback unverified — recover via SSH (old install at $CUR_DIR)"; fi
    else
        _status "failed:post-check user=$NEW_USER dir=$NEW_DIR http=$CODE"
    fi
    exit 1
fi
