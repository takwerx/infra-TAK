#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""infra-TAK privileged broker  (v10.0.5 — non-root console migration, Option B)

THE SINGLE PRIVILEGED COMPONENT.

Architecture (operator decision, PLAN-v10.0.5):
  The console runs unprivileged (`takwerx`); ALL privileged operations are
  performed by this small root daemon, which the console *asks* over a unix
  socket. The daemon enforces an allowlist/rulebook (it REFUSES the Docker /
  sudoers / shell trap-doors that make a blanket sudoers root-equivalent) and
  is the SINGLE audit-log chokepoint (ties to Compliance C3/C7).

This file is BOTH:
  * the daemon            ->  `takwerx_broker.py serve`
  * the client used by the console:
        - in-process Python  (app.py `_broker_request`) for read/write/ping
        - a CLI proxy        `takwerx_broker.py exec -- <argv...>`  that the
          console's `_sudo_wrap` returns, so the ~155 already-wrapped
          subprocess sites get mediated for free (the caller still runs a
          command list via subprocess.run; brokerctl proxies it to the daemon).

STDLIB ONLY — the privileged component must have zero third-party deps.

PHASE NOTE (this chat): the console still runs as ROOT. The broker is proven
end-to-end via `TAKWERX_FORCE_BROKER=1` + `takwerx_broker.py selftest` BEFORE
the service user is flipped. SELinux confinement of the console snaps on top in
a later step (the thin console is far easier to confine than a root monolith).
"""

import base64
import errno
import grp
import hashlib
import json
import logging
import logging.handlers
import os
import pwd
import re
import shutil
import stat
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SOCKET_PATH = os.environ.get('TAKWERX_BROKER_SOCKET', '/run/takwerx-broker.sock')
AUDIT_DIR = '/var/log/takwerx-broker'
AUDIT_LOG = os.path.join(AUDIT_DIR, 'audit.log')
BROKER_USER = 'takwerx'                       # console runs as this once flipped
MAX_MSG = 32 * 1024 * 1024                    # 32 MiB hard cap per request/response
DEFAULT_TIMEOUT = 600                         # seconds; default when caller sends no timeout
MAX_TIMEOUT = 7200                            # seconds; ceiling for caller-requested timeouts.
                                              # CloudTAK `docker compose build --no-cache` runs
                                              # 20-60+ min; clamping requests to 600s killed every
                                              # non-root CloudTAK rebuild at exactly 10 min
                                              # (test12, 2026-07-17 — exit 125 mid-build).
SELF_PATH = os.path.realpath(__file__)
# v10.1.13: sha of the source THIS daemon process was started from, captured at
# import time (the on-disk file may be newer — a console update replaces the repo
# file while the daemon keeps running old code until restarted). Reported in the
# ping response so the console can detect a stale daemon and restart it — that is
# what lets broker fixes ride Update Now instead of requiring `sudo ./start.sh`.
try:
    import hashlib as _hashlib_src
    with open(SELF_PATH, 'rb') as _sf:
        RUNNING_SRC_SHA = _hashlib_src.sha256(_sf.read()).hexdigest()
except Exception:
    RUNNING_SRC_SHA = ''
BROKER_UNIT = '/etc/systemd/system/takwerx-broker.service'

# ops #645 W1: the broker runs from a ROOT-OWNED copy of code that root fetched
# from GitHub and checked (_root_install), not from the console user's repo. Until
# W1 the unit ran <repo>/broker/takwerx_broker.py, a file `takwerx` owns, so an edit
# plus a restart made the console user root. BROKER_SECURITY_LEVEL goes up with
# every broker security fix; root never installs code with a lower level, so the
# console cannot ask for an older broker with a known hole.
# RULE: a commit that changes this file for a security reason MUST raise
# BROKER_SECURITY_LEVEL by one in the same commit. Otherwise the console can roll
# the broker back to the copy with the hole. Security reviews check this.
BROKER_ROOT_LAYOUT = 1
# 1: W1 root layout. 2: W2 part 1 (unit checks, coreutils flags). 3: W2 part 2a
# (root renders the Guard Dog scripts). Keep this line as
# exactly `BROKER_SECURITY_LEVEL = <n>`: root parses it from candidate commits.
BROKER_SECURITY_LEVEL = 3
ROOT_CODE_DIR = '/usr/local/lib/infratak-broker'
ROOT_CODE_CURRENT = ROOT_CODE_DIR + '/current'
ROOT_SRC_GIT = '/var/lib/takwerx-broker/src.git'
ROOT_CONF_DIR = '/etc/infratak'
ROOT_CONF = ROOT_CONF_DIR + '/broker.conf'
BROKER_SRC_URL = 'https://github.com/takwerx/infra-TAK.git'
SYSTEM_PYTHON = '/usr/bin/python3'
ROOT_EXEC_START = (f'ExecStart={SYSTEM_PYTHON} -I {ROOT_CODE_CURRENT}'
                   f'/broker/takwerx_broker.py serve')
RUNNING_FROM_ROOT = SELF_PATH.startswith(ROOT_CODE_DIR + '/')


def _read_root_conf(path=None):
    """key=value lines of the root-owned broker.conf. Ignored unless it is a plain
    file owned by root and not group/other-writable."""
    path = path or ROOT_CONF
    out = {}
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            return {}
        with open(path) as f:
            for ln in f:
                k, sep, v = ln.strip().partition('=')
                if sep and k and not k.startswith('#'):
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _console_repo_dir():
    """The console repo (for the v10.1.4 repo-ownership chown carve-out). From the
    repo path (pre-W1 layout) it is SELF_PATH's repo; from the root layout it is
    `console_dir` in the root-owned broker.conf. Never from client input."""
    if not RUNNING_FROM_ROOT:
        return os.path.dirname(os.path.dirname(SELF_PATH))
    d = _read_root_conf().get('console_dir', '')
    if d.startswith('/') and os.path.normpath(d) == d and d != '/':
        return d
    return '/nonexistent'


# The console repo this broker serves. Used by the v10.1.4 repo-ownership self-heal
# carve-out in _check_chown.
CONSOLE_REPO_DIR = _console_repo_dir()

# The console-owned TAK Server docker bundle is unzipped here (app.py
# TAK_DOCKER_ROOT = ~/tak-docker) and bind-mounted into the TAK containers at
# /opt/tak. The non-root console writes it DIRECTLY (it owns the dir), so it
# lives under takwerx's HOME rather than a root /opt path. The container deploy
# legitimately `ln -sfn <bundle>/tak /opt/tak` and `docker run -v <bundle>/tak:
# /opt/tak` FROM here — both were denied because /home is forbidden, which is
# the v10.0.5 container-deploy exit-126 regression. Allow this ONE subtree (NOT
# /home at large): it is takwerx-owned and is the intended /opt/tak source.
# Resolve the console user's ACTUAL home. NB: `takwerx` is created as a SYSTEM
# account (`useradd --system -d /nonexistent`), so its /etc/passwd home is the
# `/nonexistent` sentinel — but the console runs with HOME=/home/takwerx and puts
# every module there (it uses os.path.expanduser('~'), i.e. $HOME, not passwd).
# The broker must match the console, or home-resident modules (the majority of the
# born-non-root fleet) fail the allowlist. So: use the passwd home only if it is a
# REAL directory; otherwise fall back to the /home/<user> convention start.sh
# provisions. (Discovered in the v10.0.8 field test — the passwd home was
# /nonexistent and every ~/<module> path WOULD-DENY'd.)
_CONV_HOME = '/home/' + BROKER_USER
try:
    _PW_HOME = pwd.getpwnam(BROKER_USER).pw_dir or ''
except KeyError:
    _PW_HOME = ''
if _PW_HOME and _PW_HOME not in ('/nonexistent', '/', '') and os.path.isdir(_PW_HOME):
    _NONROOT_HOME = _PW_HOME
else:
    _NONROOT_HOME = _CONV_HOME
TAK_BUNDLE_DIR = os.path.join(_NONROOT_HOME, 'tak-docker')

# Module install dirs (v10.0.8 harvest — PLAN-v10.0.8 §A). Each module lives at
# ~/<name> on a born-non-root box, or (root-era install on a FLIPPED box) at
# /root/<name>. The console legitimately reads/writes compose+config files there,
# and the v10.0.5 re-home migration mv/chown's /root/<name> -> ~/<name>. Both
# roots are allowlisted for the path-checked ops:
#   /root/<name>  — root-owned, lexical match is safe (console can't plant links)
#   ~/<name>      — console-OWNED, so realpath containment is REQUIRED (same
#                   symlink-escape reasoning as TAK_BUNDLE_DIR).
MODULE_DIR_NAMES = (
    'tak-video-restreamer', 'webodm', 'netbird', 'cesium-tiles',
    'TAK-Portal', 'CloudTAK', 'node-red', 'authentik', 'eud-remote-assist',
    # ⚠️ **ATLAS MDM, and one entry covers every deployment on the box.**
    # It runs one deployment per agency, and they used to sit side by side as
    # `atlas`, `atlas-corona`, `atlas-redlands` -- siblings, which this list
    # cannot express: it expands to `<home>/<name>/`, so `<home>/atlas-corona`
    # never matched `<home>/atlas/` and every write, chown and delete inside
    # an agency was refused. 61 refusals on one deploy, all of them fatal the
    # day enforcement is switched on.
    #
    # Widening the rule was tried first -- a bare `<home>/atlas-` prefix -- and
    # it does not work either: `_within_realpath` resolves the real path
    # against a containment *directory*, and a name fragment is not one. The
    # module nests its deployments under `<home>/atlas/<slug>/` instead, which
    # is what this list already means by "one add-on, one directory".
    'atlas',
)
ROOT_MODULE_DIRS = tuple('/root/%s/' % n for n in MODULE_DIR_NAMES)
# Allowlist module dirs under EVERY plausible console home (the resolved home AND
# the /home/<user> convention), deduped — so a passwd/HOME mismatch can't strand
# them. The /nonexistent sentinel is dropped (nothing lives there anyway).
_HOME_ROOTS = tuple(dict.fromkeys(
    h for h in (_NONROOT_HOME, _CONV_HOME) if h and h not in ('/nonexistent', '/')))
HOME_MODULE_DIRS = tuple(
    os.path.join(h, n) + '/' for h in _HOME_ROOTS for n in MODULE_DIR_NAMES)

# ENFORCE vs PERMISSIVE (v10.0.5 → cutover v10.0.8, PLAN-v10.0.8 §C).
#   PERMISSIVE: a request that fails the rulebook is still EXECUTED, but logged
#   as WOULD-DENY. This was the v10.0.5–10.0.7 learning posture used to harvest
#   the real binary/path needs and complete the rulebook.
#   ENFORCE: deny means deny — the non-root console is a real privilege boundary.
#
# How the mode is decided at daemon start (_resolve_enforce). ENFORCE is now
# OPT-IN (v10.0.8) — a box NEVER flips itself; an operator turns it on, and the
# 72h clean window is the READINESS gate the operator waits for, not an automatic
# trigger. "Don't break production" is therefore the default posture.
#   TAKWERX_BROKER_ENFORCE=0  -> PERMISSIVE, hard. The KILL SWITCH / break-glass:
#       add `Environment=TAKWERX_BROKER_ENFORCE=0` to the broker unit +
#       `systemctl daemon-reload` + restart, over SSH. Overrides opt-in.
#   TAKWERX_BROKER_ENFORCE=1  -> ENFORCE, hard (explicit override; testing).
#   unset  ->  OPT-IN gate:
#       * If the operator has NOT opted in (no ENFORCE_OPTIN_FILE) -> PERMISSIVE
#         forever (watch mode), regardless of how clean the box is. The box still
#         reports its readiness (clean-for-Nh) so the console can light up the
#         "Turn on enforcing" button once eligible.
#       * If the operator HAS opted in (ENFORCE_OPTIN_FILE present — created by the
#         console's "Turn on enforcing" action via the enforce_enable op, or by
#         start.sh on a FRESH install) -> ENFORCE only once the audit window is
#         CLEAN (>=ENFORCE_CLEAN_SECS of history, zero WOULD-DENY within it). Until
#         then it stays PERMISSIVE and reports why (so a fresh box watches 72h
#         before it ever blocks — it never breaks its own initial deploy).
#   Opt-in is a RATCHET: the enforce_enable op only ever CREATES the marker, never
#   removes it. Turning enforcement back OFF is the SSH-only ENFORCE=0 kill switch —
#   so a compromised console can only ever make the box MORE locked down, never less.
#   The opt-in marker and the flip stamp are root-owned; the console cannot forge them.
ENFORCE = os.environ.get('TAKWERX_BROKER_ENFORCE') == '1'
ENFORCE_INFO = {'source': 'env' if os.environ.get('TAKWERX_BROKER_ENFORCE') else 'default'}
ENFORCE_STATE_FILE = '/var/lib/takwerx-broker/enforce.json'
ENFORCE_OPTIN_FILE = '/var/lib/takwerx-broker/enforce-optin'
ENFORCE_CLEAN_SECS = 72 * 3600      # 72h clean readiness window (PLAN §A re-sweep target)

# ---------------------------------------------------------------------------
# POLICY / RULEBOOK  — the security core. Tightening these is core .5 work;
# this is the conservative first cut. Anything not explicitly allowed is denied.
# ---------------------------------------------------------------------------

# Binaries the console may run through the broker. argv[0] matched on basename.
#
# SECURITY (v10.0.5 first-hardening pass — see PLAN-v10.0.5 + the security
# review): this is a CONSERVATIVE, FAIL-CLOSED set. Binaries that are trivial
# arbitrary-root-code / arbitrary-write primitives with no safe way to gate them
# generically — `psql` (\! meta-command), `sed` (the `e` command), `dd` (if=
# reads any file), `install` (--strip-program), raw `apt`/`dnf` (-o pre-invoke
# hooks), `openssl` (enc -out = arbitrary write), `semodule`/`setsebool`
# (disable confinement), `sysctl -w kernel.core_pattern=|cmd), user/passwd
# tooling — are DELIBERATELY NOT here. They are denied (fail-closed) until each
# is re-introduced as a dedicated, fixed-argv-shape broker op. The console still
# runs as root in this release, so denying them here only affects the
# force-broker proving path, not production.
#
# NOTE on inherent power: `systemctl start` of a unit the console can write, and
# `docker run`, are inherently near-root by nature. The broker does NOT claim to
# make those unprivileged — its value is the single audited chokepoint plus
# blocking the GRATUITOUS escalations (sudoers, shadow, arbitrary shell). Genuine
# least-privilege requires the per-op redesign tracked as the pre-flip gate.
EXEC_ALLOW = {
    # service + journal control (systemctl is verb-gated — see SYSTEMCTL_VERBS)
    'systemctl', 'journalctl', 'loginctl',
    # firewall (both families)
    'ufw', 'firewall-cmd',
    # intrusion prevention
    'fail2ban-client',
    # containers (NOTE: docker is effectively root-equivalent; see _check_docker)
    'docker',
    # Debian postgres cluster init + dpkg reconfigure (TAK native .deb deploy). dpkg
    # is no broader than the already-allowed apt/dnf the console drives.
    'pg_createcluster', 'dpkg',
    # Email Relay (postfix) admin tools: postconf edits main.cf, postmap builds the
    # sasl_passwd/generic .db maps (root-owned /etc/postfix), debconf-set-selections
    # pre-seeds the postfix install. No broader than the apt install they accompany.
    'postconf', 'postmap', 'debconf-set-selections', 'newaliases',
    # storage / kernel knobs (path-checked where they take a file). sysctl is
    # gated to safe params only (see _check_sysctl) — VM tuning, not kernel.*
    'swapon', 'swapoff', 'mkswap', 'fallocate', 'sync', 'sysctl',
    # SELinux: read-only inspection + `semanage port`/`fcontext` (gated — see
    # _check_semanage), `semodule -l/-r <tak modules>` (gated — _check_semodule),
    # `chcon -t <safe type>` (gated — _check_chcon). Module deploys/uninstalls
    # need these for TAK's own policy + cesium/caddy file labels.
    'getenforce', 'getsebool', 'restorecon', 'semanage', 'semodule', 'chcon',
    # read-only inspection (routed for a single audit point)
    'ss', 'ip', 'getent', 'getcap',
    # v10.1.9 W2: LVM/mount REPORTING tools — pure read-only (they have no write
    # subcommand at all), same class as `ss`/`ip`. Needed by the disk-layout
    # detector to see stranded space. The MUTATING LVM ops (lvextend/lvremove/
    # xfs_growfs/resize2fs) are deliberately NOT here — they are reachable only
    # through the fixed-shape `disk_reclaim` op below, never as free-form argv.
    'lvs', 'vgs', 'pvs', 'findmnt', 'lsblk',
    # v10.2.8 W5b: `pg_lsclusters --no-header` (the TAK 5.8 pre-flight's own cluster
    # check). Read-only listing; it MUST run as root — as the console user it cannot
    # read /etc/postgresql/*/main/postgresql.conf and answers `15 main <unknown> down`
    # for a cluster that is online (test6/test12, 2026-10-08): a silently wrong
    # answer, not an error. Gated to that exact argv (see _check_pg_lsclusters).
    # Without it every pre-flight run left a WOULD-DENY that holds ENFORCE off 72 h.
    'pg_lsclusters',
    # v10.1.0: `wg show …` is read-only WireGuard inspection (relay tunnel status /
    # handshake age for the connectivity anchor + Guard Dog relay health). Gated to
    # the `show` subcommand only — `wg set`/`setconf`/`genkey` are denied (see
    # _check_wg). Same read-only class as `ss`/`ip`.
    'wg',
    # v10.0.8 harvest (born-non-root fleet): `lsof` is read-only (the console
    # checks whether the apt/dpkg lock is held before an install). `find` is
    # read-only TOO once its exec/write/delete actions are gated (see _check_find)
    # — the console uses it to scan a container's postgres volume for planted
    # `.so` files (the PGMiner shared_preload check).
    'lsof', 'find',
    # gpg --dearmor of an apt repo signing key (gated — see _check_gpg)
    'gpg',
    # package managers (gated — see _check_pkgmgr: install/remove only, no -o hooks).
    # NB: installing any package runs its root post-install script — inherently
    # near-root, same bucket as systemd units / docker. The gate blocks the
    # GRATUITOUS -o/--setopt hook-command escalation, not package install itself.
    'apt', 'apt-get', 'dnf', 'yum',
    # privileged file IO via coreutils — TARGET PATHS are validated (see below)
    'tee', 'cat', 'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown',
    'touch', 'ln', 'install',
    # v10.0.8 harvest: `test` is a pure predicate — it cannot write, exec, or
    # read file CONTENTS; worst case it leaks existence/type of a path. The
    # console uses it to probe root-era module dirs (/root/<module>) that
    # takwerx cannot stat. Unrestricted args are acceptable for a no-side-effect
    # binary.
    'test',
    # v10.1.9 W7: `stat` is read-only metadata (mode/owner/size) — it cannot write,
    # exec, or read file CONTENTS, so it is the same no-side-effect class as `test`
    # above. The permissions-hardening pass needs it to check a mode BEFORE
    # chmod'ing, so it only ever narrows and never widens a deliberately-tight file.
    'stat',
    # v10.0.8 harvest: git for root-era module repos (TVR/WebODM stay at /root on
    # a flipped box). Tightly gated — see _check_git: -C <root-era module dir>
    # only; home-resident repos run git DIRECTLY as the console user, never here.
    'git',
    # transient-unit launcher — a DIRECT root-exec primitive, so gated to THREE
    # fixed shapes (kernel-patch, non-root migrate, OS upgrade — see
    # _check_systemd_run). No broader than the already-allowed
    # `systemctl start <console-written-unit>`.
    'systemd-run',
    # v10.1.0 Leg 6 (WiFi Join) — these were MISSING, so the whole WiFi card
    # no-op'd on non-root boxes (scan denied → empty list; add denied at
    # netplan generate). Field-hit 2026-07-08 on the NUC. All three tightly
    # gated to the exact shapes the WiFi card issues:
    #   iw      — `iw dev` + `iw dev <iface> scan` ONLY (read-only wireless
    #             inspection; set/del/txpower shapes denied — see _check_iw)
    #   netplan — `netplan generate|apply` ONLY, no further args (see
    #             _check_netplan). State-changing by design: that IS the
    #             feature, and the console validates-before-apply with a
    #             backup/restore. The netplan YAML itself is written via the
    #             already-path-checked install/cp under /etc/netplan/.
    #   nmcli   — the four fixed WiFi shapes (rescan / list / connection show /
    #             connect <ssid> [password <psk>]) — see _check_nmcli; free
    #             args may not start with '-' (no option injection).
    'iw', 'netplan', 'nmcli',
    # v10.1.0 Leg 6c "use this network now": switch to a SAVED network via the
    # supplicant without re-entering the password. Gated to the read + the two
    # scoped switch verbs only — see _check_wpa_cli.
    'wpa_cli',
}

# Package-manager subcommands the console legitimately uses. Anything else (and
# the `-o`/`--setopt` hook-command vector) is denied.
PKGMGR_SUBCMDS = {
    'install', 'remove', 'purge', 'reinstall', 'autoremove', 'erase',
    'update', 'upgrade', 'makecache', 'clean', 'list', 'info', 'check-update',
    'module', 'group', 'mark',
    # `dnf copr enable @caddy/caddy` — enables a COPR repo (RHEL caddy install
    # path). Repo-metadata management; the eventual package install (which runs
    # post-install scripts) is already gated by the `install` subcommand. The
    # `-o/--setopt` hook-command vector is still blocked below regardless.
    'copr',
    # `dnf config-manager --add-repo <url>` — the RHEL analogue of the allowed
    # /etc/apt/ repo-file writes (v10.1.5 WS2: non-root Docker Engine install).
    # Same class as `copr`: repo-metadata only; install stays separately gated
    # and `-o/--setopt` hook vectors stay blocked.
    'config-manager',
    # `dnf config-manager --set-enabled crb/powertools` — enables the CRB/
    # PowerTools repo (RHEL deps live there). Repo enable/disable only; same
    # bucket as copr. The dangerous `--add-repo <url>` still installs a repo def
    # but cannot run code until an install (gated). -o/--setopt stays blocked.
    'config-manager',
    # ops #168: `dnf -C updateinfo list --security` — which pending/installed
    # packages carry a security advisory, for the Guard Dog update email. A
    # metadata QUERY (no transaction, no scriptlets); same bucket as check-update.
    'updateinfo',
}

# Never executable through the broker — escalation primitives (defence in depth;
# anything not in EXEC_ALLOW is already denied).
EXEC_DENY = {
    'sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh',     # arbitrary shell
    'su', 'sudo', 'pkexec', 'runuser', 'setpriv',          # privilege pivots
    'env', 'nohup', 'nice', 'timeout', 'xargs',            # exec wrappers
    # NB: `find` moved to EXEC_ALLOW (v10.0.8) but is gated read-only by
    # _check_find — its -exec/-delete/-fprint* actions (the reason it lived here)
    # stay denied, so it is NOT a blanket allow.
    'perl', 'python', 'python3', 'ruby', 'awk', 'gawk',    # interpreters
    'sed', 'dd', 'psql', 'openssl',                        # arbitrary write/exec
    'setsebool', 'setcap',                                 # confinement / caps
    # NB: `semodule` is now ALLOWED but tightly gated (_check_semodule: -l, and
    # -r only for TAK's own policy modules) — it is NOT a blanket allow.
    'visudo', 'passwd', 'chpasswd', 'useradd', 'usermod', 'groupadd',
}

# systemctl verbs allowed. DENY: link/edit/set-property/set-environment/
# import-environment/switch-root — each can run arbitrary root code or point a
# unit at console-controlled content outside /etc/systemd/system.
SYSTEMCTL_VERBS = {
    'start', 'stop', 'restart', 'reload', 'try-restart', 'reload-or-restart',
    'enable', 'disable', 'mask', 'unmask', 'is-active', 'is-enabled',
    'is-failed', 'status', 'show', 'cat', 'daemon-reload', 'reset-failed',
    'list-units', 'list-timers', 'list-unit-files', 'kill',
    'show-environment',        # read-only dump of the manager env (ops #347: was the one WOULD-DENY)
    'reboot',                  # operator-gated reboot after a kernel patch
    'poweroff',                # operator-gated power-off — console Power Off button, password-confirmed
}

# Coreutils whose path arguments MUST live inside PATH_ALLOW (and not PATH_DENY).
PATH_CHECKED_BINS = {
    'tee', 'cat', 'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown',
    'touch', 'ln',
}

# Privileged path prefixes the console is allowed to read/write (directly via
# the write/read ops, and as targets of the path-checked coreutils above).
PATH_ALLOW = (
    '/var/lib/infratak-backups/',   # v10.3.0 W12 full-stack backups — root-owned 0700,
                                    # config copies land here; DB dumps via stack_pg_dump
    '/etc/systemd/system/',
    '/etc/fail2ban/',
    '/etc/caddy/',
    '/etc/postfix/',
    '/etc/docker/',
    '/etc/firewalld/',
    '/etc/ufw/',
    '/etc/sysctl.d/',
    '/etc/security/',
    '/etc/ssh/',
    '/etc/letsencrypt/',
    '/etc/apt/',                 # apt repo files (sources.list.d) — adding a repo,
                                 # the apt analogue of the allowed dnf copr/config-manager
    '/usr/share/keyrings/',      # apt repo signing keys (gpg --dearmor dest)
    '/etc/debsig/',              # debsig policy dir — TAK .deb signature verification
    '/usr/share/debsig/',        # debsig keyring dir (same)
    '/etc/netplan/',             # v10.1.0 Leg 6 WiFi Join: cat/cp/install of the
                                 # netplan YAML (additive AP add, validate-before-apply).
                                 # Root-owned dir; console cannot symlink-plant here.
    '/opt/tak/',
    # PostgreSQL cluster data directories, both families. The console ALREADY
    # creates, upgrades, dumps and destroys these as root through this broker —
    # initdb, pg_upgrade, pg_dump and the uninstall's DROP DATABASE all go through
    # here — so this grants no destructive power it does not already have. What it
    # fixes is the console being able to build a cluster but not clean up its own
    # FAILED attempt: a 5.8 migration that aborts part-way leaves
    # /var/lib/pgsql/<new>/data behind, every retry then dies on "New cluster
    # database cot is not empty", and the recovery the console prints ("run Update
    # again") can never succeed. On a born-non-root box the operator has no shell
    # route either, so the box is stuck with no way out through the product.
    # Measured on nuc, 2026-09-21. Same dead end exists on Debian; it was simply
    # never hit there because that migration did not fail.
    '/var/lib/pgsql/',
    '/var/lib/postgresql/',
    '/opt/tak-guarddog/',
    TAK_BUNDLE_DIR + '/',        # console-owned TAK docker bundle (ln source for /opt/tak)
    '/usr/local/etc/',
    '/var/lib/cesium-tiles/',   # RHEL cesium tiles dir (chmod 755 by the console)
    '/var/lib/takguard/',       # Guard Dog state dir (mkdir/chmod by the console)
    # v10.3.0 W4: OS-upgrade job state (status file, baseline.json, pre/ snapshot).
    # Root-owned; the console mkdirs it, writes the baseline + seeds the status,
    # and reads the status back after each console restart/reboot.
    '/var/lib/infratak-os-upgrade/',
    '/opt/mediamtx-webeditor/',  # MediaMTX web-editor module dir (owned by the mediamtx account, ops #643)
    '/opt/mediamtx-webeditor-pylib/',  # its Python packages: console-owned, read-only to the editor (ops #643)
    '/var/log/',                # log files (touch /var/log/fail2ban.log, etc.)
    # v10.0.8 harvest additions (PLAN-v10.0.8 §A):
    '/var/lib/takwerx-console/',  # console state dir (mkdir/chown at startup)
    '/var/lib/caddy/',            # Caddy data dir: LE cert reads (cert sync into TAK)
                                  # + the custom-cert caddy-readable copy writes.
                                  # root/caddy-owned — lexical match is safe.
    # NOTE: /usr/local/bin/ and /usr/sbin/ are deliberately NOT prefix-allowed —
    # they are on root's PATH, so a write there is an escalation primitive. The
    # one legit exception (the ufw->firewalld shim) is the EXACT path below.
) + ROOT_MODULE_DIRS + HOME_MODULE_DIRS   # module dirs, both roots (v10.0.8 §A)

# READ-ONLY prefixes: the broker `read` op only — NEVER writes or the
# path-checked coreutils. v10.0.8: the split Server One re-home
# (_startup_ensure_server_one_ssh_key) reads a ROOT-era SSH key under /root/.ssh
# via _read_priv and copies it into the console home (Server One already trusts
# that key — it is the console's own operational credential). A WRITE grant here
# would let the console plant /root/.ssh/authorized_keys (root login) — that
# stays denied.
PATH_ALLOW_READONLY = (
    '/root/.ssh/',
    # ops #645 W2: read only. Root shell scripts `. /etc/os-release`, and the file
    # links to /usr/lib/os-release, so a write was a root-exec primitive. The
    # console only ever reads it (fleet audit logs + code scan).
    '/etc/os-release',
)

# Exact privileged paths that are read/written but aren't directories.
PATH_ALLOW_EXACT = (
    '/etc/fstab',
    '/etc/sysctl.conf',        # vm.overcommit_memory persistence (Redis BGSAVE fix)
    '/etc/docker/daemon.json',
    '/swapfile',
    '/usr/sbin/ufw',            # ufw->firewalld shim (RHEL); see _check_install
    # Module binaries installed via `install`/`mv` to a system bin dir. EXACT
    # paths only (NOT the /usr/bin or /usr/local/bin PREFIX, which stay denied as
    # root-PATH escalation surfaces). Same inherent power as a package that drops
    # the same binary — gated to these two known files.
    '/usr/bin/caddy',                  # official static Caddy (RHEL binary install)
    '/usr/local/bin/mediamtx',         # MediaMTX (no distro package)
    # Console-owned helper scripts run by systemd units the console ALSO writes
    # (so this grants no privilege beyond the unit it's paired with — same
    # inherent near-root as writing the unit itself). Exact paths only, NOT the
    # /usr/local/sbin prefix (which stays denied as a root-PATH escalation surface).
    '/usr/local/sbin/tak-console-restart.sh',   # daily console-restart timer
    '/usr/local/sbin/infratak-f2b-notify',       # fail2ban off-box notify hook
    '/usr/local/sbin/takserver-renew-letsencrypt.sh',  # ops #633: daily LE renewal
                                                 # (takserver-cert-renewal.service); moved
                                                 # here from /opt/tak
    '/var/lib/infratak-kernel-patch.sh',         # kernel-patch job script (written by
                                                 # the console, run by the gated systemd-run)
    '/var/lib/infratak-os-upgrade.sh',           # v10.3.0 W4: OS-upgrade job script (same
                                                 # pairing — written by the console, run only
                                                 # by the third gated systemd-run shape)
    '/etc/default/takserver',                    # TAK Server JVM heap (snapshot/restore + deploy)
    # Relay tunnel config (Connectivity → Connect a Relay). _CONN_WG_IF is the
    # fleet constant 'wg0', so this is one fixed file — NOT the /etc/wireguard/
    # prefix, which would let the console plant configs for arbitrary interfaces.
    # Inherent power: wg-quick(8) runs a config's PostUp/PostDown as root, so this
    # is a root-exec primitive — but no broader than `systemctl start` of a unit
    # the console already writes into /etc/systemd/system/ (see the note at the
    # top of EXEC_ALLOW). Granted deliberately: without it the relay setup dies at
    # `install ... /etc/wireguard/wg0.conf` on every born-non-root box (issue #58).
    '/etc/wireguard/wg0.conf',
)

# NEVER, even inside an allowed prefix — the escalation / credential surface and
# the broker's own trust anchors. A least-privilege console must not be able to
# rewrite these.
PATH_DENY_EXACT = {
    '/etc/sudoers',
    '/etc/shadow', '/etc/gshadow', '/etc/passwd', '/etc/group',
    BROKER_UNIT,                         # console may NOT rewrite the broker unit
    SELF_PATH,                           # ...nor the broker code
    SOCKET_PATH,
}
PATH_DENY_PREFIX = (
    # STILL DENIED, and deliberately so. v10.1.53 added a TAK Portal sudoers
    # grant — as the fixed-shape `takportal_sudoers` op whose content the BROKER
    # composes (see _takportal_sudoers_text), NOT by relaxing this line. The
    # generic write path must never be able to mint a sudoers rule of the
    # console's own choosing; that would make the console user root outright.
    '/etc/sudoers.d/',                   # no minting new sudoers rules
    # v10.0.8: the broker unit itself is deny-listed (trust anchor), but a
    # systemd DROP-IN under its .d/ dir would override ExecStart/Environment
    # just the same (incl. the ENFORCE flag) — deny the whole drop-in dir.
    BROKER_UNIT + '.d/',
    # ops #645 W0: write-then-root-runs paths under allowlisted prefixes that the
    # console never writes through the broker (static scan + test6/test12 audit
    # logs): apt hook config (DPkg::Pre-Invoke runs on the next apt), certbot
    # renewal hooks, and the broker's own audit log (tamper / forged clean window).
    '/etc/apt/apt.conf.d/',
    '/etc/letsencrypt/renewal-hooks/',
    AUDIT_LOG,                           # audit.log and its rotations audit.log.N
    # W0 part 2: broker state (ENFORCE state, dump key) and the verified-package
    # staging dir (a file root installs after its signature check).
    '/var/lib/takwerx-broker/',
    # W1: the root-owned broker code and its config (console_dir).
    ROOT_CODE_DIR + '/',
    ROOT_CONF_DIR + '/',
) + tuple(d + '.git/' for d in ROOT_MODULE_DIRS)   # root-run git reads this config
PATH_DENY_EXACT |= {ROOT_CODE_DIR, ROOT_CONF_DIR, '/var/lib/takwerx-broker'}

# ops #645 W0: single files root executes or sources (same reason as above).
PATH_DENY_EXACT |= {
    '/opt/tak/apply-selinux.sh',         # run as root by the gated `bash` shape
    '/etc/apt/apt.conf',
    '/etc/security/namespace.init',      # pam_namespace runs it as root at login
    '/etc/ufw/before.init',              # ufw runs these as root on start/stop
    '/etc/ufw/after.init',
} | {d + '.git' for d in ROOT_MODULE_DIRS}


class Denied(Exception):
    pass


def _abs(path):
    """Lexically normalise an absolute path and reject traversal.

    We match the allowlist on the LEXICAL path, NOT realpath: the allowlisted
    dirs (/etc/*, /opt/tak*, ...) are root-owned, so a non-root console cannot
    plant an escaping symlink inside them — and some allowed roots are legit
    symlinks themselves (e.g. /opt/tak -> the versioned TAK dir), which realpath
    would wrongly push outside the allowlist. Reject '..' so no lexical escape."""
    if not path or not isinstance(path, str):
        raise Denied('empty/invalid path')
    if '\x00' in path:
        raise Denied('NUL in path')
    p = os.path.normpath(path)
    if not p.startswith('/'):
        raise Denied('path not absolute')
    if '..' in p.split('/'):
        raise Denied('path traversal')
    return p


def _within_realpath(path, root):
    """True if `path` RESOLVES (symlinks followed) to within `root`. Used to
    harden the one console-WRITABLE allowlist prefix (TAK_BUNDLE_DIR): every other
    allowlisted dir is root-owned, so `_abs`'s lexical match is safe (the console
    can't plant an escaping symlink in a root-owned dir). The bundle dir is
    takwerx-owned, so a lexical match alone would let the console `ln -s /etc
    bundle/x` then write/mount `bundle/x` to escape. realpath-containment closes
    that. (Resolving realpath here is safe BECAUSE the bundle is console-owned —
    the reason `_abs` avoids realpath, root-owned legit symlinks like /opt/tak,
    does not apply to this prefix.)"""
    try:
        # If the console-owned ROOT itself has been replaced with a symlink
        # (~/netbird -> /etc), realpath(root) == realpath(path) for an escaping
        # path and the containment compare below would pass — reject that first.
        if os.path.islink(root):
            return False
        rr = os.path.realpath(root)
        rp = os.path.realpath(path)
    except OSError:
        return False
    return rp == rr or rp.startswith(rr + '/')


# Prefixes the CONSOLE USER can write to directly (its own home) — a lexical
# allowlist match is not enough there, because the console could plant a symlink
# (dir/x -> /etc) and have the broker follow it out. These require realpath
# containment; every other allowlisted prefix is root-owned, so the cheaper
# lexical match in _abs stays safe.
# The full-stack backup root (v10.3.0 W12) is root-owned, but it is on the write
# allowlist and the console can `ln -s` inside it — so it gets realpath containment
# too, or a planted link would turn a root cp/write into the backup tree into a
# write anywhere.
# ops #643: the same goes for the MediaMTX account's dirs. MediaMTX and its
# internet-facing editor own the editor dir and can write MediaMTX's config dir
# (the editor saves with `sed -i`, which needs dir write), so a root write or read
# there must not follow a link they planted.
_MEDIAMTX_OWNED_PREFIXES = ('/opt/mediamtx-webeditor/', '/usr/local/etc/')
_CONSOLE_OWNED_PREFIXES = ((TAK_BUNDLE_DIR + '/',) + HOME_MODULE_DIRS
                           + ('/var/lib/infratak-backups/', '/opt/mediamtx-webeditor-pylib/')
                           + _MEDIAMTX_OWNED_PREFIXES)


def _path_allowed(path, readonly=False):
    """True if `path` is within the privileged read/write allowlist and not in
    the deny set. Raises Denied with a reason otherwise. `readonly=True` (the
    broker `read` op) additionally admits the PATH_ALLOW_READONLY prefixes."""
    p = _abs(path)
    if p in PATH_DENY_EXACT:
        raise Denied(f'path is in deny-list: {p}')
    for d in PATH_DENY_PREFIX:
        if p.startswith(d):
            raise Denied(f'path is under deny-prefix {d}: {p}')
    if p in PATH_ALLOW_EXACT:
        return p
    if readonly:
        for a in PATH_ALLOW_READONLY:
            if p.startswith(a) or p == a.rstrip('/'):
                return p
    for a in PATH_ALLOW:
        # match a child of the dir, OR the allowlisted dir itself (no trailing /)
        if p.startswith(a) or p == a.rstrip('/'):
            # Console-writable prefixes (the bundle dir + home module dirs)
            # require realpath containment so a planted symlink can't escape.
            if a in _CONSOLE_OWNED_PREFIXES and not _within_realpath(p, a.rstrip('/')):
                raise Denied(f'symlink escape from console-owned dir: {p}')
            return p
    raise Denied(f'path not in allow-list: {p}')


# ---------------------------------------------------------------------------
# ops #645 W2: every writable destination has a class.
#   data       root never runs it and never reads it as config that runs commands
#   validated  root reads it as config that CAN run commands: the console may put
#              bytes there only through the `write` op, and a parser checks them
#   asset      root runs it (script or binary): content must come from the
#              verified tree (W1) or a pinned checksum, never from the console
# Every PATH_ALLOW / PATH_ALLOW_EXACT entry must be in PATH_CLASS (a test fails
# otherwise). W2 ships in parts: PATH_CLASS_PENDING lists entries whose rule is not
# enforced yet, with the part that brings it. Nothing may be added to it without a
# part number.
# ---------------------------------------------------------------------------
DEST_DATA, DEST_VALIDATED, DEST_ASSET = 'data', 'validated', 'asset'
PATH_CLASS = {
    '/var/lib/infratak-backups/': DEST_DATA,
    '/etc/systemd/system/': DEST_VALIDATED,      # enforced: _check_unit_write
    '/etc/fail2ban/': DEST_VALIDATED,
    '/etc/caddy/': DEST_DATA,                    # Caddy runs as `caddy`
    '/etc/postfix/': DEST_VALIDATED,
    '/etc/docker/': DEST_VALIDATED,
    '/etc/firewalld/': DEST_DATA,
    '/etc/ufw/': DEST_DATA,                      # before/after.init deny-listed (W0)
    '/etc/sysctl.d/': DEST_VALIDATED,
    '/etc/security/': DEST_VALIDATED,
    '/etc/ssh/': DEST_VALIDATED,
    '/etc/letsencrypt/': DEST_VALIDATED,
    '/etc/apt/': DEST_VALIDATED,
    '/usr/share/keyrings/': DEST_VALIDATED,      # which repos root trusts
    '/etc/debsig/': DEST_ASSET,
    '/usr/share/debsig/': DEST_ASSET,
    '/etc/netplan/': DEST_DATA,
    '/opt/tak/': DEST_DATA,                      # TAK runs as `tak`; see pending
    '/var/lib/pgsql/': DEST_DATA,                # postgres user, not root
    '/var/lib/postgresql/': DEST_DATA,
    '/opt/tak-guarddog/': DEST_ASSET,
    TAK_BUNDLE_DIR + '/': DEST_DATA,
    '/usr/local/etc/': DEST_DATA,                # MediaMTX config, runs as the console user
    '/var/lib/cesium-tiles/': DEST_DATA,
    '/var/lib/takguard/': DEST_VALIDATED,        # Guard Dog state root scripts read
    '/var/lib/infratak-os-upgrade/': DEST_VALIDATED,
    '/opt/mediamtx-webeditor/': DEST_DATA,       # runs as the console user
    '/opt/mediamtx-webeditor-pylib/': DEST_DATA, # editor's Python packages: run by the mediamtx account, never by root
    '/var/log/': DEST_DATA,                      # broker audit log deny-listed (W0)
    '/var/lib/takwerx-console/': DEST_DATA,
    '/var/lib/caddy/': DEST_DATA,
    # exact files
    '/etc/fstab': DEST_VALIDATED,
    '/etc/sysctl.conf': DEST_VALIDATED,
    '/etc/docker/daemon.json': DEST_VALIDATED,
    '/swapfile': DEST_DATA,
    '/usr/sbin/ufw': DEST_ASSET,
    '/usr/bin/caddy': DEST_ASSET,
    '/usr/local/bin/mediamtx': DEST_ASSET,
    '/usr/local/sbin/tak-console-restart.sh': DEST_ASSET,
    '/usr/local/sbin/infratak-f2b-notify': DEST_ASSET,
    '/usr/local/sbin/takserver-renew-letsencrypt.sh': DEST_ASSET,
    '/var/lib/infratak-kernel-patch.sh': DEST_ASSET,
    '/var/lib/infratak-os-upgrade.sh': DEST_ASSET,
    '/etc/default/takserver': DEST_VALIDATED,
    '/etc/wireguard/wg0.conf': DEST_VALIDATED,
}
PATH_CLASS.update({d: DEST_DATA for d in ROOT_MODULE_DIRS + HOME_MODULE_DIRS})   # until W3
# Classed, but the class rule is not enforced yet: W2 part 2 = verified assets
# (Guard Dog and the other root scripts rendered by root from the W1 tree), part 3 =
# content parsers for the other validated config files.
PATH_CLASS_PENDING = {
    '/etc/fail2ban/': 'W2 part 3', '/etc/postfix/': 'W2 part 3', '/etc/docker/': 'W2 part 3',
    '/etc/sysctl.d/': 'W2 part 3', '/etc/security/': 'W2 part 3', '/etc/ssh/': 'W2 part 3',
    '/etc/letsencrypt/': 'W2 part 3', '/etc/apt/': 'W2 part 3',
    '/usr/share/keyrings/': 'W2 part 3', '/var/lib/takguard/': 'W2 part 3',
    '/var/lib/infratak-os-upgrade/': 'W2 part 3', '/etc/fstab': 'W2 part 3',
    '/etc/sysctl.conf': 'W2 part 3', '/etc/docker/daemon.json': 'W2 part 3',
    '/etc/default/takserver': 'W2 part 3', '/etc/wireguard/wg0.conf': 'W2 part 3',
    '/opt/tak/': 'W2 part 3',          # confirm what root runs from /opt/tak (setenv.sh)
    '/etc/debsig/': 'W2 part 2', '/usr/share/debsig/': 'W2 part 2',
    # scripts from the repo are enforced (gd_render, _gd_path_locked); the inline
    # ones in _GD_INLINE_PENDING and the state files are not yet
    '/opt/tak-guarddog/': 'W2 part 2b', '/usr/sbin/ufw': 'W2 part 2',
    '/usr/bin/caddy': 'W2 part 2', '/usr/local/bin/mediamtx': 'W2 part 2',
    '/usr/local/sbin/tak-console-restart.sh': 'W2 part 2',
    '/usr/local/sbin/infratak-f2b-notify': 'W2 part 2',
    '/usr/local/sbin/takserver-renew-letsencrypt.sh': 'W2 part 2',
    '/var/lib/infratak-kernel-patch.sh': 'W2 part 2',
    '/var/lib/infratak-os-upgrade.sh': 'W2 part 2',
}


def _dest_class(path):
    """PATH_CLASS of a normalised path: the exact entry, else the longest prefix
    (also for the prefix dir itself). None when the path is in no class."""
    if path in PATH_CLASS:
        return PATH_CLASS[path]
    best = None
    for a, cls in PATH_CLASS.items():
        if a.endswith('/') and (path.startswith(a) or path == a.rstrip('/')):
            if best is None or len(a) > len(best[0]):
                best = (a, cls)
    return best[1] if best else None


def _root_runs(path):
    """True for a validated or asset destination: root runs it or reads it as
    config that can run commands."""
    return _dest_class(path) in (DEST_VALIDATED, DEST_ASSET)


UNIT_DIR = '/etc/systemd/system'


def _in_unit_dir(path):
    return path == UNIT_DIR or path.startswith(UNIT_DIR + '/')


# Unit files the console writes (the generated check in
# tests/test_broker_unit_writes_ops645.py keeps this equal to app.py). Anything else
# under /etc/systemd/system is refused: a new unit name was a root service of the
# console's own choosing.
UNIT_FILES = frozenset({
    'authentik-log-forwarder.service', 'docker-stagger.service',
    'mediamtx.service', 'mediamtx-webeditor.service',
    'mediamtx-cert-sync.service', 'mediamtx-cert-sync.timer',
    'tak-health.service', 'tak-metrics-collector.service', 'tak-post-start.service',
    'takauthentiktasklogpurge.service', 'takauthentiktasklogpurge.timer',
    'takautovacuum.service', 'takautovacuum.timer',
    'takbuildcachereclaim.service', 'takbuildcachereclaim.timer',
    'takclientgate.service', 'takclientgate.timer', 'takclientgatesweep.service',
    'takconsolerestart.service', 'takconsolerestart.timer',
    'takdbrepack.service', 'takdbrepack.timer',
    'takrestartwatch.service',
    'takretentionguard.service', 'takretentionguard.timer',
    'takserver-cert-renewal.service', 'takserver-cert-renewal.timer',
    'takswapreclaim.service', 'takswapreclaim.timer',
    'takwerx-console.service',
    'takwerx-setup-ap.service', 'takwerxsetupapwatch.service', 'takwerxsetupapwatch.timer',
    # drop-ins
    'takserver.service.d/soft-start.conf', 'takserver.service.d/jvm-pin.conf',
    'caddy.service.d/10-takwerx-boot.conf', 'caddy.service.d/10-takwerx-acme-eab.conf',
    'mediamtx-webeditor.service.d/10-infratak-journal.conf',
    'mediamtx-webeditor.service.d/20-infratak-home.conf',
})
_UNIT_FILE_RE = re.compile(r'^tak[a-z0-9]+guard\.(service|timer)$')   # Guard Dog watchers
# Users a non-root unit may run as, and the groups it may add. A unit running as
# another user (tak, postgres) would hand the console that account, and `tak` owns
# files root runs. ops #643: MediaMTX and its web editor run as their own account.
UNIT_USERS = frozenset({BROKER_USER, 'mediamtx'})
UNIT_GROUPS = frozenset({BROKER_USER, 'caddy', 'systemd-journal'})
# These must keep a non-root User= (the plan's rule). So their drop-ins are checked
# as non-root too; every other drop-in counts as root (it can't see its base User=).
UNIT_MUST_BE_NONROOT = frozenset({'takwerx-console.service', 'mediamtx.service',
                                  'mediamtx-webeditor.service'})
_UNIT_EXEC_KEYS = frozenset({'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecCondition',
                             'ExecReload', 'ExecStop', 'ExecStopPost'})
# Keys allowed per section: what the fleet's units and app.py use. An allow-list,
# because many keys make PID 1 act as root for a non-root unit (StandardOutput=file:
# opens as root, BindPaths=, LoadCredential=, AmbientCapabilities=, PAMName=, Alias=).
_UNIT_KEYS = {
    'Unit': frozenset({
        'Description', 'Documentation', 'After', 'Before', 'Requires', 'Wants', 'BindsTo',
        'PartOf', 'Conflicts', 'StartLimitIntervalSec', 'StartLimitBurst',
        'ConditionPathExists', 'ConditionPathIsDirectory', 'ConditionFileIsExecutable',
        'ConditionFileNotEmpty', 'DefaultDependencies'}),
    'Service': _UNIT_EXEC_KEYS | frozenset({
        'Type', 'RemainAfterExit', 'Restart', 'RestartSec', 'TimeoutSec', 'TimeoutStartSec',
        'TimeoutStopSec', 'RuntimeMaxSec', 'StartLimitInterval', 'StartLimitIntervalSec',
        'StartLimitBurst', 'SuccessExitStatus', 'RestartPreventExitStatus',
        'User', 'Group', 'SupplementaryGroups', 'WorkingDirectory', 'Environment',
        'EnvironmentFile', 'StandardOutput', 'StandardError', 'SyslogIdentifier',
        'KillMode', 'KillSignal', 'SendSIGKILL', 'LimitNOFILE', 'LimitNPROC', 'Nice',
        'MemoryMax', 'MemoryHigh', 'CPUQuota', 'TasksMax', 'IOSchedulingClass',
        'IOSchedulingPriority', 'OOMScoreAdjust', 'NoNewPrivileges', 'PrivateTmp',
        'ProtectSystem', 'ProtectHome', 'ReadOnlyPaths', 'ReadWritePaths',
        'InaccessiblePaths', 'UMask', 'SELinuxContext'}),
    'Timer': frozenset({
        'OnCalendar', 'OnBootSec', 'OnStartupSec', 'OnActiveSec', 'OnUnitActiveSec',
        'OnUnitInactiveSec', 'Persistent', 'RandomizedDelaySec', 'AccuracySec', 'Unit'}),
    'Install': frozenset({'WantedBy', 'RequiredBy', 'Also'}),
}
_UNIT_SECTIONS = {'.service': ('Unit', 'Service', 'Install'),
                  '.timer': ('Unit', 'Timer', 'Install'),
                  '.conf': ('Unit', 'Service', 'Install')}       # service drop-ins
_UNIT_OUTPUTS = frozenset({'journal', 'null', 'inherit', 'journal+console', 'kmsg'})
_UNIT_SELINUX = 'system_u:system_r:unconfined_service_t:s0'
_UNIT_PATH_DIRS = ('/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin')
# env names that change what a root process loads or runs
_UNIT_ENV_DENY_RE = re.compile(
    r'^(LD_.*|BASH_ENV|ENV|BASHOPTS|SHELLOPTS|PS4|IFS|CDPATH|GLOBIGNORE|PYTHON(?!UNBUFFERED$).*'
    r'|PERL.*|RUBY.*|NODE_OPTIONS|NODE_PATH|GCONV_PATH|LOCPATH|NLSPATH|GIT_.*|HOSTALIASES'
    r'|RES_OPTIONS|LOCALDOMAIN|TMPDIR|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS'
    r'|OPENSSL_CONF|OPENSSL_MODULES|SSL_CERT_.*|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|HOME)$')
_UNIT_PY_FLAGS = frozenset({'-I', '-u', '-B', '-s', '-E'})
_UNIT_SHELLS = frozenset({'sh', 'bash', 'dash'})
# The two root units that run inline shell. Each has its own parser below; no other
# unit may use `bash -c`.
_AK_FORWARDER_SCRIPT = ('docker logs -f authentik-server-1 2>&1 | grep --line-buffered '
                        '-F invalid_login >> /var/log/authentik/auth.log')
_CONTAINER_RE = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'
_STAGGER_STEP_RES = (
    re.compile(rf'docker stop( {_CONTAINER_RE})+ 2>/dev/null; true'),
    re.compile(r'echo "(Starting [A-Za-z ]{1,40}\.\.\.|All containers started)"'),
    re.compile(rf'docker start( {_CONTAINER_RE})+'),
    re.compile(r'sleep [0-9]{1,3}'),
)
# TAK Portal: compose up from its module dir (compose itself is W3's job)
_STAGGER_TP_RE = re.compile(
    rf'\(\(cd (/[A-Za-z0-9_./-]+) && docker compose up -d\) \|\| docker start( {_CONTAINER_RE})+\)')


def _unit_name_ok(rel):
    return rel in UNIT_FILES or bool(_UNIT_FILE_RE.fullmatch(rel))


def _console_writable(path):
    """True when the console user can change `path` itself or through the broker
    (any data/validated destination, its home, the console repo, temp dirs)."""
    p = os.path.normpath(path)
    for d in ('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/run/user/',
              CONSOLE_REPO_DIR + '/', _NONROOT_HOME + '/'):
        if p.startswith(d) or p == d.rstrip('/'):
            return True
    cls = _dest_class(p)
    return cls in (DEST_DATA, DEST_VALIDATED)


# ops #645 W2 (Security re-review): the checker must read the same lines systemd
# runs. Where the two readers could differ, the shape is refused, not modelled:
# - systemd drops a comment line inside a `\` continuation and keeps joining, so
#   `ExecStart=<asset> \` / `# c` / `RestartSec=5 ; +/tmp/x` is ONE Exec line to it.
# - a line ending in `\\` (escaped backslash), or `\` then spaces, is NOT a
#   continuation to systemd (it counts escapes, it does not strip first).
# - other readers split lines on CR, VT, FF, NEL, U+2028/2029; the console never
#   writes those, or any other control character but tab.
# - the console continues lines only in Exec*= (docker-stagger's inline script).
# https://www.freedesktop.org/software/systemd/man/latest/systemd.syntax.html
_UNIT_BAD_CHARS_RE = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\ufeff]')
_UNIT_WS = ' \t'                     # systemd WHITESPACE, less the line breaks


def _unit_lines(text):
    """[(section, key, value)] of a unit file. A `\\` continuation joins the next
    line with one space (as systemd does); every shape where systemd could read
    the lines differently is refused (see above)."""
    m = _UNIT_BAD_CHARS_RE.search(text)
    if m:
        raise Denied(f'unit: control or line-separator character {m.group(0)!r} not allowed')
    def _take(raw):
        s = raw.strip(_UNIT_WS)
        if s.endswith('\\') and not raw.endswith('\\'):
            raise Denied('unit: a backslash followed by spaces at the end of a line')
        if len(s) - len(s.rstrip('\\')) > 1:
            raise Denied('unit: a line ends in more than one backslash')
        return s

    raws = text.split('\n')
    out, section, i = [], None, 0
    while i < len(raws):
        s = raws[i].strip(_UNIT_WS)
        i += 1
        if not s or s[0] in '#;':
            if s.endswith('\\'):     # systemd >= 235 skips it; older ones continued it
                raise Denied('unit: a comment line ends in a backslash')
            continue
        parts = [_take(raws[i - 1])]
        while parts[-1].endswith('\\'):
            if i >= len(raws):
                raise Denied('unit: file ends in a line continuation')
            nxt = raws[i].strip(_UNIT_WS)
            if not nxt or nxt[0] in '#;':
                raise Denied('unit: a blank or comment line inside a line continuation')
            nxt = _take(raws[i])
            i += 1
            parts[-1] = parts[-1][:-1].rstrip(_UNIT_WS)
            parts.append(nxt)
        line = ' '.join(parts)
        if line.startswith('[') and line.endswith(']'):
            if len(parts) > 1:
                raise Denied('unit: line continuation in a section header')
            section = line[1:-1]
            continue
        if '=' not in line:
            raise Denied(f'unit: not a key=value line: {line[:60]}')
        k, v = line.split('=', 1)
        k, v = k.strip(_UNIT_WS), v.strip(_UNIT_WS)
        if len(parts) > 1 and k not in _UNIT_EXEC_KEYS:
            raise Denied(f'unit: line continuation in {k[:40]}= (only Exec lines may continue)')
        out.append((section, k, v))
    return out


def _unit_split(value, what):
    import shlex
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        raise Denied(f'unit: cannot parse {what}')


def _unit_stagger_ok(script):
    for m in _STAGGER_TP_RE.finditer(script):
        if not any(m.group(1) == d.rstrip('/') for d in ROOT_MODULE_DIRS + HOME_MODULE_DIRS):
            raise Denied(f'unit: docker-stagger compose dir is not a module dir: {m.group(1)}')
    rest = _STAGGER_TP_RE.sub('docker start x', script)
    for step in rest.split('&&'):
        step = ' '.join(step.split())
        if not any(r.fullmatch(step) for r in _STAGGER_STEP_RES):
            raise Denied(f'unit: docker-stagger step not allowed: {step[:80]}')


# ops #645 W2 (Security re-review #2): a path root runs or reads from a unit is plain
# text, already normalised. systemd decodes C escapes (`\x2f`, `\057`), specifiers
# (`%T`, `%h`) and `$VAR`/`${VAR}` in Exec words; shlex and normpath do not, so
# `/opt/tak-guarddog/..\x2f..\x2ftmp/evil.sh` looked like an asset and ran /tmp/evil.sh.
# `\` and `%` are refused in every unit value (_check_unit_write); this charset also
# keeps `$`, quotes and `..` out of the words root runs.
_UNIT_PLAIN_PATH_RE = re.compile(r'/[A-Za-z0-9_./-]+')


def _unit_plain_path(path, what):
    if not _UNIT_PLAIN_PATH_RE.fullmatch(path) or os.path.normpath(path) != path:
        raise Denied(f'unit: {what} must be a plain, normalised absolute path: {path[:80]!r}')
    return path


def _unit_root_command_ok(toks, rel):
    """A command root runs from a unit: one of infra-TAK's own scripts (asset), the
    system python with safe flags on one, or the two parsed inline shells. The binary
    and the script word must be plain, normalised paths (no escapes, no `..`)."""
    binary = toks[0]
    if not binary.startswith('/'):
        raise Denied(f'unit: root command must be an absolute path: {binary[:80]}')
    p = _unit_plain_path(binary, 'root command')
    base = os.path.basename(p)
    if _unit_asset_ok(p):
        return
    if base in _UNIT_SHELLS and os.path.dirname(p) in ('/bin', '/usr/bin'):
        if len(toks) == 3 and toks[1] == '-c':
            if rel == 'authentik-log-forwarder.service' and toks[2] == _AK_FORWARDER_SCRIPT:
                return
            if rel == 'docker-stagger.service':
                return _unit_stagger_ok(toks[2])
            raise Denied(f'unit: inline shell is not allowed in {rel}')
        if len(toks) >= 2 and not toks[1].startswith('-') and _unit_asset_ok(
                _unit_plain_path(toks[1], 'root script')):
            return
        raise Denied(f'unit: root shell must run an infra-TAK script: {" ".join(toks)[:80]}')
    if re.fullmatch(r'python3(\.[0-9]+)?', base) and os.path.dirname(p) in ('/usr/bin', '/bin'):
        i = 1
        while i < len(toks) and toks[i] in _UNIT_PY_FLAGS:
            i += 1
        if i < len(toks) and toks[i].startswith('/') and _unit_asset_ok(
                _unit_plain_path(toks[i], 'root script')):
            return
        raise Denied(f'unit: root python must run an infra-TAK script: {" ".join(toks)[:80]}')
    raise Denied(f'unit: root may run only infra-TAK scripts, not {binary[:80]}')


# ops #645 W2 (Security review): systemd runs `ExecStartPre=/a.sh ; /tmp/evil.sh` as
# TWO commands; a lone `;` word separates them, and each one has its own prefixes
# (`; +/tmp/x` runs the second as root even in a non-root unit). An escaped `\;` or
# a quoted `";"` is a literal argument instead; the console never writes either, so
# both are refused rather than guessed at.
# https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Command%20lines
_UNIT_LITERAL_SEMI_RE = re.compile(r'\\;|(["\'])\s*;\s*\1')


def _unit_exec_commands(value, key):
    """[(prefixes, argv)] for every command in an Exec*= value."""
    if _UNIT_LITERAL_SEMI_RE.search(value):
        raise Denied(f'unit: {key}= has an escaped or quoted ";"')
    words = _unit_split(value, key)
    parts, cur = [], []
    for w in words:
        if w == ';':
            parts.append(cur)
            cur = []
        else:
            cur.append(w)
    parts.append(cur)
    out = []
    for toks in parts:
        if not toks:
            raise Denied(f'unit: empty command in {key}=')
        pre, first = '', toks[0]
        while first and first[0] in '-@:+!|':
            pre, first = pre + first[0], first[1:]
        if '|' in pre:
            raise Denied(f'unit: {key}=| (shell) not allowed')
        if not first:
            raise Denied(f'unit: empty command in {key}=')
        toks = [first] + toks[1:]
        if '@' in pre:
            toks = [toks[0]] + toks[2:]
        out.append((pre, toks))
    return out


def _unit_env_ok(value, root_ctx):
    if not root_ctx:
        return
    for a in _unit_split(value, 'Environment'):
        if '=' not in a:
            raise Denied(f'unit: bad Environment item: {a[:40]}')
        k, v = a.split('=', 1)
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k):
            raise Denied(f'unit: bad Environment name: {k[:40]!r}')
        if _UNIT_ENV_DENY_RE.fullmatch(k):
            raise Denied(f'unit: Environment {k} not allowed for a root process')
        if k == 'PATH':
            for d in v.split(':'):
                if not (d in _UNIT_PATH_DIRS or (d.startswith('/usr/lib/jvm/')
                                                 and '..' not in d.split('/'))):
                    raise Denied(f'unit: PATH entry not allowed for a root process: {d}')
            continue
        for t in re.findall(r'/[^\s:;,]*', v):
            if _console_writable(t):
                raise Denied(f'unit: Environment {k} points at a console-writable path')


def _check_unit_write(path, content, mode):
    """ops #645 W2: content check for a write under /etc/systemd/system. systemd runs
    every unit there as root, so the console may write only the units it owns, in a
    shape where root runs only infra-TAK's own scripts and a non-root unit cannot be
    turned into root."""
    rel = path[len(UNIT_DIR) + 1:] if path.startswith(UNIT_DIR + '/') else ''
    if not rel or not _unit_name_ok(rel):
        raise Denied(f'unit: not a unit file infra-TAK writes: {path}')
    if mode not in ('w', 'wb'):
        raise Denied('unit: append is not allowed; write the whole file')
    if len(content) > 65536 or b'\x00' in content:
        raise Denied('unit: file too big or has NUL bytes')
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise Denied('unit: not UTF-8')
    dropin = '/' in rel
    ext = os.path.splitext(rel)[1]
    sections = _UNIT_SECTIONS.get(ext)
    if not sections:
        raise Denied(f'unit: type not allowed: {rel}')
    lines = _unit_lines(text)
    user = ''
    for sec, k, v in lines:
        # systemd decodes C escapes and %-specifiers in values; the checker does not.
        # The console writes neither (line-continuation backslashes are gone by now,
        # and its two inline shells use none), so refuse them all, in every key.
        if '\\' in v or '%' in v:
            raise Denied(f'unit: {k[:40]}= has a backslash escape or a % specifier')
        if sec not in sections:
            raise Denied(f'unit: section [{sec}] not allowed in {rel}')
        if k not in _UNIT_KEYS[sec]:
            raise Denied(f'unit: key {k}= not allowed in [{sec}]')
        if k == 'User':
            user = v
    base_unit = rel.split('/', 1)[0][:-2] if dropin else rel
    if dropin:
        # A drop-in can't see the base unit's User=: root, unless the base is one of
        # the units the broker keeps non-root.
        root_ctx = base_unit not in UNIT_MUST_BE_NONROOT
    else:
        root_ctx = user in ('', 'root', '0')
        if root_ctx and rel in UNIT_MUST_BE_NONROOT:
            raise Denied(f'unit: {rel} must keep a non-root User=')
        if not root_ctx and user not in UNIT_USERS:
            raise Denied(f'unit: User={user} not allowed')
    for sec, k, v in lines:
        if k == 'User' and dropin:
            raise Denied('unit: a drop-in may not set User=')
        elif k in ('Group', 'SupplementaryGroups'):
            if dropin and k == 'Group':
                raise Denied('unit: a drop-in may not set Group=')
            for g in v.split():
                if g not in UNIT_GROUPS:
                    raise Denied(f'unit: {k}={g} not allowed')
        elif k in _UNIT_EXEC_KEYS:
            if not v:
                if not dropin:
                    raise Denied(f'unit: empty {k}=')
                continue                    # `ExecStart=` reset in a drop-in
            for pre, toks in _unit_exec_commands(v, k):
                if root_ctx or '+' in pre or '!' in pre:
                    _unit_root_command_ok(toks, rel)
        elif k == 'Environment':
            _unit_env_ok(v, root_ctx)
        elif k == 'EnvironmentFile':
            f = v[1:] if v.startswith('-') else v
            if root_ctx and (not f.startswith('/') or _console_writable(
                    _unit_plain_path(f, 'root EnvironmentFile'))):
                raise Denied('unit: root EnvironmentFile must not be console-writable')
        elif k in ('StandardOutput', 'StandardError'):
            if v not in _UNIT_OUTPUTS:
                raise Denied(f'unit: {k}={v} not allowed (PID 1 opens files as root)')
        elif k == 'SELinuxContext':
            if v != _UNIT_SELINUX:
                raise Denied(f'unit: SELinuxContext={v} not allowed')
        elif k == 'Unit' and sec == 'Timer':
            if not _unit_name_ok(v):
                raise Denied(f'unit: timer Unit={v} is not an infra-TAK unit')
        elif k == 'Also':
            for n in v.split():
                if not _unit_name_ok(n):
                    raise Denied(f'unit: Also={n} is not an infra-TAK unit')
        elif k in ('WantedBy', 'RequiredBy'):
            for n in v.split():
                if not (n.endswith('.target') or _unit_name_ok(n)):
                    raise Denied(f'unit: {k}={n} not allowed')
        elif sec == 'Unit' and k in ('Requires', 'Wants', 'BindsTo', 'After', 'Before',
                                     'PartOf', 'Conflicts'):
            if 'debug-shell' in v:
                raise Denied('unit: debug-shell not allowed')


def _check_validated_write(req):
    """ops #645 W2: the `write` op into a validated destination whose parser is
    built. Others pass for now (PATH_CLASS_PENDING says which part brings them)."""
    p = _abs(req.get('path'))
    if _in_unit_dir(p):
        _check_unit_write(p, base64.b64decode(req.get('content_b64') or ''),
                          req.get('mode', 'w'))
    if _gd_path_locked(p):
        raise Denied(f'Guard Dog scripts are installed by root from its own copy of '
                     f'infra-TAK (gd_render), not written by the console: {p}')


# ---------------------------------------------------------------------------
# ops #645 W2 part 2a: Guard Dog scripts. Root runs every script in GD_DIR (units,
# timers, the boot sequencer), and the console used to write them: fill in the
# repo template, then `write` the result. Now root reads the template from the
# verified tree it runs from (W1, /usr/local/lib/infratak-broker/<commit>/
# scripts/guarddog/), checks each value the console sends, and writes the script.
# The console can choose the values, never the code.
# ---------------------------------------------------------------------------
GD_DIR = '/opt/tak-guarddog'
_GD_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,80}\.(sh|py)$')
_GD_PLACEHOLDER_RE = re.compile(r'\b[A-Z][A-Z0-9_]*_PLACEHOLDER\b')
# Scripts app.py still builds inline. They move into the repo in W2 part 2b; until
# then the console writes them, so GD_DIR is not a closed boundary yet.
_GD_INLINE_PENDING = frozenset({
    'sms_send.py', 'sms_send.sh', 'tak-authentik-tasklog-purge.sh', 'mediamtx-cert-sync.sh',
})
# Every placeholder sits inside double quotes in the templates (a test checks it),
# so no value may hold what is special there: $ ` " \ or a control character.
_GD_UNSAFE_RE = re.compile(r'[$`"\\\x00-\x1f\x7f]')
_GD_HOST = r'[A-Za-z0-9\[][A-Za-z0-9.:_\[\]-]{0,252}'   # never a leading '-' (an ssh option)
_GD_VALUE_RES = {
    'ALERT_EMAIL_PLACEHOLDER': re.compile(r'^[A-Za-z0-9._%+@,-]{0,1024}$'),
    'ALERT_SMS_PLACEHOLDER': re.compile(r'^[A-Za-z0-9._%+@,-]{0,1024}$'),
    'CERT_PASS_PLACEHOLDER': re.compile(r'^\S{0,256}$'),
    'CONSOLE_VERSION_PLACEHOLDER': re.compile(r'^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$'),
    'UPDATE_CHANNEL_PLACEHOLDER': re.compile(r'^[a-z0-9][a-z0-9._-]{0,31}$'),
    'AK_VETTED_PLACEHOLDER': re.compile(r'^([0-9A-Za-z][0-9A-Za-z.+_-]{0,63})?$'),
    'EXTERNAL_DB_PLACEHOLDER': re.compile(r'^(true)?$'),
    'DB_HOST_PLACEHOLDER': re.compile(rf'^({_GD_HOST})?$'),
    'FEDHUB_HOST_PLACEHOLDER': re.compile(rf'^({_GD_HOST})?$'),
    'DB_PORT_PLACEHOLDER': re.compile(r'^[0-9]{0,5}$'),
    'SSH_USER_PLACEHOLDER': re.compile(r'^([A-Za-z0-9_][A-Za-z0-9._-]{0,63})?$'),
    'SSH_KEY_PLACEHOLDER': re.compile(r'^(?!.*/\.\.(/|$))(/[A-Za-z0-9._@+-]+)*$'),
}


def _gd_norm(path):
    """`/opt/tak-guarddog/./x`, `//opt/...` and `.../sub/../x` all name the same file."""
    return '/' + os.path.normpath(str(path)).lstrip('/')


# State files the console itself writes in GD_DIR (app.py; a generated test keeps
# this equal to the code). Root scripts read them as data, never run them. Their
# content check is W2 part 3.
_GD_STATE_FILES = frozenset({
    'server_identifier', 'guarddog.conf', 'known_hosts', 'diskio_email_off',
    'authentik_tasklog_purge_last.txt', '.metrics_collector_applied',
})


def _gd_path_locked(path):
    """True for a path under GD_DIR the console may no longer create or change, once
    this broker runs from the root-owned tree (gd_render needs that tree): the whole
    tree, less the inline scripts pending 2b and the named state files at depth 1.
    (Security re-review #2: a subfolder was open, `mkdir /opt/tak-guarddog/sub` then
    `write .../sub/x.sh`, and the unit check took any path under the prefix.)"""
    path = _gd_norm(path)
    if not path.startswith(GD_DIR + '/') or not _installed_commit():
        return False
    rel = path[len(GD_DIR) + 1:]
    if '/' in rel:
        return True
    return rel not in _GD_INLINE_PENDING and rel not in _GD_STATE_FILES


def _unit_asset_ok(path):
    """A root command a unit may run: a Guard Dog script directly in GD_DIR, or one
    of the exact asset files. Not a prefix asset dir (debsig), not a GD subfolder."""
    if path.startswith(GD_DIR + '/'):
        return bool(_GD_NAME_RE.fullmatch(path[len(GD_DIR) + 1:]))
    return PATH_CLASS.get(path) == DEST_ASSET and not path.endswith('/')


def _gd_template_dir():
    c = _installed_commit()
    return os.path.join(ROOT_CODE_DIR, c, 'scripts', 'guarddog') if c else ''


def _gd_fill(template, values):
    """One pass: a value is never searched for further placeholders."""
    return _GD_PLACEHOLDER_RE.sub(lambda m: values.get(m.group(0), m.group(0)), template)


def _check_gd_render(req):
    if set(req) - {'op', 'name', 'values'}:
        raise Denied('gd_render takes only name and values')
    name, values = req.get('name'), req.get('values', {})
    if not isinstance(name, str) or not _GD_NAME_RE.fullmatch(name) or name in _GD_INLINE_PENDING:
        raise Denied(f'gd_render: not a Guard Dog script name: {str(name)[:80]}')
    if not isinstance(values, dict):
        raise Denied('gd_render: values must be an object')
    for k, v in values.items():
        rx = _GD_VALUE_RES.get(k)
        if rx is None:
            raise Denied(f'gd_render: unknown placeholder: {str(k)[:60]}')
        if not isinstance(v, str) or _GD_UNSAFE_RE.search(v) or not rx.fullmatch(v):
            raise Denied(f'gd_render: value for {k} not allowed')
    if not _gd_template_dir():
        raise Denied('gd_render: this broker does not run from its root-owned copy of '
                     'infra-TAK yet (see ping root_install)')


def _do_gd_render(req):
    """Render the template from the tree this broker runs from and install it
    root:root 0755. Returns changed (False when the bytes were already there)."""
    name, values = req['name'], req.get('values') or {}
    src = os.path.join(_gd_template_dir(), name)
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return {'ok': False, 'code': 'ENOENT', 'error': f'no Guard Dog template {name} in '
                                                         f'commit {_installed_commit()[:12]}'}
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return {'ok': False, 'code': 'DENIED', 'error': f'template {name} is not a file'}
        template = os.read(fd, MAX_MSG).decode('utf-8')
    finally:
        os.close(fd)
    data = _gd_fill(template, values).encode('utf-8')
    if os.path.islink(GD_DIR) or (os.path.lexists(GD_DIR) and not os.path.isdir(GD_DIR)):
        return {'ok': False, 'code': 'DENIED', 'error': f'{GD_DIR} is not a plain directory'}
    os.makedirs(GD_DIR, mode=0o755, exist_ok=True)
    # Everything below goes through one fd of the directory, so a swap of GD_DIR for
    # a link after the check above changes nothing (Security re-review #2).
    try:
        dfd = os.open(GD_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return {'ok': False, 'code': 'DENIED', 'error': f'{GD_DIR} is not a plain directory'}
    try:
        st = os.fstat(dfd)
        if st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022:
            os.fchown(dfd, 0, 0)
            os.fchmod(dfd, 0o755)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            try:
                dst = os.fstat(fd)
                same = (stat.S_ISREG(dst.st_mode) and dst.st_size == len(data)
                        and os.read(fd, len(data) + 1) == data)
                if same:
                    os.fchown(fd, 0, 0)
                    os.fchmod(fd, 0o755)
            finally:
                os.close(fd)
        except OSError:
            same = False
        if same:
            return {'ok': True, 'changed': False}
        tmp = f'.{name}.gd-{os.getpid()}-{threading.get_ident()}'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=dfd)
        try:
            os.write(fd, data)
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            os.unlink(tmp, dir_fd=dfd)
            raise
        os.close(fd)
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        return {'ok': True, 'changed': True}
    finally:
        os.close(dfd)


def _check_exec_into_root_run(base, paths, link_args=None):
    """ops #645 W2: the coreutils path into root-run destinations.
    - cp/mv/install/tee into /etc/systemd/system: refused (only `write`, which
      checks the unit text);
    - ln with any operand in a validated or asset destination: refused (a link
      makes a later write land in a unit or a root script);
    - chown of a validated/asset path to anyone but root, chmod that lets group or
      others write it: refused (the console user could then edit it directly)."""
    for p in paths:
        if base in ('cp', 'mv', 'install', 'tee') and _in_unit_dir(p):
            raise Denied(f'{base}: unit files go through the write op only: {p}')
        if base in ('cp', 'mv', 'install', 'tee', 'mkdir', 'touch') and _gd_path_locked(p):
            raise Denied(f'{base}: Guard Dog scripts are installed by root (gd_render): {p}')
        if (base == 'mkdir' and _gd_norm(p).startswith(GD_DIR + '/')
                and _installed_commit()):
            raise Denied(f'mkdir: no folders inside the Guard Dog folder: {p}')
        # `cp X /opt/tak-guarddog/` lands as /opt/tak-guarddog/<basename X>: a script
        # name the check above never sees. The console names the file it copies.
        if (base in ('cp', 'mv', 'install', 'tee') and _gd_norm(p) == GD_DIR
                and _installed_commit()):
            raise Denied(f'{base}: name the file, not the Guard Dog folder: {p}')
        if base == 'ln' and _root_runs(p):
            raise Denied(f'ln: no links into or out of root-run paths: {p}')
    if base == 'ln':
        for t in link_args or ():
            if not t.startswith('/') and '..' in t.split('/'):
                raise Denied(f'ln: relative link target with .. not allowed: {t}')


_COREUTIL_FLAGS = {
    'chmod': frozenset({'-R', '--recursive', '-v', '-c', '-f', '--verbose', '--changes',
                        '--silent', '--quiet'}),
    'chown': frozenset({'-R', '-h', '--recursive', '--no-dereference', '-v', '-c', '-f',
                        '--verbose', '--changes', '--silent', '--quiet'}),
    'mv': frozenset({'-f', '-n', '-v', '-T', '--force', '--no-clobber', '--verbose',
                     '--no-target-directory'}),
    'ln': frozenset({'-s', '-f', '-n', '-T', '-v', '-sf', '-fs', '-sn', '-ns', '-sfn', '-snf',
                     '-fsn', '-fns', '-nsf', '-nfs', '-sfT', '--symbolic', '--force',
                     '--no-dereference', '--no-target-directory'}),
    'tee': frozenset({'-a', '--append'}),
    'rm': frozenset({'-f', '-r', '-R', '-rf', '-fr', '-Rf', '-fR', '-v', '--force', '--recursive'}),
    'mkdir': frozenset({'-p', '-v', '--parents'}),
    'rmdir': frozenset({'-p', '--parents', '--ignore-fail-on-non-empty'}),
    'touch': frozenset({'-c', '-a', '-m', '--no-create'}),
    'cat': frozenset({'-A', '-n', '-v', '-e', '-E', '-t', '-T', '-s', '-b'}),
}
# cp short-flag letters allowed (no -t target dir, no -l/-s links, no -S suffix)
_CP_SHORT = set('aprRfPdnTv')
_CP_LONG = frozenset({'--archive', '--recursive', '--force', '--no-clobber', '--no-dereference',
                      '--verbose', '--no-target-directory'})


def _owner_is_root(spec):
    user, _, group = spec.partition(':') if ':' in spec else spec.partition('.')
    return user in ('root', '0') and group in ('', 'root', '0')


def _mode_lets_go_write(mode):
    m = (mode or '').strip()
    if re.fullmatch(r'[0-7]{1,5}', m):
        d = m[-3:].rjust(3, '0')
        return bool(int(d[1]) & 2 or int(d[2]) & 2)
    for clause in m.split(','):
        for op in ('+', '='):
            if op in clause:
                who, perms = clause.split(op, 1)
                if 'w' in perms and (not who or any(c in who for c in 'goa')):
                    return True
    return False


def _check_docker(argv):
    """docker is inherently root-equivalent (run -v /:/host, --privileged, the
    docker.sock). We can't make it least-privilege in one pass — that's flagged
    in PLAN-v10.0.5 as core follow-on work. This first cut blocks the most
    obvious host-escape forms on run/create and otherwise allows the read/manage
    subcommands the console actually uses."""
    if len(argv) < 2:
        raise Denied('docker: no subcommand')
    sub = argv[1]
    # Info-only global flags (`docker --version`/`-v`/`--help`) carry no
    # subcommand and cannot mutate state. Allow them. (We do NOT blanket-allow
    # all `-*` flags: `-H tcp://host` would retarget the daemon — only this
    # explicit read-only set.)
    if sub in ('--version', '-v', '--help', '-h'):
        return
    # ops #645 W0: `docker container run …` / `docker image save …` are the same
    # commands as `docker run …` / `docker save …`. Check them under their short
    # name, or the run/create/exec/cp checks below never see them.
    if sub in ('container', 'image'):
        argv = _docker_normalize_object(argv)
        sub = argv[1]
    allowed_sub = {
        'ps', 'inspect', 'logs', 'cp', 'exec', 'restart', 'start', 'stop',
        'rm', 'kill', 'network', 'compose', 'images', 'image', 'pull', 'version',
        'info', 'stats', 'system', 'volume', 'port', 'top', 'wait', 'update',
        'create', 'run', 'tag', 'load', 'save', 'container', 'builder', 'buildx',
        # `build` builds an image from a Dockerfile. Same inherent root residual
        # as `run`/`compose build` (already allowed) — Dockerfile RUN executes in
        # the build sandbox; it is not a NEW escalation vector over what compose
        # build already permits. The console uses it for module image builds.
        'build',
    }
    if sub not in allowed_sub:
        raise Denied(f'docker subcommand not allowed: {sub}')
    if sub in ('run', 'create'):
        _check_docker_container_flags(argv[2:], f'docker {sub}')
    elif sub == 'exec':
        _check_docker_exec_flags(argv[2:], 'docker exec')
    elif sub == 'cp':
        _check_docker_cp(argv)
    elif sub == 'volume':
        _check_docker_volume(argv)
    elif sub == 'compose':
        _check_docker_compose(argv)
    elif sub in ('save', 'build', 'buildx'):
        _check_docker_build_save(argv)


# ---------------------------------------------------------------------------
# ops #645 W0 — docker escapes. Each of these was a one-command root shell on a
# non-root box in ENFORCE mode (rulebook dry run on dev d67aa04):
#   docker container run --privileged -v /:/host …   (the `container` form)
#   docker run --cap-add SYS_ADMIN --device /dev/sda …
#   docker exec --privileged <c> sh
#   docker volume create --opt type=none --opt device=/etc --opt o=bind v
#   docker compose run -v /:/host <svc>
#   docker cp <c>:/x /etc/sudoers.d/x   (and docker cp /etc/shadow <c>:/x)
# ---------------------------------------------------------------------------

# `docker container <x>` / `docker image <x>` → the short command it is the same as.
_DOCKER_CONTAINER_SUBS = {
    'run': 'run', 'create': 'create', 'exec': 'exec', 'cp': 'cp', 'start': 'start',
    'stop': 'stop', 'restart': 'restart', 'rm': 'rm', 'kill': 'kill', 'logs': 'logs',
    'inspect': 'inspect', 'port': 'port', 'top': 'top', 'wait': 'wait', 'update': 'update',
    'stats': 'stats', 'ls': 'ps', 'list': 'ps', 'ps': 'ps', 'prune': 'system',
}
_DOCKER_IMAGE_SUBS = {
    'build': 'build', 'save': 'save', 'load': 'load', 'pull': 'pull', 'tag': 'tag',
    'inspect': 'images', 'ls': 'images', 'list': 'images', 'rm': 'images',
    'prune': 'images', 'history': 'images',
}


def _docker_normalize_object(argv):
    """['docker', 'container'|'image', X, …] → ['docker', <short X>, …]. Anything
    not in the two maps is refused (fail-closed)."""
    obj = argv[1]
    if len(argv) < 3:
        raise Denied(f'docker {obj}: no subcommand')
    table = _DOCKER_CONTAINER_SUBS if obj == 'container' else _DOCKER_IMAGE_SUBS
    x = argv[2]
    if x not in table:
        raise Denied(f'docker {obj} subcommand not allowed: {x}')
    return [argv[0], table[x]] + list(argv[3:])


def _flag_split(tok):
    """'--flag=value' → ('--flag', 'value'); '--flag' → ('--flag', None)."""
    if tok.startswith('--') and '=' in tok:
        k, v = tok.split('=', 1)
        return k, v
    return tok, None


# Value-taking flags of run/create/exec/compose run whose VALUE is checked below.
_DOCKER_NS_FLAGS = ('--pid', '--ipc', '--uts', '--userns', '--cgroupns', '--network', '--net')
_DOCKER_SECOPT_OK = {'no-new-privileges', 'no-new-privileges:true', 'no-new-privileges=true'}
# Flags that give a container host power or make root read/write a host file.
# Refused outright on run/create/compose run (no console call site uses them):
_DOCKER_DENY_FLAGS = {
    '--privileged': 'gives the container full host access',
    '--cap-add': 'adds kernel capabilities',
    '--device': 'passes a host device',
    '--device-cgroup-rule': 'opens host devices',
    '--volumes-from': 'reuses another container\'s mounts',
    '--runtime': 'picks a different container runtime',
    '--env-file': 'makes root read a host file',
    '--label-file': 'makes root read a host file',
    '--cidfile': 'makes root write a host file',
}
# Every flag `docker run|create` / `docker compose run` may carry. A flag NOT in
# one of these two sets is refused: a walker that guessed would read the value of an
# unknown value-flag as the image name and stop checking the flags after it
# (`docker run --gpus all --privileged …`).
_DOCKER_RUN_VALUE_FLAGS = frozenset((
    '-v', '--volume', '--mount', '-e', '--env', '-u', '--user', '-w', '--workdir',
    '--entrypoint', '--name', '-p', '--publish', '-l', '--label', '--network', '--net',
    '--pid', '--ipc', '--uts', '--userns', '--cgroupns', '--security-opt', '--cap-add',
    '--cap-drop', '--device', '--restart', '--log-driver', '--log-opt', '-m', '--memory',
    '--cpus', '--hostname', '-h', '--add-host', '--dns', '--tmpfs', '--platform',
    '--pull', '--stop-signal', '--stop-timeout', '--shm-size', '--ulimit', '--group-add',
    '--health-cmd', '--health-interval', '--health-retries', '--health-timeout',
    '--health-start-period', '--health-start-interval',
    '--network-alias', '--ip', '--ip6', '--mac-address', '--memory-swap',
    '--memory-reservation', '--memory-swappiness', '--kernel-memory',
    '--volumes-from', '--runtime', '--env-file', '--label-file', '--cidfile',
    '--detach-keys', '--device-cgroup-rule', '-a', '--attach', '--expose', '--link',
    '--sysctl', '--storage-opt', '--cpu-shares', '-c', '--cpuset-cpus', '--cpuset-mems',
    '--cpu-period', '--cpu-quota', '--cpu-rt-period', '--cpu-rt-runtime',
    '--blkio-weight', '--blkio-weight-device', '--device-read-bps', '--device-write-bps',
    '--device-read-iops', '--device-write-iops', '--pids-limit', '--oom-score-adj',
    '--gpus', '--isolation', '--domainname', '--dns-search', '--dns-option',
    '--link-local-ip', '--annotation', '--cgroup-parent', '--init-path', '--index',
))
_DOCKER_RUN_BOOL_FLAGS = frozenset((
    '--rm', '-d', '--detach', '-i', '--interactive', '-t', '--tty', '--init',
    '--read-only', '--no-healthcheck', '--oom-kill-disable', '-P', '--publish-all',
    '-q', '--quiet', '--sig-proxy', '--disable-content-trust', '--privileged',
    '--use-api-socket',
    # docker compose run
    '--no-deps', '--service-ports', '--use-aliases', '--build', '--quiet-pull',
    '--remove-orphans', '-T', '--no-TTY',
))
_DOCKER_EXEC_VALUE_FLAGS = frozenset((
    '-e', '--env', '--env-file', '-u', '--user', '-w', '--workdir', '--detach-keys',
    '--index'))
_DOCKER_EXEC_BOOL_FLAGS = frozenset((
    '-d', '--detach', '-i', '--interactive', '-t', '--tty', '--privileged', '-T',
    '--no-TTY'))


_DOCKER_SHORT_VALUE = set('veuwplhmca')
_DOCKER_SHORT_BOOL = set('ditPqT')


def _docker_walk_flags(args, value_flags, bool_flags, what):
    """Yield (flag, value) for every flag before the first positional (image,
    service or container name). value is None for a boolean flag without `=`.
    Unknown flags are refused (fail-closed). Handles `--f=v`, `--f v`, `-v x`,
    `-v/x` (attached) and bundled booleans `-it`; a bundle that holds a value flag
    (`-dv /:/host`) is refused."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == '--' or not tok.startswith('-') or tok == '-':
            return
        k, v = _flag_split(tok)
        if not tok.startswith('--') and len(tok) > 2:
            if '-' + tok[1] in value_flags and tok[1] in _DOCKER_SHORT_VALUE:
                k, v = '-' + tok[1], tok[2:].lstrip('=')
            elif all('-' + c in bool_flags for c in tok[1:]):
                for c in tok[1:]:
                    yield '-' + c, None
                i += 1
                continue
            else:
                raise Denied(f'{what}: short flags not allowed in this form: {tok}')
        if k in value_flags:
            if v is None:
                if i + 1 >= len(args):
                    raise Denied(f'{what} {k}: missing value')
                v = args[i + 1]
                i += 1
        elif k not in bool_flags:
            raise Denied(f'{what}: flag not allowed: {k}')
        yield k, v
        i += 1


def _check_docker_container_flags(args, what, compose=False):
    """Flag checks for `docker run|create` and `docker compose run`. Only the
    words BEFORE the image/service name are flags; the rest is the container's
    own command and is not looked at (a container command is not host power)."""
    if any('/var/run/docker.sock' in a or '/run/docker.sock' in a for a in args):
        raise Denied(f'{what} mounting the docker socket denied')
    for k, v in _docker_walk_flags(args, _DOCKER_RUN_VALUE_FLAGS, _DOCKER_RUN_BOOL_FLAGS, what):
        if k == '--use-api-socket':
            raise Denied(f'{what} --use-api-socket denied: mounts the docker socket')
        if k in _DOCKER_DENY_FLAGS:
            if not (k == '--privileged' and v is not None and v.lower() == 'false'):
                raise Denied(f'{what} {k} denied: {_DOCKER_DENY_FLAGS[k]}')
        if k in _DOCKER_NS_FLAGS and (v or '').strip().lower() == 'host':
            raise Denied(f'{what} {k}=host denied: shares a host namespace')
        if k == '--security-opt' and (v or '').strip() not in _DOCKER_SECOPT_OK:
            raise Denied(f'{what} --security-opt {v!r} denied (only no-new-privileges)')
        if k in ('-v', '--volume'):
            _check_docker_mount(v or '', compose=compose)
        if k == '--mount':
            _check_docker_mount(v or '', mount_flag=True, compose=compose)


def _check_docker_exec_flags(args, what):
    """`docker exec` / `docker compose exec`: refuse --privileged (full host caps
    for the exec'd process) and the host-file flags. -u 0 stays allowed: root
    INSIDE an unprivileged container is not host root."""
    for k, v in _docker_walk_flags(args, _DOCKER_EXEC_VALUE_FLAGS, _DOCKER_EXEC_BOOL_FLAGS, what):
        if k == '--privileged' and not (v is not None and v.lower() == 'false'):
            raise Denied(f'{what} --privileged denied: gives the process full host access')
        if k == '--env-file':
            raise Denied(f'{what} {k} denied: makes root read a host file')


def _check_docker_volume(argv):
    """`docker volume create` with driver options can bind any host dir (/etc)
    into a named volume, which then passes the bind-mount check as a NAME.
    Allow only a plain `docker volume create <name>`."""
    if len(argv) < 3 or argv[2] != 'create':
        return
    rest = argv[3:]
    for tok in rest:
        if tok.startswith('-'):
            raise Denied(f'docker volume create option denied: {tok} '
                         '(driver options can bind host paths)')
    if len(rest) > 1:
        raise Denied('docker volume create: one name only')


def _check_docker_build_save(argv):
    """`docker save -o PATH` and `docker build -o PATH` write a host file as root;
    `buildx --allow security.insecure` runs privileged build steps. Path-check the
    output and refuse the insecure entitlement."""
    for i, tok in enumerate(argv[2:], start=2):
        k, v = _flag_split(tok)
        if k in ('-o', '--output'):
            if v is None:
                v = argv[i + 1] if i + 1 < len(argv) else ''
            dest = v
            if argv[1] in ('build', 'buildx') and ('dest=' in v or 'type=' in v):
                dest = ''
                for part in v.split(','):
                    if part.startswith('dest='):
                        dest = part.split('=', 1)[1]
                if not dest:
                    continue            # type=image / type=registry: no host file
            if dest == '-':
                continue
            _path_allowed(dest)
        if k == '--allow' or (k.startswith('--allow') and 'insecure' in tok):
            raise Denied(f'docker {argv[1]} --allow denied (privileged build steps)')
        if argv[1] == 'buildx' and k in ('--driver-opt', '--buildkitd-flags'):
            raise Denied(f'docker buildx {k} denied')


def _docker_compose_split(argv):
    """['docker','compose', <compose flags…>, SUB, <sub args…>] → (SUB, sub args)."""
    i = 2
    while i < len(argv):
        a = argv[i]
        if a.startswith('-'):
            k, v = _flag_split(a)
            if k in _DOCKER_VALUE_FLAGS and v is None:
                i += 1
            i += 1
            continue
        return a, argv[i + 1:]
    return None, []


def _check_docker_compose(argv):
    """`docker compose run` takes the same host-power flags as `docker run`
    (-v /:/host, --cap-add …), and `compose exec` takes --privileged. W0 checks
    those flags. The compose FILE itself is not validated yet (W3)."""
    sub, rest = _docker_compose_split(argv)
    if sub == 'run':
        _check_docker_container_flags(rest, 'docker compose run', compose=True)
    elif sub == 'exec':
        _check_docker_exec_flags(rest, 'docker compose exec')
    elif sub == 'cp':
        raise Denied('docker compose cp denied (use docker cp, which is path-checked)')


# docker cp: only these flags. -L/--follow-link makes the CLI follow a symlink in
# the source path, which turns a console-planted link into a read of any file.
_DOCKER_CP_FLAGS = {'-a', '--archive', '-q', '--quiet'}


def _docker_cp_is_container(arg):
    """docker's own rule: a path that starts with / or . is local; otherwise
    NAME:PATH (NAME without a slash) is a container path."""
    if arg == '-' or arg.startswith(('/', '.')):
        return False
    head, sep, _ = arg.partition(':')
    return bool(sep) and bool(head) and '/' not in head


def _docker_cp_parts(argv):
    """-> (src, dst, src_is_container) or raise Denied."""
    pos = []
    for tok in argv[2:]:
        if tok.startswith('-') and tok != '-':
            if tok not in _DOCKER_CP_FLAGS:
                raise Denied(f'docker cp option denied: {tok}')
            continue
        pos.append(tok)
    if len(pos) != 2:
        raise Denied('docker cp needs exactly SRC and DEST')
    src, dst = pos
    sc, dc = _docker_cp_is_container(src), _docker_cp_is_container(dst)
    if sc == dc:
        raise Denied('docker cp: exactly one side must be a container path')
    return src, dst, sc


def _docker_cp_host_direct(path, readonly):
    """True when ROOT may touch this host path itself: '-' (stdin/stdout) or a path
    the read/write allowlist admits. Any other host path is still allowed, but the
    host side then runs as the console user (see _docker_cp_staged), so it can
    reach only what that user can reach anyway."""
    if path == '-':
        return True
    try:
        _path_allowed(path, readonly=readonly)
        return True
    except Denied:
        return False


def _check_docker_cp(argv):
    """`docker cp` runs as root, so its HOST side was a read or write of any file
    (`docker cp c:/x /etc/sudoers.d/x` = root). The host path must be absolute or
    '-'. Allowlisted paths run as before; anything else is staged through the
    console user by _do_exec (no root access to that path at all)."""
    src, dst, src_is_container = _docker_cp_parts(argv)
    host = dst if src_is_container else src
    if host != '-':
        p = _abs(host)                  # absolute, no NUL, no '..'
        # The deny-list is never a docker cp target or source, staged or not.
        if p in PATH_DENY_EXACT or any(p.startswith(d) for d in PATH_DENY_PREFIX):
            raise Denied(f'docker cp host path is in the deny-list: {p}')


def _docker_cp_staged(argv, timeout):
    """Run a `docker cp` whose host path is NOT on the allowlist, without root ever
    opening that path. Root copies between the container and a fresh root-owned
    staging dir; the console user (setuid child, its own permissions) copies between
    the staging dir and the host path. Returns a subprocess.CompletedProcess.

    host -> container: user `cp -rP SRC STAGE/` ; root re-owns STAGE ;
                       root `docker cp STAGE/<name> C:PATH`
    container -> host: root `docker cp C:PATH STAGE/` ; STAGE handed to the user ;
                       user `cp -rP STAGE/<name> DEST`"""
    src, dst, src_is_container = _docker_cp_parts(argv)
    flags = [t for t in argv[2:] if t in _DOCKER_CP_FLAGS]
    pw = pwd.getpwnam(BROKER_USER)
    os.makedirs(_CP_STAGE_ROOT, mode=0o711, exist_ok=True)
    if os.path.islink(_CP_STAGE_ROOT) or not os.path.isdir(_CP_STAGE_ROOT):
        raise Denied('docker cp staging dir is not a plain directory')
    os.chown(_CP_STAGE_ROOT, 0, 0)
    os.chmod(_CP_STAGE_ROOT, 0o711)
    stage = tempfile.mkdtemp(prefix='cp-', dir=_CP_STAGE_ROOT)   # root 0700
    user_env = {'PATH': BROKER_TRUSTED_PATH, 'LC_ALL': 'C', 'HOME': '/'}

    def _as_user(cmd):
        return subprocess.run(cmd, capture_output=True, timeout=timeout, cwd='/',
                              env=user_env, user=pw.pw_uid, group=pw.pw_gid,
                              extra_groups=[])

    def _own_tree(top, uid, gid):
        for d, dirs, files in os.walk(top, followlinks=False):
            for n in dirs + files:
                os.lchown(os.path.join(d, n), uid, gid)
        os.lchown(top, uid, gid)

    docker = shutil.which('docker', path=BROKER_TRUSTED_PATH) or 'docker'
    try:
        if src_is_container:
            cpath = src.split(':', 1)[1]
            dot = cpath.endswith('/.')
            name = 'content' if dot else (os.path.basename(cpath.rstrip('/')) or 'content')
            if dot:
                os.mkdir(os.path.join(stage, 'content'), 0o700)
            r = subprocess.run([docker, 'cp'] + flags + [src, stage + '/'],
                               capture_output=True, timeout=timeout)
            if r.returncode != 0:
                return r
            _own_tree(stage, pw.pw_uid, pw.pw_gid)
            staged = os.path.join(stage, name) + ('/.' if dot else '')
            return _as_user(['cp', '-rP', '--', staged, dst])
        # host -> container
        os.chown(stage, pw.pw_uid, pw.pw_gid)
        norm = src.rstrip('/')
        dot = norm.endswith('/.')
        base = os.path.basename(norm[:-2] if dot else norm) or 'content'
        r = _as_user(['cp', '-rP', '--no-preserve=ownership', '--',
                      norm[:-2] if dot else norm, os.path.join(stage, base)])
        if r.returncode != 0:
            return r
        _own_tree(stage, 0, 0)
        os.chmod(stage, 0o700)
        staged = os.path.join(stage, base) + ('/.' if dot else '')
        if src.endswith('/') and not dot:
            staged += '/'
        return subprocess.run([docker, 'cp'] + flags + [staged, dst],
                              capture_output=True, timeout=timeout)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


# tmpfs, root 0711: the console user can enter its own staging dir but not list others.
_CP_STAGE_ROOT = '/run/takwerx-broker-cp'


def _docker_cp_needs_stage(argv):
    """True for a docker cp whose host side is not on the allowlist."""
    if not argv or os.path.basename(argv[0]) != 'docker' or len(argv) < 2:
        return False
    a = list(argv)
    if a[1] == 'container' and len(a) > 2 and a[2] == 'cp':
        a = [a[0], 'cp'] + a[3:]
    if a[1] != 'cp':
        return False
    try:
        src, dst, src_is_container = _docker_cp_parts(a)
    except Denied:
        return False
    if src_is_container:
        return not _docker_cp_host_direct(dst, readonly=False)
    return not _docker_cp_host_direct(src, readonly=True)


# Bind sources `docker compose run` may use beyond the generic check: the console
# user's own home and /tmp (CloudTAK's build step mounts both — audit logs on test6
# and test12). A root container with a rw bind of a console-writable dir is still
# near-root (setuid drop); W3 replaces this with a validated compose model.
_COMPOSE_RUN_BIND_OK = (_CONV_HOME, '/tmp')


def _check_docker_mount(spec, mount_flag=False, compose=False):
    """Reject bind mounts of sensitive host paths in a -v/--mount spec."""
    src = ''
    if mount_flag or spec.startswith('type='):  # --mount form: key=value,…
        kind = 'volume'
        for part in spec.split(','):
            k, _, v = part.partition('=')
            k = k.strip()
            if k in ('source', 'src'):
                src = v
            elif k == 'type':
                kind = v
            elif k.startswith('volume-opt') or k == 'volume-driver':
                # ops #645 W0: an inline volume with driver options can bind any
                # host path (o=bind,device=/etc) under a volume NAME.
                raise Denied(f'docker --mount {k} denied (can bind host paths)')
        if kind == 'bind' and not src.startswith('/'):
            raise Denied(f'docker --mount bind source must be absolute: {src!r}')
    else:                          # -v form: SRC:DST[:opts]
        if ':' not in spec:
            return                 # `-v /data`: an anonymous volume at a container path
        src = spec.split(':', 1)[0]
    if src.startswith(('.', '~')) or ('/' in src and not src.startswith('/')):
        # relative host path: resolved against a cwd the caller chooses
        raise Denied(f'docker bind mount with a relative host path denied: {src}')
    if not src.startswith('/'):
        return                     # named volume, not a host bind
    real = os.path.normpath(src)
    if compose:
        for ok in _COMPOSE_RUN_BIND_OK:
            if real == ok or real.startswith(ok + '/'):
                if _within_realpath(src, ok):
                    return
                raise Denied(f'docker compose run bind escapes {ok} via symlink: {src}')
    # The console's own TAK bundle dir is the LEGIT /opt/tak source mount — it is
    # under takwerx's HOME (not a root /opt path) only because the non-root
    # console unzips it there. Allow this one subtree before the /home denial, but
    # require realpath containment: the dir is console-WRITABLE, so a lexical match
    # alone would let a planted symlink (bundle/x -> /etc) root-mount any host path
    # into a root-running container. realpath follows the symlink and re-checks.
    if real == TAK_BUNDLE_DIR or real.startswith(TAK_BUNDLE_DIR + '/'):
        if _within_realpath(src, TAK_BUNDLE_DIR):
            return
        raise Denied(f'docker bind mount escapes bundle dir via symlink: {src}')
    bad = ('/', '/etc', '/root', '/home', '/boot', '/usr', '/bin', '/sbin',
           '/lib', '/lib64', '/var/run', '/run', '/proc', '/sys', '/dev')
    # Deny an exact match OR any CHILD of a sensitive root. The prefix loop MUST
    # cover the same set as `bad`: a prior version only looped a narrow subset
    # (/etc,/root,/home,/boot,/proc,/sys), so a SUBDIR of /usr,/bin,/sbin,/lib,
    # /var/run,/run,/dev — e.g. `-v /usr/local/bin:/x:rw` — was neither an exact
    # match nor caught by the prefix loop, and slipped the deny (a root-running
    # container could then drop a root-owned binary onto the host PATH). '/' is
    # excluded from the prefix loop (every abs path starts with it); the root
    # mount is caught by the exact-match branch.
    if real in bad or any(real.startswith(b + '/') for b in bad if b != '/'):
        raise Denied(f'docker bind mount of sensitive host path denied: {src}')


def check_exec(argv, cwd=None):
    """Validate an exec request against the rulebook. Returns the argv to run or
    raises Denied. argv must be a non-empty list of strings. `cwd` is the
    request's working directory — path-checked coreutils resolve their path
    args against it so a relative arg + cwd=/etc cannot escape the allowlist."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise Denied('argv must be a non-empty list of strings')
    base = os.path.basename(argv[0])
    # `runuser` is a privilege pivot (in EXEC_DENY) — but TAK Server generates its
    # certs as the unprivileged `tak` service user (the scripts are tak-owned, mode
    # 0500; the non-root console has no su/sudo). Carve a TIGHT exception BEFORE the
    # deny check: only `runuser -u tak -- <TAK cert script | keytool>`.
    if base == 'runuser':
        _check_runuser(argv)
        return argv
    # `bash` is denied (arbitrary shell) — but TAK ships ONE fixed root setup
    # script, apply-selinux.sh (compiles + `semodule -i` of TAK's own policy). It
    # uses sudo internally so it must run as root. Allow ONLY that exact script.
    if base == 'bash':
        _check_bash(argv)
        return argv
    if base in EXEC_DENY:
        raise Denied(f'binary is denied: {base}')
    if base not in EXEC_ALLOW:
        raise Denied(f'binary not in allow-list: {base}')
    if base == 'systemctl':
        _check_systemctl(argv)
    elif base == 'systemd-run':
        _check_systemd_run(argv)
    elif base == 'docker':
        _check_docker(argv)
    elif base in ('apt', 'apt-get', 'dnf', 'yum'):
        _check_pkgmgr(argv)
    elif base == 'semanage':
        _check_semanage(argv)
    elif base == 'semodule':
        _check_semodule(argv)
    elif base == 'chcon':
        _check_chcon(argv, cwd)
    elif base == 'gpg':
        _check_gpg(argv)
    elif base == 'git':
        _check_git(argv)
    elif base == 'find':
        _check_find(argv)
    elif base == 'install':
        _check_install(argv)
    elif base == 'cp':
        _check_cp(argv, cwd)
    elif base == 'sysctl':
        _check_sysctl(argv)
    elif base == 'iw':
        _check_iw(argv)
    elif base == 'netplan':
        _check_netplan(argv)
    elif base == 'nmcli':
        _check_nmcli(argv)
    elif base == 'wg':
        _check_wg(argv)
    elif base == 'pg_lsclusters':
        _check_pg_lsclusters(argv)
    elif base == 'wpa_cli':
        _check_wpa_cli(argv)
    elif base == 'chown':
        _check_chown(argv, cwd)
    elif base == 'ip':
        _check_ip(argv)
    elif base == 'dpkg':
        _check_dpkg(argv)
    elif base == 'fail2ban-client':
        _check_fail2ban_client(argv)
    elif base == 'postconf':
        _check_postconf(argv)
    elif base in PATH_CHECKED_BINS:
        _check_path_args(base, argv, cwd)
    return argv


def _check_chown(argv, cwd=None):
    """chown: path-checked like the other coreutils — plus ONE exact carve-out
    for the v10.1.4 repo-ownership self-heal. Root-shell git operations leave
    root-owned entries inside the takwerx-owned console repo; git-as-takwerx
    then cannot unlink files under them and Update Now half-applies: HEAD moves
    while the blocked files keep OLD content, and the box silently runs mixed
    versions (test8 2026-07-18: broker + flows.json stayed 10.1.3 under a
    10.1.4 HEAD). The console repairs that with exactly:

        chown -R -h takwerx:takwerx <CONSOLE_REPO_DIR>

    Safety: the target must equal the broker's OWN repo root (from SELF_PATH,
    never client input, rejected if the root itself is a symlink), the owner is
    pinned to BROKER_USER, and -h is REQUIRED so symlinks are re-owned, never
    followed (the repo is console-writable — a followed link could re-own an
    arbitrary root path). This grants nothing beyond re-asserting the design
    invariant "the console owns its repo". Every other chown shape falls
    through to the standard path allowlist."""
    if (len(argv) == 5
            and argv[1] == '-R' and argv[2] == '-h'
            and argv[3] == f'{BROKER_USER}:{BROKER_USER}'
            and os.path.normpath(argv[4]) == CONSOLE_REPO_DIR
            and not os.path.islink(CONSOLE_REPO_DIR)):
        return
    _check_path_args('chown', argv, cwd)


_IFACE_RE = re.compile(r'^[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,14}$')  # no leading '-' (option smuggling)


def _check_iw(argv):
    """iw: read-only wireless inspection ONLY — `iw dev` (list interfaces),
    `iw dev <iface> scan` (active scan) and `iw dev <iface> scan dump` (cached
    results, no radio activity). Every state-changing shape (set txpower,
    interface add/del, connect, reg set, …) is denied. v10.1.0 Leg 6."""
    rest = argv[1:]
    if rest == ['dev']:
        return
    if len(rest) == 3 and rest[0] == 'dev' and rest[2] == 'scan' and _IFACE_RE.fullmatch(rest[1]):
        return
    if len(rest) == 4 and rest[0] == 'dev' and rest[2] == 'scan' and rest[3] == 'dump' and _IFACE_RE.fullmatch(rest[1]):
        return
    raise Denied('iw: only `iw dev` and `iw dev <iface> scan [dump]` allowed')


def _check_wpa_cli(argv):
    """wpa_cli: only the shapes the "use this saved network now" flow issues:
      wpa_cli -i <iface> list_networks           (read)
      wpa_cli -i <iface> select_network <id>     (id = digits only)
      wpa_cli -i <iface> enable_network all|<id>
    Everything else — set_network (could set a psk/identity), add/remove_network,
    save_config, p2p, wps, raw `set` — is denied. iface matches the strict regex;
    the network id is numeric; `enable_network` takes `all` or a numeric id."""
    r = argv[1:]
    if len(r) >= 3 and r[0] == '-i' and _IFACE_RE.fullmatch(r[1]):
        verb = r[2]
        rest = r[3:]
        if verb == 'list_networks' and not rest:
            return
        if verb == 'select_network' and len(rest) == 1 and rest[0].isdigit():
            return
        if verb == 'enable_network' and len(rest) == 1 and (rest[0] == 'all' or rest[0].isdigit()):
            return
    raise Denied('wpa_cli: only list_networks / select_network <id> / enable_network are allowed')


def _check_wg(argv):
    """wg: read-only `wg show …` ONLY. Every mutating subcommand (set, setconf,
    addconf, syncconf, genkey, genpsk, pubkey) is denied — the console reads tunnel
    status/handshake age; it never reconfigures WireGuard (that's the anchor
    bootstrap's job, run as root)."""
    if len(argv) >= 2 and argv[1] == 'show':
        return
    raise Denied('wg: only `wg show` is allowed')


def _check_pg_lsclusters(argv):
    """pg_lsclusters: exactly `pg_lsclusters --no-header` (v10.2.8 W5b). Read-only, but
    gated to the one shape the console issues — `-s` / `--json` / anything else is
    denied rather than reasoned about."""
    if list(argv[1:]) == ['--no-header']:
        return
    raise Denied('pg_lsclusters: only `pg_lsclusters --no-header` is allowed')


def _check_netplan(argv):
    """netplan: `generate` (validate) and `apply` only, with NO further args —
    the console's WiFi add validates-before-apply with a backup/restore. The
    YAML content itself arrives via the path-checked install/cp under
    /etc/netplan/, so this cannot apply a file the path rules didn't admit.
    `netplan set`/`try --state`/anything else is denied."""
    if len(argv) == 2 and argv[1] in ('generate', 'apply'):
        return
    raise Denied('netplan: only `netplan generate` / `netplan apply` allowed')


def _check_nmcli(argv):
    """nmcli: exactly the WiFi-card shapes (NetworkManager boxes):
      nmcli dev wifi rescan
      nmcli -t -f SSID,SIGNAL dev wifi list
      nmcli -t -f NAME,TYPE connection show
      nmcli connection add type wifi con-name <ssid> ifname <iface|*> ssid <ssid>
            connection.autoconnect yes [wifi-sec.key-mgmt wpa-psk wifi-sec.psk <psk>]
      nmcli connection modify <ssid> wifi-sec.psk <psk>
    `connection add` creates a PROFILE and activates nothing — deliberately NOT
    `dev wifi connect`, which switches the live network (can drop the console's
    own uplink) and fails for out-of-range SSIDs (breaks pre-provision). Free
    args (ssid/iface/psk) must not start with '-' — no option injection. Every
    other nmcli verb (con up/down/delete, radio, device set, …) is denied."""
    rest = argv[1:]
    if rest == ['dev', 'wifi', 'rescan']:
        return
    if rest in (['-t', '-f', 'SSID,SIGNAL', 'dev', 'wifi', 'list'],
                ['-t', '-f', 'NAME,TYPE', 'connection', 'show']):
        return

    def _free(a):
        return bool(a) and not a.startswith('-')
    # v10.1.28: the console ALSO pins `ipv4.may-fail no` on the profile (added
    # 10.1.2 / 6a89690 — without it an IPv6-only associate that never gets a v4
    # lease reports success). The broker was never taught that shape, so the argv
    # became 14/18 long against a 12/16 allowlist and EVERY "Add Network" has been
    # denied on a non-root NetworkManager box since. Shipped that way since v10.1.2;
    # caught by T&E on nuc 2026-08-09 — the only born-non-root box, which is the
    # entire reason that box is a required part of the quorum.
    #
    # Parsed positionally rather than by length so the two optional tails can
    # appear independently, and so the next knob does not silently re-break it.
    # Everything matched here is a fixed literal except ssid/iface/psk, each of
    # which still goes through _free() — no option injection.
    if (len(rest) >= 12
            and rest[0:5] == ['connection', 'add', 'type', 'wifi', 'con-name']
            and _free(rest[5]) and rest[6] == 'ifname'
            and (rest[7] == '*' or _IFACE_RE.fullmatch(rest[7]))
            and rest[8] == 'ssid' and _free(rest[9])
            and rest[10:12] == ['connection.autoconnect', 'yes']):
        tail = rest[12:]
        if tail[0:2] == ['ipv4.may-fail', 'no']:      # optional, fixed literals
            tail = tail[2:]
        if not tail:                                   # open network
            return
        if (len(tail) == 4
                and tail[0:3] == ['wifi-sec.key-mgmt', 'wpa-psk', 'wifi-sec.psk']
                and _free(tail[3])):                   # WPA-PSK network
            return
    if (len(rest) == 5 and rest[0:2] == ['connection', 'modify']
            and _free(rest[2]) and rest[3] == 'wifi-sec.psk' and _free(rest[4])):
        return
    # v10.1.0 Leg 6c: forget a saved network.  nmcli connection delete <name>
    if len(rest) == 3 and rest[0:2] == ['connection', 'delete'] and _free(rest[2]):
        return
    # v10.1.0 Leg 6c: switch to a saved network.  nmcli connection up <name>
    if len(rest) == 3 and rest[0:2] == ['connection', 'up'] and _free(rest[2]):
        return
    raise Denied('nmcli: only the WiFi scan/list/profile-add/delete/up shapes are allowed')


def _check_pkgmgr(argv):
    """apt/dnf/yum: allow only the package subcommands the console uses, and
    block the `-o`/`--setopt` hook-command vector (e.g.
    `apt-get -o APT::Update::Pre-Invoke::=cmd`). Installing a package still runs
    its root post-install script — that residual is inherent to package mgmt."""
    # The ONLY --setopt permitted: clean_requirements_on_remove (a benign bool
    # controlling dependency cleanup on `dnf remove takserver`; cannot run code).
    # Every other -o/--setopt — especially the Pre-Invoke/hook vectors — is denied.
    SAFE_SETOPT = 'clean_requirements_on_remove'
    # Ops #152: the read-only OS-updates check (`dnf -C check-update`) skips a
    # repo it cannot read instead of failing whole. Allowed ONLY as this exact
    # literal — a boolean that cannot name a file, URL or command.
    SAFE_SETOPT_EXACT = {'skip_if_unavailable=True'}
    sub = None
    for a in argv[1:]:
        # -o KEY=VAL / --option / --setopt run arbitrary config incl. exec hooks
        if a.startswith('--setopt='):
            if a.split('=', 1)[1] in SAFE_SETOPT_EXACT:
                continue
            key = a.split('=', 1)[1].split('=', 1)[0].strip()
            if key != SAFE_SETOPT:
                raise Denied(f'{argv[0]}: --setopt {key} not allowed')
            continue
        if a in ('-o', '--option', '--setopt') or a.startswith(('-o', '--option=')):
            raise Denied(f'{argv[0]}: -o/--setopt option not allowed')
        if '::' in a and a.startswith('-'):
            raise Denied(f'{argv[0]}: config-override option not allowed: {a}')
        if sub is None and not a.startswith('-'):
            sub = a
    if sub is None:
        raise Denied(f'{argv[0]}: no subcommand')
    if sub not in PKGMGR_SUBCMDS:
        raise Denied(f'{argv[0]} subcommand not allowed: {sub}')
    # ops #645 W0 part 2: options. `dnf --config=X` / `--installroot` /
    # `--repofrompath` / `--nogpgcheck`, `apt-get --allow-unauthenticated` and
    # friends point the package manager at config, plugins or packages of the
    # caller's choosing (root code). Only the options the console uses pass.
    base = os.path.basename(argv[0])
    for a in argv[1:]:
        if not a.startswith('-') or a.startswith('--setopt='):
            continue
        if a in _PKGMGR_FLAGS:
            continue
        if a.startswith(_PKGMGR_VALUE_FLAGS):
            v = a.split('=', 1)[1]
            if not v or not _PKGMGR_VALUE_RE.fullmatch(v):
                raise Denied(f'{argv[0]}: option value not allowed: {a}')
            continue
        if (base in ('apt', 'apt-get') and len(a) > 2 and a[0] == '-' and a[1] != '-'
                and set(a[1:]) <= _APT_SHORT_BUNDLE):
            continue                     # -qq, -qy, -yq
        raise Denied(f'{argv[0]}: option not allowed: {a}')
    pos = [a for a in argv[1:] if not a.startswith('-')]
    if sub == 'config-manager' and '--add-repo' in argv:
        for a in pos[1:]:
            if not a.startswith(_PKG_REPO_URL_PREFIXES) or '..' in a:
                raise Denied(f'{argv[0]} config-manager --add-repo: repo URL not on the allow-list: {a}')
    if sub == 'copr' and pos[1:] != ['enable', '@caddy/caddy']:
        raise Denied(f'{argv[0]} copr: only `enable @caddy/caddy` is allowed')
    # ops #645 W0: `apt-get install ./x.deb` / `dnf install /home/…/x.rpm` /
    # `dnf install https://anywhere/x.rpm` install a package of the CALLER's
    # choosing, and its scripts run as root. Package NAMES resolve through the
    # configured, signed repos; a URL must be one of the fixed repo-RPM sources
    # the console uses. A LOCAL file must be a .deb (apt) or .rpm (dnf/yum) and
    # is checked as root at run time, in both modes (_pkg_stage_verified): a TAK
    # Server package signed with the pinned TAK release key, or the Caddy .deb
    # matching Caddy's published SHA-512. Anything else is refused there.
    if sub in _PKG_INSTALL_SUBS:
        for a in pos[1:]:
            if '://' in a:
                if not a.startswith(_PKG_URL_PREFIXES) or '..' in a or '@' in a.split('://', 1)[1].split('/', 1)[0]:
                    raise Denied(f'{argv[0]} {sub}: package URL not on the allow-list: {a}')
                continue
            if _pkg_arg_is_file(a):
                want = '.deb' if base in ('apt', 'apt-get') else '.rpm'
                if not a.endswith(want):
                    raise Denied(f'{argv[0]} {sub}: only a {want} package file can be installed from a path: {a}')
                if not _PKG_FILE_NAME_RE.fullmatch(os.path.basename(a)):
                    raise Denied(f'{argv[0]} {sub}: {_pkg_name_hint(os.path.basename(a))}')


# The only package URLs the console installs (repo-release RPMs, RHEL family).
_PKG_URL_PREFIXES = (
    'https://dl.fedoraproject.org/pub/epel/',
    'https://download.postgresql.org/pub/repos/yum/reporpms/',
    'https://download1.rpmfusion.org/free/el/',
)

# ops #645 W0 part 2 — package-manager options, repos and local package files.
_PKG_INSTALL_SUBS = ('install', 'reinstall', 'upgrade', 'localinstall')
# Options the console uses (static scan of app.py/modules + test6/test12 audit logs),
# plus harmless output/answer switches. Everything else is refused, above all
# -c/--config, --installroot, --repofrompath, --nogpgcheck, --allow-unauthenticated,
# --downloaddir/--destdir, --enableplugin, --forcearch.
_PKGMGR_FLAGS = frozenset({
    '-y', '--yes', '--assume-yes', '--assumeyes', '-q', '-qq', '--quiet',
    '--assumeno', '--assume-no', '-C', '--cacheonly', '-v', '--verbose',
    '-s', '--simulate', '--dry-run', '--just-print', '--refresh',
    '--allow-downgrades', '--reinstall', '--purge', '--auto-remove', '--autoremove',
    '--no-install-recommends', '--no-install-suggests', '-f', '--fix-broken',
    '-m', '--fix-missing', '--only-upgrade', '--no-remove', '--with-new-pkgs',
    '--upgradable', '--installed', '--all', '--available', '--enabled', '--disabled',
    '--security', '--nobest', '--best', '--allowerasing', '--skip-broken',
    '--set-enabled', '--set-disabled', '--add-repo', '--enable', '--disable',
})
_PKGMGR_VALUE_FLAGS = ('--exclude=', '--enablerepo=', '--disablerepo=')
_PKGMGR_VALUE_RE = re.compile(r'^[A-Za-z0-9_.+*?,:@-]+$')     # names and globs, no '/'
_APT_SHORT_BUNDLE = frozenset('yqfsm')
# `dnf config-manager --add-repo` (Docker CE on the RHEL family).
_PKG_REPO_URL_PREFIXES = ('https://download.docker.com/linux/',)
# A package FILE name: what TAK.gov and Caddy publish (letters, digits, . _ + ~ -).
# The console's upload route saves names through werkzeug secure_filename (spaces
# become _, brackets go), so a browser's "takserver_…_all (1).deb" arrives as
# "takserver_…_all_1.deb" and passes. A file copied in by hand may not.
_PKG_FILE_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+~-]*\.(deb|rpm)$')


def _pkg_name_hint(name):
    """Plain refusal text for a package file whose NAME fails _PKG_FILE_NAME_RE."""
    return (f'package file "{name[:120]}" was not installed: its name has characters '
            f'infra-TAK does not accept. A package file name may use only letters, '
            f'digits and . _ + ~ - and must start with a letter or digit. Rename the '
            f'file (for example, remove spaces and brackets such as " (1)"), or upload '
            f'it again from the console page, then try again. Nothing was installed.')


def _pkg_arg_is_file(a):
    """True when apt/dnf would read this package argument as a local file: it has
    a '/', or ends in a package-file suffix (apt and dnf both take `x.deb` /
    `x.rpm` in the working directory as a file)."""
    return '://' not in a and ('/' in a or a.endswith(
        ('.deb', '.udeb', '.ddeb', '.rpm', '.dsc', '.changes')))


# The TAK Server release key. TAK.gov signs every takserver .deb (debsig
# `_gpgorigin`) and .rpm with it. Taken from the debsig keyring TAK's own install
# steps create (/usr/share/debsig/keyrings/F06237936851F5B5/debsig.gpg), same on
# test6 and test12, and it verifies takserver_5.8-RELEASE84 (.deb and .rpm).
# If TAK.gov ever rotates it, a TAK install from a file stops with
# _TAK_KEY_CHANGED_HINT until infra-TAK ships the new key here.
_TAK_PKG_KEY_FPR = '71C03345F393DBD0E03AEB2BF06237936851F5B5'
_TAK_PKG_KEY_ASC = '''\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGAwFLcBDADAeSns0R5l4dJpsHy7N0ZXjA8vm6MBrmRR6Fym+UNY0+wUwNwJ
Y41fRwstBQ2ZhzNYQDI1bwjUoVbDi4w2Db+BjutglpVmTt7sEHnhP+U/SfSXT1LW
3zx8qGJa0UCx+ktxokCM78qtiB0K5NBDw8QJfMep1r0GNE/t/wpnWmOBOw2BHdVE
8NJyyW37HB+Zi8ASswYMK31JebvBTU078a7sf97QQtxMa2afwuEX2iwhQhz3nEeZ
O11hSa6Yrbq1wQzI6JTAPhQKcbcocjJyzv/nsJzhXMRMoFnruZHsXn5PtGlWy+EC
6MZbygyY64fH0xB3ruzyCyKj5EidcA5OrxBd1albeRfq3Uu1XLLlZoeTTkePpUlb
K/GsBYwLRb7uYleCNn5FQfyB84vsQibLcxDpWIwUu5jmbvTFTvmETXZaZw7wUdiI
gRNRL+dbByPHbtdtEXPKUrDOEaKER7gZmD+GmgXUTwL3pen2H81hvmFtU3FMqWNo
P8Nmy1Clmk+tKKkAEQEAAbQ3VEFLIFByb2R1Y3QgQ2VudGVyIFRBSyBTZXJ2ZXIg
UmVsZWFzZSA8c3VwcG9ydEB0YWsuZ292PokBzgQTAQgAOBYhBHHAM0Xzk9vQ4Drr
K/BiN5NoUfW1BQJgMBS3AhsvBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEPBi
N5NoUfW1cO0L/R9cYeDa8vdhFGKU9vgBmi8h8zRkZMXyRK4Avt5tMyfftbZfkE+R
lWMxf4U6bO1TSZw9BhWxtWKxVMB+B7YeZ7ua2n5y0cdofcIh13MvA0JIkW4yUqFH
hnoGyQNpyiio8pmlzElmw4bngrX0tq/l4F5x9y/bvJ2lrIjv9SjTWClj03RDcbUY
qBStbKBuxQIF5FCaSyp4WKd00Qx1rmE3Pea/SArcqXzKGCoovL8/zd1y5xvWHah7
I/X+AqRWcvnaEnKqBJ1J9sWot79fV1lHQsx5GLjPcg5AkDaVvi2zCvs+Ppa442uF
A2Q3oGxGypMs4RnGb7isre928okIdqQCsosHT6601AdtuvGTcG6zzMbhf0DajnFV
zmrLeAWTJXBOdQoR27wjRSeMihGpZpytP/athCkcLRMXc74xuxWFYWZ76QmekxyV
Z4mle/EyVr3yg1+XU2q7QyG0BpYCrdkBKutO4hJihZreDq8udLtzCrkyKJTCxe0g
xA09pVPS+bAzGA==
=Heiq
-----END PGP PUBLIC KEY BLOCK-----
'''
_TAK_KEY_CHANGED_HINT = (
    'If TAK.gov now signs its packages with a new key, update infra-TAK (Update Now) '
    'to a version that knows the new key, then run this again. Nothing was installed.')
# Caddy's own GitHub release .deb (the fallback install when Cloudsmith is down).
_CADDY_DEB_RE = re.compile(r'^caddy_(\d+\.\d+\.\d+)_linux_(amd64|arm64|armv[5-7]|386|ppc64le|s390x|riscv64)\.deb$')
_CADDY_SUMS_URL = 'https://github.com/caddyserver/caddy/releases/download/v{ver}/caddy_{ver}_checksums.txt'
# Root-only staging dir: the package root installs is a copy only root can change.
_PKG_STAGE_ROOT = '/var/lib/takwerx-broker/pkg-stage'


def _fpr_spaced(fpr):
    return ' '.join(fpr[i:i + 4] for i in range(0, len(fpr), 4))


def _pkg_refuse(name, why):
    raise Denied(f'package file {name} was not installed: {why}')


def _tak_key_packets():
    """The pinned TAK key as binary OpenPGP packets (a keyring gpgv accepts)."""
    body = [ln.strip() for ln in _TAK_PKG_KEY_ASC.strip().splitlines()[1:-1]]
    body = [ln for ln in body if ln and ':' not in ln and not ln.startswith('=')]
    return base64.b64decode(''.join(body))


def _ar_members(f):
    """[(name, offset, size)] of a Debian package (an `ar` archive)."""
    if f.read(8) != b'!<arch>\n':
        raise ValueError('not a Debian package (no ar header)')
    out = []
    while True:
        h = f.read(60)
        if not h:
            return out
        if len(h) != 60 or h[58:60] != b'`\n':
            raise ValueError('damaged Debian package (bad ar member header)')
        name = h[0:16].decode('ascii', 'replace').strip().rstrip('/')
        size = int(h[48:58].decode('ascii', 'replace').strip() or '-1')
        if size < 0:
            raise ValueError('damaged Debian package (bad ar member size)')
        off = f.tell()
        out.append((name, off, size))
        f.seek(off + size + (size & 1))


def _gpgv_tak(sig_path, feed, workdir, name):
    """Run gpgv on `sig_path` against the pinned TAK key only; `feed(stdin)` writes
    the signed bytes. Refuses (Denied) unless the signature is good and made by
    the pinned key."""
    gpgv = shutil.which('gpgv', path=BROKER_TRUSTED_PATH)
    if not gpgv:
        _pkg_refuse(name, 'gpgv is not installed, so its TAK signature cannot be checked')
    ring = os.path.join(workdir, 'tak-release.gpg')
    with open(ring, 'wb') as k:
        k.write(_tak_key_packets())
    env = {'PATH': BROKER_TRUSTED_PATH, 'LC_ALL': 'C', 'GNUPGHOME': workdir}
    p = subprocess.Popen([gpgv, '--status-fd', '1', '--keyring', ring, sig_path, '-'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=env, cwd=workdir)
    try:
        feed(p.stdin)
    except BrokenPipeError:
        pass
    except BaseException:
        p.kill()
        p.wait()
        raise
    finally:
        try:
            p.stdin.close()
        except BrokenPipeError:
            pass
    status = p.stdout.read().decode('ascii', 'replace')
    rc = p.wait()
    _tak_sig_verdict(rc, status, name)


def _tak_sig_verdict(rc, status, name):
    """Judge gpgv --status-fd output. Good = exit 0, GOODSIG, and a VALIDSIG whose
    primary-key fingerprint is the pinned TAK key."""
    lines = [ln.split() for ln in status.splitlines() if ln.startswith('[GNUPG:] ')]
    valid = [ln for ln in lines if len(ln) > 2 and ln[1] == 'VALIDSIG']
    good = any(len(ln) > 1 and ln[1] == 'GOODSIG' for ln in lines)
    if rc == 0 and good and valid and all(
            ln[-1].upper() == _TAK_PKG_KEY_FPR for ln in valid):
        return
    other = [ln[2] for ln in lines if len(ln) > 2 and ln[1] in ('ERRSIG', 'NO_PUBKEY')]
    bad = any(len(ln) > 1 and ln[1] == 'BADSIG' for ln in lines)
    want = f'the TAK Server release key ({_fpr_spaced(_TAK_PKG_KEY_FPR)})'
    if bad:
        _pkg_refuse(name, f'its signature does not match its content (damaged or changed '
                          f'after TAK.gov signed it). Download it again from TAK.gov.')
    if other:
        _pkg_refuse(name, f'it is signed with key {other[0]}, not {want}. {_TAK_KEY_CHANGED_HINT}')
    _pkg_refuse(name, f'it has no valid signature from {want}. Only TAK Server packages '
                      f'from TAK.gov (and the Caddy .deb from Caddy\'s GitHub release) can be '
                      f'installed from a file.')


def _verify_tak_deb(path, name, workdir):
    """debsig origin signature: `_gpgorigin` signs debian-binary + control.tar.* +
    data.tar.* (in that order). The member list must be exactly that shape, so
    dpkg installs exactly the bytes that were checked."""
    with open(path, 'rb') as f:
        try:
            mem = _ar_members(f)
        except ValueError as e:
            _pkg_refuse(name, str(e))
        names = [m[0] for m in mem]
        signed = [m for m in mem if not m[0].startswith('_gpg')]
        ok_shape = (len(signed) == 3 and signed[0][0] == 'debian-binary'
                    and re.fullmatch(r'^control\.tar(\.(gz|xz|zst))?$', signed[1][0])
                    and re.fullmatch(r'^data\.tar(\.(gz|xz|zst|bz2|lzma))?$', signed[2][0])
                    and names[:3] == [m[0] for m in signed])
        sig = [m for m in mem if m[0] == '_gpgorigin']
        if not sig:
            _pkg_refuse(name, f'it has no TAK.gov signature (no _gpgorigin). Only TAK Server '
                              f'packages from TAK.gov (and the Caddy .deb from Caddy\'s GitHub '
                              f'release) can be installed from a file.')
        if not ok_shape or len(sig) != 1:
            _pkg_refuse(name, f'unexpected package layout {names}')
        f.seek(sig[0][1])
        sig_path = os.path.join(workdir, '_gpgorigin')
        with open(sig_path, 'wb') as s:
            s.write(f.read(min(sig[0][2], 1 << 16)))

        def feed(stdin):
            for _n, off, size in signed:
                f.seek(off)
                left = size
                while left:
                    b = f.read(min(1 << 20, left))
                    if not b:
                        raise ValueError('truncated package')
                    left -= len(b)
                    stdin.write(b)
        try:
            _gpgv_tak(sig_path, feed, workdir, name)
        except ValueError as e:
            _pkg_refuse(name, str(e))


def _verify_tak_rpm(path, name, workdir):
    """rpm: check the signature with a throwaway rpm database that holds ONLY the
    pinned TAK key, so a good signature can only be TAK's."""
    rpmkeys = shutil.which('rpmkeys', path=BROKER_TRUSTED_PATH)
    if not rpmkeys:
        _pkg_refuse(name, 'rpmkeys is not installed, so its TAK signature cannot be checked')
    db = os.path.join(workdir, 'rpmdb')
    os.mkdir(db, 0o700)
    asc = os.path.join(workdir, 'tak-release.asc')
    with open(asc, 'w') as k:
        k.write(_TAK_PKG_KEY_ASC)
    env = {'PATH': BROKER_TRUSTED_PATH, 'LC_ALL': 'C'}
    r = subprocess.run([rpmkeys, '--dbpath', db, '--import', asc], capture_output=True,
                       text=True, timeout=120, env=env, cwd=workdir)
    if r.returncode != 0:
        _pkg_refuse(name, f'could not load the TAK key for the check: {(r.stderr or r.stdout).strip()[:200]}')
    r = subprocess.run([rpmkeys, '--dbpath', db, '--checksig', '-v', path], capture_output=True,
                       text=True, timeout=900, env=env, cwd=workdir)
    _tak_rpm_verdict(r.returncode, (r.stdout or '') + (r.stderr or ''), name)


def _tak_rpm_verdict(rc, out, name):
    kid = _TAK_PKG_KEY_FPR[-8:].lower()
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    sig_ok = [ln for ln in lines if re.search(r'Signature, key ID ([0-9a-f]+): OK$', ln)]
    bad = any(re.search(r': (NOT OK|BAD|NOKEY|NOTTRUSTED|NOTFOUND)\b', ln) for ln in lines)
    if rc == 0 and sig_ok and all(f'key ID {kid}: OK' in ln for ln in sig_ok) and not bad:
        return
    want = f'the TAK Server release key ({_fpr_spaced(_TAK_PKG_KEY_FPR)})'
    nokey = re.search(r'key ID ([0-9a-f]+): NOKEY', out)
    if nokey and nokey.group(1) != kid:
        _pkg_refuse(name, f'it is signed with key {nokey.group(1)}, not {want}. {_TAK_KEY_CHANGED_HINT}')
    if bad and not nokey:
        _pkg_refuse(name, 'its signature or digest does not match its content (damaged or '
                          'changed after TAK.gov signed it). Download it again from TAK.gov.')
    _pkg_refuse(name, f'it has no valid signature from {want}. Only TAK Server packages '
                      f'from TAK.gov can be installed from a file.')


def _verify_caddy_deb(path, name, m):
    """Caddy's GitHub release .deb: SHA-512 must match the release checksums file,
    fetched here by root over HTTPS (the console's copy of it is not trusted)."""
    import urllib.request
    ver = m.group(1)
    url = _CADDY_SUMS_URL.format(ver=ver)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            sums = r.read(1 << 20).decode('utf-8', 'replace')
    except Exception as e:  # noqa: BLE001 — any fetch failure refuses the install
        _pkg_refuse(name, f'could not fetch Caddy\'s checksum file ({url}): {type(e).__name__}')
    want = next((ln.split()[0].lower() for ln in sums.splitlines()
                 if len(ln.split()) == 2 and ln.split()[1] == name), None)
    if not want:
        _pkg_refuse(name, f'it is not listed in Caddy\'s v{ver} checksum file')
    h = hashlib.sha512()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    if h.hexdigest() != want:
        _pkg_refuse(name, f'its SHA-512 does not match Caddy\'s v{ver} checksum file')


def _pkg_local_files(argv, cwd):
    """[(argv index, absolute path)] of the local package-file args of an
    apt/dnf/yum install. Relative paths resolve against the request cwd."""
    if not argv or os.path.basename(argv[0]) not in ('apt', 'apt-get', 'dnf', 'yum'):
        return []
    base_cwd = cwd if (isinstance(cwd, str) and cwd.startswith('/')) else '/'
    sub, out = None, []
    for i, a in enumerate(argv[1:], 1):
        if a.startswith('-'):
            continue
        if sub is None:
            sub = a
            if sub not in _PKG_INSTALL_SUBS:
                return []
            continue
        if _pkg_arg_is_file(a):
            out.append((i, os.path.normpath(a if a.startswith('/') else os.path.join(base_cwd, a))))
    return out


def _pkg_stage_verified(argv, cwd, timeout):
    """ops #645 W0 part 2 (both modes): for an install that names local package
    files, copy each one AS THE CONSOLE USER into a fresh root-only dir, check the
    copy as root, and return (argv pointing at the checked copies, stage dir).
    Root never opens the caller's path, and the console cannot change the copy
    between the check and the install. Returns (argv, None) when there is no
    local file. Raises Denied with a plain reason when a file fails its check."""
    files = _pkg_local_files(argv, cwd)
    if not files:
        return argv, None
    pw = pwd.getpwnam(BROKER_USER)
    os.makedirs(_PKG_STAGE_ROOT, mode=0o711, exist_ok=True)
    if os.path.islink(_PKG_STAGE_ROOT) or not os.path.isdir(_PKG_STAGE_ROOT):
        raise Denied('package staging dir is not a plain directory')
    os.chown(_PKG_STAGE_ROOT, 0, 0)
    os.chmod(_PKG_STAGE_ROOT, 0o711)
    _pkg_stage_sweep()
    stage = tempfile.mkdtemp(prefix='pkg-', dir=_PKG_STAGE_ROOT)    # root 0700
    try:
        new = list(argv)
        user_env = {'PATH': BROKER_TRUSTED_PATH, 'LC_ALL': 'C', 'HOME': '/'}
        groups = os.getgrouplist(pw.pw_name, pw.pw_gid)
        for idx, src in files:
            name = os.path.basename(src)
            if not _PKG_FILE_NAME_RE.fullmatch(name):
                raise Denied(_pkg_name_hint(name))
            _pkg_stage_space_check(src, name, pw, groups, user_env)
            work = tempfile.mkdtemp(prefix='chk-', dir=stage)
            dst = os.path.join(stage, name)
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                r = subprocess.run(['cat', '--', src], stdout=out, stderr=subprocess.PIPE,
                                   timeout=timeout, cwd='/', env=user_env, user=pw.pw_uid,
                                   group=pw.pw_gid, extra_groups=groups)
            if r.returncode != 0:
                err = (r.stderr or b'').decode('utf-8', 'replace').strip()[:200]
                if 'No space left' in err:
                    _pkg_refuse(name, _pkg_space_msg(None, None))
                _pkg_refuse(name, f'{BROKER_USER} cannot read {src}: {err}')
            m = _CADDY_DEB_RE.fullmatch(name)
            if m and os.path.basename(argv[0]) in ('apt', 'apt-get'):
                _verify_caddy_deb(dst, name, m)
            elif name.endswith('.deb'):
                _verify_tak_deb(dst, name, work)
            else:
                _verify_tak_rpm(dst, name, work)
            shutil.rmtree(work, ignore_errors=True)
            os.chmod(dst, 0o644)         # apt reads local debs as _apt
            new[idx] = dst
        os.chmod(stage, 0o711)
        return new, stage
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


# Head room left free on the staging filesystem after the copy (apt/dnf, logs).
_PKG_STAGE_HEADROOM = 256 * 1024 * 1024


def _pkg_space_msg(need, free):
    mb = lambda n: f'{(n + (1 << 20) - 1) >> 20} MB'  # noqa: E731
    have = f' It needs about {mb(need)} there, and {mb(free)} is free.' if need else ''
    return (f'there is not enough free disk space under {_PKG_STAGE_ROOT} to check it '
            f'before install.{have} Free up disk space on this server, then try again. '
            f'Nothing was installed.')


def _pkg_stage_space_check(src, name, pw, groups, env):
    """Refuse with a plain message, before the copy, when the staging filesystem
    cannot hold a copy of `src` plus head room (a TAK package is ~650 MB). The
    size is read AS THE CONSOLE USER (`stat`), so root never looks at the
    caller's path. If the size cannot be read, the copy itself reports it."""
    r = subprocess.run(['stat', '-L', '-c', '%s', '--', src], capture_output=True,
                       timeout=30, cwd='/', env=env, user=pw.pw_uid, group=pw.pw_gid,
                       extra_groups=groups)
    try:
        size = int(r.stdout.decode('ascii', 'replace').strip()) if r.returncode == 0 else None
    except ValueError:
        size = None
    if size is None:
        return
    st = os.statvfs(_PKG_STAGE_ROOT)
    free = st.f_bavail * st.f_frsize
    need = size + _PKG_STAGE_HEADROOM
    if free < need:
        _pkg_refuse(name, _pkg_space_msg(need, free))


def _pkg_stage_sweep(max_age=6 * 3600):
    """Remove staging dirs a killed broker left behind (a TAK package is ~650 MB)."""
    try:
        now = time.time()
        for n in os.listdir(_PKG_STAGE_ROOT):
            p = os.path.join(_PKG_STAGE_ROOT, n)
            if n.startswith('pkg-') and now - os.lstat(p).st_mtime > max_age:
                shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# ops #645 W0 — ip, dpkg, fail2ban-client, postconf. Each had NO gate, and each
# was a one-command root shell: `ip netns exec x /bin/sh`, `dpkg -i evil.deb`,
# `fail2ban-client set <jail> action … actionban '<cmd>'`,
# `postconf -e daemon_directory=<console dir>`. Allow only the shapes the console
# uses (static scan of app.py/modules + 10 days of test6/test12 audit logs).
# ---------------------------------------------------------------------------

_IP_OPTS = {'-4', '-6', '-o', '-oneline', '-j', '-json', '-p', '-pretty', '-br', '-brief',
            '-d', '-details', '-s', '-stats', '-statistics', '-c', '-color', '-h',
            '-human', '-N', '-numeric', '-r', '-resolve'}
_IP_OBJECTS = {'addr', 'address', 'a', 'route', 'r', 'ro', 'link', 'l', 'neigh',
               'neighbor', 'neighbour', 'n', 'rule', 'ru', 'maddr', 'maddress'}
_IP_READ_CMDS = {'show', 'list', 'lst', 'ls', 'sh', 'get'}
_IP_BAD_WORDS = {'add', 'del', 'delete', 'change', 'replace', 'set', 'flush', 'exec',
                 'netns', 'append', 'prepend', 'save', 'restore', 'test'}


def _check_ip(argv):
    """`ip`: read-only listing only (`ip [-4|-6|-o|-j…] addr|route|link|neigh|rule
    [show|list|get …]`). No netns, no batch, no change verbs."""
    i = 1
    while i < len(argv) and argv[i].startswith('-'):
        if argv[i] not in _IP_OPTS:
            raise Denied(f'ip option not allowed: {argv[i]}')
        i += 1
    if i >= len(argv) or argv[i] not in _IP_OBJECTS:
        raise Denied(f'ip: only read-only addr/route/link/neigh/rule listing is allowed')
    rest = argv[i + 1:]
    if rest and rest[0] not in _IP_READ_CMDS:
        raise Denied(f'ip {argv[i]}: only show/list/get is allowed, not {rest[0]!r}')
    for w in rest:
        if w in _IP_BAD_WORDS or w.startswith('-b'):
            raise Denied(f'ip: {w!r} not allowed')


_DPKG_NAME_RE = re.compile(r'^[A-Za-z0-9*?][A-Za-z0-9+.:~_*?-]*$')
_DPKG_NOARG = {'--print-architecture', '--print-foreign-architectures', '--version',
               '--set-selections', '--audit', '-C'}
_DPKG_QUERY = {'-l', '--list', '-s', '--status', '-L', '--listfiles', '-V', '--verify',
               '--get-selections'}
_DPKG_REMOVE = {'--purge', '-P', '--remove', '-r'}


def _check_dpkg(argv):
    """`dpkg`: query, configure, remove and selection shapes only. `-i`/`--install`
    /`--unpack`/`-x`/`--root`/`--admindir`/`--force-*` (other than --force-all on a
    removal) are refused: they install or unpack a file of the caller's choosing."""
    a = argv[1:]
    if not a:
        raise Denied('dpkg: no action')
    act, rest = a[0], a[1:]
    if act in _DPKG_NOARG:
        if rest:
            raise Denied(f'dpkg {act} takes no arguments')
        return
    if act in _DPKG_QUERY:
        for x in rest:
            if not _DPKG_NAME_RE.fullmatch(x):
                raise Denied(f'dpkg {act}: not a package name: {x}')
        return
    if act in ('-S', '--search'):
        if not rest or any(x.startswith('-') for x in rest):
            raise Denied('dpkg -S: patterns only')
        return
    if act == '--compare-versions':
        if len(rest) != 3 or any(x.startswith('-') for x in (rest[0], rest[2])):
            raise Denied('dpkg --compare-versions: V1 OP V2')
        return
    if act == '--configure':
        if rest in (['-a'], ['--pending']):
            return
        if rest and all(_DPKG_NAME_RE.fullmatch(x) and '*' not in x and '?' not in x for x in rest):
            return
        raise Denied('dpkg --configure: -a or package names only')
    if act in _DPKG_REMOVE or (act == '--force-all' and rest and rest[0] in _DPKG_REMOVE):
        names = [x for x in a if x not in _DPKG_REMOVE and x != '--force-all']
        if [x for x in a if x in _DPKG_REMOVE].__len__() != 1:
            raise Denied('dpkg: one removal action')
        if not names or not all(_DPKG_NAME_RE.fullmatch(x) and '*' not in x and '?' not in x for x in names):
            raise Denied('dpkg removal: package names only')
        return
    raise Denied(f'dpkg action not allowed: {act}')


_F2B_JAIL_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$')
_F2B_IP_RE = re.compile(r'^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$')
_F2B_RELOAD_OPTS = {'--restart', '--unban', '--if-exists', '--all'}


def _check_fail2ban_client(argv):
    """`fail2ban-client`: status, reload, ban/unban and `get` (read-only). Every
    other `set` (action*, addaction, addlogpath, logtarget, dbfile …), `add`,
    `start`, `-c`/`--conf`/`-s` are refused: fail2ban-server is root and runs
    whatever action command it is given."""
    a = argv[1:]
    if not a:
        raise Denied('fail2ban-client: no command')
    cmd, rest = a[0], a[1:]
    if cmd in ('--version', '-V', '-h', '--help', 'ping', 'version') and not rest:
        return
    if cmd == 'status':
        if len(rest) <= 1 and all(_F2B_JAIL_RE.fullmatch(x) for x in rest):
            return
        raise Denied('fail2ban-client status [JAIL] only')
    if cmd == 'reload':
        jails = [x for x in rest if x not in _F2B_RELOAD_OPTS]
        if len(jails) <= 1 and all(_F2B_JAIL_RE.fullmatch(x) for x in jails):
            return
        raise Denied('fail2ban-client reload [--restart] [JAIL] only')
    if cmd == 'set':
        if (len(rest) >= 3 and _F2B_JAIL_RE.fullmatch(rest[0]) and rest[1] in ('banip', 'unbanip')
                and all(_F2B_IP_RE.fullmatch(x) or x == '--report-absent' for x in rest[2:])):
            return
        raise Denied('fail2ban-client set: only JAIL banip|unbanip IP…')
    if cmd == 'unban':
        if rest == ['--all'] or (rest and all(_F2B_IP_RE.fullmatch(x) for x in rest)):
            return
        raise Denied('fail2ban-client unban: IPs or --all only')
    if cmd == 'banned':
        if all(_F2B_IP_RE.fullmatch(x) for x in rest):
            return
        raise Denied('fail2ban-client banned [IP…] only')
    if cmd == 'get':
        if rest and all(not x.startswith('-') for x in rest):
            return
        raise Denied('fail2ban-client get: no options')
    raise Denied(f'fail2ban-client command not allowed: {cmd}')


# postconf -e keys the console may set (Email Relay). Keys that name a program,
# a directory or a command (daemon_directory, *_command, *_path, mailbox_*,
# content_filter …) are NOT here: Postfix's root master runs them.
_POSTCONF_EDIT_KEYS = {
    'myhostname', 'mydomain', 'myorigin', 'mydestination', 'relayhost',
    'inet_interfaces', 'inet_protocols', 'mynetworks', 'smtp_sasl_auth_enable',
    'smtp_sasl_password_maps', 'smtp_sasl_security_options',
    'smtp_sasl_tls_security_options', 'smtp_sasl_mechanism_filter',
    'smtp_tls_security_level', 'smtp_tls_CAfile', 'smtp_tls_wrappermode',
    'smtp_use_tls', 'smtp_tls_loglevel', 'smtp_generic_maps', 'sender_canonical_maps',
    'header_size_limit', 'message_size_limit', 'smtputf8_enable', 'compatibility_level',
}
_POSTCONF_KEY_RE = re.compile(r'^[a-z0-9_]+$', re.I)


def _check_postconf(argv):
    """`postconf`: read (`postconf [-n|-h|-d|-x] [KEY…]`) and `-e KEY=VALUE` for the
    Email Relay keys only. -c/-M/-F/-P/-X/-# and exec-capable keys are refused."""
    edit = False
    for x in argv[1:]:
        if x.startswith('-'):
            if x == '-e':
                edit = True
            elif x not in ('-n', '-h', '-d', '-x'):
                raise Denied(f'postconf option not allowed: {x}')
            continue
        if edit:
            key, sep, val = x.partition('=')
            key = key.strip()
            if not sep or key not in _POSTCONF_EDIT_KEYS:
                raise Denied(f'postconf -e: key not allowed: {key or x}')
            if any(c in val for c in '\n\r|') or '$' in val:
                raise Denied(f'postconf -e {key}: value not allowed')
        elif not _POSTCONF_KEY_RE.fullmatch(x):
            raise Denied(f'postconf: not a parameter name: {x}')


# SELinux file-context types the console may LABEL (semanage fcontext / chcon).
# Content/exec types for serving files (cesium tiles, the caddy binary) — NOT
# security-sensitive domains. Relabelling to e.g. shadow_t / unconfined_t stays
# denied.
SELINUX_SAFE_TYPES = {'httpd_sys_content_t', 'httpd_exec_t', 'bin_t',
                      'var_t', 'usr_t', 'cert_t'}
# SELinux policy MODULES the console may remove (TAK's own, on uninstall). It
# may NOT remove arbitrary modules (e.g. another service's confinement, or its
# own future takwerx_console policy).
SEMODULE_REMOVABLE = {'takserver', 'takserver-policy'}
# The one file-context rule the console adds (RHEL Cesium tiles, app.py
# `_cesium_ensure_dir`). semanage fcontext takes nothing else.
SEMANAGE_FCONTEXT_CESIUM = '/var/lib/cesium-tiles(/.*)?'


def _check_semanage(argv):
    """semanage manages SELinux policy bits. Allow `semanage port` (custom Caddy
    ports -> http_port_t) and the one `semanage fcontext` rule for the Cesium
    tiles dir (served by httpd). Deny login/user/boolean/etc. and every other
    path or type."""
    if len(argv) < 2 or argv[1] not in ('port', 'fcontext'):
        raise Denied('semanage: only `semanage port` / `semanage fcontext` allowed')
    # ops #645 W0 add-on (Security review): exact shapes only. semanage parses with
    # argparse, which takes unique prefixes (`--typ=shadow_t`) and attached values
    # (`-tshadow_t`), and the last -t wins, so reading just `-t`/`--type=` was not a
    # gate. The console sends exactly these (app.py `_selinux_http_port`, cesium tiles).
    rest = argv[2:]
    if argv[1] == 'port':
        if rest == ['-l']:
            return
        if (len(rest) == 6 and rest[0] in ('-a', '-m') and rest[1:3] == ['-t', 'http_port_t']
                and rest[3] == '-p' and rest[4] in ('tcp', 'udp')
                and re.fullmatch(r'[0-9]{1,5}', rest[5])):
            return
        raise Denied('semanage port: only -l, or -a|-m -t http_port_t -p tcp|udp PORT')
    # Security re-review: any absolute path was allowed (`-t httpd_sys_content_t
    # /etc/shadow`, `/.*`). The console labels one thing: the RHEL Cesium tiles dir
    # (app.py `_cesium_ensure_dir`, always /var/lib/cesium-tiles on RHEL).
    if rest == ['-a', '-t', 'httpd_sys_content_t', SEMANAGE_FCONTEXT_CESIUM]:
        return
    raise Denied('semanage fcontext: only -a -t httpd_sys_content_t '
                 f'{SEMANAGE_FCONTEXT_CESIUM} (the Cesium tiles dir)')


def _check_semodule(argv):
    """SELinux policy module management. Allow `-l`/`--list-modules` (read-only)
    and `-r <module>` ONLY for TAK's own policy modules (removed on uninstall).
    Deny `-i`/`-B`/`-X` and removal of any other module (which could strip
    another service's — or the console's own — confinement)."""
    args = [a for a in argv[1:]]
    if not args:
        raise Denied('semodule: no operation')
    # list forms
    if all(a in ('-l', '--list-modules', '-lfull', '--list', '-a') or a.startswith('--list')
           for a in args):
        return
    # removal: -r NAME [-r NAME ...], no other ops
    i = 0
    saw_remove = False
    while i < len(args):
        a = args[i]
        if a in ('-r', '--remove'):
            if i + 1 >= len(args):
                raise Denied('semodule -r: missing module name')
            name = args[i + 1]
            if name not in SEMODULE_REMOVABLE:
                raise Denied(f'semodule -r: module not removable: {name}')
            saw_remove = True
            i += 2
            continue
        if a.startswith('-'):
            raise Denied(f'semodule: option not allowed: {a}')
        raise Denied(f'semodule: unexpected arg: {a}')
    if not saw_remove:
        raise Denied('semodule: only -l / -r <tak module> allowed')


# TAK Server's cert scripts (tak-owned, mode 0500) and its truststore import must
# run AS the unprivileged `tak` service user — that's how TAK is designed to make
# its CA/keystores, and the non-root console has no su/sudo. Allow ONLY
# `runuser -u tak -- <X>` where X is a TAK cert script under /opt/tak/certs/ or
# `keytool`. Any other target user (esp. root) or command stays denied.
_TAK_CERT_SCRIPTS = ('/opt/tak/certs/makeRootCa.sh', '/opt/tak/certs/makeCert.sh')
# Postgres admin tooling run AS the postgres OS user (peer-auth) — the non-root
# console has no `sudo -u postgres`, so TAK Server DB ops (health probes, vacuum/
# reindex, db size/stats, snapshot pg_dump, rollback pg_restore, purge drop) route
# `runuser -u postgres -- <pg tool>` through the broker. This grants the postgres
# privilege level (DB admin) the ops already need. The postgres OS user is
# unprivileged at the OS layer, BUT psql `COPY … TO PROGRAM`/untrusted-language
# functions execute shell AS postgres, and postgres → root is a documented pivot
# (shared_preload). So we whitelist the pg binaries (no `runuser -u postgres --
# bash`) AND bound `psql` to non-RCE SQL via _PSQL_FORBIDDEN below.
_PG_AS_POSTGRES = {'psql', 'pg_dump', 'pg_dumpall', 'pg_restore', 'pg_isready',
                   'vacuumdb', 'reindexdb', 'createdb', 'dropdb', 'pg_basebackup'}

# psql sub-strings that yield code execution / arbitrary file IO as the postgres
# OS user. Matched case-insensitively against the whitespace-normalized psql argv
# (see _check_runuser). The console's admin SQL (size/count/ALTER SYSTEM/reload)
# contains none of these, so this blocks the escalation vector without affecting
# legitimate use.
_PSQL_FORBIDDEN = (
    'program',                # COPY … TO/FROM PROGRAM, \copy … PROGRAM
    '\\!',                    # psql shell-escape meta-command
    'lo_import', 'lo_export', # large-object file IO
    'pg_read_file', 'pg_read_binary_file', 'pg_read_server_files',
    'pg_write_server_files', 'pg_ls_dir',  # server-side file functions
    'plpython', 'plperlu',    # untrusted procedural languages
    'language c',             # C-language function → native code
)


# psql flags the console passes as postgres (code scan of every _pg_exec /
# _cot_pg_exec call + test6/test12 audit logs): -t -A -X -q, and -c SQL, -d DB,
# -F SEP, -p PORT. getopt also takes them bundled (`-tAc SQL`, `-tAF,`) and with the
# value attached (`-dcot`), so the walk below parses them the way getopt does.
# No long options at all: getopt_long accepts any unique prefix (`--fil=` is
# `--file=`), so a long-option deny-list cannot hold.
_PSQL_BOOL = frozenset('tAXq')
_PSQL_VALUE = frozenset('cdFp')
_PSQL_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,62}$')   # a plain DB name, no conninfo/URI


def _psql_value_ok(flag, v):
    if flag == 'c':
        # `-c '\o |cmd'` / `-c '\copy … '`: a -c string that starts with a backslash
        # is a psql meta-command, run by psql itself as postgres. SQL only.
        if v.lstrip().startswith('\\'):
            raise Denied('runuser: psql meta-command denied as postgres')
    elif flag == 'd':
        if not _PSQL_NAME_RE.fullmatch(v):
            raise Denied(f'runuser: psql database name not allowed: {v[:60]!r}')
    elif flag == 'p':
        if not re.fullmatch(r'[0-9]{1,5}', v):
            raise Denied(f'runuser: psql port not allowed: {v[:20]!r}')
    elif flag == 'F':
        if len(v) > 4:
            raise Denied('runuser: psql field separator too long')


def _check_psql_flags(args):
    """Walk psql's argv like getopt does, allowing only the console's flags.
    Positionals (DB name, user name) must be plain names."""
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith('--') or a == '-':
            raise Denied(f'runuser: psql option not allowed as postgres: {a!r}')
        if a.startswith('-'):
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in _PSQL_BOOL:
                    j += 1
                    continue
                if ch in _PSQL_VALUE:
                    if j + 1 < len(a):
                        v = a[j + 1:]
                    elif i + 1 < len(args):
                        i += 1
                        v = args[i]
                    else:
                        raise Denied(f'runuser: psql -{ch} needs a value')
                    _psql_value_ok(ch, v)
                    break
                raise Denied(f'runuser: psql option not allowed as postgres: -{ch} in {a!r}')
            i += 1
            continue
        if not _PSQL_NAME_RE.fullmatch(a):
            raise Denied(f'runuser: psql argument not allowed as postgres: {a[:60]!r}')
        i += 1


def _check_runuser(argv):
    # form: runuser -u <tak|postgres> -- CMD [args...]
    if len(argv) < 5 or argv[1] != '-u' or argv[3] != '--':
        raise Denied('runuser: only `runuser -u <tak|postgres> -- <cmd>` allowed')
    target, cmd = argv[2], argv[4]
    if target == 'tak':
        if cmd in _TAK_CERT_SCRIPTS or os.path.basename(cmd) == 'keytool':
            return
        raise Denied(f'runuser: command not allowed as tak: {cmd}')
    if target == 'postgres':
        pgcmd = os.path.basename(cmd)
        if pgcmd not in _PG_AS_POSTGRES:
            raise Denied(f'runuser: command not allowed as postgres: {cmd}')
        # `psql` can be turned into arbitrary code execution AS the postgres OS
        # user — COPY … TO/FROM PROGRAM, \copy … PROGRAM, the \! shell escape, the
        # untrusted procedural languages, and lo_*/server-side file functions — and
        # postgres-OS-user → root is a documented pivot (write shared_preload, wait
        # for a cluster restart; see the PGMiner incident). The console only ever
        # runs admin SELECT/ALTER/size queries here, so refuse any of those
        # primitives in the psql argv. pg_dump/pg_restore/pg_isready take no inline
        # SQL and pass through. NB: a token blocklist is defense-in-depth, not a
        # hermetic seal — the real boundary is that the console never passes
        # attacker-controlled SQL.
        if pgcmd == 'psql':
            # Allowlist-shape the psql gate. The console only ever runs inline admin
            # SQL (`psql -c "<fixed query>"`); it never reads SQL from a file or stdin.
            # Reject the -f/--file/stdin forms: they execute a script file whose
            # contents the token-blocklist below never sees, so `psql -f /tmp/x.sql`
            # containing `COPY … TO PROGRAM 'sh …'` would bypass the RCE guard and
            # run as the postgres OS user (documented postgres→root pivot). The
            # PGOPTIONS-via-env vector is already closed — _do_exec drops all
            # caller-supplied env.
            # ops #645 W0 add-on (Security review): an exact flag allow-list, not a
            # deny-list of `-f` spellings (`-f/tmp/x.sql`, `--fil=…`, `-qAtf x` passed).
            _check_psql_flags(argv[5:])
            blob = ' '.join(' '.join(str(a) for a in argv[4:]).lower().split())
            for tok in _PSQL_FORBIDDEN:
                if tok in blob:
                    raise Denied(f'runuser: psql primitive denied as postgres: {tok!r}')
        return
    if target == 'mediamtx':
        # ops #643 + #649: the console replaces the web editor's admin/admin in users.json.
        # That file and its dir belong to the `mediamtx` account, so the script runs AS that
        # account (never as root in a dir it can plant links in). Exactly one shape: the
        # script comes on stdin and may only name users.json. The caller (the console) is
        # already more trusted than `mediamtx`: this hands it nothing it could not do.
        if argv[4:] == ['python3', '-I', '-', '/opt/mediamtx-webeditor/users.json']:
            return
        raise Denied(f'runuser: command not allowed as mediamtx: {argv[4:]}')
    raise Denied(f'runuser: target user not allowed: {target}')


# git subcommands the console uses on a root-era module repo (version poll +
# module update). Read/refresh only — no push, no arbitrary config. NB: `fetch`
# is deliberately NOT here — no caller uses it, and `git fetch <repo>` accepts a
# transport-schemed remote (`ext::sh -c …`, `ssh://…`) that runs an arbitrary
# command AS ROOT. `pull` shares that risk, so its positional args are
# additionally scheme-filtered below.
_GIT_SUBCMDS = {'rev-parse', 'pull', 'checkout', 'describe', 'status', 'log'}
# Flags allowed AFTER the subcommand. Closed set: several git flags execute
# commands (--upload-pack=<cmd> runs locally for local/ssh remotes,
# --receive-pack likewise), so unknown flags are denied, not ignored.
_GIT_SUBFLAGS = {'--ff-only', '--short', '--', '-q', '--quiet', '--tags',
                 '--porcelain', '--abbrev-ref', '--oneline'}


def _check_git(argv):
    """git for ROOT-ERA module repos only (v10.0.8 — PLAN §A). Allowed shape:
        git -C /root/<module> [-c safe.directory=<x>] <read/refresh subcommand> ...
    Constraints:
      * -C is REQUIRED and must be a root-era module dir (root-owned — the
        console cannot plant hooks/config there). Home-resident repos are
        console-owned; the console runs git on those DIRECTLY as takwerx, so a
        broker (root) git over a takwerx-writable repo — where .git/hooks and
        .git/config are attacker-plantable root-exec vectors — never happens.
      * -c is allowed for safe.directory ONLY (other config keys, e.g.
        core.fsmonitor / core.sshCommand, execute commands).
      * subcommand must be in the read/refresh set (no push/gc/filter-branch).
    """
    root_dirs = tuple(d.rstrip('/') for d in ROOT_MODULE_DIRS)
    saw_c_dir = None
    sub = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-C':
            if i + 1 >= len(argv):
                raise Denied('git: -C without a directory')
            saw_c_dir = os.path.normpath(argv[i + 1])
            i += 2
            continue
        if a == '-c':
            if i + 1 >= len(argv) or not argv[i + 1].startswith('safe.directory='):
                raise Denied('git: only -c safe.directory=<dir> is allowed')
            i += 2
            continue
        if a.startswith('-'):
            # global flags before the subcommand can redirect execution
            # (--exec-path=<dir> runs the caller's git-* binaries as root);
            # post-subcommand flags are a CLOSED set for the same reason
            # (--upload-pack=<cmd> executes locally on pull/fetch).
            if sub is None:
                raise Denied(f'git: global option not allowed: {a}')
            if a not in _GIT_SUBFLAGS:
                raise Denied(f'git: option not allowed: {a}')
            i += 1
            continue
        if sub is None:
            sub = a
            i += 1
            continue
        # Positional AFTER the subcommand. The console only ever passes a bare
        # ref/pathspec (HEAD, ., a branch name). A transport-schemed remote
        # (`ext::sh -c …`, `ssh://…`, `file://…`, an absolute path) as a `pull`
        # positional makes git run an arbitrary command AS ROOT — refuse any
        # positional carrying a scheme (`:`) or an absolute path. Legit refs and
        # pathspecs never contain ':' and never start with '/'.
        if ':' in a or a.startswith('/'):
            raise Denied(f'git: positional looks like a remote/URL, refused: {a}')
        i += 1
    if saw_c_dir not in root_dirs:
        raise Denied(f'git: -C must be a root-era module dir, got: {saw_c_dir}')
    if sub not in _GIT_SUBCMDS:
        raise Denied(f'git: subcommand not allowed: {sub}')
    _check_git_dir_root_owned(saw_c_dir)


def _check_git_dir_root_owned(repo):
    """ops #645 W0: root git reads <repo>/.git/config, and config keys run commands
    (core.fsmonitor, core.hooksPath, remote.*.uploadpack, filter drivers …). The
    root-era module dirs are on the WRITE allowlist, so .git is now deny-listed for
    writes; this exec-time check also refuses a .git (or its config / hooks dir) that
    is a symlink, not root's, or writable by group or others — e.g. one a migration
    `chown -R` handed to the console user."""
    for rel, want_dir in (('.git', True), ('.git/config', False), ('.git/hooks', True)):
        p = os.path.join(repo, rel)
        try:
            st = os.lstat(p)
        except (FileNotFoundError, NotADirectoryError):
            continue                    # git itself fails on a missing repo
        except PermissionError:
            continue                    # only in tests: the broker runs as root
        if stat.S_ISLNK(st.st_mode) or (stat.S_ISDIR(st.st_mode) != want_dir):
            raise Denied(f'git: {p} is not a plain {"directory" if want_dir else "file"}')
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise Denied(f'git: {p} must be root-owned and not group/other-writable')


# TAK's rpm/deb ships apply-selinux.sh which compiles + installs TAK's own SELinux
# policy module (and uses sudo internally), so it must run as root. Allow ONLY this
# one exact, TAK-provided script — never `bash -c`, never any other path.
_TAK_BASH_SCRIPTS = ('/opt/tak/apply-selinux.sh',)


def _check_bash(argv):
    if len(argv) != 2 or argv[1] not in _TAK_BASH_SCRIPTS:
        raise Denied('bash: only the TAK apply-selinux.sh script is allowed')
    _check_tak_script_trusted(argv[1])


def _check_tak_script_trusted(path):
    """ops #645 W0: `bash /opt/tak/apply-selinux.sh` runs as root, and /opt/tak was on
    the write allowlist (and may be a link into the console's own TAK bundle). Run it
    only when the file and every directory up to / are real (no symlink), owned by
    root or the TAK service user, and not writable by group/other — i.e. as the TAK
    package installed it. Broker writes to the exact path are deny-listed too."""
    owners = {0}
    try:
        owners.add(pwd.getpwnam('tak').pw_uid)
    except KeyError:
        pass
    cur = ''
    for c in [''] + [c for c in path.split('/') if c]:
        cur = (cur.rstrip('/') + '/' + c) if c else '/'
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return                      # bash fails on a missing file by itself
        except PermissionError:
            return                      # only in tests: the broker runs as root
        if stat.S_ISLNK(st.st_mode) or st.st_uid not in owners or st.st_mode & 0o022:
            raise Denied(f'bash: {cur} is not as the TAK package installed it '
                         '(symlink, foreign owner or group/other-writable)')


def _check_gpg(argv):
    """gpg is only allowed to DEARMOR an apt repo signing key to an allowlisted
    path: `gpg [--batch --yes] --dearmor -o /usr/share/keyrings/<x>.gpg`. The key
    material arrives on stdin (a downloaded public key). Deny every other gpg
    operation (sign/encrypt/export-secret/edit-key/keyserver/etc.)."""
    has_dearmor = '--dearmor' in argv
    out = None
    ok_flags = {'--batch', '--yes', '--dearmor', '-o', '--output', '-q', '--quiet'}
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ('-o', '--output'):
            if i + 1 >= len(argv):
                raise Denied('gpg: -o without path')
            out = argv[i + 1]
            i += 2
            continue
        if a.startswith('--output='):
            out = a.split('=', 1)[1]
            i += 1
            continue
        if a.startswith('-') and a not in ok_flags:
            raise Denied(f'gpg: option not allowed: {a}')
        i += 1
    if not has_dearmor:
        raise Denied('gpg: only --dearmor is allowed')
    if out is None:
        raise Denied('gpg: --dearmor requires -o <allowlisted path>')
    _path_allowed(out)


# find actions that WRITE, DELETE, or EXECUTE — the reason find was denied. Every
# other find primitive only reads/traverses/prints-to-stdout, which is harmless
# metadata inspection (same class as `test`/`ss`). NB: match the base action name
# AND its `=`/space forms; `-fprintf FILE` etc. write to an arbitrary path.
_FIND_DENIED_ACTIONS = ('-exec', '-execdir', '-ok', '-okdir', '-delete',
                        '-fprintf', '-fprint', '-fprint0', '-fls')


def _check_find(argv):
    """find is read-only ONLY once its command/write/delete actions are refused.
    The console uses `find <dir> -maxdepth N -name … -type f` to scan a container
    volume for planted `.so` files. Deny -exec*/-ok*/-delete/-fprint*/-fls (which
    run commands or write files as root); everything else is traversal + stdout."""
    for a in argv[1:]:
        base = a.split('=', 1)[0]
        if base in _FIND_DENIED_ACTIONS:
            raise Denied(f'find: action not allowed: {a}')


def _check_cp(argv, cwd=None):
    """cp: the DESTINATION (last positional) must be allowlisted; the SOURCE is a
    root READ, allowed from anywhere EXCEPT a deny-listed secret — the same model
    as install(1) (the console stages e.g. an LE p12 or a module overlay from
    /tmp or its own install tree into an allowlisted dir). One extra guard cp
    needs that install does not: a RECURSIVE copy (`cp -r /etc …`) would clone a
    whole secret tree past the single-path deny check, so for -r/-R/-a every
    source must ALSO be allowlisted (strict), not merely non-deny."""
    recursive = False
    positionals = []
    for a in argv[1:]:
        # ops #645 W2: no target-dir flag (the dest would skip the check below), no
        # -l/-s (a hard link to a unit file turns a data write into a unit write)
        if a.startswith('--'):
            if a not in _CP_LONG and not a.startswith(('--preserve=', '--no-preserve=')):
                raise Denied(f'cp: option not allowed: {a}')
        elif a.startswith('-') and a != '-' and not set(a[1:]) <= _CP_SHORT:
            raise Denied(f'cp: option not allowed: {a}')
        if a.startswith('-') and a != '-':
            # ops #645 W0: `--preserve=mode` without ownership makes ROOT the owner
            # of a copy that keeps the source's setuid bit (a console-made 4755
            # file becomes a root setuid binary). -p/-a also keep the owner, so the
            # bit stays on the console's own uid: those stay allowed.
            if a.startswith('--preserve='):
                keep = a.split('=', 1)[1].split(',')
                if 'mode' in keep and not ({'ownership', 'all'} & set(keep)):
                    raise Denied('cp --preserve=mode without ownership not allowed')
            if a in ('-r', '-R', '-a', '--recursive', '--archive') or (
                    len(a) > 1 and a[0] == '-' and not a.startswith('--')
                    and any(c in a[1:] for c in 'raR')):
                recursive = True
            continue
        positionals.append(a)
    if len(positionals) < 2:
        raise Denied('cp: need at least a source and a destination')
    base_cwd = cwd if (cwd and isinstance(cwd, str) and cwd.startswith('/')) else '/'
    def _resolve(p):
        return p if p.startswith('/') else os.path.join(base_cwd, p)
    dst = _resolve(positionals[-1])
    _check_exec_into_root_run('cp', [_path_allowed(dst)])   # dest allowlisted, not a unit
    for src in positionals[:-1]:
        sp = _resolve(src)
        if recursive:
            _path_allowed(sp)                # -r: source strictly allowlisted too
        else:
            spn = os.path.normpath(sp)
            if spn in PATH_DENY_EXACT or any(spn.startswith(d) for d in PATH_DENY_PREFIX):
                raise Denied(f'cp: source not permitted: {src}')


def _check_chcon(argv, cwd=None):
    """chcon relabels a file's SELinux type. Allow ONLY `-t <safe type>` on an
    allowlisted path (the console relabels its own binaries/content, e.g.
    /usr/bin/caddy -> httpd_exec_t). Deny -u/-r (user/role), --reference, and
    relabelling to a security-sensitive type or an off-allowlist path."""
    t = None
    paths = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-t' and i + 1 < len(argv):
            t = argv[i + 1]
            i += 2
            continue
        if a.startswith('--type='):
            t = a.split('=', 1)[1]
            i += 1
            continue
        if a in ('-R', '-v', '-h', '--no-dereference', '-P'):
            i += 1
            continue
        if a.startswith('-'):
            raise Denied(f'chcon: option not allowed: {a}')
        paths.append(a)
        i += 1
    if t is None or t not in SELINUX_SAFE_TYPES:
        raise Denied(f'chcon: type not in safe set: {t}')
    base_cwd = cwd if (cwd and isinstance(cwd, str) and cwd.startswith('/')) else '/'
    for p in paths:
        _path_allowed(p if p.startswith('/') else os.path.join(base_cwd, p))


SYSCTL_SAFE_PREFIXES = ('vm.', 'fs.', 'net.', 'dev.')


def _check_sysctl(argv):
    """sysctl can set `kernel.core_pattern=|cmd` (arbitrary root exec on crash),
    `kernel.modprobe`, `kernel.hotplug`, etc. Allow ONLY safe tuning namespaces
    (the console uses vm.swappiness / vm.overcommit_memory)."""
    for a in argv[1:]:
        if a.startswith('-'):
            if a in ('-w', '-n', '-q', '-e', '-N', '-a', '-A'):
                continue
            raise Denied(f'sysctl flag not allowed: {a}')
        param = a.split('=', 1)[0].strip()
        if not param.startswith(SYSCTL_SAFE_PREFIXES):
            raise Denied(f'sysctl param not in safe namespace (vm./fs./net.): {param}')


# ops #645 W0 add-on (Security review): install(1) takes ONLY the flags the
# console uses (code scan + test6/test12 audit logs): `-D`, `-m MODE`, `-o OWNER`,
# `-g GROUP`, and `-mMODE` attached. A deny-list of flag spellings was bypassed by
# GNU's unique long-option prefixes (`--mo=4755`, `--own=`, `--strip-p=`, `--tar=`)
# and combined short flags (`-Dm4755`), so every other flag is refused.
_INSTALL_OWNERS = frozenset({'root', 'tak'})
_INSTALL_MODE_RE = re.compile(r'^0?[0-7]{3}$')     # plain rwx modes: no setuid/setgid/sticky


def _parse_install(argv):
    """Walk install(1)'s argv with the exact allow-list. Returns (owners, paths)."""
    owners, paths = [], []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == '-D':
            i += 1
            continue
        if a in ('-m', '-o', '-g'):
            if i + 1 >= len(argv):
                raise Denied(f'install: {a} needs a value')
            v = argv[i + 1]
            if a == '-m':
                if not _INSTALL_MODE_RE.fullmatch(v):
                    raise Denied(f'install: mode not allowed: {v}')
            elif v not in _INSTALL_OWNERS:
                raise Denied(f'install: owner/group not allowed: {v}')
            else:
                owners.append(v)
            i += 2
            continue
        if a.startswith('-m') and len(a) > 2:
            if not _INSTALL_MODE_RE.fullmatch(a[2:]):
                raise Denied(f'install: mode not allowed: {a[2:]}')
            i += 1
            continue
        if a.startswith('-'):
            raise Denied(f'install: option not allowed: {a}')
        paths.append(a)
        i += 1
    return owners, paths


def _check_install(argv):
    """install(1): `install [-D] [-m MODE] [-o OWNER] [-g GROUP] src dst`. The
    SOURCE is a read of a console-owned file (anywhere); only the DEST must be
    allowlisted. Only the console's own flags pass (_parse_install), which also
    closes `--strip-program=cmd` (root runs it) and `-t`/`--target-directory`
    (the dest would skip the check below)."""
    owners, paths = _parse_install(argv)
    if paths:
        dst = _path_allowed(paths[-1])   # dst = last positional path
        _check_exec_into_root_run('install', [dst])          # ops #645 W2
        if _root_runs(dst) and any(o not in ('root', '0') for o in owners):
            raise Denied(f'install: root-run paths stay root-owned: {dst}')
        # SOURCE hardening: install(1) reads its source(s) as ROOT and can copy to
        # an allowlisted (console-readable) dest, so an unguarded source is an
        # arbitrary root-READ primitive (e.g. `install -m 0644 /etc/shadow
        # <allowlisted-dest>` then read the dest as the console user). A legit
        # source may be any console-owned file, but never a deny-listed secret —
        # reject sources in PATH_DENY.
        for src in paths[:-1]:
            sp = os.path.normpath(src)
            if sp in PATH_DENY_EXACT or any(sp.startswith(d) for d in PATH_DENY_PREFIX):
                raise Denied(f'install: source not permitted: {src}')


# systemd-run is a DIRECT root-exec primitive (it can launch any command as root,
# and via --property=ExecStartPre=/--scope/--pty etc. inject more). It is allowed
# ONLY in the exact shape the kernel-patch job uses: the fixed transient unit name
# running the fixed, broker-written /var/lib/infratak-kernel-patch.sh, with only
# the StandardOutput/StandardError append-to-the-known-log properties and the
# exact --setenv strings the job uses. This is no broader than `systemctl start`
# of a console-written unit (already allowed); anything else is denied.
_KPATCH_UNIT_NAME = 'infratak-kernel-patch'
_KPATCH_SCRIPT = '/var/lib/infratak-kernel-patch.sh'
_KPATCH_LOG = '/var/log/takguard/kernel-patch.log'
_SYSTEMD_RUN_ALLOWED_PROPERTIES = {
    'StandardOutput=append:' + _KPATCH_LOG,
    'StandardError=append:' + _KPATCH_LOG,
}
# env vars are not exec, BUT they can turn the fixed `/bin/bash <script>` into
# arbitrary root exec: BASH_ENV/ENV source a file in a non-interactive shell,
# LD_PRELOAD/LD_LIBRARY_PATH hijack the loader, and even PATH=<attacker dir>
# redirects the script's bare `apt-get`/`dnf`. The whole invocation is a fixed
# shape, so pin the EXACT --setenv strings (key AND value), not just keys.
_SYSTEMD_RUN_ALLOWED_SETENV = {
    'DEBIAN_FRONTEND=noninteractive',
    'NEEDRESTART_MODE=a',
    'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
}


# v10.0.8: second fixed systemd-run shape — the non-root migration job
# (app.py console_migrate_nonroot_api). Only launched by a ROOT console (the
# route refuses non-root), but permissive root boxes route it through the broker
# for audit, so the shape must be in the rulebook or it pollutes the clean-audit
# flip gate with WOULD-DENY noise. Same inherent power as the kernel-patch job.
_MIGRATE_UNIT_NAME = 'infratak-nonroot-migrate'
_MIGRATE_LOG = '/var/log/takwerx-console-nonroot-migrate.log'
_MIGRATE_SCRIPT_SUFFIX = '/scripts/migrate-console-nonroot.sh'
_MIGRATE_ALLOWED_PROPERTIES = {
    'StandardOutput=append:' + _MIGRATE_LOG,
    'StandardError=append:' + _MIGRATE_LOG,
    # RHEL/SELinux: the migrate unit must run unconfined (same treatment the
    # console + broker units already carry) — exact string, nothing else.
    'SELinuxContext=system_u:system_r:unconfined_service_t:s0',
}

# v10.3.0 W4: THIRD fixed systemd-run shape — the console-driven in-place Ubuntu
# 22.04 -> 24.04 upgrade (app.py _os_upgrade_start_job). Same inherent power as
# the kernel-patch job (root runs a console-written script), pinned the same way:
# this unit name, exactly `/bin/bash /var/lib/infratak-os-upgrade.sh`, the two
# append-log properties, and the kernel-patch --setenv allowlist plus ONE extra
# pinned by full KEY=VALUE: RELEASE_UPGRADER_NO_SCREEN=1. ubuntu-release-upgrader
# re-execs itself inside GNU screen unless that variable is set
# (DistUpgradeMain.py, ubuntu/noble), and a transient unit has no tty for screen.
# Nothing else widens; a fourth unit or an unpinned --setenv fails
# /redteam-selfaudit (REGRESSION:broker-systemd-run).
_OSUP_UNIT_NAME = 'infratak-os-upgrade'
_OSUP_SCRIPT = '/var/lib/infratak-os-upgrade.sh'
_OSUP_LOG = '/var/log/infratak-os-upgrade.log'
_OSUP_ALLOWED_PROPERTIES = {
    'StandardOutput=append:' + _OSUP_LOG,
    'StandardError=append:' + _OSUP_LOG,
}
_OSUP_ALLOWED_SETENV = _SYSTEMD_RUN_ALLOWED_SETENV | {
    'RELEASE_UPGRADER_NO_SCREEN=1',
}


def _check_systemd_run(argv):
    """Allow ONLY the three fixed transient-unit invocations: the kernel-patch job,
    the non-root migration job and the OS-upgrade job (v10.3.0 W4). Everything
    else is denied. --setenv values are pinned by FULL `KEY=VALUE` per unit — an
    env var is enough to turn the fixed `/bin/bash <script>` into arbitrary root
    exec (BASH_ENV, LD_PRELOAD, PATH), so the key alone is never enough."""
    saw_unit = None
    positionals = []
    props = []
    setenvs = []
    for a in argv[1:]:
        if positionals:
            # past the launched command — the rest are ITS args (validated as
            # part of the fixed positional shape below), not systemd-run flags
            positionals.append(a)
            continue
        if a in ('--no-block', '--collect'):
            continue
        if a.startswith('--unit='):
            unit = a.split('=', 1)[1]
            if unit not in (_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME, _OSUP_UNIT_NAME):
                raise Denied(f'systemd-run: only units {_KPATCH_UNIT_NAME}/'
                             f'{_MIGRATE_UNIT_NAME}/{_OSUP_UNIT_NAME} allowed')
            saw_unit = unit
            continue
        if a.startswith('--description='):
            continue
        if a.startswith('--property='):
            props.append(a.split('=', 1)[1])
            continue
        if a.startswith('--setenv='):
            setenvs.append(a.split('=', 1)[1])   # the FULL KEY=VALUE, checked per unit below
            continue
        if a.startswith('-'):
            raise Denied(f'systemd-run: flag not allowed: {a}')
        positionals.append(a)
    if saw_unit is None:
        raise Denied('systemd-run: missing required --unit=')
    allowed_setenv = _OSUP_ALLOWED_SETENV if saw_unit == _OSUP_UNIT_NAME else _SYSTEMD_RUN_ALLOWED_SETENV
    for s in setenvs:
        if s not in allowed_setenv:
            raise Denied(f'systemd-run: setenv not allowed: --setenv={s}')
    if saw_unit == _KPATCH_UNIT_NAME:
        for p in props:
            if p not in _SYSTEMD_RUN_ALLOWED_PROPERTIES:
                raise Denied(f'systemd-run: property not allowed: --property={p}')
        if positionals != ['/bin/bash', _KPATCH_SCRIPT]:
            raise Denied(f'systemd-run: only `/bin/bash {_KPATCH_SCRIPT}` allowed')
        return
    if saw_unit == _OSUP_UNIT_NAME:
        for p in props:
            if p not in _OSUP_ALLOWED_PROPERTIES:
                raise Denied(f'systemd-run: property not allowed: --property={p}')
        if positionals != ['/bin/bash', _OSUP_SCRIPT]:
            raise Denied(f'systemd-run: only `/bin/bash {_OSUP_SCRIPT}` allowed')
        return
    # migrate shape: /bin/bash <install>/scripts/migrate-console-nonroot.sh
    # --apply --auto-rollback. The install dir varies per box; the script is
    # console-written either way — same inherent near-root as a console-written
    # unit, so pin everything EXCEPT the install prefix.
    for p in props:
        if p not in _MIGRATE_ALLOWED_PROPERTIES:
            raise Denied(f'systemd-run: property not allowed: --property={p}')
    if (len(positionals) != 4 or positionals[0] != '/bin/bash'
            or not positionals[1].endswith(_MIGRATE_SCRIPT_SUFFIX)
            or '..' in positionals[1].split('/')
            or positionals[2:] != ['--apply', '--auto-rollback']):
        raise Denied('systemd-run: only `/bin/bash <install>%s --apply '
                     '--auto-rollback` allowed' % _MIGRATE_SCRIPT_SUFFIX)


def _check_systemctl(argv):
    """Allow only safe systemctl verbs. `link`/`edit`/`set-property`/
    `set-environment`/`switch-root` can run arbitrary root code or point a unit
    at console-controlled content, so they are denied."""
    for a in argv[1:]:
        if a.startswith('-'):
            continue               # global flag (--now, --no-block, -p, ...)
        if a in SYSTEMCTL_VERBS:
            return                 # first non-flag token is the verb
        raise Denied(f'systemctl verb not allowed: {a}')
    return                         # no verb (e.g. `systemctl --version`) — fine


def _mode_setid_bits(mode):
    """-> (setuid, setgid) a chmod/install MODE grants."""
    m = (mode or '').strip()
    if re.fullmatch(r'[0-7]{1,5}', m):
        d = int(m[-4]) if len(m) >= 4 else 0
        return bool(d & 4), bool(d & 2)
    suid = sgid = False
    for clause in m.split(','):
        for op in ('+', '='):
            if op in clause and 's' in clause.split(op, 1)[1]:
                who = clause.split(op, 1)[0] or 'a'
                suid = suid or any(c in who for c in 'ua')
                sgid = sgid or any(c in who for c in 'ga')
    return suid, sgid


def _check_mode_no_setid(mode, what, dirs_ok=False):
    """ops #645 W0: refuse a setuid/setgid bit. Root setting 4755 on a file the
    console wrote (or can write) is a root shell; no console call site sets one.
    Setgid on a DIRECTORY only makes new files inherit the group (the console runs
    `chmod 2775 /usr/local/etc`): allowed when the caller has checked that every
    target is a real directory (dirs_ok)."""
    suid, sgid = _mode_setid_bits(mode)
    if suid or (sgid and not dirs_ok):
        raise Denied(f'{what}: setuid/setgid mode not allowed: {mode}')


def _all_real_dirs(paths):
    """True when every path is an existing directory and not a symlink."""
    for p in paths:
        try:
            st = os.lstat(p)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode):
            return False
    return bool(paths)


def _check_path_args(base, argv, cwd=None):
    """For coreutils that mutate/read files, EVERY non-flag path argument must
    resolve (against the request cwd) into PATH_ALLOW and out of PATH_DENY.
    Relative args are NOT exempt — they are joined to cwd first, because the
    daemon honours a caller-supplied cwd (so `tee passwd` with cwd=/etc would
    otherwise hit /etc/passwd)."""
    base_cwd = cwd if (cwd and isinstance(cwd, str) and cwd.startswith('/')) else '/'
    # chmod/chown take a non-path first positional (the MODE / OWNER:GROUP) which
    # must NOT be treated as a path operand.
    skip_first_positional = base in ('chmod', 'chown')
    seen_positional = False
    checked, raw, owner_spec = [], [], None
    # ops #645 W2: only the flags each tool really uses (code scan + fleet audit
    # logs). Other flags carried paths past the check: `chmod -w,o+w /etc/passwd`
    # (GNU chmod reads a dash mode, and the file was skipped as "the mode"),
    # `chown --reference=F /etc/passwd`, `mv|ln --target-directory=/etc/sudoers.d`.
    allowed = _COREUTIL_FLAGS.get(base)
    for a in argv[1:]:
        if not a.startswith('-'):
            continue
        if allowed is None or not (a in allowed or (base == 'chown' and a.startswith('--from='))
                                   or (base == 'mkdir' and (a.startswith('--mode=')
                                                            or re.fullmatch(r'-m[0-7]{3,4}', a)))):
            raise Denied(f'{base}: option not allowed: {a}')
    if base == 'chmod':
        pos = [a for a in argv[1:] if not a.startswith('-')]
        if pos:
            targets = [p if p.startswith('/') else os.path.join(base_cwd, p) for p in pos[1:]]
            recursive = any(a in ('-R', '--recursive') or
                            (a.startswith('-') and not a.startswith('--') and 'R' in a)
                            for a in argv[1:])
            # setgid is fine on directories, but -R would also hit the files inside
            _check_mode_no_setid(pos[0], 'chmod',
                                 dirs_ok=not recursive and _all_real_dirs(targets))
    for a in argv[1:]:
        if base == 'chmod' and a.startswith('--reference'):
            raise Denied('chmod --reference not allowed (can copy a setuid bit)')
        if base == 'mkdir' and (a.startswith('--mode') or (a.startswith('-m') and len(a) > 2)):
            _check_mode_no_setid(a.split('=', 1)[1] if '=' in a else a[2:], 'mkdir',
                                 dirs_ok=True)
        if a == '--' or a.startswith('-'):
            continue               # flag — coreutils flags here don't take paths
        if skip_first_positional and not seen_positional:
            seen_positional = True
            owner_spec = a
            continue               # the MODE (chmod) / OWNER (chown) arg
        seen_positional = True
        # Everything else is a path operand and must be allowlisted.
        target = a if a.startswith('/') else os.path.join(base_cwd, a)
        checked.append(_path_allowed(target))   # raises Denied if outside allowlist
        raw.append(a)
    # ops #645 W2: no exec route around the content checks of root-run paths
    _check_exec_into_root_run(base, checked, link_args=raw if base == 'ln' else None)
    rr = [t for t in checked if _root_runs(t)]
    if rr and base == 'chown' and owner_spec is not None and not _owner_is_root(owner_spec):
        raise Denied(f'chown: root-run paths stay root-owned: {rr[0]}')
    if rr and base == 'chmod' and owner_spec is not None and _mode_lets_go_write(owner_spec):
        raise Denied(f'chmod: root-run paths may not be group/other-writable: {rr[0]}')


# ---------------------------------------------------------------------------
# Audit log  (single chokepoint — Compliance C3/C7)
# ---------------------------------------------------------------------------
def _make_audit_logger():
    log = logging.getLogger('takwerx-broker-audit')
    log.setLevel(logging.INFO)
    if log.handlers:
        return log
    try:
        os.makedirs(AUDIT_DIR, exist_ok=True)
        os.chmod(AUDIT_DIR, 0o750)
        h = logging.handlers.RotatingFileHandler(
            AUDIT_LOG, maxBytes=20 * 1024 * 1024, backupCount=10)
    except OSError:
        h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    log.addHandler(h)
    # also mirror to journal/stderr so `journalctl -u takwerx-broker` shows it
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(sh)
    return log


AUDIT = None
# post-flip DENY visibility (PLAN-v10.0.8 §C): count denials since daemon start
# so the Cyber Controls card can surface them (read via ping — the console
# cannot read the audit log dir directly). WARNING level makes them stand out
# in `journalctl -u takwerx-broker -p warning`.
_DENY_LOCK = threading.Lock()
_DENY_COUNT = 0


def audit(peer, op, summary, verdict, detail=''):
    global _DENY_COUNT
    if AUDIT is None:
        return
    rec = {
        'op': op, 'verdict': verdict, 'summary': summary,
        'peer_uid': peer[1] if peer else None,
        'peer_pid': peer[0] if peer else None,
    }
    if detail:
        rec['detail'] = detail[:500]
    if verdict == 'DENY':
        with _DENY_LOCK:
            _DENY_COUNT += 1
        AUDIT.warning(json.dumps(rec))
    else:
        AUDIT.info(json.dumps(rec))


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------
def _peercred(sock):
    """(pid, uid, gid) of the connecting process via SO_PEERCRED — kernel-
    provided identity, unforgeable."""
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize('3i'))
        return struct.unpack('3i', creds)   # (pid, uid, gid)
    except (OSError, AttributeError):
        # AttributeError: SO_PEERCRED is Linux-only. Fail closed — a peer we
        # can't authenticate is rejected by _allowed_peer((-1)).
        return (-1, -1, -1)


def _allowed_peer(uid):
    """Only root or the console user may talk to the broker."""
    if uid == 0:
        return True
    try:
        return uid == pwd.getpwnam(BROKER_USER).pw_uid
    except KeyError:
        return False


def _recv_all(conn):
    buf = bytearray()
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > MAX_MSG:
            raise Denied('request exceeds MAX_MSG')
    return bytes(buf)


# Fixed, root-owned PATH used to resolve EVERY exec'd binary to a trusted
# absolute location (see _do_exec). Identical to the systemd-run gate's pinned
# PATH. Deliberately excludes /usr/local/* and anything writable by the console
# user, so a basename allowlist match can never resolve to a caller-planted
# binary.
BROKER_TRUSTED_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


def _do_exec(req):
    # NB: the allow/deny decision is made in _dispatch (so permissive mode can
    # execute-and-log). Do NOT re-validate the ALLOWLIST here or permissive mode
    # would block. The two steps below are EXECUTION-TIME HARDENING (not an
    # allow/deny decision): they normalize WHAT actually runs so a request that
    # passed the basename-only allowlist can't smuggle a different binary or a
    # loader-hijacking environment past it. They apply in both modes.
    argv = req.get('argv')
    if not isinstance(argv, list) or not argv:
        raise Denied('argv must be a non-empty list')
    # HARDENING (argv[0] spoof): check_exec matches the binary on basename ONLY,
    # but subprocess runs argv[0] verbatim — so argv[0]='/home/takwerx/x/systemctl'
    # would pass the allowlist (basename 'systemctl') yet execute the caller's
    # binary as root. Resolve the basename against a FIXED trusted PATH and run
    # THAT, ignoring any caller-supplied directory. Any argv[0] that carries a
    # directory but doesn't resolve onto the trusted PATH is refused. The bash/
    # runuser carve-outs reach here too, so their /tmp/bash spoof closes as well.
    _resolved = shutil.which(os.path.basename(argv[0]), path=BROKER_TRUSTED_PATH)
    if _resolved:
        argv = [_resolved] + list(argv[1:])
    elif '/' in argv[0]:
        raise Denied(f'exec path not on trusted PATH: {argv[0]}')
    inp = req.get('input_b64')
    input_bytes = base64.b64decode(inp) if inp else None
    timeout = min(int(req.get('timeout') or DEFAULT_TIMEOUT), MAX_TIMEOUT)
    cwd = req.get('cwd') or None
    if cwd and not (isinstance(cwd, str) and os.path.isdir(cwd)):
        cwd = None
    # ops #348: `docker compose --project-directory D` means "act as if run from D". Compose
    # resolves RELATIVE entries of COMPOSE_FILE (TAK Portal's `docker-compose.marketplace.yml` in
    # CloudTAK's .env) against the working directory, NOT --project-directory, so the caller's
    # cwd (the console's, usually `/`) made stop/up fail with "stat /docker-compose.marketplace.yml".
    # D is already in the argv check_exec saw; a caller could always send it as cwd, so this
    # grants nothing new.
    _pd = compose_project_dir(argv)
    if _pd:
        cwd = _pd
    # HARDENING (env injection): NEVER honor a caller-supplied `env`. check_exec
    # validates argv only; a merged-in LD_PRELOAD/LD_LIBRARY_PATH/BASH_ENV/ENV/PATH
    # turns ANY allowed binary into arbitrary root code (the same vector the
    # systemd-run gate pins exact --setenv strings against). No broker exec request
    # carries env (the CLI proxy can't forward it either), so dropping it removes
    # nothing legitimate. The child inherits the broker's own root env, plus only
    # the explicit apt non-interactive keys below.
    env = None
    if os.path.basename(argv[0]) in ('apt', 'apt-get'):
        env = dict(os.environ)
        env.setdefault('DEBIAN_FRONTEND', 'noninteractive')
        env.setdefault('NEEDRESTART_MODE', 'l')
        # DEBIAN_FRONTEND does not answer dpkg's conffile prompt: a package whose config
        # file is already on disk (the console writes /etc/caddy/Caddyfile before Caddy is
        # installed) died at "end of file on stdin at conffile prompt" and was left iU.
        # Keep the file on disk — the same choice the OS upgrade makes (L4). Fixed value,
        # set here because the -o Dpkg::Options form is denied by _check_pkgmgr.
        env.setdefault('DPKG_FORCE', 'confdef,confold')
    if _docker_cp_needs_stage(argv):
        # ops #645 W0 (hardening, both modes): a docker cp whose host path is not on
        # the allowlist never lets root open that path; the console user does the
        # host side with its own permissions.
        a = list(argv)
        if a[1] == 'container':
            a = [a[0], 'cp'] + a[3:]
        proc = _docker_cp_staged(a, timeout)
    else:
        # ops #645 W0 part 2 (both modes): a local .deb/.rpm installs only as a
        # root-checked copy (TAK release key, or Caddy's published SHA-512).
        argv, pkg_stage = _pkg_stage_verified(argv, cwd, timeout)
        try:
            proc = subprocess.run(argv, input=input_bytes, capture_output=True,
                                  timeout=timeout, cwd=cwd, env=env)
        finally:
            if pkg_stage:
                shutil.rmtree(pkg_stage, ignore_errors=True)
    return {
        'ok': True,
        'returncode': proc.returncode,
        'stdout_b64': base64.b64encode(proc.stdout or b'').decode(),
        'stderr_b64': base64.b64encode(proc.stderr or b'').decode(),
    }


def _is_console_owned(path):
    """True if `path` is under a console-WRITABLE allowlist prefix (bundle dir or
    a home module dir). Those dirs are owned by the console user, so it can plant
    a symlink at the target between the allowlist check and the write."""
    return any(path == p.rstrip('/') or path.startswith(p) for p in _CONSOLE_OWNED_PREFIXES)


def _write_all(fd, data):
    """os.write() until every byte is out (one call may write less than asked)."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _atomic_replace(path, content, perm):
    """Write `content` to `path` by temp file + rename, so a process that already has
    the old file open (a running bash script reads its source as it goes) keeps the OLD
    inode and finishes cleanly. ops #666 / infra-TAK #473: the in-place O_TRUNC write
    in _do_write rewrote tak-post-start.sh under a running unit and the unit died with
    exit 2.

    Returns True when done. Returns False, having changed nothing, when the target is a
    kind of file that must keep being written in place: a symlink, a non-regular file,
    a file with other hard links, or a mount point (rename gives EBUSY/EXDEV). Any other
    failure (disk full...) raises with the target untouched. It never falls back after a
    failed write: truncating the target then would be the very bug this fixes."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None and (not stat.S_ISREG(st.st_mode) or st.st_nlink > 1):
        return False
    d, base = os.path.split(path)
    tmp = os.path.join(d, '.%s.tmp-%d-%s' % (base, os.getpid(), os.urandom(4).hex()))
    # 0o600 until the final mode is set, so a secret never sits readable in the temp file.
    # A new file with no perm keeps the old 0o644 (subject to umask) via the open mode.
    create_mode = 0o644 if (st is None and perm is None) else 0o600
    # O_EXCL|O_NOFOLLOW: a planted link at the temp name can never be written through.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, create_mode)
    try:
        try:
            if perm is not None:
                os.fchmod(fd, int(perm))
            elif st is not None:
                os.fchmod(fd, stat.S_IMODE(st.st_mode))
            if st is not None:
                try:
                    os.fchown(fd, st.st_uid, st.st_gid)
                except OSError:
                    pass
                try:   # keep the SELinux label an in-place write would have kept (Rocky)
                    os.setxattr(tmp, 'security.selinux', os.getxattr(path, 'security.selinux'))
                except (OSError, AttributeError):
                    pass
            _write_all(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.rename(tmp, path)
        except OSError as e:
            if e.errno in (errno.EBUSY, errno.EXDEV):
                os.unlink(tmp)
                return False
            raise
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:   # make the rename itself durable; best effort
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
    return True


def _do_write(req):
    # Decision made in _dispatch; here only normalize (reject NUL/traversal) so
    # permissive mode can still execute an off-allowlist write (console is root).
    # We deliberately follow symlinks for ROOT-owned prefixes (a non-root console
    # cannot plant a symlink there, and legit targets like /etc/os-release ->
    # /usr/lib/os-release must resolve). For CONSOLE-OWNED prefixes the console
    # CAN swap the final component to a symlink after the allowlist check passed
    # (TOCTOU), so open the final component O_NOFOLLOW there — a swapped symlink
    # then fails the open instead of redirecting a root write off-allowlist.
    path = _abs(req.get('path'))
    content = base64.b64decode(req.get('content_b64') or '')
    mode = req.get('mode', 'w')
    append = mode in ('a', 'ab')
    # ops #666: `atomic` is the console asking for temp file + rename (scripts a running
    # process may be reading). Full-file writes only; append stays in place. Opt-in per
    # request because a rename breaks a single-file bind mount into a container and a log
    # a running process holds open, and in-place writes keep both working.
    if req.get('atomic') is True and not append:
        if _atomic_replace(path, content, req.get('perm')):
            return {'ok': True}
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    if _is_console_owned(path):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o644)
    try:
        if content:
            os.write(fd, content)
        perm = req.get('perm')
        if perm is not None:
            os.fchmod(fd, int(perm))   # fchmod on the fd — never re-resolves the path
    finally:
        os.close(fd)
    return {'ok': True}


def _do_read(req):
    path = _abs(req.get('path'))   # decision in _dispatch; normalize only here
    try:
        with open(path, 'rb') as f:
            data = f.read(MAX_MSG)
    except FileNotFoundError:
        # An allowlisted path that simply doesn't exist is a MISS, not a broker
        # ERROR — poll-before-exists reads (e.g. the kernel-patch log before any
        # patch has run) must not pollute the audit ERROR stream. The access
        # decision was already audited ALLOW in _dispatch; surface a benign
        # not-found so the caller's _read_priv raises (absent), as before, but
        # the handler's generic except never logs ERROR for it.
        return {'ok': False, 'code': 'ENOENT', 'error': 'not found'}
    return {'ok': True, 'content_b64': base64.b64encode(data).decode()}


# ---------------------------------------------------------------------------
# pg_dump-to-FILE op (v10.0.8 — PLAN §B). The non-root snapshot path could not
# stream a pg_dump through the exec proxy (MAX_MSG 32MiB cap → the DB dump was
# skipped and snapshots shipped config-only). This op has the BROKER write the
# dump to disk itself: it opens the destination file as root and runs
# `runuser -u postgres -- pg_dump -Fc <db>` with stdout pointed at it, so the
# socket never carries the dump. Fail-closed in BOTH broker modes (a brand-new
# op has no root-era behavior for permissive mode to preserve).
# ---------------------------------------------------------------------------
SNAPSHOT_DIR = '/opt/tak/snapshots'
# Container-TAK installs keep the cot DB INSIDE this container (no host postgres
# user/cluster) — the op then runs `docker exec -u postgres <this> pg_dump`.
# Fixed name; any other container is denied.
_PG_DUMP_CONTAINER = 'takserver-db'
# v10.2.3: pg_dump waits forever for its table locks by default — one session holding
# an exclusive lock on a cot table stalled the 5.8 pre-migration backup for the whole
# window (lutak.net 2026-10-02). Fail after this and let the console name the holder.
# Same value as the console's _COT_DUMP_LOCK_WAIT.
_PG_DUMP_LOCK_WAIT = '120s'
# v10.2.12: the console sizes the dump window from the cot database (10 min + 15 min/GB);
# clamping it to DEFAULT_TIMEOUT killed a healthy 14 GB dump mid-COPY (infra-TAK #126).
# Capped at the 6 h the tak58 migration op allows. Same value as the console's _COT_DUMP_MAX_S.
_PG_DUMP_MAX_TIMEOUT = 6 * 3600
# Dump-authenticity key (SECURITY, v10.0.8): the snapshot dir lives under the
# console-writable /opt/tak/ prefix, so the console CAN write arbitrary bytes to
# a *.pgdump path. Restoring an attacker-crafted pg custom archive would run its
# embedded TOC (COPY … FROM PROGRAM / plpython) as the postgres superuser — a
# documented postgres→root pivot, and exactly the code-exec the psql gate
# (_PSQL_FORBIDDEN) exists to deny. So the broker HMACs every dump it PRODUCES
# (sidecar <path>.hmac) and refuses to pg_restore any file whose HMAC does not
# verify. The key is root-only (0600); the console cannot forge the sidecar.
_DUMP_HMAC_KEY_FILE = '/var/lib/takwerx-broker/dump.key'


def _dump_hmac_key():
    """Read (or create once) the root-only key used to authenticate broker dumps."""
    try:
        with open(_DUMP_HMAC_KEY_FILE, 'rb') as f:
            k = f.read()
            if len(k) >= 32:
                return k
    except OSError:
        pass
    k = os.urandom(32)
    try:
        os.makedirs(os.path.dirname(_DUMP_HMAC_KEY_FILE), exist_ok=True)
        tmp = _DUMP_HMAC_KEY_FILE + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, k)
        os.close(fd)
        os.replace(tmp, _DUMP_HMAC_KEY_FILE)
    except OSError:
        pass   # can't persist — HMAC then only holds within this boot; still fail-closed
    return k


def _dump_hmac(path):
    import hashlib
    import hmac as _hmac
    h = _hmac.new(_dump_hmac_key(), digestmod=hashlib.sha256)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


# PGMiner incident-response scan (v10.0.8 — closes harvest class 9). The CloudTAK
# postgis (and TAK Server) databases were exploited in the wild by a crypto-miner
# that drops a malicious `.so` into the postgres data dir and auto-loads it via
# shared_preload_libraries (see the May 2026 incident). The console's scanner needs
# to read/quarantine files in that data dir, which lives in a ROOT-owned docker
# volume with a random name — un-allowlistable, and it must work with the container
# STOPPED (host access, not `docker exec`). Rather than open the whole
# /var/lib/docker/volumes tree to the console, the broker does the fixed, safe
# remediation ITSELF, scoped to an allowlisted postgres container's own volume:
# find `.so` at depth 1, quarantine them, and comment out a live
# shared_preload_libraries. It NEVER writes attacker-controlled content (no .so
# writes, no arbitrary conf) — so it cannot be turned into a malware-plant.
_PGMINER_CONTAINERS = {'cloudtak-postgis-1', 'takserver-db'}


def _check_pgminer_scan(req):
    c = req.get('container')
    if c not in _PGMINER_CONTAINERS:
        raise Denied(f'pgminer_scan: container not allowed: {c!r}')


def _resolve_pg_data_dir(container):
    """Host path of `container`'s /var/lib/postgresql/data mount, or None. Works on
    a stopped-but-existing container. Constrained to a real docker-volume _data
    path so a renamed/hostile container can't redirect it off-volume."""
    docker = shutil.which('docker', path=BROKER_TRUSTED_PATH)
    if not docker:
        return None
    try:
        r = subprocess.run(
            [docker, 'inspect', container, '-f',
             '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}'
             '{{.Source}}{{end}}{{end}}'],
            capture_output=True, text=True, timeout=15)
    except subprocess.SubprocessError:
        return None
    p = (r.stdout or '').strip()
    if (r.returncode == 0 and p.startswith('/var/lib/docker/volumes/')
            and p.endswith('/_data') and '..' not in p.split('/') and os.path.isdir(p)):
        return p
    return None


def _do_pgminer_scan(req):
    container = req.get('container')
    data = _resolve_pg_data_dir(container)
    if not data:
        return {'ok': False, 'error': f'could not resolve postgres data volume for {container}'}
    out = {'ok': True, 'container': container, 'data_dir': data,
           'so_files': [], 'quarantined': [], 'preload_disabled': False, 'preload_was': None}
    # 1. malicious .so at depth 1 (the shared_preload payload)
    try:
        so = [f for f in os.listdir(data)
              if f.endswith('.so') and os.path.isfile(os.path.join(data, f))]
    except OSError as e:
        return {'ok': False, 'error': f'listdir failed: {e}'}
    out['so_files'] = so
    if so:
        qdir = os.path.join(data, 'quarantine-' + time.strftime('%Y%m%d-%H%M%S'))
        try:
            os.makedirs(qdir, exist_ok=True)
            for f in so:
                try:
                    os.replace(os.path.join(data, f), os.path.join(qdir, f))
                    out['quarantined'].append(f)
                except OSError:
                    pass
        except OSError as e:
            out['quarantine_error'] = str(e)
    # 2. comment out a live shared_preload_libraries (the auto-load hook)
    conf = os.path.join(data, 'postgresql.conf')
    try:
        with open(conf) as f:
            body = f.read()
    except OSError:
        body = ''
    if body:
        import re as _re
        pat = _re.compile(
            r"(?m)^([ \t]*shared_preload_libraries[ \t]*=[ \t]*['\"](.*?)['\"])")
        m = pat.search(body)
        if m and m.group(2).strip():
            out['preload_was'] = m.group(2)
            new = pat.sub(lambda mm: '#INFRATAK_DISABLED# ' + mm.group(1), body)
            try:
                with open(conf, 'w') as f:
                    f.write(new)
                out['preload_disabled'] = True
            except OSError as e:
                out['preload_error'] = str(e)
    out['compromised'] = bool(out['quarantined'] or out['preload_disabled'])
    return out


def _check_pg_dump(req):
    path = req.get('path')
    p = _abs(path)
    # /opt/tak is a symlink on container installs — compare realpaths (the tree
    # is root-owned, so following links here is safe).
    if not _within_realpath(p, SNAPSHOT_DIR):
        raise Denied(f'pg_dump: destination must be under {SNAPSHOT_DIR}/: {p}')
    db = req.get('db') or 'cot'
    if not (isinstance(db, str) and db.replace('_', '').isalnum()):
        raise Denied(f'pg_dump: invalid database name: {db!r}')
    container = req.get('container')
    if container is not None and container != _PG_DUMP_CONTAINER:
        raise Denied(f'pg_dump: only container {_PG_DUMP_CONTAINER} allowed: {container!r}')



# ── TAK 5.8 database migration (infra-TAK v10.2.0 W4b) ──────────────────────
# TAK 5.8's package refuses to finish on a PostgreSQL 15 server and tells the
# operator to run /opt/tak/db-utils/upgrade-db.sh by hand. Between those two
# steps TAK is DOWN, so infra-TAK drives both as one operation — which means the
# unprivileged console must be able to run that script.
#
# This is a real privilege grant: the script runs as root, calls pg_upgrade,
# su - postgres, and systemctl. It is bounded as tightly as that allows:
#   * ONE hard-coded path. Not caller-supplied, not a prefix, not a glob.
#   * NO caller argv, env, or cwd reaches it.
#   * The file must be root-owned and not group/world-writable — checked at call
#     time, not trusted from install time. If a non-root user can rewrite the
#     script, running it would launder their code to root through us; refusing on
#     a bad mode is the difference between a bounded grant and a backdoor.
#   * It must be a regular file, not a symlink (checked with lstat), so a swapped
#     symlink cannot redirect the grant at another executable.
# Vendor-owned content is the residual risk we accept: we are choosing to run
# TAK's migration script as root, deliberately, because the alternative is an
# operator doing exactly that by hand with the server already down.
_TAK58_UPGRADE_DB = '/opt/tak/db-utils/upgrade-db.sh'
# TAK's schema setup, which runs SchemaManager. Needed as its own op because the
# 5.8 migration can leave the schema un-applied (EL md5->scram, see app.py) and the
# repair has to re-run it. Same bound: one fixed path, no caller argv.
_TAK58_SETUP_DB = '/opt/tak/db-utils/takserver-setup-db.sh'


def _check_tak58_script(req, path, opname):
    if req.get('argv') or req.get('cwd') or req.get('env'):
        raise Denied('%s: takes no argv/cwd/env' % opname)
    try:
        st = os.lstat(path)
    except OSError:
        raise Denied(f'{opname}: {path} not present (is TAK Server 5.8 installed?)')
    if stat.S_ISLNK(st.st_mode):
        raise Denied(f'{opname}: refusing a symlink')
    if not stat.S_ISREG(st.st_mode):
        raise Denied(f'{opname}: not a regular file')
    # OWNERSHIP — measured, not assumed. TAK 5.8-RELEASE75 ships this script
    # `tak:tak` mode 544 (verified on dev-4, 2026-09-01), NOT root-owned, so a
    # root-only rule refuses every real box. Accept root or the `tak` service
    # account that the package installs it under, and nothing else.
    #
    # Residual risk, stated plainly rather than engineered around: the `tak` user
    # can chmod and rewrite a file it owns, so tak -> root is reachable through
    # this op. That is NOT a risk we introduce — TAK's own documented instruction
    # is `sudo /opt/tak/db-utils/upgrade-db.sh`, which grants exactly the same
    # thing to exactly the same user, and TAK Server already runs as `tak`. We
    # automate the vendor's step; we do not widen it. What we DO add over the
    # manual path is the write-permission check below: a script any *other* local
    # user could edit is refused outright.
    _allowed_uids = {0}
    try:
        _allowed_uids.add(pwd.getpwnam('tak').pw_uid)
    except KeyError:
        pass
    if st.st_uid not in _allowed_uids:
        raise Denied(f'{opname}: {path} is owned by uid {st.st_uid}, expected root or the '
                     'tak service account — refusing to run it as root')
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Denied(f'{opname}: {path} is group/world-writable '
                     f'(mode {oct(st.st_mode & 0o7777)}) — refusing to run it as root')
    return True


def _check_tak58_upgrade_db(req):
    return _check_tak58_script(req, _TAK58_UPGRADE_DB, 'tak58_upgrade_db')


def _check_tak58_setup_db(req):
    return _check_tak58_script(req, _TAK58_SETUP_DB, 'tak58_setup_db')


def _do_tak58_script(req, path, opname):
    """Run the vendor migration, streaming combined output back to the caller.

    The script has no shebang and uses bashisms, so /bin/sh (dash on Ubuntu) emits
    noise while still doing its job — the exit code is the only verdict, and the
    caller is told as much. Deliberately run under `sh` exactly as the vendor's own
    instructions do, so we reproduce the supported path rather than a variant.
    """
    _check_tak58_script(req, path, opname)
    sh = shutil.which('sh', path=BROKER_TRUSTED_PATH)
    if not sh:
        return {'ok': False, 'error': 'sh not found on trusted PATH'}
    timeout = min(int(req.get('timeout') or 6 * 3600), 6 * 3600)
    try:
        proc = subprocess.run([sh, path], cwd='/',
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': f'{opname} exceeded {timeout}s'}
    out = (proc.stdout or b'').decode(errors='replace')
    return {'ok': proc.returncode == 0, 'returncode': proc.returncode,
            'output': out[-60000:]}


def _do_tak58_upgrade_db(req):
    return _do_tak58_script(req, _TAK58_UPGRADE_DB, 'tak58_upgrade_db')


def _do_tak58_setup_db(req):
    return _do_tak58_script(req, _TAK58_SETUP_DB, 'tak58_setup_db')


def _do_pg_dump(req):
    path = _abs(req.get('path'))
    db = req.get('db') or 'cot'
    if req.get('container'):
        docker = shutil.which('docker', path=BROKER_TRUSTED_PATH)
        if not docker:
            return {'ok': False, 'error': 'docker not found on trusted PATH'}
        argv = [docker, 'exec', '-u', 'postgres', _PG_DUMP_CONTAINER,
                'pg_dump', '--lock-wait-timeout=' + _PG_DUMP_LOCK_WAIT, '-Fc', db]
    else:
        runuser = shutil.which('runuser', path=BROKER_TRUSTED_PATH)
        pg_dump = shutil.which('pg_dump', path=BROKER_TRUSTED_PATH)
        if not runuser or not pg_dump:
            return {'ok': False, 'error': 'runuser/pg_dump not found on trusted PATH'}
        argv = [runuser, '-u', 'postgres', '--', pg_dump,
                '--lock-wait-timeout=' + _PG_DUMP_LOCK_WAIT, '-Fc', db]
    return _dump_to_file(argv, path, req.get('timeout'), 'pg_dump')


def _dump_to_file(argv, path, timeout, opname, sidecar=True):
    """Run a dump argv with stdout pointed at a root-opened `path`, then chmod 0600
    and write the HMAC sidecar (`sidecar=False` for non-pg_restore output such as the
    Node-RED tar). Shared by pg_dump, stack_pg_dump and stack_nodered_tar."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    timeout = min(int(timeout or DEFAULT_TIMEOUT), _PG_DUMP_MAX_TIMEOUT)
    # stdout goes straight to the root-opened file — the 32MiB socket cap never
    # applies, and postgres needs no write access to the snapshot dir.
    # Own session: a timeout kills pg_dump itself, not just runuser — an orphaned
    # pg_dump kept its table locks and snapshot open until this daemon restarted.
    # (With `docker exec` the pg_dump inside the container outlives the client;
    # the lock-wait cap is what bounds that case.)
    # O_NOFOLLOW: a symlink planted at the destination must not redirect a root
    # write (the backup tree is on the write allowlist for config copies).
    for p_ in (path, path + '.hmac'):
        if os.path.islink(p_):
            os.unlink(p_)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            err = proc.communicate(timeout=timeout)[1]
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.communicate()
            err = None
    if err is None:
        try:
            os.unlink(path)
        except OSError:
            pass
        return {'ok': False, 'error': '%s did not finish within %d s' % (opname, timeout)}
    if proc.returncode != 0:
        try:
            os.unlink(path)    # never leave a truncated/empty dump behind
        except OSError:
            pass
        return {'ok': False, 'returncode': proc.returncode,
                'error': (err or b'').decode(errors='replace')[:500]}
    os.chmod(path, 0o600)
    # Authenticity sidecar — proves the broker produced this dump, so pg_restore
    # will accept it (and reject any console-planted archive). Best-effort: if the
    # sidecar can't be written, restore simply won't trust the dump later.
    try:
        if sidecar:
            sc = path + '.hmac'
            fd = os.open(sc, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            os.write(fd, _dump_hmac(path).encode())
            os.close(fd)
    except OSError:
        pass
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return {'ok': True, 'size': os.path.getsize(path), 'sha256': h.hexdigest()}


# ── Full-stack backup DB dumps (infra-TAK v10.3.0 W12.b) ─────────────────────
# The module databases (Authentik, TAK Portal, CloudTAK) live inside their own
# postgres containers. The console names the container; the broker supplies the
# role and database from this fixed table — nothing caller-supplied reaches the
# argv but the container key. Destination: <STACK_BACKUP_DIR>/<label>/<file>.pgdump
# only, one level deep, so a dump can never land elsewhere or nest.
STACK_BACKUP_DIR = '/var/lib/infratak-backups'
_STACK_PG_CONTAINERS = {
    'authentik-postgresql-1': ('authentik', 'authentik'),
    'tak-portal-postgres':    ('takportal', 'takportal'),
    'cloudtak-postgis-1':     ('docker', 'gis'),
}


def _stack_backup_name_ok(name):
    return (isinstance(name, str) and 0 < len(name) <= 96
            and name[0].isalnum() and all(c.isalnum() or c in '-_.' for c in name)
            and '..' not in name)


def _check_stack_pg_dump(req):
    container = req.get('container')
    if container not in _STACK_PG_CONTAINERS:
        raise Denied(f'stack_pg_dump: container not allowed: {container!r}')
    p = _abs(req.get('path'))
    rel = p[len(STACK_BACKUP_DIR) + 1:] if p.startswith(STACK_BACKUP_DIR + '/') else ''
    parts = rel.split('/')
    if (len(parts) != 2 or not _stack_backup_name_ok(parts[0])
            or not _stack_backup_name_ok(parts[1]) or not parts[1].endswith('.pgdump')):
        raise Denied(f'stack_pg_dump: destination must be {STACK_BACKUP_DIR}/<label>/<name>.pgdump: {p}')
    return p


def _do_stack_pg_dump(req):
    path = _check_stack_pg_dump(req)
    user, db = _STACK_PG_CONTAINERS[req['container']]
    docker = shutil.which('docker', path=BROKER_TRUSTED_PATH)
    if not docker:
        return {'ok': False, 'error': 'docker not found on trusted PATH'}
    # Root 0711 (pass-through, no listing: the console reaches only its own .dl-*
    # staging dirs); each backup dir 0700. Refuse symlinks at either level.
    for d, mode in ((STACK_BACKUP_DIR, 0o711), (os.path.dirname(path), 0o700)):
        if os.path.islink(d):
            return {'ok': False, 'error': f'refusing symlinked backup dir: {d}'}
        os.makedirs(d, mode=mode, exist_ok=True)
        os.chmod(d, mode)
    argv = [docker, 'exec', req['container'], 'pg_dump', '-U', user,
            '--lock-wait-timeout=' + _PG_DUMP_LOCK_WAIT, '-Fc', db]
    return _dump_to_file(argv, path, req.get('timeout'), 'stack_pg_dump')


# v10.3.x: the Node-RED archive (global context, config-backups, flows). The tar used
# to stream through the exec proxy, so one reply carried it base64-encoded and a busy
# Node-RED (test12: 26.7 MB tar) passed MAX_MSG — "Back up now" ended INCOMPLETE. Like
# the pg dumps, the broker now writes it to disk itself. Nothing caller-supplied reaches
# the argv: the container and the script are fixed here; the caller names only the label.
_STACK_NODERED_CONTAINER = 'nodered'
_STACK_NODERED_TAR_NAME = 'nodered-data.tar'
_STACK_NODERED_TAR_SH = ('cd / && set -- && for p in data/context data/config-backups data/flows.json '
                         'data/flows_cred.json; do [ -e "$p" ] && set -- "$@" "$p"; done; '
                         '[ $# -gt 0 ] && exec tar -cf - "$@"')


def _check_stack_nodered_tar(req):
    p = _abs(req.get('path'))
    rel = p[len(STACK_BACKUP_DIR) + 1:] if p.startswith(STACK_BACKUP_DIR + '/') else ''
    parts = rel.split('/')
    if (len(parts) != 2 or not _stack_backup_name_ok(parts[0])
            or parts[1] != _STACK_NODERED_TAR_NAME):
        raise Denied(f'stack_nodered_tar: destination must be '
                     f'{STACK_BACKUP_DIR}/<label>/{_STACK_NODERED_TAR_NAME}: {p}')
    return p


def _do_stack_nodered_tar(req):
    path = _check_stack_nodered_tar(req)
    docker = shutil.which('docker', path=BROKER_TRUSTED_PATH)
    if not docker:
        return {'ok': False, 'error': 'docker not found on trusted PATH'}
    for d, mode in ((STACK_BACKUP_DIR, 0o711), (os.path.dirname(path), 0o700)):
        if os.path.islink(d):
            return {'ok': False, 'error': f'refusing symlinked backup dir: {d}'}
        os.makedirs(d, mode=mode, exist_ok=True)
        os.chmod(d, mode)
    argv = [docker, 'exec', _STACK_NODERED_CONTAINER, 'sh', '-c', _STACK_NODERED_TAR_SH]
    res = _dump_to_file(argv, path, req.get('timeout'), 'stack_nodered_tar', sidecar=False)
    if res.get('ok') and not res.get('size'):
        try:
            os.unlink(path)
        except OSError:
            pass
        return {'ok': False, 'error': 'nodered tar is empty'}
    return res


def _check_pg_restore(req):
    # same gate as pg_dump: source file must live under the snapshot tree
    _check_pg_dump(req)


def _newest_pg_client(name):
    """Highest-versioned PostgreSQL client binary on this host, else PATH lookup.

    pg_restore REFUSES an archive written by a newer pg_dump:

        pg_restore: error: unsupported version (1.16) in file header

    `shutil.which` returns Debian's pg_wrapper, which selects the DEFAULT cluster
    version — on a TAK box that is 15, because TAK's own package depends on
    postgresql-15. Once a managed database has been upgraded to 18 (which the 5.8
    pre-flight requires), the console dumps it with an 18 client and this
    verification step could no longer read the result, failing the pre-migration
    backup and blocking the update with a message about a corrupt archive when the
    archive was fine. Measured against az-test-rds 18.6, 2026-09-19: pg_restore 15
    rejected the file header, pg_restore 18 read 522 TOC entries from it.

    Only versioned binaries in the distributions' own root-owned directories are
    considered, by exact pattern — this must not become a way to point the broker
    at an attacker-writable binary, which is the whole reason BROKER_TRUSTED_PATH
    exists. Each candidate must be a regular file, owned by root, and not writable
    by group or other.
    """
    best = None
    for pattern in ('/usr/lib/postgresql/%d/bin/', '/usr/pgsql-%d/bin/'):
        for major in range(30, 8, -1):
            cand = (pattern % major) + name
            try:
                st = os.stat(cand)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_uid != 0 or (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                continue
            if not os.access(cand, os.X_OK):
                continue
            if best is None or major > best[0]:
                best = (major, cand)
            break
    if best:
        return best[1]
    return shutil.which(name, path=BROKER_TRUSTED_PATH)


def _do_pg_restore(req):
    """Symmetric to _do_pg_dump (v10.0.8 §B): the broker opens the snapshot dump
    as root and feeds it to pg_restore's stdin — the dump never crosses the
    socket (the old stage-copy + exec-proxy path hit the 32MiB cap on any real
    database). NB: pg_restore exits 1 on non-fatal warnings; the returncode is
    passed through for the caller to interpret, as before."""
    path = _abs(req.get('path'))
    db = req.get('db') or 'cot'
    if not os.path.isfile(path):
        return {'ok': False, 'code': 'ENOENT', 'error': f'dump not found: {path}'}
    # AUTHENTICITY (v10.0.8): only restore a dump the broker itself produced —
    # verify the HMAC sidecar. Without this, the console (which can write bytes to
    # the /opt/tak/snapshots tree) could restore a crafted archive whose TOC runs
    # code as the postgres superuser. Constant-time compare.
    import hmac as _hmac
    try:
        with open(path + '.hmac') as f:
            want = f.read().strip()
    except OSError:
        want = ''
    if not want or not _hmac.compare_digest(want, _dump_hmac(path)):
        return {'ok': False, 'code': 'DENIED',
                'error': 'dump failed authenticity check — not a broker-produced snapshot'}
    # v10.2.0 W3: list_only — prove an archive is READABLE without restoring it.
    # The console cannot do this itself: broker-written dumps are root-owned 0600,
    # and `runuser -u postgres -- pg_restore` therefore gets EACCES. Reading the
    # TOC needs no database at all, so it runs as root here and returns a count.
    # The HMAC compare above already proves the bytes are intact; parsing the TOC
    # additionally proves the archive is well-formed, which is what a pre-migration
    # backup check is actually claiming.
    if req.get('list_only'):
        pg_restore = _newest_pg_client('pg_restore')
        if not pg_restore:
            return {'ok': False, 'error': 'pg_restore not found on trusted PATH'}
        proc = subprocess.run([pg_restore, '--list', path],
                              capture_output=True, timeout=600)
        out = (proc.stdout or b'').decode(errors='replace')
        toc = [l for l in out.splitlines() if l.strip() and not l.lstrip().startswith(';')]
        return {'ok': proc.returncode == 0 and bool(toc),
                'returncode': proc.returncode, 'toc_entries': len(toc),
                'error': (proc.stderr or b'').decode(errors='replace')[:400]}
    if req.get('container'):
        docker = shutil.which('docker', path=BROKER_TRUSTED_PATH)
        if not docker:
            return {'ok': False, 'error': 'docker not found on trusted PATH'}
        argv = [docker, 'exec', '-i', '-u', 'postgres', _PG_DUMP_CONTAINER,
                'pg_restore', '--clean', '-d', db]
    else:
        runuser = shutil.which('runuser', path=BROKER_TRUSTED_PATH)
        pg_restore = shutil.which('pg_restore', path=BROKER_TRUSTED_PATH)
        if not runuser or not pg_restore:
            return {'ok': False, 'error': 'runuser/pg_restore not found on trusted PATH'}
        argv = [runuser, '-u', 'postgres', '--', pg_restore, '--clean', '-d', db]
    timeout = min(int(req.get('timeout') or DEFAULT_TIMEOUT), DEFAULT_TIMEOUT)
    with open(path, 'rb') as inp:
        proc = subprocess.run(argv, stdin=inp, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=timeout)
    return {'ok': True, 'returncode': proc.returncode,
            'stderr': (proc.stderr or b'').decode(errors='replace')[-500:]}


def _check_stack_pg_restore(req):
    # same gate as stack_pg_dump: pinned container, <root>/<label>/<name>.pgdump only
    return _check_stack_pg_dump(req)


def _do_stack_pg_restore(req):
    """W12.d: restore a full-stack backup dump into its module's postgres container.
    Only a dump the broker itself produced (HMAC sidecar) is accepted — the backup
    tree is on the write allowlist, so the console could otherwise plant an archive
    whose TOC runs code as the database superuser. `verify_only` checks the HMAC and
    the archive's TOC without touching the database (the restore preflight)."""
    import hmac as _hmac
    path = _check_stack_pg_restore(req)
    if os.path.islink(path) or not os.path.isfile(path):
        return {'ok': False, 'code': 'ENOENT', 'error': f'dump not found: {path}'}
    try:
        with open(path + '.hmac') as f:
            want = f.read().strip()
    except OSError:
        want = ''
    if not want or not _hmac.compare_digest(want, _dump_hmac(path)):
        return {'ok': False, 'code': 'DENIED',
                'error': 'dump failed authenticity check — not a broker-produced backup'}
    if req.get('verify_only'):
        pg_restore = _newest_pg_client('pg_restore')
        if not pg_restore:
            return {'ok': True, 'toc_entries': None, 'note': 'HMAC verified; no host pg_restore to read the TOC'}
        proc = subprocess.run([pg_restore, '--list', path], capture_output=True, timeout=600)
        toc = [l for l in (proc.stdout or b'').decode(errors='replace').splitlines()
               if l.strip() and not l.lstrip().startswith(';')]
        return {'ok': proc.returncode == 0 and bool(toc), 'toc_entries': len(toc),
                'error': (proc.stderr or b'').decode(errors='replace')[:400]}
    user, db = _STACK_PG_CONTAINERS[req['container']]
    docker = shutil.which('docker', path=BROKER_TRUSTED_PATH)
    if not docker:
        return {'ok': False, 'error': 'docker not found on trusted PATH'}
    argv = [docker, 'exec', '-i', req['container'], 'pg_restore', '-U', user,
            '--clean', '--if-exists', '--no-owner', '-d', db]
    timeout = min(int(req.get('timeout') or DEFAULT_TIMEOUT), _PG_DUMP_MAX_TIMEOUT)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as inp:
        proc = subprocess.run(argv, stdin=inp, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=timeout)
    # pg_restore exits 1 on non-fatal warnings — passed through for the caller.
    return {'ok': True, 'returncode': proc.returncode,
            'stderr': (proc.stderr or b'').decode(errors='replace')[-800:]}


# /etc/ssl/openssl.cnf is a ROOT CODE-EXEC surface (it can load engines/providers
# via .so). The console's ONE legitimate edit is flipping the cert subject encoding
# for TAK client compat: `string_mask = utf8only` -> `string_mask = nombstr`. So
# rather than allowlist writes to it (which would hand the console a code-exec
# primitive), the broker permits a write ONLY when the new content is EXACTLY the
# current file with that single substitution applied — nothing else changed.
_OPENSSL_CNF = '/etc/ssl/openssl.cnf'
_OPENSSL_FROM = 'string_mask = utf8only'
_OPENSSL_TO = 'string_mask = nombstr'


def _check_openssl_cnf_write(req):
    try:
        with open(_OPENSSL_CNF) as f:
            cur = f.read()
    except OSError as e:
        raise Denied(f'openssl.cnf: cannot read current file to validate patch: {e}')
    new = base64.b64decode(req.get('content_b64') or '').decode('utf-8', 'replace')
    expected = cur.replace(_OPENSSL_FROM, _OPENSSL_TO)
    if new != expected:
        raise Denied('openssl.cnf: write is not the exact string_mask patch (refused '
                     '— this file can load code, so only the one known edit is allowed)')


#
# v10.1.9 W2/WI-3 — disk reclaim (fixed-shape op, NOT free-form argv)
#
# Fresh installs strand most of the disk away from TAK: RHEL/Anaconda parks it in
# a separate /home LV, Ubuntu leaves unallocated VG extents. Reclaiming it needs
# lvextend/lvremove/xfs_growfs/resize2fs — a set that, as free-form argv, is an
# arbitrary data-destruction primitive (`lvremove vg/root`). So it is exposed ONLY
# as this one op, whose entire argument surface is {mode, confirm_lv}: the broker
# resolves every device itself and enforces its own pre-flight.
#
# Two modes:
#   grow_free  — non-destructive: extend root into FREE extents + grow the FS.
#   fold_home  — DESTRUCTIVE: back up /home, unmount it, lvremove it, absorb into
#                root. Guarded by: /home must be a separate LV in root's VG, its
#                used bytes must be under FOLD_HOME_MAX_USED, and the caller must
#                echo back the exact LV path it means to destroy (confirm_lv).
# The console layers its own operator password re-confirm on top (WI-3 route).
FOLD_HOME_MAX_USED = 2 * 1024 ** 3      # 2 GiB — refuse to fold a /home in real use
_DISK_RECLAIM_MODES = ('grow_free', 'fold_home')


def _check_disk_reclaim(req):
    mode = req.get('mode')
    if mode not in _DISK_RECLAIM_MODES:
        raise Denied(f'disk_reclaim: mode must be one of {_DISK_RECLAIM_MODES}')
    if mode == 'fold_home':
        cl = req.get('confirm_lv')
        if not isinstance(cl, str) or not cl.strip():
            raise Denied('disk_reclaim fold_home: confirm_lv (the exact LV to destroy) is required')
        # Never let the confirmation name root/swap even if the caller insists.
        if re.search(r'/(root|swap)$', cl.strip()):
            raise Denied(f'disk_reclaim: refusing to remove {cl} — only a /home LV may be folded in')


def _lvm_root_info():
    """Resolve (root_dev, root_fstype, vg, root_lv) from the live system. Returns
    None for any piece we cannot determine; callers must treat that as 'refuse'."""
    def _run(argv):
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            return (r.stdout or '').strip() if r.returncode == 0 else ''
        except Exception:
            return ''
    root_dev = _run(['findmnt', '-no', 'SOURCE', '/'])
    root_fs = _run(['findmnt', '-no', 'FSTYPE', '/'])
    vg = _run(['lvs', '--noheadings', '-o', 'vg_name', root_dev]).strip() if root_dev else ''
    lv = _run(['lvs', '--noheadings', '-o', 'lv_name', root_dev]).strip() if root_dev else ''
    return root_dev, root_fs, vg, lv


def _grow_root_fs(root_dev, root_fs, log):
    if root_fs == 'xfs':
        r = subprocess.run(['xfs_growfs', '/'], capture_output=True, text=True, timeout=300)
    elif root_fs in ('ext2', 'ext3', 'ext4'):
        r = subprocess.run(['resize2fs', root_dev], capture_output=True, text=True, timeout=600)
    else:
        log.append(f'Unknown root filesystem {root_fs!r} — LV grown but filesystem NOT resized.')
        return False
    ok = r.returncode == 0
    log.append(('Filesystem grown.' if ok else 'Filesystem grow FAILED: ' + (r.stderr or '')[:200]))
    return ok


def _restore_fstab(log):
    """Undo the fold-in's /home comment-out. EVERY failure path after the fstab
    edit must call this: a box left with /home commented out does not remount it
    on the next boot, which is a broken box even though nothing was destroyed."""
    try:
        with open('/etc/fstab.takwerx-bak') as f:
            orig = f.read()
        with open('/etc/fstab', 'w') as f:
            f.write(orig)
        log.append('/etc/fstab restored from backup.')
        return True
    except OSError as e:
        log.append(f'/etc/fstab restore FAILED ({e}) — restore it by hand from /etc/fstab.takwerx-bak.')
        return False


# Interactive shells are disposable: signing one out costs the operator a
# re-login and nothing else. Everything ELSE holding /home (a database, a
# container, a service) is never force-killed — it gets a named refusal.
_CLOSABLE_SHELLS = frozenset(('bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'login'))


def _home_holders():
    """Processes holding a cwd / root / exe / open fd under /home.

    A busy /home makes umount fail, and escalating to `umount -l` there is worse
    than refusing: lazy-detach hides the mount from findmnt while the device stays
    open, so the lvremove that follows fails with /home ALREADY unmounted and
    fstab ALREADY rewritten. Enumerate the holders up front instead and refuse
    while the box is still completely untouched.

    Returns dicts {pid, comm, tty, path, closable}. `closable` marks a plain
    interactive shell — on a fresh box there is ALWAYS one, because whoever
    installed the machine is logged in at its console sitting in their own home
    directory (field-proven on the Rocky NUC, 2026-07-24: `login -- takwerx` on
    tty1). Refusing on that alone would make the fold-in unreachable for exactly
    the box it exists to fix."""
    holders = []
    mine = {os.getpid(), os.getppid()}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        links = [f'/proc/{pid}/cwd', f'/proc/{pid}/root', f'/proc/{pid}/exe']
        try:
            links += [f'/proc/{pid}/fd/{fd}' for fd in os.listdir(f'/proc/{pid}/fd')]
        except OSError:
            pass
        for link in links:
            try:
                tgt = os.readlink(link)
            except OSError:
                continue
            if tgt != '/home' and not tgt.startswith('/home/'):
                continue
            try:
                with open(f'/proc/{pid}/comm') as f:
                    comm = f.read().strip()
            except OSError:
                comm = '?'
            try:
                tty = os.readlink(f'/proc/{pid}/fd/0')
                tty = tty if tty.startswith('/dev/') else ''
            except OSError:
                tty = ''
            ipid = int(pid)
            holders.append({
                'pid': ipid, 'comm': comm, 'tty': tty, 'path': tgt,
                # A shell holding /home ONLY as its working directory is safe to
                # sign out. One with a file open under /home is doing real work
                # (an editor, a running script) and is treated as unsafe.
                'closable': (comm.lstrip('-') in _CLOSABLE_SHELLS
                             and ipid not in mine and ipid != 1
                             and link.endswith('/cwd')),
            })
            break
    return sorted(holders, key=lambda h: h['pid'])


def _describe_holder(h):
    return f"{h['comm']} (pid {h['pid']}{', ' + h['tty'] if h['tty'] else ''})"


def _close_home_shells(holders, log):
    """SIGTERM then SIGKILL the closable shells. Returns the still-live holders."""
    for h in holders:
        try:
            os.kill(h['pid'], signal.SIGTERM)
        except OSError:
            pass
    for _ in range(10):                      # up to ~5s for a clean exit
        time.sleep(0.5)
        if not _home_holders():
            break
    for h in _home_holders():
        if h['closable']:
            try:
                os.kill(h['pid'], signal.SIGKILL)
            except OSError:
                pass
    time.sleep(1)
    if holders:
        log.append('Signed out of /home: ' + ', '.join(_describe_holder(h) for h in holders) + '.')
    return _home_holders()


def _do_disk_reclaim(req):
    """Execute the reclaim. Returns {'ok':bool,'log':[...],'df_after':str}."""
    mode = req.get('mode')
    log = []
    root_dev, root_fs, vg, root_lv = _lvm_root_info()
    if not (root_dev and vg and root_lv):
        return {'ok': False, 'error': 'root is not an LVM logical volume — nothing to reclaim', 'log': log}

    if mode == 'grow_free':
        r = subprocess.run(['vgs', '--noheadings', '-o', 'vg_free', '--units', 'b', vg],
                           capture_output=True, text=True, timeout=20)
        free_b = int(re.sub(r'\D', '', r.stdout or '0') or 0)
        if free_b < 1024 ** 3:
            return {'ok': False, 'error': 'no free extents to reclaim (need ≥1 GiB)', 'log': log}
        e = subprocess.run(['lvextend', '-l', '+100%FREE', f'{vg}/{root_lv}'],
                           capture_output=True, text=True, timeout=300)
        if e.returncode != 0:
            return {'ok': False, 'error': 'lvextend failed: ' + (e.stderr or '')[:200], 'log': log}
        log.append(f'Root LV extended into {free_b // 1024 ** 3} GB of free extents.')
        _grow_root_fs(root_dev, root_fs, log)
        df = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=15)
        return {'ok': True, 'log': log, 'df_after': (df.stdout or '').strip()}

    # ---- fold_home: DESTRUCTIVE ----
    home_dev = subprocess.run(['findmnt', '-no', 'SOURCE', '/home'],
                              capture_output=True, text=True, timeout=20)
    home_dev = (home_dev.stdout or '').strip()
    if not home_dev:
        return {'ok': False, 'error': '/home is not a separate mount — nothing to fold', 'log': log}
    hv = subprocess.run(['lvs', '--noheadings', '-o', 'vg_name,lv_name', home_dev],
                        capture_output=True, text=True, timeout=20)
    parts = (hv.stdout or '').split()
    if hv.returncode != 0 or len(parts) < 2:
        return {'ok': False, 'error': '/home is not an LVM volume — refusing', 'log': log}
    home_vg, home_lv = parts[0], parts[1]
    if home_vg != vg:
        return {'ok': False, 'error': f'/home LV is in VG {home_vg}, root is in {vg} — refusing', 'log': log}
    lv_path = f'{home_vg}/{home_lv}'
    if (req.get('confirm_lv') or '').strip() not in (lv_path, f'/dev/{lv_path}', home_dev):
        return {'ok': False, 'error': f'confirm_lv does not match the resolved /home LV ({lv_path})', 'log': log}

    used = subprocess.run(['df', '-B1', '--output=used', '/home'], capture_output=True, text=True, timeout=20)
    used_b = int(re.sub(r'\D', '', (used.stdout or '').splitlines()[-1]) or 0) if used.returncode == 0 else -1
    if used_b < 0:
        return {'ok': False, 'error': 'could not measure /home usage — refusing', 'log': log}
    if used_b > FOLD_HOME_MAX_USED:
        return {'ok': False, 'error': f'/home holds {used_b // 1024 ** 2} MB (limit '
                                      f'{FOLD_HOME_MAX_USED // 1024 ** 2} MB) — refusing to fold a /home in real use',
                'log': log}
    log.append(f'/home is {lv_path}, {used_b // 1024 ** 2} MB used — within the fold-in limit.')

    # /home holds every user's SSH PRIVATE KEYS, so neither the staging copy nor the
    # archive may live in world-writable /var/tmp. Mode 0600/0700 is not enough there:
    # the paths are fixed and predictable, so ANY local account — including the
    # non-root console user this broker exists to contain — can pre-plant a symlink
    # and have root follow it, truncating an arbitrary root-owned file and landing the
    # whole key archive somewhere the attacker owns and can read. Both now live under
    # the broker's own root-only state dir (nobody but root can create a path there),
    # and the archive is opened O_EXCL|O_NOFOLLOW so a link at that path is a hard
    # error rather than a target. Mode is still set BEFORE any data is written.
    fold_dir = '/var/lib/takwerx-broker/home-fold'
    stage = fold_dir + '/stage'
    backup = fold_dir + '/takwerx-home-backup.tar.gz'
    try:
        os.makedirs(fold_dir, exist_ok=True)
        os.chmod(fold_dir, 0o700)
    except OSError as e:
        return {'ok': False, 'error': f'could not create the fold-in work directory: {e}', 'log': log}
    subprocess.run(['rm', '-rf', stage], capture_output=True, timeout=60)
    os.makedirs(stage, mode=0o700, exist_ok=True)
    os.chmod(stage, 0o700)
    rs = subprocess.run(['rsync', '-aXS', '/home/', stage + '/'], capture_output=True, text=True, timeout=1800)
    if rs.returncode != 0:
        return {'ok': False, 'error': 'rsync of /home failed: ' + (rs.stderr or '')[:200], 'log': log}
    try:
        if os.path.lexists(backup):
            os.unlink(backup)       # lexists+unlink: never follow, always replace
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(backup, 0o600)
    except OSError as e:
        return {'ok': False, 'error': f'could not create the backup archive securely: {e}', 'log': log}
    tb = subprocess.run(['tar', 'czf', backup, '-C', stage, '.'], capture_output=True, text=True, timeout=1800)
    if tb.returncode != 0:
        return {'ok': False, 'error': 'tar backup of /home failed: ' + (tb.stderr or '')[:200], 'log': log}
    os.chmod(backup, 0o600)   # re-assert: tar may recreate the file
    log.append(f'/home staged to {stage} and archived to {backup} (both root-only, 0600).')

    # Running containers pin /home in their mount namespaces — a host umount alone
    # does NOT release it (field-proven 2026-07-22, needed a reboot). Stop docker
    # BEFORE looking for holders, so container pins are already gone by then, and
    # before touching /etc/fstab, so a refusal leaves the box wholly unmodified.
    docker_was_active = subprocess.run(['systemctl', 'is-active', 'docker'],
                                       capture_output=True, text=True, timeout=20).stdout.strip() == 'active'
    if docker_was_active:
        subprocess.run(['systemctl', 'stop', 'docker'], capture_output=True, timeout=300)
        subprocess.run(['systemctl', 'stop', 'docker.socket'], capture_output=True, timeout=120)
        log.append('Docker stopped to release /home mount pins.')

    def _restore_docker():
        if docker_was_active:
            subprocess.run(['systemctl', 'start', 'docker'], capture_output=True, timeout=300)
            log.append('Docker restarted.')

    def _refuse_holders(hs):
        _restore_docker()
        names = ', '.join(_describe_holder(h) for h in hs[:8])
        more = '' if len(hs) <= 8 else f' (+{len(hs) - 8} more)'
        return {'ok': False, 'error': f'/home is in use by {names}{more} — close it and retry. '
                                      'Nothing was changed.', 'log': log}

    holders = _home_holders()
    if holders:
        stubborn = [h for h in holders if not h['closable']]
        if stubborn:
            # Something real is using /home. Never force it — name it and stop.
            return _refuse_holders(stubborn)
        if not req.get('close_shells'):
            return _refuse_holders(holders)
        holders = _close_home_shells(holders, log)
        if holders:
            return _refuse_holders(holders)

    # fstab: back up, then comment out the /home line.
    try:
        with open('/etc/fstab') as f:
            fstab = f.read()
        with open('/etc/fstab.takwerx-bak', 'w') as f:
            f.write(fstab)
        new = []
        for line in fstab.splitlines(True):
            fields = line.split()
            if not line.lstrip().startswith('#') and len(fields) > 1 and fields[1] == '/home':
                new.append('#' + line)      # v10.1.9 fold-in
            else:
                new.append(line)
        with open('/etc/fstab', 'w') as f:
            f.writelines(new)
        log.append('/etc/fstab updated (backup at /etc/fstab.takwerx-bak).')
    except OSError as e:
        _restore_fstab(log)     # the write itself may have half-landed
        _restore_docker()
        return {'ok': False, 'error': f'fstab update failed: {e}', 'log': log}

    # Plain umount only. If it fails the box is put back exactly as it was — see
    # _home_holders() for why lazy-detach must never lead into the lvremove below.
    um = subprocess.run(['umount', '/home'], capture_output=True, text=True, timeout=120)
    if um.returncode != 0:
        _restore_fstab(log)
        _restore_docker()
        return {'ok': False, 'error': '/home would not unmount: ' + (um.stderr or '').strip()[:200] +
                                      ' — fstab restored, nothing destroyed.', 'log': log}
    log.append('/home unmounted.')

    rm = subprocess.run(['lvremove', '-f', lv_path], capture_output=True, text=True, timeout=300)
    if rm.returncode != 0:
        _restore_fstab(log)     # MUST precede the remount — `mount /home` reads fstab
        subprocess.run(['mount', '/home'], capture_output=True, timeout=60)
        _restore_docker()
        return {'ok': False, 'error': 'lvremove failed: ' + (rm.stderr or '')[:200] +
                                      ' — /home remounted, nothing destroyed.', 'log': log}
    log.append(f'{lv_path} removed.')

    ex = subprocess.run(['lvextend', '-l', '+100%FREE', f'{vg}/{root_lv}'],
                        capture_output=True, text=True, timeout=300)
    if ex.returncode != 0:
        _restore_docker()
        return {'ok': False, 'error': 'lvextend failed after removing /home: ' + (ex.stderr or '')[:200] +
                                      f' — data is safe in {backup}.', 'log': log}
    _grow_root_fs(root_dev, root_fs, log)

    # Restore the dotfiles into the now-plain /home directory.
    os.makedirs('/home', exist_ok=True)
    subprocess.run(['rsync', '-aXS', stage + '/', '/home/'], capture_output=True, timeout=1800)
    subprocess.run(['restorecon', '-R', '/home'], capture_output=True, timeout=300)
    log.append(f'/home contents restored (archive kept at {backup}).')
    _restore_docker()

    df = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=15)
    return {'ok': True, 'log': log, 'df_after': (df.stdout or '').strip(), 'backup': backup}


# ---------------------------------------------------------------------------
# v10.1.53 — TAK Portal privileged sudoers grant (fixed-shape op)
# ---------------------------------------------------------------------------
# WHY THIS IS AN OP AND NOT A PATH_ALLOW ENTRY:
#   '/etc/sudoers.d/' is in PATH_DENY_PREFIX ("no minting new sudoers rules") and
#   it STAYS there. A console that can write an arbitrary sudoers file simply IS
#   root, which is the thing this broker exists to prevent. So the grant ships the
#   way the mutating LVM ops did (disk_reclaim): a fixed-shape op whose CONTENT
#   the broker owns. The request carries an action and NOTHING else — no username,
#   no file content, no paths. The target is the module constant BROKER_USER, so
#   there is no injection surface to get wrong.
#
# WHY THE GRANT EXISTS:
#   TAK Portal runs in a container and reaches the host over SSH as the console
#   user to do four things: issue integration-user client certs (makeCert.sh, run
#   as `tak`), read/write CoreConfig.xml, run its certs-permission repair script,
#   and restart takserver. Since the v10.0.5 non-root flip that account has been
#   password-LOCKED with no sudo, and the Portal's own bootstrap needs a sudo
#   PASSWORD to install this very file — so it can never run, and every privileged
#   Portal feature has been dead fleet-wide. Field report: Cory Foy, 2026-08-28;
#   reproduced on test6/test12 (TAK_SSH_SUDOERS_CONFIGURED=false on both).
#   See docs/PLAN-v10.1.53.md.
#
# WHAT WE DELIBERATELY DO NOT GRANT — upstream's own installer grants both:
#   * (root) NOPASSWD: tail   — unrestricted, i.e. a root READ primitive for every
#     file on the box (/etc/shadow, the TAK CA key, .config/auth.json), handed to a
#     network-facing container that holds the SSH private key.
#   * (root) NOPASSWD: reboot — the console already owns power controls.
#   Operator decision 2026-08-28. Granting either later is a deliberate widening
#   with its own /module-scan — never a patch.
TAKPORTAL_SUDOERS_PATH = '/etc/sudoers.d/tak-portal'
TAKPORTAL_REPAIR_SCRIPT = '/opt/tak/utils/tak-portal-repair-certs.sh'
TAKPORTAL_CORECONFIG = '/opt/tak/CoreConfig.xml'
TAKPORTAL_TAK_USER = 'tak'

# The HARDENED grant (TAK Portal 2.0.19+): least privilege for the portal's SSH user.
#   * no rule for the portal repair script (nothing under a directory the `tak`
#     user owns is ever run as root);
#   * CoreConfig `cat`/`tee` still match the exact commands the portal sends
#     (`sudo -n cat|tee /opt/tak/CoreConfig.xml`), but they resolve — through a
#     per-user secure_path — to ROOT-OWNED wrappers that drop to `tak` before
#     touching the file;
#   * the marketplace helper is installed from a PINNED sha256 and granted by
#     exact path.
# Every box gets this grant (ops #644). A TAK Portal older than 2.0.19 used to
# keep the v10.1.53 legacy text; its marketplace and cert
# repair now need a TAK Portal update instead.
TAKPORTAL_LIBEXEC = '/usr/local/libexec/infratak'
TAKPORTAL_WRAP_DIR = TAKPORTAL_LIBEXEC + '/portal-bin'
TAKPORTAL_WRAPPED = ('cat', 'tee')
TAKPORTAL_HELPER = '/usr/local/libexec/tak-portal/marketplace-helper'
TAKPORTAL_LEFTOVER_SUDOERS = '/etc/sudoers.d/tak-portal-marketplace'
TAKPORTAL_HARDENED_MIN_VERSION = (2, 0, 19)
# sha256 of host-helpers/marketplace-helper in TAK Portal releases
# (ValleyTacticalSolutions/TAK-Portal). The helper is granted as root, so we only
# ever install bytes we have reviewed; a portal that ships a different helper gets
# it granted after the new hash is added here (with a /module-scan), never before.
#   c240a12a… version 1, 2.0.19-2.0.22
#   4d093f4b… version 3, 2.0.29: adds apply-caddyfile (writes /etc/caddy/Caddyfile, the file
#             Deploy To Caddy needs) and validates it as the `caddy` user (runuser/setpriv/su),
#             so `import /etc/shadow` is refused and only a line number is echoed, never file
#             contents (TAK Portal #81, ops #340). Versions 2 (2.0.23-2.0.24) and the 2.0.26/2.0.28
#             build ran `caddy validate` as root on caller text; they stay unpinned.
#   0eb07556… version 4, 2.0.31: same as 4d093f4b… except the as-root fallback of `caddy validate`
#             only carries on when EVERY error line is permission-denied AND names /var/log/caddy or
#             /var/lib/caddy (before: any all-permission-denied output). A tightening; no new command,
#             path or input. Reviewed by Security Fri Nov 6, 2026 (ops #538).
#   5996839d… 2.0.32 (still prints version 4): 0eb07556… plus docker_compose_with_pull_retry, which wraps
#             the two `docker compose build/up` calls `rebuild` already made and retries up to 3 times on
#             a dropped Docker Hub layer or 5xx (never on a 429). Fixed command, mktemp log it deletes,
#             one digits-only env var. No new caller-controlled input or privilege. Reviewed by Security
#             Fri Nov 6, 2026 (ops #538).
TAKPORTAL_HELPER_SHA256 = frozenset({
    'c240a12aa8978e106c94c0303a0e116f3e08dff0ba7c6a9273c0422ad92e3bb4',
    '4d093f4b834bda8ad712c5df4155929dd9b40f4d14ecded0cdd01b84d14c4559',
    '0eb07556d0d3618574ce4b135bf8866fca269c053c67f61c8e0ad97defa26cb6',
    '5996839d6d663e3f1c6230a7d64c8f2580e8776b6be1ee708e9f02eec8b86d58',
})
# 'status' is read-only and exists because the console CANNOT read the grant
# itself: /etc/sudoers.d/ is deny-listed for reads as well as writes, and on a
# born-non-root box the directory is 0750 root:root anyway. Without it the UI
# would have to guess at the state of a security-relevant file.
_TAKPORTAL_SUDOERS_ACTIONS = ('install', 'remove', 'status')

# Resolve command paths from these dirs ONLY — never PATH, never shutil.which().
# On a born-non-root box the console user's PATH leads with /opt/infratak/.shims,
# which is takwerx-WRITABLE; resolving through it would put a shim path in a
# NOPASSWD rule and hand the console user unconditional root. Fixed dirs, plus an
# ownership check on each hit.
_SUDOERS_BIN_DIRS = ('/usr/bin', '/bin', '/usr/sbin', '/sbin')


def _sudoers_safe_binaries(name):
    """Every standard, root-owned path at which `name` exists, in a stable order.

    Returns a LIST, not one path, on purpose: sudo matches a rule by the
    fully-qualified path it resolves the command to, and it does not resolve
    symlinks. On usrmerge systems both /bin/cat and /usr/bin/cat exist and are the
    same file, but only the string sudo happens to resolve will match a rule. A
    rule that names the other one never matches — and a non-matching sudoers rule
    fails SILENTLY (no grant, no error), which is exactly the kind of bug that
    burns a T&E cycle. Emitting every real path costs a few lines and removes the
    guess."""
    out = []
    for d in _SUDOERS_BIN_DIRS:
        p = os.path.join(d, name)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if os.path.islink(p):
            # Keep the LINK path (that is what sudo may resolve to) but validate
            # the target it points at.
            try:
                st = os.stat(p)
            except OSError:
                continue
        if not os.path.isfile(p):
            continue
        # Refuse anything not root-owned or writable by group/other — a NOPASSWD
        # rule on a non-root-owned binary is a trap door.
        if st.st_uid != 0 or (st.st_mode & 0o022):
            continue
        if p not in out:
            out.append(p)
    return out


def _takportal_sudoers_text(user=BROKER_USER, variant='hardened', helper=False):
    """The ONE definition of the grant.

    variant 'hardened' — ops #217: no script rules, CoreConfig cat/tee through
                         root-owned wrappers that drop to `tak`, and (helper=True)
                         the pinned marketplace helper.
    The v10.1.53 'legacy' text is gone (ops #644). A TAK Portal older than 2.0.19 gets the hardened
    grant too; its marketplace and cert repair need a TAK Portal update.

    app.py imports THIS function for the root-console path rather than keeping its
    own copy, so the two can never drift — a drifted sudoers template is a
    security bug, not a cosmetic one.

    Returns the file content, or raises Denied when the box cannot support the
    grant (no /opt/tak, containerized TAK, missing `tak` user, unresolvable
    binaries)."""
    if not re.fullmatch(r'^[a-z_][a-z0-9_-]{0,31}$', str(user or '')):
        raise Denied(f'takportal_sudoers: refusing unsafe user name {user!r}')
    if variant != 'hardened':
        raise Denied(f'takportal_sudoers: unknown grant variant {variant!r}')
    return _takportal_hardened_text(user, helper)


def _takportal_hardened_text(user, helper):
    """The hardened grant (ops #217). See the comment above TAKPORTAL_LIBEXEC."""
    lines = [
        '# Managed by infra-TAK (ops #217). Do not edit by hand.',
        '#',
        '# TAK Portal 2.0.19+. Nothing here runs a file that the `tak` user can',
        '# write as root: no rule for the portal repair script, and the CoreConfig',
        '# cat/tee below resolve (secure_path) to root-owned wrappers in',
        f'# {TAKPORTAL_WRAP_DIR} that drop to `tak` first, so root never',
        '# reads or writes through a path the `tak` user controls.',
        f'Defaults:{user} !requiretty',
        f'Defaults:{user} secure_path="{TAKPORTAL_WRAP_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
    ]
    systemctl = _sudoers_safe_binaries('systemctl')
    if not systemctl:
        raise Denied(f'takportal_sudoers: cannot resolve a root-owned systemctl in {_SUDOERS_BIN_DIRS}')
    for name in TAKPORTAL_WRAPPED:
        lines.append(f'{user} ALL=(root) NOPASSWD: {TAKPORTAL_WRAP_DIR}/{name} {TAKPORTAL_CORECONFIG}')
    for p in systemctl:
        lines.append(f'{user} ALL=(root) NOPASSWD: {p} restart takserver')
    # Cert issuance: makeCert.sh must run AS the tak user, which owns /opt/tak.
    lines.append(f'{user} ALL=({TAKPORTAL_TAK_USER}) NOPASSWD: ALL')
    if helper:
        lines.append(f'{user} ALL=(root) NOPASSWD: {TAKPORTAL_HELPER}')
    return '\n'.join(lines) + '\n'


def _takportal_wrapper_text(name):
    """Body of the root-owned wrapper for `cat` / `tee` (see TAKPORTAL_LIBEXEC)."""
    real = (_sudoers_safe_binaries(name) or [None])[0]
    setpriv = (_sudoers_safe_binaries('setpriv') or [None])[0]
    if not real or not setpriv:
        raise Denied(f'takportal_sudoers: cannot resolve a root-owned {name}/setpriv '
                     f'in {_SUDOERS_BIN_DIRS}')
    return (
        '#!/bin/sh\n'
        '# Managed by infra-TAK (ops #217). Do not edit by hand.\n'
        "# TAK Portal's `sudo -n " + name + " " + TAKPORTAL_CORECONFIG + "` lands here: sudo searches\n"
        '# this directory first for the portal user (secure_path in\n'
        '# /etc/sudoers.d/tak-portal). Run as root with exactly that one argument,\n'
        f'# the real {name} runs AS `{TAKPORTAL_TAK_USER}`, so root never reads or writes through\n'
        '# a path that user controls. Anything else runs unchanged\n'
        '# (commands sudo starts as `tak` inherit the same PATH).\n'
        f'if [ "$(id -u)" = 0 ] && [ "$#" -eq 1 ] && [ "$1" = \'{TAKPORTAL_CORECONFIG}\' ]; then\n'
        f'  exec {setpriv} --reuid={TAKPORTAL_TAK_USER} --regid={TAKPORTAL_TAK_USER} --init-groups {real} -- "$1"\n'
        'fi\n'
        f'exec {real} "$@"\n'
    )


def _root_dir_chain_ok(path):
    """True when every component of `path` is a real directory (no symlink),
    owned by root and not writable by group/other."""
    cur = '/'
    parts = [c for c in path.split('/') if c]
    for c in [''] + parts:
        cur = os.path.join(cur, c) if c else '/'
        try:
            st = os.lstat(cur)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o022):
            return False
    return True


def _ensure_root_dir(path):
    """Create `path` (0755 root:root) when missing; Denied if any component that
    exists is not a root-owned, non-writable, non-symlink directory."""
    cur = '/'
    for c in [c for c in path.split('/') if c]:
        cur = os.path.join(cur, c)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            os.mkdir(cur, 0o755)
            os.chown(cur, 0, 0)
            os.chmod(cur, 0o755)
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o022):
            raise Denied(f'takportal_sudoers: {cur} is not a root-owned, non-writable '
                         'directory — refusing to place a root-run file under it')


def _write_root_file(path, data, mode):
    """Atomically install `data` at `path` as root:root `mode` (same-dir rename)."""
    _ensure_root_dir(os.path.dirname(path))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.infratak-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fchown(f.fileno(), 0, 0)
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _root_file_ok(path, want_sha256=None, want_bytes=None):
    """A regular, root-owned file nobody else can write, in a root-only
    directory chain, whose content matches (bytes, or one of a set of sha256)."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o022):
            return False
        if not _root_dir_chain_ok(os.path.dirname(path)):
            return False
        with open(path, 'rb') as f:
            data = f.read(1 << 20)
    except OSError:
        return False
    if want_bytes is not None:
        return data == want_bytes
    return hashlib.sha256(data).hexdigest() in (want_sha256 or ())


def _takportal_wrappers_ok():
    try:
        return all(_root_file_ok(f'{TAKPORTAL_WRAP_DIR}/{n}', want_bytes=_takportal_wrapper_text(n).encode())
                   for n in TAKPORTAL_WRAPPED)
    except Denied:
        return False


def _takportal_install_wrappers():
    for n in TAKPORTAL_WRAPPED:
        _write_root_file(f'{TAKPORTAL_WRAP_DIR}/{n}', _takportal_wrapper_text(n).encode(), 0o755)
    if not _takportal_wrappers_ok():
        raise Denied('takportal_sudoers: wrapper install did not verify (not root-owned/unwritable) '
                     '— refusing to grant')


def _read_small_nofollow(path, limit=1 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError('not a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            return f.read(limit + 1)[:limit]
    finally:
        os.close(fd)


def _takportal_version_tuple(ver):
    m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)', str(ver or '').strip())
    return tuple(int(x) for x in m.groups()) if m else None


def _takportal_decide(user=BROKER_USER):
    """Which grant this box gets, from the TAK Portal checkout in the console
    user's home. Read as root from a directory that user controls, so: no git
    (config hooks run code), O_NOFOLLOW, size-capped, and the helper bytes are
    only ever USED if they hash to a pinned value.

    The checkout is operator-writable, so it only picks which pinned helper to
    grant and what the status row says; the variant is always 'hardened' (ops #644
    removed the legacy text). portal_old: TAK Portal is older than
    2.0.19, so its marketplace and cert repair need a TAK Portal update."""
    out = {'variant': 'hardened', 'reason': 'no TAK Portal checkout found', 'portal_version': '',
           'portal_old': False,
           'helper_bytes': None, 'helper_reason': 'no TAK Portal checkout found',
           'helper_unreviewed': False}
    try:
        portal = os.path.join(pwd.getpwnam(user).pw_dir, 'TAK-Portal')
    except KeyError:
        return out
    if os.path.islink(portal) or not os.path.isdir(portal):
        return out
    ver = ''
    try:
        ver = str((json.loads(_read_small_nofollow(os.path.join(portal, 'package.json')).decode('utf-8', 'replace'))
                   or {}).get('version') or '')
    except (OSError, ValueError, AttributeError):
        pass
    out['portal_version'] = ver
    try:
        data = _read_small_nofollow(os.path.join(portal, 'host-helpers', 'marketplace-helper'), 262144)
    except OSError:
        data = None
    if data is not None:
        if hashlib.sha256(data).hexdigest() in TAKPORTAL_HELPER_SHA256:
            out['helper_bytes'] = data
            out['helper_reason'] = ''
        else:
            out['helper_unreviewed'] = True
            out['helper_reason'] = ('this TAK Portal ships a newer marketplace helper that infra-TAK '
                                    'has not reviewed yet (sha256 not pinned)')
    else:
        out['helper_reason'] = 'no host-helpers/marketplace-helper in the TAK Portal checkout'
    tup = _takportal_version_tuple(ver)
    # The helper file only exists from 2.0.19, so it also proves "new enough"
    # when package.json lags (upstream has shipped a release without bumping it).
    if data is None and tup is not None and tup < TAKPORTAL_HARDENED_MIN_VERSION:
        out['portal_old'] = True
        out['reason'] = (f'TAK Portal {ver} is older than '
                         f'{".".join(map(str, TAKPORTAL_HARDENED_MIN_VERSION))} — its marketplace '
                         'and cert repair need a TAK Portal update')
    else:
        out['reason'] = f'TAK Portal {ver or "version unknown"}'
    return out


def _takportal_helper_ok():
    return _root_file_ok(TAKPORTAL_HELPER, want_sha256=TAKPORTAL_HELPER_SHA256)


def _takportal_helper_current(decision):
    """The installed helper is exactly the pinned one this TAK Portal ships. With
    more than one pinned hash, "some pinned helper is installed" is not enough: a box
    holding the old one would never pick up the portal's newer reviewed helper
    (ops #340: apply-caddyfile only exists in the newer one)."""
    want = decision.get('helper_bytes')
    if want is None:
        return _takportal_helper_ok()
    return _root_file_ok(TAKPORTAL_HELPER, want_bytes=want)


def _takportal_remove_leftover():
    """Drop TAK Portal <2.0.19's `NOPASSWD: ALL` marketplace drop-in. True when
    a file was removed."""
    try:
        st = os.lstat(TAKPORTAL_LEFTOVER_SUDOERS)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    os.unlink(TAKPORTAL_LEFTOVER_SUDOERS)
    return True


def _takportal_sudoers_supported():
    """(ok, reason) — whether this box can carry the grant at all.

    Native TAK only. On a containerized/ARM install /opt/tak is a SYMLINK into the
    console user's docker bundle, there is no host `tak` user and no
    takserver.service, so every line of the grant would be meaningless. Skipping
    is the correct outcome there, and the console says so rather than warning."""
    if not os.path.isdir('/opt/tak'):
        return False, 'TAK Server is not installed on this host (/opt/tak missing)'
    if os.path.islink('/opt/tak'):
        return False, 'containerized TAK Server (/opt/tak is a symlink) — no host tak user to grant'
    try:
        pwd.getpwnam(TAKPORTAL_TAK_USER)
    except KeyError:
        return False, f'no `{TAKPORTAL_TAK_USER}` user on this host'
    try:
        if pwd.getpwnam(BROKER_USER).pw_uid == 0:
            return False, f'console user {BROKER_USER} resolves to uid 0 — grant is meaningless'
    except KeyError:
        return False, f'console user {BROKER_USER} does not exist'
    return True, ''


def _check_takportal_sudoers(req):
    action = req.get('action')
    if action not in _TAKPORTAL_SUDOERS_ACTIONS:
        raise Denied(f'takportal_sudoers: action must be one of {_TAKPORTAL_SUDOERS_ACTIONS}')
    # Removing a grant is de-escalation, and 'status' only reports — both are
    # permitted even on a box that could not RECEIVE a grant (a box that cannot
    # hold one is exactly where a stale file most wants finding and clearing).
    if action in ('remove', 'status'):
        return
    ok, why = _takportal_sudoers_supported()
    if not ok:
        raise Denied(f'takportal_sudoers: {why}')
    # raises Denied if the text (or, hardened, a wrapper) cannot be built
    variant = _takportal_decide()['variant']
    _takportal_sudoers_text(variant=variant)
    if variant == 'hardened':
        for n in TAKPORTAL_WRAPPED:
            _takportal_wrapper_text(n)


def _do_takportal_sudoers(req):
    action = req.get('action')
    if action == 'status':
        ok, why = _takportal_sudoers_supported()
        present = os.path.exists(TAKPORTAL_SUDOERS_PATH)
        matches = False
        mode = ''
        decision = _takportal_decide()
        variant = decision['variant']
        helper_ok = _takportal_helper_ok()
        hardened = (variant == 'hardened')
        wrappers_ok = _takportal_wrappers_ok() if hardened else True
        # An install would still have to put the helper in place.
        helper_pending = hardened and decision['helper_bytes'] is not None and not _takportal_helper_current(decision)
        if present:
            try:
                with open(TAKPORTAL_SUDOERS_PATH) as f:
                    current = f.read()
                st = os.stat(TAKPORTAL_SUDOERS_PATH)
                mode = oct(st.st_mode & 0o777)
                if ok:
                    matches = (current == _takportal_sudoers_text(
                        variant=variant, helper=(hardened and helper_ok))
                        and wrappers_ok and not helper_pending)
            except (OSError, Denied):
                pass
        return {'ok': True, 'present': present, 'matches': matches, 'mode': mode,
                'supported': ok, 'reason': why, 'path': TAKPORTAL_SUDOERS_PATH,
                'variant': variant, 'variant_reason': decision['reason'],
                'portal_old': bool(decision.get('portal_old')),
                'wrappers_ok': wrappers_ok,
                'helper': {'granted': bool(hardened and helper_ok),
                           'installed': helper_ok, 'reason': decision['helper_reason'],
                           'unreviewed': bool(decision.get('helper_unreviewed'))},
                'leftover_marketplace_sudoers': os.path.lexists(TAKPORTAL_LEFTOVER_SUDOERS)}
    if action == 'remove':
        # The wrappers and the helper exist only for this grant; they go with it.
        for n in TAKPORTAL_WRAPPED:
            try:
                os.unlink(f'{TAKPORTAL_WRAP_DIR}/{n}')
            except OSError:
                pass
        if _takportal_helper_ok():
            try:
                os.unlink(TAKPORTAL_HELPER)
            except OSError:
                pass
        try:
            os.unlink(TAKPORTAL_SUDOERS_PATH)
            return {'ok': True, 'removed': True, 'path': TAKPORTAL_SUDOERS_PATH}
        except FileNotFoundError:
            return {'ok': True, 'removed': False, 'path': TAKPORTAL_SUDOERS_PATH,
                    'message': 'no grant file present'}
        except OSError as e:
            return {'ok': False, 'error': f'could not remove {TAKPORTAL_SUDOERS_PATH}: {e}'}

    decision = _takportal_decide()
    variant = decision['variant']
    helper_granted = False
    if variant == 'hardened':
        # Root-owned, tak-unwritable files FIRST; the grant only goes in once
        # they verify, so a half-installed hardened grant can never exist.
        try:
            _takportal_install_wrappers()
            if decision['helper_bytes'] is not None:
                if not _takportal_helper_current(decision):
                    _write_root_file(TAKPORTAL_HELPER, decision['helper_bytes'], 0o755)
            helper_granted = _takportal_helper_ok()
        except (OSError, Denied) as e:
            return {'ok': False, 'error': f'hardened TAK Portal grant not installed: {e}'}
    content = _takportal_sudoers_text(variant=variant, helper=helper_granted)
    # Stage in /etc so os.replace() is an atomic same-filesystem rename, and so a
    # half-written file is never visible inside sudoers.d (sudo reads every file
    # in that directory on every invocation).
    fd, tmp = tempfile.mkstemp(dir='/etc', prefix='.tak-portal-sudoers-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        os.chown(tmp, 0, 0)
        os.chmod(tmp, 0o440)
        visudo = (_sudoers_safe_binaries('visudo') or [None])[0]
        if not visudo:
            return {'ok': False, 'error': 'visudo not found — refusing to install an unvalidated sudoers file'}
        chk = subprocess.run([visudo, '-cf', tmp], capture_output=True, text=True, timeout=20)
        if chk.returncode != 0:
            # Never install a file sudo cannot parse: a broken drop-in can take
            # sudo down for EVERY user on the box, root included.
            return {'ok': False,
                    'error': 'visudo rejected the generated grant (not installed): '
                             + ((chk.stderr or chk.stdout or '').strip()[:300])}
        os.replace(tmp, TAKPORTAL_SUDOERS_PATH)
        tmp = None
        removed = False
        if variant == 'hardened':
            # TAK Portal <2.0.19 wrote a NOPASSWD: ALL drop-in here; the
            # hardened grant must not sit beside it.
            try:
                removed = _takportal_remove_leftover()
            except OSError as e:
                return {'ok': False, 'error': f'grant installed but could not remove '
                                              f'{TAKPORTAL_LEFTOVER_SUDOERS}: {e}'}
        return {'ok': True, 'path': TAKPORTAL_SUDOERS_PATH, 'content': content,
                'variant': variant, 'variant_reason': decision['reason'],
                'helper_granted': helper_granted, 'helper_reason': decision['helper_reason'],
                'removed_leftover': removed}
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# ops #200 — the Java CA keystore follows the OS trust store (fixed-shape op)
# ---------------------------------------------------------------------------
# Ubuntu keeps a second copy of the CA list for Java, /etc/ssl/certs/java/cacerts, and
# native TAK Server's distro OpenJDK uses it as its default truststore. ca-certificates-
# java's hook only hears about a root when update-ca-certificates prints a "-<path>" line
# for it, and it never does when a package update simply DROPS a root: the dangling
# symlink is swept as an orphan, silently. So every root distrusted since the keystore was
# built stays trusted by Java. Measured on test8, 2026-10-23 (Ubuntu 22.04, ca-certificates
# 20260816ubuntu0.22.04.1): Java still trusted 43 roots the OS store had dropped, and was
# missing 17 the OS had added since.
#
# The op takes NO arguments: the broker works out the difference itself and feeds it to
# Debian's own hook, the same tool, alias names and storepass update-ca-certificates
# uses, so there is no second keystore writer to drift. Only `debian:` aliases (the ones
# that hook owns) are touched; anything an operator imported under another alias stays.
# RHEL needs none of this: update-ca-trust regenerates its Java keystore from the system
# store, and there /etc/ssl/certs/java/cacerts is a symlink into it.
JAVA_CACERTS = '/etc/ssl/certs/java/cacerts'
JAVA_CACERTS_HOOK = '/etc/ca-certificates/update.d/jks-keystore'
JAVA_CACERTS_DEFAULTS = '/etc/default/cacerts'
JAVA_CACERTS_BACKUP = '/var/backups/infratak-java-cacerts.bak'
SYSTEM_CERTS_DIR = '/etc/ssl/certs'
_SYSTEM_CA_SOURCES = ('/usr/share/ca-certificates/', '/usr/local/share/ca-certificates/')
# Mozilla's bundle is ~145 roots. Far fewer means /etc/ssl/certs is broken, not that the
# world distrusted everyone — never "sync" the Java keystore down to that.
_JAVA_CACERTS_MIN_SYSTEM_ROOTS = 50
_JAVA_CACERTS_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}
_KEYTOOL_DEBIAN_ALIAS = re.compile(r'^debian:(.+?),\s.*\btrustedCertEntry\b')


def _java_cacerts_settings():
    """(updates_enabled, storepass), read from /etc/default/cacerts the way the hook does:
    it sources that file and runs only when it sets cacerts_updates=yes."""
    enabled, storepass = False, 'changeit'
    try:
        with open(JAVA_CACERTS_DEFAULTS, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = re.match(r'''^\s*(storepass|cacerts_updates)=(['"]?)(.*?)\2\s*$''', line)
                if not m:
                    continue
                if m.group(1) == 'storepass':
                    storepass = m.group(3)
                else:
                    enabled = m.group(3) == 'yes'
    except OSError:
        pass
    return enabled, storepass


def _java_cacerts_supported():
    """(ok, reason). A box that cannot be synced is skipped, never denied: a DENY would
    count against the broker's ENFORCE readiness for something that is not a fault."""
    if os.path.islink(JAVA_CACERTS):
        return False, f'{JAVA_CACERTS} is a symlink (update-ca-trust keeps it in step)'
    if not os.path.isfile(JAVA_CACERTS):
        return False, 'no Java CA keystore on this host'
    try:
        st = os.lstat(JAVA_CACERTS_HOOK)
    except OSError:
        return False, 'ca-certificates-java is not installed'
    # We run this file as root, so it must be one only root could have put there.
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o022):
        return False, f'{JAVA_CACERTS_HOOK} is not a root-owned regular file — not running it'
    if not _sudoers_safe_binaries('keytool'):
        return False, f'no root-owned keytool in {_SUDOERS_BIN_DIRS}'
    if not _java_cacerts_settings()[0]:
        return False, f'Java keystore updates are turned off in {JAVA_CACERTS_DEFAULTS}'
    return True, ''


def _java_cacerts_drift(keytool, storepass):
    """(stale_aliases, missing_pems, system_root_count), or None if keytool cannot read
    the keystore. Names are compared case-insensitively: JKS lowercases its aliases."""
    try:
        r = subprocess.run([keytool, '-list', '-keystore', JAVA_CACERTS, '-storepass', storepass],
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=120, env=_JAVA_CACERTS_ENV, cwd='/')
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    java = {}
    for line in (r.stdout or '').splitlines():
        m = _KEYTOOL_DEBIAN_ALIAS.match(line)
        if m:
            java[m.group(1).lower()] = m.group(1)
    system = {}
    try:
        names = os.listdir(SYSTEM_CERTS_DIR)
    except OSError:
        names = []
    for name in names:
        path = os.path.join(SYSTEM_CERTS_DIR, name)
        # update-ca-certificates' own links only; the hash links and the bundle are not roots
        if not name.endswith('.pem') or not os.path.islink(path):
            continue
        if os.path.realpath(path).startswith(_SYSTEM_CA_SOURCES) and os.path.isfile(path):
            system[name.lower()] = name
    stale = sorted(java[k] for k in java if k not in system)
    missing = sorted(system[k] for k in system if k not in java)
    return stale, missing, len(system)


def _check_java_cacerts_sync(req):
    # Nothing in the request is read, so there is nothing to validate. Whether this box
    # can be synced is decided in _do_java_cacerts_sync and reported as a skip.
    return


def _do_java_cacerts_sync(req):
    ok, why = _java_cacerts_supported()
    if not ok:
        return {'ok': True, 'skipped': why}
    keytool = _sudoers_safe_binaries('keytool')[0]
    storepass = _java_cacerts_settings()[1]
    before = _java_cacerts_drift(keytool, storepass)
    if before is None:
        return {'ok': False, 'error': f'keytool could not read {JAVA_CACERTS}'}
    stale, missing, n_system = before
    if n_system < _JAVA_CACERTS_MIN_SYSTEM_ROOTS:
        return {'ok': False, 'error': f'only {n_system} CA roots in {SYSTEM_CERTS_DIR} — '
                                      'refusing to sync the Java keystore down to that'}
    if not stale and not missing:
        return {'ok': True, 'removed': [], 'added': []}
    try:
        os.makedirs(os.path.dirname(JAVA_CACERTS_BACKUP), exist_ok=True)
        shutil.copy2(JAVA_CACERTS, JAVA_CACERTS_BACKUP)
    except OSError as e:
        return {'ok': False, 'error': f'could not back up {JAVA_CACERTS} (nothing changed): {e}'}
    # The hook's input protocol, as update-ca-certificates writes it: "-<path>" drops alias
    # debian:<basename> (the file need not exist), "+<path>" imports the file under it.
    feed = ''.join(f'-{os.path.join(SYSTEM_CERTS_DIR, a)}\n' for a in stale) + \
        ''.join(f'+{os.path.join(SYSTEM_CERTS_DIR, n)}\n' for n in missing)
    try:
        r = subprocess.run([JAVA_CACERTS_HOOK], input=feed, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=300,
                           env=_JAVA_CACERTS_ENV, cwd='/')
        hook_rc, hook_out = r.returncode, ((r.stderr or '') + (r.stdout or '')).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        hook_rc, hook_out = -1, str(e)
    after = _java_cacerts_drift(keytool, storepass)
    if after is None:
        # A keystore Java cannot open breaks every outbound TLS call TAK makes, which is far
        # worse than the stale roots. Put the old one back.
        try:
            shutil.copy2(JAVA_CACERTS_BACKUP, JAVA_CACERTS)
        except OSError as e:
            return {'ok': False, 'error': f'keystore unreadable after the update and the restore '
                                          f'from {JAVA_CACERTS_BACKUP} failed: {e}'}
        return {'ok': False, 'error': 'keystore unreadable after the update — restored the previous '
                                      f'one (hook rc {hook_rc}: {hook_out[-300:]})'}
    left_stale = {a.lower() for a in after[0]}
    left_missing = {n.lower() for n in after[1]}
    return {'ok': hook_rc == 0,
            'removed': [a for a in stale if a.lower() not in left_stale],
            'added': [n for n in missing if n.lower() not in left_missing],
            'still_stale': after[0], 'still_missing': after[1],
            'backup': JAVA_CACERTS_BACKUP,
            **({} if hook_rc == 0 else {'error': f'hook rc {hook_rc}: {hook_out[-300:]}'})}


# ---------------------------------------------------------------------------
# ops #202 — the MediaMTX web editor's certifi drops distrusted roots (fixed-shape op)
# ---------------------------------------------------------------------------
# The MediaMTX module pip-installs requests, which brings certifi: Mozilla's CA list as of
# the install. Every MediaMTX deploy and update runs `pip3 install -U certifi` since
# v10.2.29, but Update Now deploys nothing, so an older install keeps its copy. Measured
# 2026-10-24 on two Ubuntu 22.04 boxes: certifi 2026.02.25 in /usr/local, still carrying
# emSign ECC Root CA - G3, for root's python3 and for the editor's (it runs as takwerx and
# has no copy of its own, so it loads the same one).
#
# The op takes NO arguments and only acts where the web editor is installed. It asks root's
# python3, then the editor user's, which certifi they load, and upgrades a pip-installed
# copy that still holds a distrusted root (matched by public key): root's in /usr/local,
# the user's own in its home with --user. A distro certifi is left alone: Debian and RHEL
# patch theirs to hand out the OS bundle, which the OS updates.
CERTIFI_EDITOR_DIR = '/opt/mediamtx-webeditor'
CERTIFI_EDITOR_USER = 'takwerx'          # mediamtx-webeditor.service User=
CERTIFI_PYTHON = '/usr/bin/python3'      # and its ExecStart interpreter
CERTIFI_ROOT_PIP_PREFIX = '/usr/local/'  # where root's `pip3 install` puts packages
# sha256 of the root's DER SubjectPublicKeyInfo. Add the next distrusted root here.
CERTIFI_DISTRUSTED_SPKI = {
    '8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782': 'emSign ECC Root CA - G3',
}
_CERTIFI_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8',
                'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1'}
_CERTIFI_WHERE = 'import certifi, sys; sys.stdout.write(certifi.where())'
_PEM_CERT = re.compile(rb'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', re.S)


def _der_tlv(buf, i):
    """(tag, content_start, end) of the DER element at buf[i]."""
    tag, n = buf[i], buf[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(buf[j:j + k], 'big')
        j += k
    if j + n > len(buf):
        raise ValueError('truncated DER')
    return tag, j, j + n


def _cert_spki_sha256(der):
    """sha256 of a certificate's DER SubjectPublicKeyInfo — the same bytes `openssl x509
    -pubkey | openssl pkey -pubin -outform DER` gives — or None when it does not parse."""
    try:
        _, i, _ = _der_tlv(der, 0)               # Certificate
        _, i, end = _der_tlv(der, i)             # tbsCertificate
        fields = []
        while i < end and len(fields) < 7:
            tag, _, nxt = _der_tlv(der, i)
            fields.append((tag, i, nxt))
            i = nxt
        if fields and fields[0][0] == 0xA0:      # [0] version
            fields = fields[1:]
        # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
        tag, a, b = fields[5]
    except (IndexError, ValueError):
        return None
    return hashlib.sha256(der[a:b]).hexdigest() if tag == 0x30 else None


def _bundle_distrusted(path):
    """Names of the CERTIFI_DISTRUSTED_SPKI roots in a PEM bundle, or None if unreadable."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return None
    found = []
    for m in _PEM_CERT.finditer(data):
        try:
            der = base64.b64decode(b''.join(m.group(1).split()))
        except ValueError:
            continue
        name = CERTIFI_DISTRUSTED_SPKI.get(_cert_spki_sha256(der))
        if name and name not in found:
            found.append(name)
    return found


def _certifi_runner(user):
    """(argv prefix, python flags, env, home) to run CERTIFI_PYTHON as `user` (None: root),
    or None. Root runs -I: pip's root installs go to /usr/local, never /root/.local. The
    editor user runs -E only, because the service runs without -I and its user site counts."""
    if user is None:
        return [], ['-I'], dict(_CERTIFI_ENV, HOME='/root'), None
    try:
        home = pwd.getpwnam(user).pw_dir
    except KeyError:
        return None
    runuser = _sudoers_safe_binaries('runuser')
    if not runuser:
        return None
    return ([runuser[0], '-u', user, '--'], ['-E'],
            dict(_CERTIFI_ENV, HOME=home, USER=user, LOGNAME=user), home)


def _certifi_view(user):
    """What `user`'s python3 loads: {'where', 'pip', 'distrusted'}; {} for no certifi or a
    distro one; None when it could not be asked."""
    run = _certifi_runner(user)
    if run is None:
        return None
    prefix, flags, env, home = run
    try:
        r = subprocess.run(prefix + [CERTIFI_PYTHON] + flags + ['-c', _CERTIFI_WHERE],
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=60, env=env, cwd='/')
    except (OSError, subprocess.TimeoutExpired):
        return None
    where = (r.stdout or '').strip() if r.returncode == 0 else ''
    if not where:
        return {}                                 # no certifi for this python
    where = os.path.realpath(where)
    if os.path.basename(os.path.dirname(where)) != 'certifi':
        return {}                                 # distro certifi: the OS bundle
    if user is None:
        pip_copy = where.startswith(CERTIFI_ROOT_PIP_PREFIX)
    else:
        pip_copy = bool(home) and where.startswith(os.path.realpath(home).rstrip('/') + '/')
    return {'where': where, 'pip': pip_copy, 'distrusted': _bundle_distrusted(where) or []}


def _certifi_pip_upgrade(user):
    """(ok, output tail) of `python3 -m pip install -U certifi` as `user` (None: root)."""
    prefix, flags, env, _home = _certifi_runner(user)
    argv = (prefix + [CERTIFI_PYTHON] + flags +
            ['-m', 'pip', 'install', '--upgrade', '--only-binary', ':all:',
             '--timeout', '30', '--retries', '2'] + ([] if user is None else ['--user']) +
            ['certifi'])
    out = ''
    # An externally-managed python (Ubuntu 24.04, pip 23+) needs --break-system-packages;
    # Ubuntu 22.04's pip 22.0 does not know the option. Same fallback as the deploy.
    for extra in (['--break-system-packages'], []):
        try:
            r = subprocess.run(argv + extra, capture_output=True, text=True, encoding='utf-8',
                               errors='replace', timeout=240, env=env, cwd='/')
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, str(e)[-300:]
        out = ((r.stdout or '') + (r.stderr or '')).strip()
        if r.returncode == 0:
            return True, out[-300:]
        if 'no such option' not in out:
            break
    return False, out[-300:]


def _check_certifi_upgrade(req):
    # Nothing in the request is read. Whether this box needs it is decided in
    # _do_certifi_upgrade and reported as a skip, never a denial.
    return


def _do_certifi_upgrade(req):
    if not os.path.isdir(CERTIFI_EDITOR_DIR):
        return {'ok': True, 'skipped': 'MediaMTX web editor is not installed'}
    try:
        st = os.stat(CERTIFI_PYTHON)
    except OSError:
        return {'ok': True, 'skipped': f'no {CERTIFI_PYTHON}'}
    # We run it as root, so it must be one only root could have put there.
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o022):
        return {'ok': True, 'skipped': f'{CERTIFI_PYTHON} is not a root-owned file — not running it'}
    users = [None]
    try:
        pwd.getpwnam(CERTIFI_EDITOR_USER)
        users.append(CERTIFI_EDITOR_USER)
    except KeyError:
        pass
    upgraded, still, errors = [], [], []
    for user in users:                            # root first: the editor may share its copy
        label = user or 'root'
        before = _certifi_view(user)
        if not before or not before['distrusted']:
            continue
        if not before['pip']:
            still.append({'user': label, 'path': before['where'], 'roots': before['distrusted']})
            continue
        ok, out = _certifi_pip_upgrade(user)
        after = _certifi_view(user) or {}
        left = after.get('distrusted') or []
        if left or after.get('where') is None:
            still.append({'user': label, 'path': after.get('where') or before['where'],
                          'roots': left or before['distrusted']})
            errors.append(f'{label}: ' + (out if not ok else 'certifi still holds ' + ', '.join(left)))
        else:
            upgraded.append({'user': label, 'path': before['where'], 'removed': before['distrusted']})
    return {'ok': not errors, 'upgraded': upgraded, 'still_stale': still,
            **({'error': '; '.join(errors)[-600:]} if errors else {})}


# ── Leftover PostgreSQL 15 cluster after the TAK 5.8 migration (GH #273) ──────
# upgrade-db.sh runs pg_upgrade in COPY mode, so the 15 cluster stays on disk,
# stopped, as the rollback. Nothing ever removes it: the reporter's sat at 15 GB for
# weeks next to a 14 GB PostgreSQL 18 cluster. `inspect` reports it (the console user
# cannot read a postgres 0700 data dir, let alone `du` it); `drop` removes it.
#   * The request carries an action and NOTHING else — no path, no major, no argv.
#     Both majors and both layouts are constants here.
#   * `drop` re-checks everything itself at call time and refuses unless the 15
#     cluster is stopped AND a PostgreSQL 18 cluster is running. The console's own
#     gates (password, confirmation, "18 is healthy") are not trusted in its place.
#   * Never follows a symlink, and PG_VERSION must say 15, so the op cannot be pointed
#     at anything but a real PostgreSQL 15 data directory.
_PG_OLD_MAJOR = 15
_PG_NEW_MAJOR = 18
_PG_CLUSTER_LAYOUTS = (
    ('debian', '/var/lib/postgresql/{major}/main'),     # postgresql-common
    ('rhel', '/var/lib/pgsql/{major}/data'),            # PGDG on EL
)


def _pg_cluster_dir(major):
    """(family, data_dir) of a real `major` cluster, or (None, None)."""
    for fam, tmpl in _PG_CLUSTER_LAYOUTS:
        p = tmpl.format(major=major)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            continue
        try:
            with open(os.path.join(p, 'PG_VERSION')) as fh:
                if fh.read().strip() != str(major):
                    continue
        except OSError:
            continue
        return fam, p
    return None, None


def _pg_cluster_running(path):
    # postmaster.pid exists while the postmaster runs. A crash can leave a stale one;
    # that reads as "running" and refuses the drop, which is the safe direction.
    return os.path.lexists(os.path.join(path, 'postmaster.pid'))


def _pg_dir_bytes(path):
    """Disk use of a directory tree, like `du -sb` (os.walk never follows symlinks)."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for n in files:
            try:
                total += os.lstat(os.path.join(root, n)).st_blocks * 512
            except OSError:
                pass
    return total


def _check_pg_old_cluster(req):
    if req.get('action') not in ('inspect', 'drop'):
        raise Denied(f"pg_old_cluster: action must be 'inspect' or 'drop': {req.get('action')!r}")
    extra = set(req) - {'op', 'action', 'timeout'}
    if extra:
        raise Denied(f'pg_old_cluster: takes no other fields: {sorted(extra)}')


def _pg_old_cluster_facts():
    fam, old = _pg_cluster_dir(_PG_OLD_MAJOR)
    if not old:
        return {'ok': True, 'found': False, 'major': _PG_OLD_MAJOR}
    _nf, new = _pg_cluster_dir(_PG_NEW_MAJOR)
    return {'ok': True, 'found': True, 'major': _PG_OLD_MAJOR, 'family': fam, 'path': old,
            'running': _pg_cluster_running(old), 'bytes': _pg_dir_bytes(old),
            'new_major': _PG_NEW_MAJOR, 'new_path': new,
            'new_running': bool(new) and _pg_cluster_running(new)}


def _do_pg_old_cluster(req):
    _check_pg_old_cluster(req)
    f = _pg_old_cluster_facts()
    if req.get('action') == 'inspect' or not f.get('found'):
        if req.get('action') == 'drop':
            return {**f, 'ok': False, 'error': f'no PostgreSQL {_PG_OLD_MAJOR} cluster found'}
        return f
    if f['running']:
        return {**f, 'ok': False, 'error': f'the PostgreSQL {_PG_OLD_MAJOR} cluster is running '
                                           f'(postmaster.pid in {f["path"]}) — not removing it'}
    if not f['new_running']:
        return {**f, 'ok': False, 'error': f'no running PostgreSQL {_PG_NEW_MAJOR} cluster — the '
                                           f'{_PG_OLD_MAJOR} cluster may still be the only database'}
    out = ''
    drop = shutil.which('pg_dropcluster', path=BROKER_TRUSTED_PATH) if f['family'] == 'debian' else None
    if drop:
        # The supported removal: data dir AND /etc/postgresql/15/main, cluster unregistered.
        try:
            r = subprocess.run([drop, str(_PG_OLD_MAJOR), 'main'], cwd='/', capture_output=True,
                               text=True, timeout=1800)
            out = ((r.stdout or '') + (r.stderr or '')).strip()[-2000:]
        except subprocess.SubprocessError as e:
            out = str(e)[:300]
    else:
        systemctl = shutil.which('systemctl', path=BROKER_TRUSTED_PATH)
        if systemctl:
            subprocess.run([systemctl, 'disable', f'postgresql-{_PG_OLD_MAJOR}'],
                           capture_output=True, timeout=30)
    if os.path.isdir(f['path']) and not os.path.islink(f['path']):
        # EL has no pg_dropcluster; on Debian this is the fallback if it failed.
        shutil.rmtree(f['path'], ignore_errors=True)
    gone = not os.path.lexists(f['path'])
    return {**f, 'ok': gone, 'removed': gone, 'freed_bytes': f['bytes'] if gone else 0,
            'output': out, **({} if gone else {'error': f'{f["path"]} is still present'})}


def _evaluate(req):
    """Return ('ALLOW'|'DENY', reason) for a data-plane request WITHOUT executing
    it. Never raises."""
    op = req.get('op')
    try:
        if op == 'exec':
            check_exec(req.get('argv') or [], req.get('cwd'))
        elif op == 'write' and _abs(req.get('path')) == _OPENSSL_CNF:
            _check_openssl_cnf_write(req)      # exact-patch gate, not a blanket allow
        elif op in ('write', 'read'):
            _path_allowed(req.get('path'), readonly=(op == 'read'))
            if op == 'write':
                _check_validated_write(req)     # ops #645 W2
        elif op == 'pg_dump':
            _check_pg_dump(req)
        elif op == 'stack_pg_dump':
            _check_stack_pg_dump(req)
        elif op == 'stack_nodered_tar':
            _check_stack_nodered_tar(req)
        elif op == 'stack_pg_restore':
            _check_stack_pg_restore(req)
        elif op == 'pg_restore':
            _check_pg_restore(req)
        elif op == 'pgminer_scan':
            _check_pgminer_scan(req)
        elif op == 'disk_reclaim':
            _check_disk_reclaim(req)
        elif op == 'takportal_sudoers':
            _check_takportal_sudoers(req)
        elif op == 'tak58_upgrade_db':
            _check_tak58_upgrade_db(req)
        elif op == 'tak58_setup_db':
            _check_tak58_setup_db(req)
        elif op == 'java_cacerts_sync':
            _check_java_cacerts_sync(req)
        elif op == 'certifi_upgrade':
            _check_certifi_upgrade(req)
        elif op == 'pg_old_cluster':
            _check_pg_old_cluster(req)
        elif op == 'mediamtx_account':
            _check_mediamtx_account(req)
        elif op == 'gd_render':
            _check_gd_render(req)           # ops #645 W2 part 2a
        else:
            return ('DENY', f'unknown op: {op}')
        return ('ALLOW', '')
    except Denied as d:
        return ('DENY', str(d))


def _summary(req):
    op = req.get('op')
    if op == 'exec':
        argv = [str(a) for a in (req.get('argv') or [])]
        # Redact secrets that legitimately ride in argv (v10.1.0: the nmcli WiFi
        # profile shapes carry the operator-entered PSK — it must never reach
        # the persistent audit log or journald; CJIS "secrets never logged").
        # Generic rule: the token FOLLOWING a literal password-ish key.
        for i, a in enumerate(argv[:-1]):
            if a in _SECRET_VALUE_FLAGS:
                argv[i + 1] = '***'
        # In-token secrets (v10.1.4 WS15): the CloudTAK postgis sync rides the DB
        # password INSIDE a single argv token, so the following-token rule above
        # misses it — `psql ... -c "ALTER USER docker WITH PASSWORD 'secret'"` and
        # the env-assignment `PGPASSWORD=secret`. Redact the secret substring in
        # place (CJIS "secrets never logged"; the audit dir is root-only 0750, this
        # closes the last plaintext-DB-password path into the log + journald).
        argv = [_redact_inline_secrets(a) for a in argv]
        return ' '.join(argv)[:200]
    return str(req.get('path'))[:200]


# Argv keys whose NEXT token is a secret: nmcli WiFi PSK, keytool store/key
# passwords (ops #347: `keytool -storepass <pw>` was logged in clear), openssl
# -passin/-passout (`pass:<pw>`).
_SECRET_VALUE_FLAGS = frozenset((
    'password', 'wifi-sec.psk',
    '-storepass', '-keypass', '-srcstorepass', '-deststorepass', '-srckeypass',
    '-destkeypass', '-passin', '-passout', '-passwd',
))

_INLINE_SECRET_RES = (
    # PASSWORD '...' / PASSWORD "..." (SQL role DDL — quote style preserved, value masked)
    re.compile(r"(?i)(PASSWORD\s+)('[^']*'|\"[^\"]*\"|\S+)"),
    # PGPASSWORD=... / *_PASSWORD=... / *PASSWD=... / *TOKEN=... / *SECRET=... env assignments
    re.compile(r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY)=)(\S+)"),
)


def _redact_inline_secrets(s):
    """Mask secret values embedded inside a single argv token (SQL PASSWORD '…'
    and NAME=value env assignments). Never raises."""
    try:
        out = s
        for rx in _INLINE_SECRET_RES:
            out = rx.sub(lambda m: m.group(1) + '***', out)
        return out
    except Exception:
        return s


def _summary_safe(req, field=None):
    """Best-effort summary/op for audit on the exception paths, where `req` may be
    empty or unparsed. `field='op'` returns the op name; otherwise the summary.
    Never raises — these run inside `except` handlers."""
    try:
        if not isinstance(req, dict):
            return 'unknown' if field == 'op' else ''
        if field == 'op':
            return str(req.get('op') or 'unknown')
        return _summary(req)
    except Exception:
        return 'unknown' if field == 'op' else ''


def _dispatch(req, peer):
    op = req.get('op')
    if op == 'ping':
        audit(peer, 'ping', '', 'ALLOW')
        return {'ok': True, 'pong': True, 'enforce': ENFORCE,
                'enforce_info': ENFORCE_INFO, 'deny_count': _DENY_COUNT,
                'readiness': _enforce_readiness(fresh=False),
                'src_sha': RUNNING_SRC_SHA, 'src_path': SELF_PATH,
                # ops #645 W1: '' until the broker runs from the root-owned layout
                'installed_commit': _installed_commit(),
                'root_install': dict(ROOT_MOVE_STATE),
                'security_level': BROKER_SECURITY_LEVEL}
    if op == 'broker_update':
        # ops #645 W1: fixed shape, fail-closed in both modes. Root fetches the
        # commit itself and installs it only if it is on GitHub main/dev/v* and
        # not below this broker's security level (_root_install).
        commit = req.get('commit')
        summary = str(commit)[:64]
        if set(req) - {'op', 'commit'} or not (
                isinstance(commit, str) and _COMMIT_RE.fullmatch(commit)):
            audit(peer, op, summary, 'DENY', 'bad broker_update request')
            return {'ok': False, 'code': 'DENIED',
                    'error': 'broker_update takes only a full 40-character commit id'}
        audit(peer, op, summary, 'ALLOW')
        r = _do_broker_update(req)
        if not r.get('ok'):
            audit(peer, op, summary, 'ERROR', r.get('error', '')[:300])
        return r
    if op == 'enforce_enable':
        # Operator opts the box in to enforcement (ratchet — enable only). Audited.
        audit(peer, 'enforce_enable', '', 'ALLOW')
        return _do_enforce_enable(req)
    # dry-run: report what the rulebook WOULD do, without executing. Used by the
    # self-test to verify deny rules even while the broker runs permissive.
    if op == 'check':
        inner = req.get('req') or {}
        verdict, reason = _evaluate(inner)
        return {'ok': True, 'verdict': verdict, 'reason': reason, 'enforce': ENFORCE}
    if op in ('pg_dump', 'stack_pg_dump', 'stack_nodered_tar', 'stack_pg_restore', 'pg_restore', 'pgminer_scan', 'disk_reclaim',
              'takportal_sudoers', 'tak58_upgrade_db', 'tak58_setup_db', 'java_cacerts_sync', 'certifi_upgrade',
              'pg_old_cluster', 'mediamtx_account', 'gd_render'):
        verdict, reason = _evaluate(req)
        if op == 'pgminer_scan':
            summary = req.get('container', '')
        elif op == 'java_cacerts_sync':
            summary = JAVA_CACERTS
        elif op == 'certifi_upgrade':
            summary = CERTIFI_EDITOR_DIR
        elif op == 'stack_nodered_tar':
            summary = f"{_STACK_NODERED_CONTAINER} -> {req.get('path')}"
        elif op in ('stack_pg_dump', 'stack_pg_restore'):
            summary = f"{req.get('container')} {'->' if op == 'stack_pg_dump' else '<-'} {req.get('path')}"
        elif op == 'pg_old_cluster':
            summary = f"action={req.get('action')} major={_PG_OLD_MAJOR}"
        elif op == 'mediamtx_account':
            summary = MEDIAMTX_USER
        elif op == 'disk_reclaim':
            summary = f"mode={req.get('mode')} lv={req.get('confirm_lv') or '-'}"
        elif op == 'takportal_sudoers':
            summary = f"action={req.get('action')} user={BROKER_USER}"
        elif op == 'tak58_upgrade_db':
            summary = _TAK58_UPGRADE_DB
        elif op == 'tak58_setup_db':
            summary = _TAK58_SETUP_DB
        elif op == 'gd_render':
            summary = f"{GD_DIR}/{str(req.get('name'))[:80]} keys={','.join(sorted(map(str, req.get('values') or {})))[:200]}"
        else:
            summary = _summary(req)
        if verdict == 'DENY':
            # fail-closed in BOTH modes — new ops, nothing legacy to preserve
            audit(peer, op, summary, 'DENY', reason)
            return {'ok': False, 'code': 'DENIED', 'error': reason}
        audit(peer, op, summary, 'ALLOW')
        if op == 'pg_dump':
            return _do_pg_dump(req)
        if op == 'stack_pg_dump':
            return _do_stack_pg_dump(req)
        if op == 'stack_nodered_tar':
            return _do_stack_nodered_tar(req)
        if op == 'stack_pg_restore':
            return _do_stack_pg_restore(req)
        if op == 'pg_restore':
            return _do_pg_restore(req)
        if op == 'disk_reclaim':
            return _do_disk_reclaim(req)
        if op == 'takportal_sudoers':
            return _do_takportal_sudoers(req)
        if op == 'tak58_upgrade_db':
            return _do_tak58_upgrade_db(req)
        if op == 'tak58_setup_db':
            return _do_tak58_setup_db(req)
        if op == 'java_cacerts_sync':
            return _do_java_cacerts_sync(req)
        if op == 'certifi_upgrade':
            return _do_certifi_upgrade(req)
        if op == 'pg_old_cluster':
            return _do_pg_old_cluster(req)
        if op == 'mediamtx_account':
            return _do_mediamtx_account(req)
        if op == 'gd_render':
            return _do_gd_render(req)
        return _do_pgminer_scan(req)
    if op in ('exec', 'write', 'read'):
        verdict, reason = _evaluate(req)
        summary = _summary(req)
        if verdict == 'DENY':
            if ENFORCE:
                audit(peer, op, summary, 'DENY', reason)
                return {'ok': False, 'code': 'DENIED', 'error': reason}
            # permissive: record what WOULD be denied, then execute anyway (the
            # console is root today, so this is mediation+audit, not a new hole).
            audit(peer, op, summary, 'WOULD-DENY', reason)
        else:
            audit(peer, op, summary, 'ALLOW')
        if op == 'exec':
            return _do_exec(req)
        if op == 'write':
            return _do_write(req)
        return _do_read(req)
    audit(peer, str(op), '', 'DENY', 'unknown op')
    return {'ok': False, 'code': 'DENIED', 'error': f'unknown op: {op}'}


# ---------------------------------------------------------------------------
# MediaMTX profile (ops #643)
# ---------------------------------------------------------------------------
# MediaMTX and its web editor (internet-facing) run as their own account, not the
# console's. They used to share `takwerx`, so an editor bug could edit the console's
# code in /opt/infratak or send the broker anything the console may. They still need
# a few root actions (upgrade/rollback the MediaMTX binary, restart their own units,
# install codec packages, open their stream ports), so they get their OWN socket and
# only the argv shapes the editor actually sends (mediamtx-installer
# config-editor/mediamtx_config_editor.py: _mtx_broker_exec / mtx_copy_priv /
# mtx_install_binary / _firewall_exec / deps install). Always enforced: there is no
# permissive mode on this socket, and every request is audited with the peer uid.
MEDIAMTX_USER = 'mediamtx'
MEDIAMTX_SOCKET_PATH = os.environ.get('TAKWERX_BROKER_MEDIAMTX_SOCKET',
                                      '/run/takwerx-broker-mediamtx.sock')
_MTX_BIN = '/usr/local/bin/mediamtx'
_MTX_CONF = '/usr/local/etc/mediamtx.yml'
_MTX_CONF_BACKUPS = '/usr/local/etc/mediamtx_backups/'
_MTX_EDITOR_DIR = '/opt/mediamtx-webeditor/'
_MTX_BIN_STAGED = '/opt/mediamtx-webeditor/binstage/mediamtx'
_MTX_UNITS = frozenset(('mediamtx', 'mediamtx.service',
                        'mediamtx-webeditor', 'mediamtx-webeditor.service'))
_MTX_SYSTEMCTL_VERBS = frozenset(('is-active', 'is-enabled', 'status',
                                  'start', 'stop', 'restart'))
# The editor's own DEPS_PACKAGES (Dependencies tab), nothing else.
_MTX_PKGS = {
    'apt': frozenset(('ffmpeg', 'gstreamer1.0-tools', 'gstreamer1.0-plugins-base',
                      'gstreamer1.0-plugins-good', 'gstreamer1.0-plugins-bad',
                      'gstreamer1.0-libav', 'gstreamer1.0-rtsp')),
    'dnf': frozenset(('ffmpeg', 'gstreamer1', 'gstreamer1-plugins-base',
                      'gstreamer1-plugins-good', 'gstreamer1-plugins-bad-free',
                      'gstreamer1-plugins-ugly-free', 'gstreamer1-libav',
                      'gstreamer1-plugins-bad-freeworld', 'gstreamer1-plugins-ugly',
                      'gstreamer1-rtsp-server')),
}
# Stream ports are the operator's choice in the editor, so any port may be opened or
# closed EXCEPT these: SSH/HTTP(S) access to the box and the loopback-only admin
# surfaces of infra-TAK and its modules. Opening one of those to the internet, or
# closing SSH or 443, is not something a streaming editor ever needs to do.
_MTX_FW_PROTECTED_PORTS = frozenset((
    22, 80, 443,
    5001,                     # infra-TAK console
    5080, 9898, 8888,         # MediaMTX web editor, MediaMTX API, HLS (Caddy only)
    9996, 9997, 9998, 9999,   # MediaMTX playback/CloudTAK media API/metrics/pprof
    8080, 8443, 8444, 8446, 8089, 9001,   # TAK Server
    9000, 9090, 9443,         # Authentik
    5432, 6432,               # Postgres, pgbouncer
    1880,                     # Node-RED
))
_MTX_PORT_RE = re.compile(r'^([0-9]{1,5})/(tcp|udp)$')
_MTX_BACKUP_NAME_RE = re.compile(r'^[A-Za-z0-9._-]+$')
_ELF_MAGIC = b'\x7fELF'


def _mtx_uid():
    try:
        return pwd.getpwnam(MEDIAMTX_USER).pw_uid
    except KeyError:
        return None


def _mtx_clean_path(p):
    """Absolute, normalised, no NUL and no `..` — else Denied."""
    if not isinstance(p, str) or not p.startswith('/') or '\x00' in p:
        raise Denied(f'mediamtx: bad path {p!r}')
    if os.path.normpath(p) != p.rstrip('/') or '/../' in p + '/':
        raise Denied(f'mediamtx: path not normalised: {p}')
    return p


def _mtx_own_path(p):
    """True for paths that belong to MediaMTX itself: the editor dir, the config file
    and its backups. A copy between these runs AS the mediamtx account, so a symlink
    it planted can only reach what it could already read or write."""
    return (p.startswith(_MTX_EDITOR_DIR) or p.startswith(_MTX_CONF_BACKUPS)
            or p == _MTX_CONF or (p.startswith(_MTX_CONF + '.')
                                  and _MTX_BACKUP_NAME_RE.fullmatch(os.path.basename(p))))


def _mtx_port_ok(spec):
    m = _MTX_PORT_RE.fullmatch(spec or '')
    if not m:
        raise Denied(f'mediamtx: bad port spec {spec!r}')
    port = int(m.group(1))
    if not 1 <= port <= 65535:
        raise Denied(f'mediamtx: bad port {port}')
    if port in _MTX_FW_PROTECTED_PORTS:
        raise Denied(f'mediamtx: port {port} is not a stream port')
    return True


def check_mediamtx_exec(argv):
    """Classify one exec request from the mediamtx account.

    Returns 'root' (run as root, exact shape checked here), 'user' (run as the
    mediamtx account) or 'install' (the staged-binary swap, done in-process by
    _mtx_install_binary). Raises Denied for everything else."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise Denied('mediamtx: argv must be a non-empty list of strings')
    if any('\x00' in a for a in argv):
        raise Denied('mediamtx: NUL in argv')
    cmd, args = argv[0], argv[1:]
    if '/' in cmd:
        raise Denied(f'mediamtx: bare command names only: {cmd}')
    if cmd == 'systemctl':
        if len(args) == 2 and args[0] == 'is-active' and args[1] == 'takwerx-broker':
            return 'root'                       # the editor's "is the broker there" probe
        if len(args) == 2 and args[0] in _MTX_SYSTEMCTL_VERBS and args[1] in _MTX_UNITS:
            return 'root'
        raise Denied(f'mediamtx: systemctl {" ".join(args)[:80]} not allowed')
    if cmd == 'test':
        # Cert-file existence check (resolve_existing_cert): only cert/key names.
        if (len(args) == 2 and args[0] == '-f'
                and _mtx_clean_path(args[1]).endswith(('.crt', '.key', '.pem', '.cer'))):
            return 'root'
        raise Denied('mediamtx: test only as `test -f <cert or key file>`')
    if cmd == 'cp':
        if len(args) != 2:
            raise Denied('mediamtx: cp takes exactly SRC DST (no flags)')
        src, dst = _mtx_clean_path(args[0]), _mtx_clean_path(args[1])
        if src == _MTX_BIN_STAGED and dst == _MTX_BIN:
            return 'install'
        if dst == _MTX_BIN:
            raise Denied(f'mediamtx: the binary is installed only from {_MTX_BIN_STAGED}')
        if (src == _MTX_BIN or _mtx_own_path(src)) and _mtx_own_path(dst):
            return 'user'
        raise Denied(f'mediamtx: cp {src} -> {dst} not allowed')
    if cmd == 'chmod':
        if args == ['755', _MTX_BIN]:
            return 'root'
        raise Denied('mediamtx: chmod only as `chmod 755 /usr/local/bin/mediamtx`')
    if cmd == 'restorecon':
        if args == [_MTX_BIN]:
            return 'root'
        raise Denied('mediamtx: restorecon only on /usr/local/bin/mediamtx')
    if cmd in ('apt-get', 'dnf'):
        pm = 'apt' if cmd == 'apt-get' else 'dnf'
        if args == (['update', '-qq'] if pm == 'apt' else ['-q', 'makecache']):
            return 'root'
        fixed = ['install', '-y', '-q'] if pm == 'apt' else ['install', '-y']
        if args[:len(fixed)] == fixed:
            pkgs = args[len(fixed):]
            if pkgs and all(p in _MTX_PKGS[pm] for p in pkgs):
                return 'root'
        raise Denied(f'mediamtx: {cmd} {" ".join(args)[:120]} not allowed')
    if cmd == 'ufw':
        if args == ['status']:
            return 'root'
        if len(args) == 2 and args[0] == 'allow' and _mtx_port_ok(args[1]):
            return 'root'
        if len(args) == 3 and args[:2] == ['delete', 'allow'] and _mtx_port_ok(args[2]):
            return 'root'
        raise Denied(f'mediamtx: ufw {" ".join(args)[:80]} not allowed')
    if cmd == 'firewall-cmd':
        if args == ['--list-ports']:
            return 'root'
        rest = args[1:] if args[:1] == ['--permanent'] else args
        if len(rest) == 1:
            for flag in ('--add-port=', '--remove-port='):
                if rest[0].startswith(flag) and _mtx_port_ok(rest[0][len(flag):]):
                    return 'root'
        raise Denied(f'mediamtx: firewall-cmd {" ".join(args)[:80]} not allowed')
    raise Denied(f'mediamtx: command not allowed: {cmd}')


def _mtx_install_binary():
    """Swap the staged MediaMTX binary into /usr/local/bin as root, without ever
    following a link the mediamtx account could plant: the staged file is opened
    O_NOFOLLOW from a dir whose real path is checked, must be a regular file owned by
    the mediamtx account, and must be an ELF. Written to a temp file next to the
    target (root-owned dir) and renamed over it. The binary is never run here."""
    uid = _mtx_uid()
    if uid is None:
        raise Denied('mediamtx: account missing')
    stage_dir = os.path.dirname(_MTX_BIN_STAGED)
    if os.path.realpath(stage_dir) != stage_dir:
        raise Denied('mediamtx: staging dir is a link')
    fd = os.open(_MTX_BIN_STAGED, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid:
            raise Denied('mediamtx: staged binary must be a regular file owned by mediamtx')
        if st.st_size > 512 * 1024 * 1024:
            raise Denied('mediamtx: staged binary too large')
        with os.fdopen(os.dup(fd), 'rb') as src:
            head = src.read(4)
            if head != _ELF_MAGIC:
                raise Denied('mediamtx: staged file is not an ELF binary')
            tmp_fd, tmp = tempfile.mkstemp(dir=os.path.dirname(_MTX_BIN), prefix='.mediamtx-new-')
            try:
                with os.fdopen(tmp_fd, 'wb') as out:
                    out.write(head)
                    shutil.copyfileobj(src, out, 1024 * 1024)
                    os.fchmod(out.fileno(), 0o755)
                os.replace(tmp, _MTX_BIN)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
    finally:
        os.close(fd)
    return {'ok': True, 'returncode': 0, 'stdout_b64': '', 'stderr_b64': ''}


def _mtx_run(argv, timeout, as_user):
    """Run an already-classified argv. `as_user` drops to the mediamtx account."""
    resolved = shutil.which(argv[0], path=BROKER_TRUSTED_PATH)
    if not resolved:
        raise Denied(f'mediamtx: {argv[0]} not on the trusted PATH')
    kw = {}
    env = None
    if as_user:
        uid = _mtx_uid()
        if uid is None:
            raise Denied('mediamtx: account missing')
        pw = pwd.getpwuid(uid)
        kw = {'user': uid, 'group': pw.pw_gid, 'extra_groups': []}
        env = {'PATH': BROKER_TRUSTED_PATH, 'HOME': '/', 'LC_ALL': 'C'}
    elif os.path.basename(resolved) == 'apt-get':
        env = dict(os.environ)
        env.setdefault('DEBIAN_FRONTEND', 'noninteractive')
        env.setdefault('NEEDRESTART_MODE', 'l')
        env.setdefault('DPKG_FORCE', 'confdef,confold')
    proc = subprocess.run([resolved] + list(argv[1:]), capture_output=True,
                          timeout=timeout, cwd='/', env=env, **kw)
    return {
        'ok': True,
        'returncode': proc.returncode,
        'stdout_b64': base64.b64encode(proc.stdout or b'').decode(),
        'stderr_b64': base64.b64encode(proc.stderr or b'').decode(),
    }


def _dispatch_mediamtx(req, peer):
    """The whole rulebook for the mediamtx socket. Fail closed in every mode."""
    op = req.get('op') if isinstance(req, dict) else None
    if op != 'exec':
        audit(peer, f'mediamtx:{op}', '', 'DENY', 'only exec is served to mediamtx')
        return {'ok': False, 'code': 'DENIED', 'error': f'op not allowed for mediamtx: {op}'}
    argv = req.get('argv')
    summary = _summary(req)
    try:
        kind = check_mediamtx_exec(argv)
    except Denied as d:
        audit(peer, 'mediamtx:exec', summary, 'DENY', str(d))
        return {'ok': False, 'code': 'DENIED', 'error': str(d)}
    audit(peer, 'mediamtx:exec', summary, 'ALLOW', kind)
    timeout = min(int(req.get('timeout') or DEFAULT_TIMEOUT), MAX_TIMEOUT)
    if kind == 'install':
        return _mtx_install_binary()
    return _mtx_run(argv, timeout, as_user=(kind == 'user'))


def _allowed_mediamtx_peer(uid):
    """The mediamtx socket serves the mediamtx account (and root, for checks) only.
    The console account is refused here: it has its own socket and rulebook."""
    return uid == 0 or (uid is not None and uid >= 0 and uid == _mtx_uid())


_MTX_SRV = None
_MTX_SRV_LOCK = threading.Lock()


def _check_mediamtx_account(req):
    """Fixed-shape op: no arguments are read, so there is nothing to validate."""
    extra = set(req) - {'op'}
    if extra:
        raise Denied(f'mediamtx_account takes no arguments: {sorted(extra)}')


def _mtx_account_problem():
    """Why an existing `mediamtx` account is unfit to run MediaMTX, or ''."""
    try:
        pw = pwd.getpwnam(MEDIAMTX_USER)
    except KeyError:
        return 'missing'
    if pw.pw_uid == 0 or pw.pw_gid == 0:
        return 'mediamtx account is uid/gid 0'
    try:
        if MEDIAMTX_USER in grp.getgrnam(BROKER_USER).gr_mem:
            return f'mediamtx account is in group {BROKER_USER}'
        if pw.pw_gid == grp.getgrnam(BROKER_USER).gr_gid:
            return f'mediamtx account has primary group {BROKER_USER}'
    except KeyError:
        pass
    return ''


def _do_mediamtx_account(req):
    """Create the `mediamtx` system account (own group, no home, no shell) when it is
    missing, then serve the mediamtx socket. The console asks for this before it moves
    the MediaMTX units off its own account. Never adds groups to an existing account."""
    global _MTX_SRV
    created = False
    if _mtx_account_problem() == 'missing':
        groupadd = shutil.which('groupadd', path=BROKER_TRUSTED_PATH)
        useradd = shutil.which('useradd', path=BROKER_TRUSTED_PATH)
        if not groupadd or not useradd:
            return {'ok': False, 'code': 'ERROR', 'error': 'groupadd/useradd not found'}
        try:
            grp.getgrnam(MEDIAMTX_USER)
        except KeyError:
            subprocess.run([groupadd, '--system', MEDIAMTX_USER],
                           capture_output=True, timeout=30)
        nologin = '/usr/sbin/nologin' if os.path.exists('/usr/sbin/nologin') else '/sbin/nologin'
        r = subprocess.run([useradd, '--system', '-g', MEDIAMTX_USER, '-M', '-d', '/nonexistent',
                            '-s', nologin, MEDIAMTX_USER], capture_output=True, timeout=30)
        if r.returncode != 0 and _mtx_account_problem() == 'missing':
            return {'ok': False, 'code': 'ERROR',
                    'error': 'useradd failed: ' + (r.stderr or b'').decode(errors='replace')[-200:]}
        created = True
    problem = _mtx_account_problem()
    if problem:
        return {'ok': False, 'code': 'ERROR', 'error': problem}
    with _MTX_SRV_LOCK:
        if _MTX_SRV is None or not os.path.exists(MEDIAMTX_SOCKET_PATH):
            _MTX_SRV = _start_mediamtx_listener()
    return {'ok': True, 'created': created, 'uid': _mtx_uid(),
            'socket': MEDIAMTX_SOCKET_PATH if _MTX_SRV is not None else ''}


def _unlink_mediamtx_socket():
    try:
        os.unlink(MEDIAMTX_SOCKET_PATH)
    except OSError:
        pass


def _start_mediamtx_listener():
    """Serve the mediamtx socket in a daemon thread when the account exists.
    Returns the server, or None (no fit account yet, so nothing to serve)."""
    if _mtx_account_problem():
        return None
    gid = pwd.getpwnam(MEDIAMTX_USER).pw_gid
    _unlink_mediamtx_socket()
    srv = _Server(MEDIAMTX_SOCKET_PATH, _MediamtxHandler)
    try:
        os.chown(MEDIAMTX_SOCKET_PATH, 0, gid)
        os.chmod(MEDIAMTX_SOCKET_PATH, 0o660)
    except OSError as e:
        srv.server_close()
        _unlink_mediamtx_socket()
        sys.stderr.write(f'takwerx-broker: mediamtx socket perms failed, not serving it: {e}\n')
        return None
    threading.Thread(target=srv.serve_forever, daemon=True, name='mediamtx-socket').start()
    return srv


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        # v10.2.8 W3: every request is counted while it runs, so the daily recycle can
        # wait for an idle moment instead of killing work in flight (_recycle_watch).
        _inflight_add(1)
        try:
            self._handle()
        finally:
            _inflight_add(-1)

    def _handle(self):
        conn = self.request
        peer = _peercred(conn)
        if not _allowed_peer(peer[1]):
            audit(peer, 'connect', '', 'DENY', 'unauthorized peer uid')
            try:
                conn.sendall(json.dumps({'ok': False, 'code': 'DENIED',
                                         'error': 'unauthorized peer'}).encode())
            except OSError:
                pass
            return
        req = {}
        try:
            raw = _recv_all(conn)
            req = json.loads(raw.decode())
            resp = _dispatch(req, peer)
        except Denied as d:
            # A Denied raised OUTSIDE _evaluate (so _dispatch never audited it) —
            # log it here so EVERY refusal hits the audit chokepoint, not just
            # rulebook denials. Without this a refusal surfaces to the client as a
            # bare exit-126 with nothing in the audit log (the v10.0.5 anomaly).
            resp = {'ok': False, 'code': 'DENIED', 'error': str(d)}
            audit(peer, _summary_safe(req, 'op'), _summary_safe(req), 'DENY', str(d))
        except subprocess.TimeoutExpired:
            resp = {'ok': False, 'code': 'TIMEOUT', 'error': 'command timed out'}
            audit(peer, _summary_safe(req, 'op'), _summary_safe(req), 'ERROR', 'command timed out')
        except Exception as e:  # noqa: BLE001 — broker must never crash a worker thread
            resp = {'ok': False, 'code': 'ERROR', 'error': f'{type(e).__name__}: {e}'}
            audit(peer, _summary_safe(req, 'op'), _summary_safe(req), 'ERROR', f'{type(e).__name__}: {e}')
        try:
            data = json.dumps(resp).encode()
            if len(data) > MAX_MSG:
                audit(peer, _summary_safe(req, 'op'), _summary_safe(req), 'ERROR',
                      'response exceeds MAX_MSG')
                data = json.dumps({'ok': False, 'code': 'ERROR',
                                   'error': 'response exceeds MAX_MSG'}).encode()
            conn.sendall(data)
        except OSError:
            pass


class _MediamtxHandler(socketserver.BaseRequestHandler):
    """The mediamtx socket (ops #643): same framing as _Handler, its own rulebook."""

    def handle(self):
        _inflight_add(1)
        try:
            self._handle()
        finally:
            _inflight_add(-1)

    def _handle(self):
        conn = self.request
        peer = _peercred(conn)
        if not _allowed_mediamtx_peer(peer[1]):
            audit(peer, 'mediamtx:connect', '', 'DENY', 'unauthorized peer uid')
            try:
                conn.sendall(json.dumps({'ok': False, 'code': 'DENIED',
                                         'error': 'unauthorized peer'}).encode())
            except OSError:
                pass
            return
        req = {}
        try:
            req = json.loads(_recv_all(conn).decode())
            resp = _dispatch_mediamtx(req, peer)
        except Denied as d:
            resp = {'ok': False, 'code': 'DENIED', 'error': str(d)}
            audit(peer, 'mediamtx:exec', _summary_safe(req), 'DENY', str(d))
        except subprocess.TimeoutExpired:
            resp = {'ok': False, 'code': 'TIMEOUT', 'error': 'command timed out'}
            audit(peer, 'mediamtx:exec', _summary_safe(req), 'ERROR', 'command timed out')
        except Exception as e:  # noqa: BLE001 — never crash a worker thread
            resp = {'ok': False, 'code': 'ERROR', 'error': f'{type(e).__name__}: {e}'}
            audit(peer, 'mediamtx:exec', _summary_safe(req), 'ERROR', f'{type(e).__name__}: {e}')
        try:
            data = json.dumps(resp).encode()
            if len(data) > MAX_MSG:
                data = json.dumps({'ok': False, 'code': 'ERROR',
                                   'error': 'response exceeds MAX_MSG'}).encode()
            conn.sendall(data)
        except OSError:
            pass


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def _audit_line_ts(line):
    """Epoch seconds from an audit line's asctime prefix, or None."""
    try:
        return time.mktime(time.strptime(line[:19], '%Y-%m-%d %H:%M:%S'))
    except (ValueError, OverflowError):
        return None


def _audit_clean_window(now=None):
    """Evaluate the ENFORCE flip gate against the broker's own audit history:
    returns (clean: bool, why: str, clean_since: str|None). Clean means the log
    holds at least ENFORCE_CLEAN_SECS of history AND no WOULD-DENY inside that
    window. A fresh/empty log is NOT clean — no evidence, no flip."""
    now = now or time.time()
    files = [AUDIT_LOG + (('.%d' % i) if i else '') for i in range(10, -1, -1)]
    oldest_ts = None
    newest_wd = None
    for fp in files:
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, errors='replace') as f:
                for line in f:
                    ts = _audit_line_ts(line)
                    if ts is None:
                        continue
                    if oldest_ts is None or ts < oldest_ts:
                        oldest_ts = ts
                    if '"verdict": "WOULD-DENY"' in line and (newest_wd is None or ts > newest_wd):
                        newest_wd = ts
        except OSError:
            continue
    if oldest_ts is None:
        return False, 'no audit history yet', None
    if now - oldest_ts < ENFORCE_CLEAN_SECS:
        return False, ('audit history spans only %.1fh (< %dh required)'
                       % ((now - oldest_ts) / 3600.0, ENFORCE_CLEAN_SECS // 3600)), None
    if newest_wd is not None and now - newest_wd < ENFORCE_CLEAN_SECS:
        return False, ('WOULD-DENY seen %.1fh ago (need %dh clean)'
                       % ((now - newest_wd) / 3600.0, ENFORCE_CLEAN_SECS // 3600)), None
    since = newest_wd or oldest_ts
    return True, '', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(since))


# v10.3.0: the audit window is up to 11 x 20 MB of JSON lines. Scanning it on every
# `ping` took 50 s on a box with weeks of history (test6, 216 MB), so every caller
# with a timeout -- the OS-upgrade preflight (45 s), the broker card (5 s) -- failed,
# and concurrent pings each re-read the whole log. The answer changes on the scale
# of hours (the window is 72 h), so `ping` serves a cached result and refreshes it
# in the background; only the enforce decision paths wait for a fresh scan.
_READINESS_TTL = 600
_READINESS_LOCK = threading.Lock()
_READINESS_CACHE = {'at': 0.0, 'val': None, 'busy': False}


def _audit_clean_window_safe():
    try:
        return _audit_clean_window()
    except Exception as e:
        return False, f'gate evaluation error: {e}', None


def _readiness_refresh():
    try:
        val = _audit_clean_window_safe()
        with _READINESS_LOCK:
            _READINESS_CACHE.update(at=time.time(), val=val)
    finally:
        with _READINESS_LOCK:
            _READINESS_CACHE['busy'] = False


def _audit_clean_window_cached():
    """Never blocks on the scan: returns the last result (refreshing it in the
    background once older than _READINESS_TTL), or a 'still checking' answer
    before the first scan has finished."""
    with _READINESS_LOCK:
        val, age, busy = _READINESS_CACHE['val'], time.time() - _READINESS_CACHE['at'], _READINESS_CACHE['busy']
        if (val is None or age > _READINESS_TTL) and not busy:
            _READINESS_CACHE['busy'] = True
            threading.Thread(target=_readiness_refresh, daemon=True).start()
    if val is None:
        return False, 'checking the audit history', None
    return val


def _enforce_readiness(fresh=True):
    """Report the box's enforce readiness for the console card WITHOUT changing
    mode. Returns a dict: opted_in, clean, ready, reason, clean_since. Never
    raises. `ready` = opted_in is not required — a box is 'ready' (eligible) once
    its audit window is clean, whether or not the operator has opted in yet.
    fresh=False (ping) answers from the background cache instead of scanning."""
    try:
        opted_in = os.path.exists(ENFORCE_OPTIN_FILE)
    except OSError:
        opted_in = False
    if fresh:
        clean, why, since = _audit_clean_window_safe()
        with _READINESS_LOCK:
            _READINESS_CACHE.update(at=time.time(), val=(clean, why, since))
    else:
        clean, why, since = _audit_clean_window_cached()
    return {'opted_in': opted_in, 'clean': clean, 'ready': clean,
            'reason': why, 'clean_since': since,
            'clean_secs_required': ENFORCE_CLEAN_SECS}


def _resolve_enforce():
    """Decide the broker mode at daemon start (see the ENFORCE block up top).
    OPT-IN: a box enforces only if the operator has opted in AND the audit window
    is clean. It never flips on its own. Returns (enforce, info). Never raises."""
    env = os.environ.get('TAKWERX_BROKER_ENFORCE')
    if env == '0':
        return False, {'source': 'env-killswitch',
                       'stay_permissive_reason': 'TAKWERX_BROKER_ENFORCE=0 kill switch set'}
    if env == '1':
        return True, {'source': 'env', 'flipped_at': 'install'}
    # Sticky stamp: once a box has enforced (opted-in + clean), keep enforcing
    # across restarts even if new WOULD-DENYs appear (they can't, in enforce mode).
    try:
        with open(ENFORCE_STATE_FILE) as f:
            state = json.load(f)
        if state.get('flipped_at'):
            state.setdefault('source', 'opt-in')
            return True, state
    except (OSError, ValueError):
        pass
    rd = _enforce_readiness()
    if not rd['opted_in']:
        # Operator has not turned enforcement on — stay in watch mode regardless
        # of readiness. This is the production-safe default.
        msg = ('operator has not enabled enforcement; ' +
               ('READY to enable (audit clean)' if rd['clean']
                else 'not yet eligible — %s' % rd['reason']))
        return False, {'source': 'opt-in', 'opted_in': False, 'ready': rd['clean'],
                       'stay_permissive_reason': msg, 'clean_since': rd['clean_since']}
    if not rd['clean']:
        # Opted in but not yet proven clean (e.g. a fresh box in its first 72h, or
        # a box still shaking out coverage) — watch until the window is clean.
        return False, {'source': 'opt-in', 'opted_in': True, 'ready': False,
                       'stay_permissive_reason':
                           'enforcement enabled — waiting for clean window: %s' % rd['reason']}
    # Opted in AND clean -> enforce, and stamp it sticky.
    state = {'source': 'opt-in', 'opted_in': True,
             'flipped_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'clean_since': rd['clean_since']}
    try:
        os.makedirs(os.path.dirname(ENFORCE_STATE_FILE), exist_ok=True)
        tmp = ENFORCE_STATE_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, ENFORCE_STATE_FILE)
    except OSError as e:
        state['stamp_warning'] = str(e)
    return True, state


def _do_enforce_enable(req):
    """Create the opt-in marker (RATCHET — only ever enables). The box will then
    enforce on the NEXT broker start IF its audit window is clean; the console
    restarts the broker right after calling this. Never removes the marker —
    turning enforcement off is the SSH-only ENFORCE=0 kill switch."""
    try:
        os.makedirs(os.path.dirname(ENFORCE_OPTIN_FILE), exist_ok=True)
        with open(ENFORCE_OPTIN_FILE, 'w') as f:
            f.write(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + '\n')
        os.chmod(ENFORCE_OPTIN_FILE, 0o644)
    except OSError as e:
        return {'ok': False, 'error': f'could not write opt-in marker: {e}'}
    rd = _enforce_readiness()
    return {'ok': True, 'opted_in': True, 'ready': rd['clean'], 'reason': rd['reason'],
            'note': ('will enforce on next broker restart (audit clean)' if rd['clean']
                     else 'opted in; will enforce once the audit window is clean — %s' % rd['reason'])}


def _selinux_policy_converge():
    """v10.1.18 (SELinux enforce-the-domain): refresh the console's shipped
    SELinux modules on EXISTING boxes. start.sh installs them at provision time,
    but the console-update path never re-runs start.sh, so .te version bumps
    (0.2 -> 0.3 -> 1.0/enforcing) historically only reached freshly-provisioned
    boxes — the NUC burned 50-70k would-deny AVCs/day on a stale module for
    three weeks. The broker daemon executes from the repo and is restarted onto
    new source by the console's boot converge (app.py
    _broker_converge_running_source), so THIS hook runs root-side on every
    update that changes broker code, and the console's read-only canary
    (_startup_selinux_policy_canary) requests one extra broker restart for
    .te-only bumps. REFRESH-ONLY by design: a module a box was never
    provisioned with (root installs) is not first-installed here. Not a client
    op — no rulebook surface is added.
    """
    if os.geteuid() != 0 or not shutil.which('getenforce'):
        return
    try:
        r = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=10)
        if (r.stdout or '').strip() == 'Disabled':
            return
    except Exception:
        return
    selinux_dir = os.path.join(os.path.dirname(os.path.dirname(SELF_PATH)), 'selinux')
    try:
        listed = subprocess.run(['semodule', '-l'], capture_output=True, text=True,
                                timeout=60).stdout or ''
    except Exception as e:
        AUDIT.info(json.dumps({'op': 'selinux-policy', 'verdict': 'ERROR',
                               'summary': f'semodule -l failed: {e}'}))
        return
    installed = {ln.strip().split()[0] for ln in listed.splitlines() if ln.strip()}
    for name in ('takwerx_console', 'takwerx_console_confined'):
        te = os.path.join(selinux_dir, name + '.te')
        if name not in installed or not os.path.isfile(te):
            continue
        want = ''
        try:
            with open(te) as f:
                m = re.match(r'^module\s+%s\s+([0-9.]+)' % re.escape(name), f.readline())
            want = m.group(1) if m else ''
        except OSError:
            continue
        stamp = '/etc/selinux/.takwerx-%s.ver' % name    # same stamp start.sh writes
        try:
            with open(stamp) as f:
                have = f.read().strip()
        except OSError:
            have = ''
        if not want or have == want:
            continue
        # checkpolicy ships checkmodule/semodule_package; start.sh installs it on
        # provision but a minimal image may lack it. dnf-only is deliberate: this
        # code is gated on getenforce (SELinux hosts = RHEL family here); guard
        # anyway so a missing dnf can't kill the converge thread.
        if not shutil.which('checkmodule') and shutil.which('dnf'):
            try:
                subprocess.run(['dnf', 'install', '-y', 'checkpolicy'],
                               capture_output=True, timeout=300)
            except Exception:
                pass
        if not (shutil.which('checkmodule') and shutil.which('semodule_package')):
            AUDIT.info(json.dumps({'op': 'selinux-policy', 'verdict': 'ERROR',
                                   'summary': f'{name}: checkpolicy tools unavailable — module stays at {have or "unknown"}'}))
            continue
        import tempfile
        tmp = tempfile.mkdtemp(prefix='takwerx-selinux-')
        try:
            mod, pp = os.path.join(tmp, name + '.mod'), os.path.join(tmp, name + '.pp')
            for argv in (['checkmodule', '-M', '-m', '-o', mod, te],
                         ['semodule_package', '-o', pp, '-m', mod],
                         ['semodule', '-i', pp]):
                r = subprocess.run(argv, capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    AUDIT.info(json.dumps({'op': 'selinux-policy', 'verdict': 'ERROR',
                                           'summary': f'{name} {have or "?"} -> {want}: {argv[0]} failed: {(r.stderr or r.stdout or "")[:300]}'}))
                    break
            else:
                with open(stamp, 'w') as f:
                    f.write(want + '\n')
                os.chmod(stamp, 0o644)
                AUDIT.info(json.dumps({'op': 'selinux-policy', 'verdict': 'INFO',
                                       'summary': f'{name} refreshed {have or "unstamped"} -> {want}'}))
        except Exception as e:
            AUDIT.info(json.dumps({'op': 'selinux-policy', 'verdict': 'ERROR',
                                   'summary': f'{name}: {type(e).__name__}: {e}'}))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# v10.2.8 W3: recycle once a day — but only when idle
# ---------------------------------------------------------------------------
# Until 10.2.8 the unit carried `RuntimeMaxSec=24h`, so systemd stopped the broker every
# 24 h whatever it was doing. A stop SIGTERMs the whole cgroup, children included, so a
# brokered `docker compose build` that spanned the moment died with it (T&E 2026-10-08,
# test6: "Service reached runtime time limit" cut a CloudTAK build 30 s in → the console
# saw `cannot reach broker: Expecting value` → exit 125). Draining on SIGTERM cannot fix
# that — the child is already signalled. So the unit no longer has a runtime limit and the
# broker recycles itself: after RECYCLE_AFTER_SECS of uptime it waits for a moment with no
# request in flight, stops accepting, and exits 0; `Restart=always` brings it back in 2 s
# (the same window the old recycle had). Code staleness stays bounded separately — the
# console restarts the broker whenever its source hash changes.
# 23 h, not 24: a box that took this release still runs under the OLD unit's
# RuntimeMaxSec=24h until _converge_own_unit() lands, and the idle recycle must win that
# race whenever the broker is idle.
RECYCLE_AFTER_SECS = 23 * 3600
RECYCLE_POLL_SECS = 5
RECYCLE_NOTE_SECS = 3600        # how often a deferred recycle says so in the audit log
RECYCLE_DRAIN_MAX_SECS = 6 * 3600
# ops #113: "nothing in flight at this instant" is not idle. The console's privileged calls
# arrive one after another, each a few ms, so a 5 s poll almost always sees zero in flight
# — even mid-burst. test6, 2026-10-20 13:14:58Z: the recycle fired between two calls of the
# post-update Guard Dog timer loop (calls every <1 s), and the console's next calls in the
# 3.3 s gap failed. So the recycle also waits for RECYCLE_QUIET_SECS with no request at all.
# 15 s, not more: test6's audit log has a background request every ~30 s all day (no 60 s
# gap in 36 h), so a longer window would defer the recycle forever. RECYCLE_QUIET_MAX_SECS
# bounds that anyway — the console waits out a restarting broker now, so a recycle that
# never finds a quiet window still goes at the next idle moment instead of never.
RECYCLE_QUIET_SECS = 15
RECYCLE_QUIET_MAX_SECS = 3600
# After unlinking the socket, how long the accept loop keeps running so a client that
# connected just before the unlink is served instead of reset with its request unread.
RECYCLE_UNLINK_GRACE_SECS = 1

_INFLIGHT = 0
_INFLIGHT_LOCK = threading.Lock()
_LAST_ACTIVITY = None           # monotonic time a request last started or finished


def _inflight_add(n):
    global _INFLIGHT, _LAST_ACTIVITY
    with _INFLIGHT_LOCK:
        _INFLIGHT += n
        _LAST_ACTIVITY = time.monotonic()
        return _INFLIGHT


def _inflight():
    with _INFLIGHT_LOCK:
        return _INFLIGHT


def _last_activity():
    with _INFLIGHT_LOCK:
        return _LAST_ACTIVITY


def _recycle_after_secs():
    """RECYCLE_AFTER_SECS, unless TAKWERX_BROKER_RECYCLE_SECS is set. That variable is a
    TEST HOOK for the T&E drill only (a unit drop-in, root-written) — never a fleet knob;
    floored at 60 s so a typo cannot turn the broker into a restart loop."""
    v = os.environ.get('TAKWERX_BROKER_RECYCLE_SECS', '').strip()
    if not v:
        return RECYCLE_AFTER_SECS
    try:
        return max(60, int(v))
    except ValueError:
        return RECYCLE_AFTER_SECS


def _unlink_socket():
    try:
        os.unlink(SOCKET_PATH)
    except OSError:
        pass


def _recycle_watch(srv, after, started, clock=time.monotonic, sleep=time.sleep,
                   poll=RECYCLE_POLL_SECS, note_every=RECYCLE_NOTE_SECS, log=None,
                   quiet=RECYCLE_QUIET_SECS, quiet_max=RECYCLE_QUIET_MAX_SECS,
                   unlink=None, grace=RECYCLE_UNLINK_GRACE_SECS):
    """Stop `srv` once uptime >= `after`, nothing is in flight AND no request started or
    finished in the last `quiet` seconds (or, after `quiet_max` past `after` without such a
    window, at the first moment nothing is in flight). Returns 'idle'.

    The socket is unlinked first, so a new client waits for the restarted broker (ENOENT)
    rather than queueing on a socket nobody will accept on; the accept loop keeps running
    for `grace` to serve anything that connected just before. `srv.shutdown()` only stops
    the accept loop; requests already accepted keep running, and serve() waits for them
    before it exits — so the in-flight count can only fall after this decides."""
    log = log or (lambda summary: AUDIT and AUDIT.info(json.dumps(
        {'op': 'recycle', 'verdict': 'INFO', 'summary': summary})))
    last_note = None
    while True:
        sleep(poll)
        now = clock()
        up = now - started
        if up < after:
            continue
        n = _inflight()
        last = _last_activity()
        idle_for = None if last is None else now - last
        if n == 0 and (idle_for is None or idle_for >= quiet or up - after >= quiet_max):
            log('recycle: idle after %.1fh uptime (%s) — exiting for a clean restart'
                % (up / 3600.0, 'no request yet' if idle_for is None
                   else 'last request %.0fs ago' % idle_for))
            if unlink:
                unlink()
            sleep(grace)
            srv.shutdown()
            return 'idle'
        if last_note is None or now - last_note >= note_every:
            log('recycle deferred: %d request(s) in flight' % n if n else
                'recycle deferred: busy (last request %.0fs ago, waiting for %ds quiet)'
                % (idle_for, quiet))
            last_note = now


# Lines this broker removes from its OWN unit at startup. Nothing else in the unit is
# touched — in particular the TAKWERX_BROKER_ENFORCE line start.sh writes.
OWN_UNIT_DROP_PREFIXES = ('RuntimeMaxSec=',)


def _converge_own_unit(unit_path=BROKER_UNIT, run=None):
    """v10.2.8 W3: drop `RuntimeMaxSec=` from this broker's own unit, then daemon-reload.

    The console cannot do it: on a non-root box `_startup_ensure_broker()` writes the
    unit with a raw open(), which fails as `takwerx` (and the rulebook refuses writes to
    the broker's unit, on purpose). Measured on test6, 2026-10-08: the unit was last
    written 2026-07-01 and still carried RuntimeMaxSec=24h after the console took the
    release. The broker runs as root and owns this file, so it converges it itself —
    no request-driven op, no new surface. Returns True when it changed the unit.
    """
    run = run or subprocess.run
    try:
        with open(unit_path) as f:
            cur = f.read()
    except OSError:
        return None
    lines = cur.splitlines(keepends=True)
    keep = [ln for ln in lines if not ln.strip().startswith(OWN_UNIT_DROP_PREFIXES)]
    if len(keep) == len(lines):
        return False
    tmp = unit_path + '.takwerx-tmp'
    with open(tmp, 'w') as f:
        f.write(''.join(keep))
    os.chmod(tmp, 0o644)
    os.replace(tmp, unit_path)
    systemctl = shutil.which('systemctl', path=BROKER_TRUSTED_PATH) or '/bin/systemctl'
    run([systemctl, 'daemon-reload'], capture_output=True, timeout=60)
    return True


# ---------------------------------------------------------------------------
# ops #645 W1 — root-owned broker code, installed only from verified GitHub commits
# ---------------------------------------------------------------------------
# Layout:  ROOT_CODE_DIR/<commit>/{broker,selinux}/  root 0755/0644 (git archive)
#          ROOT_CODE_CURRENT -> <commit>              (atomic symlink swap)
#          ROOT_SRC_GIT                               bare, blob-less mirror, root 0700
#          ROOT_CONF  console_dir=<console repo>      root 0644
# Unit:    ROOT_EXEC_START (system python, -I: no script dir, user site or PYTHON* env)
# A commit is installed only when root itself fetched it from BROKER_SRC_URL (never
# the console's git config), it is on main, dev or a v* tag there, and its broker
# declares BROKER_ROOT_LAYOUT and a BROKER_SECURITY_LEVEL not below this one.
_COMMIT_RE = re.compile(r'^[0-9a-f]{40}$')
_SRC_REFSPECS = ('+refs/heads/main:refs/heads/main', '+refs/heads/dev:refs/heads/dev',
                 '+refs/tags/v*:refs/tags/v*')
_SRC_ALLOWED_REFS = ('refs/heads/main', 'refs/heads/dev', 'refs/tags/v*')
_ARCHIVE_PATHS = ('broker', 'selinux', 'scripts/guarddog')   # W2 part 2a: Guard Dog templates
_ROOT_KEEP = 3                       # commit dirs kept (current + 2 to roll back to)
_ROOT_LOCK = threading.Lock()
ROOT_MOVE_STATE = {'state': 'installed' if RUNNING_FROM_ROOT else 'not-started',
                   'reason': ''}


def _installed_commit():
    """The commit this broker runs from (root layout), else ''."""
    if not RUNNING_FROM_ROOT:
        return ''
    c = os.path.basename(os.path.dirname(os.path.dirname(SELF_PATH)))
    return c if _COMMIT_RE.fullmatch(c) else ''


def _src_git(args, timeout=600):
    """git as root on the root-only mirror: no system/global config, no hooks."""
    git = shutil.which('git', path=BROKER_TRUSTED_PATH)
    if not git:
        raise Denied('broker update: git is not installed')
    env = {'PATH': BROKER_TRUSTED_PATH, 'LC_ALL': 'C', 'HOME': os.path.dirname(ROOT_SRC_GIT),
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_TERMINAL_PROMPT': '0', 'GIT_DIR': ROOT_SRC_GIT}
    return subprocess.run([git, '-c', 'core.hooksPath=' + os.devnull,
                           '-c', 'core.fsmonitor=false'] + list(args),
                          capture_output=True, text=True, timeout=timeout, env=env, cwd='/')


def _src_ok(r, what):
    if r.returncode != 0:
        raise Denied(f'broker update: {what} failed: {(r.stderr or r.stdout).strip()[:300]}')
    return r.stdout


def _src_fetch():
    """Create/refresh the root-only mirror from BROKER_SRC_URL (commits + trees;
    blobs come on demand at archive time)."""
    parent = os.path.dirname(ROOT_SRC_GIT)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    if not os.path.isdir(ROOT_SRC_GIT):
        _src_ok(_src_git(['init', '-q', '--bare', ROOT_SRC_GIT]), 'git init')
    if os.path.islink(ROOT_SRC_GIT):
        raise Denied('broker update: source mirror is a symlink')
    os.chown(ROOT_SRC_GIT, 0, 0)
    os.chmod(ROOT_SRC_GIT, 0o700)
    for k, v in (('remote.origin.url', BROKER_SRC_URL), ('remote.origin.promisor', 'true'),
                 ('remote.origin.partialclonefilter', 'blob:none'),
                 ('extensions.partialclone', 'origin')):
        _src_ok(_src_git(['config', k, v]), 'git config')
    _src_ok(_src_git(['fetch', '-q', '--prune', '--no-tags', '--filter=blob:none',
                      'origin'] + list(_SRC_REFSPECS), timeout=900), 'fetch from GitHub')


def _src_verify(commit):
    """Refuse (Denied) unless `commit` is on main, dev or a v* tag of the mirror."""
    if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
        raise Denied('broker update: commit must be a full 40-character commit id')
    if _src_git(['cat-file', '-e', commit + '^{commit}']).returncode != 0:
        raise Denied(f'broker update: commit {commit[:12]} is not on GitHub '
                     f'({BROKER_SRC_URL})')
    refs = _src_ok(_src_git(['for-each-ref', '--format=%(refname)', '--contains', commit]
                            + list(_SRC_ALLOWED_REFS)), 'for-each-ref').split()
    if not refs:
        raise Denied(f'broker update: commit {commit[:12]} is not on main, dev or a '
                     f'release tag')
    return refs


def _src_level(text):
    """(root_layout, security_level) declared by a broker source file."""
    lay = re.search(r'^BROKER_ROOT_LAYOUT = (\d+)\s*$', text, re.M)
    lvl = re.search(r'^BROKER_SECURITY_LEVEL = (\d+)\s*$', text, re.M)
    return (int(lay.group(1)) if lay else 0, int(lvl.group(1)) if lvl else 0)


def _fix_tree_perms(top):
    for root, dirs, files in os.walk(top):
        for n in dirs + files:
            p = os.path.join(root, n)
            if os.path.islink(p):
                raise Denied(f'broker update: symlink in the archive: {p}')
            os.chown(p, 0, 0)
            os.chmod(p, 0o755 if os.path.isdir(p) else 0o644)
    os.chown(top, 0, 0)
    os.chmod(top, 0o755)


def _root_install(commit, fetch=True):
    """Fetch, verify and install `commit` under ROOT_CODE_DIR, then point `current`
    at it. Returns the install dir. Raises Denied with a plain reason."""
    with _ROOT_LOCK:
        if fetch:
            _src_fetch()
        _src_verify(commit)
        os.makedirs(ROOT_CODE_DIR, mode=0o755, exist_ok=True)
        if os.path.islink(ROOT_CODE_DIR) or not os.path.isdir(ROOT_CODE_DIR):
            raise Denied('broker update: code dir is not a plain directory')
        os.chown(ROOT_CODE_DIR, 0, 0)
        os.chmod(ROOT_CODE_DIR, 0o755)
        dest = os.path.join(ROOT_CODE_DIR, commit)
        tmp = tempfile.mkdtemp(prefix='.new-', dir=ROOT_CODE_DIR)
        try:
            tar = os.path.join(tmp, '.src.tar')
            # only the listed paths the commit has (a broker-only test commit has no
            # scripts/; real infra-TAK commits have all three)
            have = _src_ok(_src_git(['ls-tree', '--name-only', commit, '--']
                                    + list(_ARCHIVE_PATHS)), 'ls-tree').split()
            paths = [x for x in _ARCHIVE_PATHS if x in have]
            if 'broker' not in paths:
                raise Denied(f'broker update: commit {commit[:12]} has no broker')
            _src_ok(_src_git(['archive', '--format=tar', '-o', tar, commit, '--'] + paths,
                             timeout=900), 'git archive')
            tarbin = shutil.which('tar', path=BROKER_TRUSTED_PATH) or 'tar'
            r = subprocess.run([tarbin, '-x', '-f', tar, '-C', tmp, '--no-same-owner',
                                '--no-same-permissions'], capture_output=True, text=True,
                               timeout=300, cwd='/', env={'PATH': BROKER_TRUSTED_PATH,
                                                          'LC_ALL': 'C'})
            _src_ok(r, 'unpack')
            os.unlink(tar)
            _fix_tree_perms(tmp)
            src = os.path.join(tmp, 'broker', 'takwerx_broker.py')
            try:
                with open(src) as f:
                    text = f.read()
            except OSError:
                raise Denied(f'broker update: commit {commit[:12]} has no broker')
            lay, lvl = _src_level(text)
            if lay < 1:
                raise Denied(f'broker update: commit {commit[:12]} predates the root-owned '
                             f'broker layout')
            if lvl < BROKER_SECURITY_LEVEL:
                raise Denied(f'broker update: commit {commit[:12]} has broker security '
                             f'level {lvl}, below this broker\'s {BROKER_SECURITY_LEVEL}')
            py = SYSTEM_PYTHON if os.path.exists(SYSTEM_PYTHON) else sys.executable
            r = subprocess.run([py, '-I', '-c', 'import ast,sys; ast.parse(open(sys.argv[1]).read())',
                                src], capture_output=True, text=True, timeout=120, cwd='/',
                               env={'PATH': BROKER_TRUSTED_PATH, 'LC_ALL': 'C'})
            _src_ok(r, f'syntax check with {py}')
            if os.path.lexists(dest):
                shutil.rmtree(dest, ignore_errors=True)
            os.rename(tmp, dest)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        link = os.path.join(ROOT_CODE_DIR, '.current.new')
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(commit, link)
        os.replace(link, ROOT_CODE_CURRENT)
        _root_prune(commit)
        return dest


def _root_prune(keep_commit):
    """Keep the newest _ROOT_KEEP commit dirs (always the current and the running one)."""
    try:
        dirs = [n for n in os.listdir(ROOT_CODE_DIR) if _COMMIT_RE.fullmatch(n)]
        dirs.sort(key=lambda n: os.lstat(os.path.join(ROOT_CODE_DIR, n)).st_mtime, reverse=True)
        keep = set(dirs[:_ROOT_KEEP]) | {keep_commit, _installed_commit()}
        for n in dirs:
            if n not in keep:
                shutil.rmtree(os.path.join(ROOT_CODE_DIR, n), ignore_errors=True)
        for n in os.listdir(ROOT_CODE_DIR):
            if n.startswith('.new-'):
                shutil.rmtree(os.path.join(ROOT_CODE_DIR, n), ignore_errors=True)
    except OSError:
        pass


def _write_root_conf(console_dir):
    os.makedirs(ROOT_CONF_DIR, mode=0o755, exist_ok=True)
    os.chown(ROOT_CONF_DIR, 0, 0)
    os.chmod(ROOT_CONF_DIR, 0o755)
    tmp = ROOT_CONF + '.tmp'
    with open(tmp, 'w') as f:
        f.write('# infra-TAK broker (ops #645 W1). Written by root; the console cannot change it.\n'
                f'console_dir={console_dir}\n')
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o644)
    os.replace(tmp, ROOT_CONF)


def _unit_point_at_root(unit_path=BROKER_UNIT, run=None):
    """Point this broker's unit at the root-owned code (ROOT_EXEC_START), keeping every
    other line (ENFORCE env, SELinux context). Returns True when it changed the unit."""
    run = run or subprocess.run
    with open(unit_path) as f:
        cur = f.read()
    lines = cur.splitlines(keepends=True)
    out = [ROOT_EXEC_START + '\n' if ln.strip().startswith('ExecStart=') else ln for ln in lines]
    if out == lines:
        return False
    if not any(ln.strip().startswith('ExecStart=') for ln in lines):
        raise Denied('broker update: own unit has no ExecStart line')
    tmp = unit_path + '.takwerx-tmp'
    with open(tmp, 'w') as f:
        f.write(''.join(out))
    os.chmod(tmp, 0o644)
    os.replace(tmp, unit_path)
    systemctl = shutil.which('systemctl', path=BROKER_TRUSTED_PATH) or '/bin/systemctl'
    run([systemctl, 'daemon-reload'], capture_output=True, timeout=60)
    return True


def _restart_self_later(delay=2.0, run=None):
    """Restart this broker after the reply went out (the restart kills this process)."""
    run = run or subprocess.run
    systemctl = shutil.which('systemctl', path=BROKER_TRUSTED_PATH) or '/bin/systemctl'

    def _go():
        run([systemctl, '--no-block', 'restart', 'takwerx-broker'], capture_output=True,
            timeout=30)
    t = threading.Timer(delay, _go)
    t.daemon = True
    t.start()
    return t


def _do_broker_update(req, restart=_restart_self_later):
    """op broker_update {commit}: install a verified commit and restart onto it."""
    commit = req.get('commit')
    if RUNNING_FROM_ROOT and commit == _installed_commit():
        return {'ok': True, 'installed_commit': commit, 'changed': False}
    try:
        _root_install(commit)
        if not RUNNING_FROM_ROOT:
            _write_root_conf(CONSOLE_REPO_DIR)
        _unit_point_at_root()
    except Denied as e:
        return {'ok': False, 'code': 'DENIED', 'error': str(e)}
    except Exception as e:  # noqa: BLE001 — report, never crash the daemon
        return {'ok': False, 'error': f'broker update failed: {type(e).__name__}: {e}'}
    restart()
    return {'ok': True, 'installed_commit': commit, 'changed': True, 'restarting': True}


def _repo_head_commit(repo):
    """The commit checked out in the console repo, read from .git files as text (root
    never runs git in a repo the console user owns). '' when it cannot tell.
    Only plain files inside a real .git dir are read: .git itself must not be a
    link, a path whose realpath leaves .git is refused (a linked parent dir), and
    the open is non-blocking so a FIFO planted as a ref cannot hang the broker."""
    gd = os.path.join(repo, '.git')
    try:
        if not stat.S_ISDIR(os.lstat(gd).st_mode):
            return ''
        gd_real = os.path.realpath(gd)
    except OSError:
        return ''

    def _read(p, n=4096):
        try:
            if os.path.commonpath([os.path.realpath(p), gd_real]) != gd_real:
                return ''
            fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                         | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0))
            with os.fdopen(fd) as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    return ''
                return f.read(n)
        except (OSError, UnicodeDecodeError, ValueError):
            return ''
    head = _read(os.path.join(gd, 'HEAD')).strip()
    if _COMMIT_RE.fullmatch(head):
        return head
    m = re.fullmatch(r'^ref: (refs/[A-Za-z0-9._/-]+)$', head)
    if not m or '..' in m.group(1):
        return ''
    val = _read(os.path.join(gd, *m.group(1).split('/'))).strip()
    if _COMMIT_RE.fullmatch(val):
        return val
    for ln in _read(os.path.join(gd, 'packed-refs'), 1 << 22).splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[1] == m.group(1) and _COMMIT_RE.fullmatch(parts[0]):
            return parts[0]
    return ''


def _root_move_first(restart=_restart_self_later, log=None):
    """At start from the repo path (pre-W1 boxes): install the console's checked-out
    commit under the root layout and restart onto it. On any failure, stay on the
    repo path and say why in ping (`root_install`); the next start retries."""
    log = log or (lambda v, s: AUDIT and AUDIT.info(json.dumps(
        {'op': 'root-move', 'verdict': v, 'summary': s})))
    if RUNNING_FROM_ROOT or os.geteuid() != 0:
        return False
    commit = _repo_head_commit(CONSOLE_REPO_DIR)
    if not commit:
        ROOT_MOVE_STATE.update(state='pending', reason='cannot read the console commit')
        log('ERROR', 'root move pending: cannot read the console commit')
        return False
    ROOT_MOVE_STATE.update(state='running', reason=commit[:12])
    r = _do_broker_update({'commit': commit}, restart=restart)
    if not r.get('ok'):
        ROOT_MOVE_STATE.update(state='pending', reason=r.get('error', '')[:300])
        log('ERROR', 'root move pending: ' + r.get('error', '')[:300])
        return False
    ROOT_MOVE_STATE.update(state='installed', reason=commit[:12])
    log('INFO', f'root move: installed {commit[:12]} under {ROOT_CODE_DIR}, restarting onto it')
    return True


def _drain(max_secs=RECYCLE_DRAIN_MAX_SECS, clock=time.monotonic, sleep=time.sleep):
    """Wait for in-flight requests to finish (bounded). True when drained."""
    t0 = clock()
    while _inflight() > 0:
        if clock() - t0 >= max_secs:
            return False
        sleep(1)
    return True


def serve():
    global AUDIT, ENFORCE, ENFORCE_INFO, _MTX_SRV
    if os.geteuid() != 0:
        sys.stderr.write('takwerx-broker: serve must run as root\n')
        return 2
    AUDIT = _make_audit_logger()
    ENFORCE, ENFORCE_INFO = _resolve_enforce()
    if ENFORCE:
        _mode_msg = ('broker ENFORCE enabled (source=%s%s)'
                     % (ENFORCE_INFO.get('source'),
                        ', audit clean since %s' % ENFORCE_INFO['clean_since']
                        if ENFORCE_INFO.get('clean_since') else ''))
    else:
        _mode_msg = ('broker staying PERMISSIVE: %s'
                     % ENFORCE_INFO.get('stay_permissive_reason', 'unknown'))
    AUDIT.info(json.dumps({'op': 'startup', 'verdict': 'INFO', 'summary': _mode_msg}))
    # fresh socket
    try:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    except OSError:
        pass
    srv = _Server(SOCKET_PATH, _Handler)
    # root:takwerx 0660 — only root and the console user may connect.
    try:
        gid = grp.getgrnam(BROKER_USER).gr_gid
    except KeyError:
        gid = 0
    try:
        os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, 0o660)
    except OSError as e:
        sys.stderr.write(f'takwerx-broker: socket perms warning: {e}\n')
    AUDIT.info(json.dumps({'op': 'startup', 'verdict': 'INFO',
                           'summary': f'listening on {SOCKET_PATH}'}))
    # ops #643: MediaMTX + its editor get their own socket and short list (only once
    # their account exists; the console's startup migration creates it).
    try:
        with _MTX_SRV_LOCK:
            _MTX_SRV = _start_mediamtx_listener()
    except Exception as e:  # noqa: BLE001 — never let this stop the main socket
        sys.stderr.write(f'takwerx-broker: mediamtx socket not started: {e}\n')
    if _MTX_SRV is not None:
        AUDIT.info(json.dumps({'op': 'startup', 'verdict': 'INFO',
                               'summary': f'listening on {MEDIAMTX_SOCKET_PATH} (mediamtx list)'}))
    # SELinux module refresh runs AFTER the socket is up (a policy rebuild can
    # take tens of seconds; the console's boot ping must not wait on it).
    threading.Thread(target=_selinux_policy_converge, daemon=True,
                     name='selinux-policy-converge').start()
    try:
        if _converge_own_unit():
            AUDIT.info(json.dumps({'op': 'startup', 'verdict': 'INFO',
                                   'summary': 'own unit converged: RuntimeMaxSec removed '
                                              '(daily recycle is idle-only now) + daemon-reload'}))
    except Exception as e:  # noqa: BLE001 — never let a unit tidy-up stop the broker
        AUDIT.info(json.dumps({'op': 'startup', 'verdict': 'ERROR',
                               'summary': 'own unit converge failed: %s' % e}))
    # ops #645 W1: a broker still started from the console repo moves itself to
    # the root-owned layout (after the socket is up; a fetch can take a while).
    if not RUNNING_FROM_ROOT:
        threading.Thread(target=_root_move_first, daemon=True, name='root-move').start()
    _after = _recycle_after_secs()
    threading.Thread(target=_recycle_watch, args=(srv, _after, time.monotonic()),
                     kwargs={'unlink': _unlink_socket},
                     daemon=True, name='recycle-watch').start()
    if _after != RECYCLE_AFTER_SECS:
        AUDIT.info(json.dumps({'op': 'startup', 'verdict': 'INFO',
                               'summary': 'recycle threshold overridden to %ds '
                                          '(TAKWERX_BROKER_RECYCLE_SECS test hook)' % _after}))
    _audit_clean_window_cached()   # warm the readiness cache so the first ping is fast
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        # Unlink first so a new client fails fast (ENOENT) instead of waiting in the
        # backlog of a socket nobody will accept on; then let accepted work finish.
        # (The idle recycle has already unlinked it; this covers every other exit.)
        _unlink_socket()
        try:
            srv.server_close()
        except OSError:
            pass
        if _MTX_SRV is not None:
            _unlink_mediamtx_socket()
            try:
                _MTX_SRV.shutdown()
                _MTX_SRV.server_close()
            except OSError:
                pass
        if not _drain():
            AUDIT.info(json.dumps({'op': 'recycle', 'verdict': 'ERROR',
                                   'summary': 'recycle: %d request(s) still running after '
                                              '%ds — exiting anyway' % (_inflight(),
                                                                        RECYCLE_DRAIN_MAX_SECS)}))
    return 0


# ---------------------------------------------------------------------------
# Client  (used by the CLI proxy + selftest; app.py has its own in-process copy)
# ---------------------------------------------------------------------------
# ops #262: a first Print install from TAK Portal's marketplace (`docker compose ... up -d
# --build cloudtak-print`, 2 GB Chromium image) was killed at exactly the 600 s default on a
# busy box and the job showed failed although the image finished building. That call comes
# from TAK Portal through the docker shim, so no caller sets TAKWERX_BROKER_TIMEOUT for it.
# When the env is unset, an image-build or image-pull command gets BUILD_TIMEOUT instead.
# Everything else keeps the default; an explicit TAKWERX_BROKER_TIMEOUT always wins.
BUILD_TIMEOUT = 3600
_DOCKER_VALUE_FLAGS = frozenset((
    '-c', '--context', '-H', '--host', '-l', '--log-level', '--config',          # docker
    '-f', '--file', '-p', '--project-name', '--profile', '--env-file',           # compose
    '--project-directory', '--progress', '--ansi', '--parallel'))


def default_timeout(argv):
    """BUILD_TIMEOUT for `docker build|pull`, `docker buildx build` and `docker compose
    build|up|pull|create`; 0 (no opinion, the daemon's own default) for anything else."""
    if not argv or os.path.basename(argv[0]) != 'docker':
        return 0
    words, skip = [], False
    for a in argv[1:]:
        if skip:
            skip = False
        elif a.startswith('-'):
            skip = a in _DOCKER_VALUE_FLAGS
        else:
            words.append(a)
            if len(words) == 2:
                break
    if words[:1] in (['build'], ['pull']):
        return BUILD_TIMEOUT
    if words[:2] == ['buildx', 'build']:
        return BUILD_TIMEOUT
    if words[:1] == ['compose'] and words[1:2] and words[1] in ('build', 'up', 'pull', 'create'):
        return BUILD_TIMEOUT
    return 0


def compose_project_dir(argv):
    """The existing absolute directory named by `docker compose --project-directory D ...`
    (also `--project-directory=D`), or None. Only compose's own flags before its subcommand
    count, so a `--project-directory` that is an argument of something else (`run`, `exec`)
    is never read."""
    if not argv or os.path.basename(argv[0]) != 'docker':
        return None
    words, skip, found = [], False, None
    pending = False
    for a in argv[1:]:
        if skip:
            skip = False
            if pending:
                found, pending = a, False
            continue
        if a.startswith('-'):
            if len(words) == 1 and a.startswith('--project-directory='):
                found = a.split('=', 1)[1]
            elif a in _DOCKER_VALUE_FLAGS:
                skip = True
                pending = len(words) == 1 and a == '--project-directory'
            continue
        words.append(a)
        if len(words) == 1 and a != 'compose':
            return None
        if len(words) == 2:
            break
    if found and found.startswith('/') and os.path.isdir(found):
        return found
    return None


def client_send(req, timeout=DEFAULT_TIMEOUT):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCKET_PATH)
    s.sendall(json.dumps(req).encode())
    s.shutdown(socket.SHUT_WR)
    buf = bytearray()
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > MAX_MSG:
            break
    s.close()
    return json.loads(bytes(buf).decode())


def cli_exec(args):
    """`takwerx_broker.py exec -- <argv...>` — proxy a command to the daemon,
    preserving the subprocess.run(list, ...) contract the console relies on.
    stdin -> input; cwd is forwarded so callers' cwd= reaches the real command;
    daemon stdout/stderr are written back; exit code mirrors the command."""
    if args and args[0] == '--':
        args = args[1:]
    if not args:
        sys.stderr.write('takwerx_broker exec: no command\n')
        return 2
    stdin_data = b''
    if not sys.stdin.isatty():
        try:
            stdin_data = sys.stdin.buffer.read()
        except Exception:
            stdin_data = b''
    req = {
        'op': 'exec',
        'argv': args,
        'cwd': os.getcwd(),
        'input_b64': base64.b64encode(stdin_data).decode() if stdin_data else None,
    }
    # Long-command support: callers (app.py build paths) export TAKWERX_BROKER_TIMEOUT
    # (seconds) so a CloudTAK --no-cache rebuild isn't killed at the 600s default. The
    # value rides the request (daemon clamps to MAX_TIMEOUT) and stretches the client
    # socket wait past the daemon-side subprocess deadline. Timeout-only — the daemon
    # still ignores all caller env for the child process itself.
    try:
        _env_t = int(os.environ.get('TAKWERX_BROKER_TIMEOUT') or 0)
    except ValueError:
        _env_t = 0
    if _env_t > 0:
        req['timeout'] = min(_env_t, MAX_TIMEOUT)
    elif default_timeout(args):
        req['timeout'] = default_timeout(args)
    try:
        resp = client_send(req, timeout=(req.get('timeout') or DEFAULT_TIMEOUT) + 60)
    except (OSError, socket.timeout, ValueError) as e:
        # v10.1.40 (B3a): ValueError covers json.JSONDecodeError (and UnicodeDecodeError),
        # which client_send's closing json.loads() raises whenever the daemon dies
        # mid-request and the response comes back empty or truncated. It was NOT caught
        # here, so it escaped main() as an unhandled traceback and the process exited 1
        # instead of the 125 this path documents. The console's _startup_ensure_broker()
        # then read rc=1 as a FAILED restart, refused (correctly, v10.1.13) to stamp it,
        # and the stale .broker_srcstamp made it restart the broker again on the NEXT
        # console start — forever, on every box in the fleet. Any mid-request daemon
        # death hit this, not just the self-restart; see PLAN-v10.1.40 §4B.
        sys.stderr.write(f'takwerx_broker: cannot reach broker: {e}\n')
        return 125
    if not resp.get('ok'):
        sys.stderr.write(f"takwerx_broker: {resp.get('code')}: {resp.get('error')}\n")
        return 126
    sys.stdout.buffer.write(base64.b64decode(resp.get('stdout_b64') or ''))
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(base64.b64decode(resp.get('stderr_b64') or ''))
    sys.stderr.buffer.flush()
    return int(resp.get('returncode', 0))


def cli_selftest():
    """Prove the broker path end-to-end: ping, an allowed read, an allowed
    exec, and confirm two dangerous requests are DENIED. Prints PASS/FAIL."""
    results = []

    def check(name, cond, detail=''):
        results.append((name, bool(cond), detail))

    # 1. ping
    try:
        r = client_send({'op': 'ping'})
        check('ping', r.get('ok') and r.get('pong'), str(r))
    except Exception as e:
        check('ping', False, str(e))
        _print_selftest(results)
        return 1

    # 2. allowed exec (read-only): getenforce or systemctl --version
    try:
        r = client_send({'op': 'exec', 'argv': ['systemctl', '--version']})
        check('exec(systemctl --version)', r.get('ok') and r.get('returncode') == 0)
    except Exception as e:
        check('exec(systemctl --version)', False, str(e))

    # 3. allowed read: /etc/os-release
    try:
        r = client_send({'op': 'read', 'path': '/etc/os-release'})
        ok = r.get('ok') and base64.b64decode(r.get('content_b64') or '')
        check('read(/etc/os-release)', ok)
    except Exception as e:
        check('read(/etc/os-release)', False, str(e))

    # 4. allowed write+read round-trip under an allowed prefix (the broker's own
    #    log dir always exists, unlike module dirs which may not be deployed)
    probe = os.path.join(AUDIT_DIR, '.selftest')
    try:
        r1 = client_send({'op': 'write', 'path': probe,
                          'content_b64': base64.b64encode(b'ok').decode()})
        r2 = client_send({'op': 'read', 'path': probe})
        got = base64.b64decode(r2.get('content_b64') or '') if r2.get('ok') else b''
        check('write+read round-trip', r1.get('ok') and got == b'ok')
        client_send({'op': 'exec', 'argv': ['rm', '-f', probe]})
    except Exception as e:
        check('write+read round-trip', False, str(e))

    # 5. policy DENIES write to sudoers (dry-run — valid in permissive mode too)
    try:
        r = client_send({'op': 'check', 'req': {'op': 'write', 'path': '/etc/sudoers.d/evil'}})
        check('Policy blocks sudoers write', r.get('ok') and r.get('verdict') == 'DENY', str(r))
    except Exception as e:
        check('Policy blocks sudoers write', False, str(e))

    # 6. policy DENIES arbitrary shell
    try:
        r = client_send({'op': 'check', 'req': {'op': 'exec', 'argv': ['bash', '-c', 'id']}})
        check('Policy blocks arbitrary shell', r.get('ok') and r.get('verdict') == 'DENY', str(r))
    except Exception as e:
        check('Policy blocks arbitrary shell', False, str(e))

    # 7. v10.0.8 gates: git outside module dirs, pg_dump outside the snapshot
    #    tree, and a WRITE to the read-only /root/.ssh grant — all DENY.
    for name, req in (
        ('Policy blocks git outside module dirs',
         {'op': 'exec', 'argv': ['git', '-C', '/etc', 'rev-parse', 'HEAD']}),
        ('Policy blocks pg_dump outside snapshots',
         {'op': 'pg_dump', 'path': '/etc/evil.pgdump'}),
        ('Policy blocks stack_pg_dump outside the backup tree',
         {'op': 'stack_pg_dump', 'container': 'authentik-postgresql-1',
          'path': '/etc/evil.pgdump'}),
        ('Policy blocks stack_nodered_tar outside the backup tree',
         {'op': 'stack_nodered_tar', 'path': '/etc/evil.tar'}),
        ('Policy blocks stack_nodered_tar of another file name',
         {'op': 'stack_nodered_tar', 'path': '/var/lib/infratak-backups/x/other.tar'}),
        ('Policy blocks stack_pg_restore outside the backup tree',
         {'op': 'stack_pg_restore', 'container': 'authentik-postgresql-1',
          'path': '/opt/tak/snapshots/x/cot.pgdump'}),
        ('Policy blocks stack_pg_dump of an unlisted container',
         {'op': 'stack_pg_dump', 'container': 'evil',
          'path': '/var/lib/infratak-backups/x/evil.pgdump'}),
        ('Policy blocks write to /root/.ssh',
         {'op': 'write', 'path': '/root/.ssh/authorized_keys'}),
        ('Policy blocks non-patch openssl.cnf write',
         {'op': 'write', 'path': '/etc/ssl/openssl.cnf',
          'content_b64': base64.b64encode(b'engines=/tmp/evil.so\n').decode()}),
        ('Policy blocks pgminer_scan of an unlisted container',
         {'op': 'pgminer_scan', 'container': 'evil'}),
    ):
        try:
            r = client_send({'op': 'check', 'req': req})
            check(name, r.get('ok') and r.get('verdict') == 'DENY', str(r))
        except Exception as e:
            check(name, False, str(e))

    return _print_selftest(results)


def _print_selftest(results):
    allok = all(ok for _, ok, _ in results)
    for name, ok, detail in results:
        line = f"  [{'PASS' if ok else 'FAIL'}] {name}"
        if not ok and detail:
            line += f"   -- {detail}"
        print(line)
    print('SELFTEST', 'PASS' if allok else 'FAIL')
    return 0 if allok else 1


def main(argv):
    if not argv:
        sys.stderr.write('usage: takwerx_broker.py {serve|exec -- <cmd>|ping|selftest}\n')
        return 2
    cmd = argv[0]
    if cmd == 'serve':
        return serve()
    if cmd == 'exec':
        return cli_exec(argv[1:])
    if cmd == 'ping':
        try:
            r = client_send({'op': 'ping'})
            print(json.dumps(r))
            return 0 if r.get('ok') else 1
        except Exception as e:
            sys.stderr.write(f'ping failed: {e}\n')
            return 1
    if cmd == 'selftest':
        return cli_selftest()
    if cmd == 'update' and len(argv) == 2:
        # ops #645 W1: ask the broker to install a verified commit (console converge)
        try:
            r = client_send({'op': 'broker_update', 'commit': argv[1]}, timeout=1200)
            print(json.dumps(r))
            return 0 if r.get('ok') else 1
        except Exception as e:
            sys.stderr.write(f'update failed: {e}\n')
            return 1
    sys.stderr.write(f'unknown command: {cmd}\n')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
