#!/usr/bin/env python3
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
import grp
import json
import logging
import logging.handlers
import os
import pwd
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
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
BROKER_UNIT = '/etc/systemd/system/takwerx-broker.service'
# The console repo this broker ships inside (…/broker/takwerx_broker.py -> repo
# root). Used by the v10.1.4 repo-ownership self-heal carve-out in _check_chown —
# derived from SELF_PATH, never from client input.
CONSOLE_REPO_DIR = os.path.dirname(os.path.dirname(SELF_PATH))

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
    # v10.0.8 harvest: git for root-era module repos (TVR/WebODM stay at /root on
    # a flipped box). Tightly gated — see _check_git: -C <root-era module dir>
    # only; home-resident repos run git DIRECTLY as the console user, never here.
    'git',
    # transient-unit launcher — a DIRECT root-exec primitive, so gated to the ONE
    # fixed kernel-patch shape (see _check_systemd_run). No broader than the
    # already-allowed `systemctl start <console-written-unit>`.
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
    '/opt/tak-guarddog/',
    TAK_BUNDLE_DIR + '/',        # console-owned TAK docker bundle (ln source for /opt/tak)
    '/usr/local/etc/',
    '/var/lib/cesium-tiles/',   # RHEL cesium tiles dir (chmod 755 by the console)
    '/var/lib/takguard/',       # Guard Dog state dir (mkdir/chmod by the console)
    '/opt/mediamtx-webeditor/',  # MediaMTX web-editor module dir (chown to takwerx)
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
)

# Exact privileged paths that are read/written but aren't directories.
PATH_ALLOW_EXACT = (
    '/etc/fstab',
    '/etc/os-release',
    '/etc/sysctl.conf',         # vm.overcommit_memory persistence (Redis BGSAVE fix)
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
    '/var/lib/infratak-kernel-patch.sh',         # kernel-patch job script (written by
                                                 # the console, run by the gated systemd-run)
    '/etc/default/takserver',                    # TAK Server JVM heap (snapshot/restore + deploy)
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
    '/etc/sudoers.d/',                   # no minting new sudoers rules
    # v10.0.8: the broker unit itself is deny-listed (trust anchor), but a
    # systemd DROP-IN under its .d/ dir would override ExecStart/Environment
    # just the same (incl. the ENFORCE flag) — deny the whole drop-in dir.
    BROKER_UNIT + '.d/',
)


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
_CONSOLE_OWNED_PREFIXES = (TAK_BUNDLE_DIR + '/',) + HOME_MODULE_DIRS


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
        joined = ' '.join(argv)
        if '--privileged' in argv:
            raise Denied('docker run/create --privileged denied')
        for i, a in enumerate(argv):
            if a in ('--pid', '--ipc', '--userns') and i + 1 < len(argv) and argv[i + 1] == 'host':
                raise Denied(f'docker run/create {a}=host denied')
            if a in ('--pid=host', '--ipc=host', '--userns=host'):
                raise Denied(f'docker run/create {a} denied')
            if a in ('-v', '--volume', '--mount'):
                spec = argv[i + 1] if i + 1 < len(argv) else ''
                _check_docker_mount(spec)
            if a.startswith('-v=') or a.startswith('--volume=') or a.startswith('--mount='):
                _check_docker_mount(a.split('=', 1)[1])
        # docker.sock passthrough = host root
        if '/var/run/docker.sock' in joined or '/run/docker.sock' in joined:
            raise Denied('docker run/create mounting the docker socket denied')


def _check_docker_mount(spec):
    """Reject bind mounts of sensitive host paths in a -v/--mount spec."""
    src = ''
    if spec.startswith('type='):  # --mount form: type=bind,source=/x,...
        for part in spec.split(','):
            if part.startswith(('source=', 'src=')):
                src = part.split('=', 1)[1]
    else:                          # -v form: SRC:DST[:opts]
        src = spec.split(':', 1)[0]
    if not src.startswith('/'):
        return                     # named volume, not a host bind
    real = os.path.normpath(src)
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
    elif base == 'wpa_cli':
        _check_wpa_cli(argv)
    elif base == 'chown':
        _check_chown(argv, cwd)
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
    if len(rest) == 3 and rest[0] == 'dev' and rest[2] == 'scan' and _IFACE_RE.match(rest[1]):
        return
    if len(rest) == 4 and rest[0] == 'dev' and rest[2] == 'scan' and rest[3] == 'dump' and _IFACE_RE.match(rest[1]):
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
    if len(r) >= 3 and r[0] == '-i' and _IFACE_RE.match(r[1]):
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
    if (len(rest) in (12, 16)
            and rest[0:5] == ['connection', 'add', 'type', 'wifi', 'con-name']
            and _free(rest[5]) and rest[6] == 'ifname'
            and (rest[7] == '*' or _IFACE_RE.match(rest[7]))
            and rest[8] == 'ssid' and _free(rest[9])
            and rest[10:12] == ['connection.autoconnect', 'yes']
            and (len(rest) == 12 or (rest[12:15] == ['wifi-sec.key-mgmt', 'wpa-psk', 'wifi-sec.psk']
                                     and _free(rest[15])))):
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
    sub = None
    for a in argv[1:]:
        # -o KEY=VAL / --option / --setopt run arbitrary config incl. exec hooks
        if a.startswith('--setopt='):
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


def _check_semanage(argv):
    """semanage manages SELinux policy bits. Allow `semanage port` (custom Caddy
    ports -> http_port_t) and `semanage fcontext -t <safe content/exec type>`
    (cesium tiles served by httpd). Deny login/user/boolean/etc. and any
    relabel to a security-sensitive type."""
    if len(argv) < 2 or argv[1] not in ('port', 'fcontext'):
        raise Denied('semanage: only `semanage port` / `semanage fcontext` allowed')
    if argv[1] == 'fcontext':
        t = None
        for i, a in enumerate(argv[2:], start=2):
            if a == '-t' and i + 1 < len(argv):
                t = argv[i + 1]
            elif a.startswith('--type='):
                t = a.split('=', 1)[1]
        if t is None or t not in SELINUX_SAFE_TYPES:
            raise Denied(f'semanage fcontext: type not in safe set: {t}')


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
            for a in argv[5:]:
                if a in ('-f', '--file', '-') or a.startswith('--file='):
                    raise Denied(f'runuser: psql script/stdin input denied as postgres: {a!r}')
            blob = ' '.join(' '.join(str(a) for a in argv[4:]).lower().split())
            for tok in _PSQL_FORBIDDEN:
                if tok in blob:
                    raise Denied(f'runuser: psql primitive denied as postgres: {tok!r}')
        return
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


# TAK's rpm/deb ships apply-selinux.sh which compiles + installs TAK's own SELinux
# policy module (and uses sudo internally), so it must run as root. Allow ONLY this
# one exact, TAK-provided script — never `bash -c`, never any other path.
_TAK_BASH_SCRIPTS = ('/opt/tak/apply-selinux.sh',)


def _check_bash(argv):
    if len(argv) != 2 or argv[1] not in _TAK_BASH_SCRIPTS:
        raise Denied('bash: only the TAK apply-selinux.sh script is allowed')


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
        if a == '--':
            continue
        if a.startswith('-') and a != '-':
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
    _path_allowed(dst)                       # destination must be allowlisted
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


def _check_install(argv):
    """install(1): `install -m MODE src dst`. The SOURCE is a read of a
    console-owned file (anywhere); only the DEST must be allowlisted. Block the
    `--strip-program=cmd` arbitrary-exec vector."""
    for a in argv[1:]:
        if a in ('-S', '--strip') or a.startswith('--strip-program'):
            raise Denied('install: --strip-program/--strip not allowed')
    paths = [a for a in argv[1:] if not a.startswith('-')
             and a not in ('0755', '0644', '0700', '0600', '0750')]
    # the mode value follows -m; drop a bare numeric mode if present
    paths = [a for a in paths if not (len(a) <= 4 and a.isdigit())]
    if paths:
        _path_allowed(paths[-1])   # dst = last positional path
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


def _check_systemd_run(argv):
    """Allow ONLY the two fixed transient-unit invocations: the kernel-patch job
    and the non-root migration job. Everything else is denied."""
    saw_unit = None
    positionals = []
    props = []
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
            if unit not in (_KPATCH_UNIT_NAME, _MIGRATE_UNIT_NAME):
                raise Denied(f'systemd-run: only units {_KPATCH_UNIT_NAME}/'
                             f'{_MIGRATE_UNIT_NAME} allowed')
            saw_unit = unit
            continue
        if a.startswith('--description='):
            continue
        if a.startswith('--property='):
            props.append(a.split('=', 1)[1])
            continue
        if a.startswith('--setenv='):
            if a.split('=', 1)[1] not in _SYSTEMD_RUN_ALLOWED_SETENV:
                raise Denied(f'systemd-run: setenv not allowed: {a}')
            continue
        if a.startswith('-'):
            raise Denied(f'systemd-run: flag not allowed: {a}')
        positionals.append(a)
    if saw_unit is None:
        raise Denied('systemd-run: missing required --unit=')
    if saw_unit == _KPATCH_UNIT_NAME:
        for p in props:
            if p not in _SYSTEMD_RUN_ALLOWED_PROPERTIES:
                raise Denied(f'systemd-run: property not allowed: --property={p}')
        if positionals != ['/bin/bash', _KPATCH_SCRIPT]:
            raise Denied(f'systemd-run: only `/bin/bash {_KPATCH_SCRIPT}` allowed')
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
    for a in argv[1:]:
        if a == '--' or a.startswith('-'):
            continue               # flag — coreutils flags here don't take paths
        if skip_first_positional and not seen_positional:
            seen_positional = True
            continue               # the MODE (chmod) / OWNER (chown) arg
        seen_positional = True
        # Everything else is a path operand and must be allowlisted.
        target = a if a.startswith('/') else os.path.join(base_cwd, a)
        _path_allowed(target)      # raises Denied if outside allowlist


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
    proc = subprocess.run(argv, input=input_bytes, capture_output=True,
                          timeout=timeout, cwd=cwd, env=env)
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


def _do_pg_dump(req):
    path = _abs(req.get('path'))
    db = req.get('db') or 'cot'
    if req.get('container'):
        docker = shutil.which('docker', path=BROKER_TRUSTED_PATH)
        if not docker:
            return {'ok': False, 'error': 'docker not found on trusted PATH'}
        argv = [docker, 'exec', '-u', 'postgres', _PG_DUMP_CONTAINER,
                'pg_dump', '-Fc', db]
    else:
        runuser = shutil.which('runuser', path=BROKER_TRUSTED_PATH)
        pg_dump = shutil.which('pg_dump', path=BROKER_TRUSTED_PATH)
        if not runuser or not pg_dump:
            return {'ok': False, 'error': 'runuser/pg_dump not found on trusted PATH'}
        argv = [runuser, '-u', 'postgres', '--', pg_dump, '-Fc', db]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    timeout = min(int(req.get('timeout') or DEFAULT_TIMEOUT), DEFAULT_TIMEOUT)
    # stdout goes straight to the root-opened file — the 32MiB socket cap never
    # applies, and postgres needs no write access to the snapshot dir.
    with open(path, 'wb') as out:
        proc = subprocess.run(argv, stdout=out, stderr=subprocess.PIPE, timeout=timeout)
    if proc.returncode != 0:
        try:
            os.unlink(path)    # never leave a truncated/empty dump behind
        except OSError:
            pass
        return {'ok': False, 'returncode': proc.returncode,
                'error': (proc.stderr or b'').decode(errors='replace')[:500]}
    os.chmod(path, 0o600)
    # Authenticity sidecar — proves the broker produced this dump, so pg_restore
    # will accept it (and reject any console-planted archive). Best-effort: if the
    # sidecar can't be written, restore simply won't trust the dump later.
    try:
        sc = path + '.hmac'
        fd = os.open(sc, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, _dump_hmac(path).encode())
        os.close(fd)
    except OSError:
        pass
    return {'ok': True, 'size': os.path.getsize(path)}


def _check_pg_restore(req):
    # same gate as pg_dump: source file must live under the snapshot tree
    _check_pg_dump(req)


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
        elif op == 'pg_dump':
            _check_pg_dump(req)
        elif op == 'pg_restore':
            _check_pg_restore(req)
        elif op == 'pgminer_scan':
            _check_pgminer_scan(req)
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
            if a in ('password', 'wifi-sec.psk'):
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
                'readiness': _enforce_readiness()}
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
    if op in ('pg_dump', 'pg_restore', 'pgminer_scan'):
        verdict, reason = _evaluate(req)
        summary = req.get('container', '') if op == 'pgminer_scan' else _summary(req)
        if verdict == 'DENY':
            # fail-closed in BOTH modes — new ops, nothing legacy to preserve
            audit(peer, op, summary, 'DENY', reason)
            return {'ok': False, 'code': 'DENIED', 'error': reason}
        audit(peer, op, summary, 'ALLOW')
        if op == 'pg_dump':
            return _do_pg_dump(req)
        if op == 'pg_restore':
            return _do_pg_restore(req)
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


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
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


def _enforce_readiness():
    """Report the box's enforce readiness for the console card WITHOUT changing
    mode. Returns a dict: opted_in, clean, ready, reason, clean_since. Never
    raises. `ready` = opted_in is not required — a box is 'ready' (eligible) once
    its audit window is clean, whether or not the operator has opted in yet."""
    try:
        opted_in = os.path.exists(ENFORCE_OPTIN_FILE)
    except OSError:
        opted_in = False
    try:
        clean, why, since = _audit_clean_window()
    except Exception as e:
        clean, why, since = False, f'gate evaluation error: {e}', None
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


def serve():
    global AUDIT, ENFORCE, ENFORCE_INFO
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
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.unlink(SOCKET_PATH)
        except OSError:
            pass
    return 0


# ---------------------------------------------------------------------------
# Client  (used by the CLI proxy + selftest; app.py has its own in-process copy)
# ---------------------------------------------------------------------------
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
    try:
        resp = client_send(req, timeout=(req.get('timeout') or DEFAULT_TIMEOUT) + 60)
    except (OSError, socket.timeout) as e:
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
    sys.stderr.write(f'unknown command: {cmd}\n')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
