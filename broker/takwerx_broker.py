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
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SOCKET_PATH = os.environ.get('TAKWERX_BROKER_SOCKET', '/run/takwerx-broker.sock')
AUDIT_DIR = '/var/log/takwerx-broker'
AUDIT_LOG = os.path.join(AUDIT_DIR, 'audit.log')
BROKER_USER = 'takwerx'                       # console runs as this once flipped
MAX_MSG = 32 * 1024 * 1024                    # 32 MiB hard cap per request/response
DEFAULT_TIMEOUT = 600                         # seconds; broker-side ceiling
SELF_PATH = os.path.realpath(__file__)
BROKER_UNIT = '/etc/systemd/system/takwerx-broker.service'

# The console-owned TAK Server docker bundle is unzipped here (app.py
# TAK_DOCKER_ROOT = ~/tak-docker) and bind-mounted into the TAK containers at
# /opt/tak. The non-root console writes it DIRECTLY (it owns the dir), so it
# lives under takwerx's HOME rather than a root /opt path. The container deploy
# legitimately `ln -sfn <bundle>/tak /opt/tak` and `docker run -v <bundle>/tak:
# /opt/tak` FROM here — both were denied because /home is forbidden, which is
# the v10.0.5 container-deploy exit-126 regression. Allow this ONE subtree (NOT
# /home at large): it is takwerx-owned and is the intended /opt/tak source.
try:
    _NONROOT_HOME = pwd.getpwnam(BROKER_USER).pw_dir or '/home/takwerx'
except KeyError:
    _NONROOT_HOME = '/home/takwerx'
TAK_BUNDLE_DIR = os.path.join(_NONROOT_HOME, 'tak-docker')

# ENFORCE vs PERMISSIVE (v10.0.5).
#   PERMISSIVE (default this release): a request that fails the rulebook is still
#   EXECUTED, but logged as WOULD-DENY. The console runs as ROOT today, so routing
#   through the broker must MEDIATE + AUDIT, never break a legit op (denying a
#   binary the console needs buys no security while root). Permissive mode lets us
#   collect the real binary/path needs from WOULD-DENY records and build an
#   accurate enforce-list BEFORE the non-root flip.
#   ENFORCE (set TAKWERX_BROKER_ENFORCE=1): deny means deny. This is the posture
#   the box must be in BEFORE the console is ever flipped to a non-root user.
ENFORCE = os.environ.get('TAKWERX_BROKER_ENFORCE') == '1'

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
    # transient-unit launcher — a DIRECT root-exec primitive, so gated to the ONE
    # fixed kernel-patch shape (see _check_systemd_run). No broader than the
    # already-allowed `systemctl start <console-written-unit>`.
    'systemd-run',
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
    'env', 'nohup', 'nice', 'timeout', 'xargs', 'find',    # exec wrappers / -exec
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
    '/opt/tak/',
    '/opt/tak-guarddog/',
    TAK_BUNDLE_DIR + '/',        # console-owned TAK docker bundle (ln source for /opt/tak)
    '/usr/local/etc/',
    '/var/lib/cesium-tiles/',   # RHEL cesium tiles dir (chmod 755 by the console)
    '/var/lib/takguard/',       # Guard Dog state dir (mkdir/chmod by the console)
    '/opt/mediamtx-webeditor/',  # MediaMTX web-editor module dir (chown to takwerx)
    '/var/log/',                # log files (touch /var/log/fail2ban.log, etc.)
    # NOTE: /usr/local/bin/ and /usr/sbin/ are deliberately NOT prefix-allowed —
    # they are on root's PATH, so a write there is an escalation primitive. The
    # one legit exception (the ufw->firewalld shim) is the EXACT path below.
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
        rr = os.path.realpath(root)
        rp = os.path.realpath(path)
    except OSError:
        return False
    return rp == rr or rp.startswith(rr + '/')


def _path_allowed(path):
    """True if `path` is within the privileged read/write allowlist and not in
    the deny set. Raises Denied with a reason otherwise."""
    p = _abs(path)
    if p in PATH_DENY_EXACT:
        raise Denied(f'path is in deny-list: {p}')
    for d in PATH_DENY_PREFIX:
        if p.startswith(d):
            raise Denied(f'path is under deny-prefix {d}: {p}')
    if p in PATH_ALLOW_EXACT:
        return p
    for a in PATH_ALLOW:
        # match a child of the dir, OR the allowlisted dir itself (no trailing /)
        if p.startswith(a) or p == a.rstrip('/'):
            # The bundle dir is the lone console-WRITABLE prefix — require realpath
            # containment so a planted symlink under it can't escape (the other
            # prefixes are root-owned, so they keep the cheaper lexical match).
            if a == TAK_BUNDLE_DIR + '/' and not _within_realpath(p, TAK_BUNDLE_DIR):
                raise Denied(f'symlink escape from bundle dir: {p}')
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
    elif base == 'install':
        _check_install(argv)
    elif base == 'sysctl':
        _check_sysctl(argv)
    elif base in PATH_CHECKED_BINS:
        _check_path_args(base, argv, cwd)
    return argv


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


def _check_systemd_run(argv):
    """Allow ONLY the fixed kernel-patch transient-unit invocation."""
    saw_unit = False
    positionals = []
    for a in argv[1:]:
        if a in ('--no-block', '--collect'):
            continue
        if a.startswith('--unit='):
            if a.split('=', 1)[1] != _KPATCH_UNIT_NAME:
                raise Denied(f'systemd-run: only unit {_KPATCH_UNIT_NAME} allowed')
            saw_unit = True
            continue
        if a.startswith('--description='):
            continue
        if a.startswith('--property='):
            if a.split('=', 1)[1] not in _SYSTEMD_RUN_ALLOWED_PROPERTIES:
                raise Denied(f'systemd-run: property not allowed: {a}')
            continue
        if a.startswith('--setenv='):
            if a.split('=', 1)[1] not in _SYSTEMD_RUN_ALLOWED_SETENV:
                raise Denied(f'systemd-run: setenv not allowed: {a}')
            continue
        if a.startswith('-'):
            raise Denied(f'systemd-run: flag not allowed: {a}')
        positionals.append(a)
    if not saw_unit:
        raise Denied(f'systemd-run: missing required --unit={_KPATCH_UNIT_NAME}')
    if positionals != ['/bin/bash', _KPATCH_SCRIPT]:
        raise Denied(f'systemd-run: only `/bin/bash {_KPATCH_SCRIPT}` allowed')


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


def audit(peer, op, summary, verdict, detail=''):
    if AUDIT is None:
        return
    rec = {
        'op': op, 'verdict': verdict, 'summary': summary,
        'peer_uid': peer[1] if peer else None,
        'peer_pid': peer[0] if peer else None,
    }
    if detail:
        rec['detail'] = detail[:500]
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
    timeout = min(int(req.get('timeout') or DEFAULT_TIMEOUT), DEFAULT_TIMEOUT)
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


def _do_write(req):
    # Decision made in _dispatch; here only normalize (reject NUL/traversal) so
    # permissive mode can still execute an off-allowlist write (console is root).
    # NB: we deliberately follow symlinks here. The symlink-escape vector (M2) is
    # closed elsewhere: a non-root console cannot plant a symlink in the
    # allowlisted dirs (they are root-owned), and `ln` is path-checked so it
    # cannot create one pointing outside the allowlist. O_NOFOLLOW would also
    # break LEGIT symlinked targets (e.g. /etc/os-release -> /usr/lib/os-release).
    path = _abs(req.get('path'))
    content = base64.b64decode(req.get('content_b64') or '')
    mode = req.get('mode', 'w')
    append = mode in ('a', 'ab')
    with open(path, 'ab' if append else 'wb') as f:
        f.write(content)
    perm = req.get('perm')
    if perm is not None:
        os.chmod(path, int(perm))
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


def _evaluate(req):
    """Return ('ALLOW'|'DENY', reason) for a data-plane request WITHOUT executing
    it. Never raises."""
    op = req.get('op')
    try:
        if op == 'exec':
            check_exec(req.get('argv') or [], req.get('cwd'))
        elif op in ('write', 'read'):
            _path_allowed(req.get('path'))
        else:
            return ('DENY', f'unknown op: {op}')
        return ('ALLOW', '')
    except Denied as d:
        return ('DENY', str(d))


def _summary(req):
    op = req.get('op')
    if op == 'exec':
        return ' '.join(map(str, req.get('argv') or []))[:200]
    return str(req.get('path'))[:200]


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
        return {'ok': True, 'pong': True, 'enforce': ENFORCE}
    # dry-run: report what the rulebook WOULD do, without executing. Used by the
    # self-test to verify deny rules even while the broker runs permissive.
    if op == 'check':
        inner = req.get('req') or {}
        verdict, reason = _evaluate(inner)
        return {'ok': True, 'verdict': verdict, 'reason': reason, 'enforce': ENFORCE}
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


def serve():
    global AUDIT
    if os.geteuid() != 0:
        sys.stderr.write('takwerx-broker: serve must run as root\n')
        return 2
    AUDIT = _make_audit_logger()
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
    try:
        resp = client_send(req)
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
