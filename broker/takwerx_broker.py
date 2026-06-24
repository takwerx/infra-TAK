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
    # storage / kernel knobs (path-checked where they take a file)
    'swapon', 'swapoff', 'mkswap', 'fallocate', 'sync',
    # SELinux read-only inspection
    'getenforce', 'getsebool', 'restorecon',
    # read-only inspection (routed for a single audit point)
    'ss', 'ip', 'getent', 'getcap',
    # privileged file IO via coreutils — TARGET PATHS are validated (see below)
    'tee', 'cat', 'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown',
    'touch', 'ln',
}

# Never executable through the broker — escalation primitives (defence in depth;
# anything not in EXEC_ALLOW is already denied).
EXEC_DENY = {
    'sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh',     # arbitrary shell
    'su', 'sudo', 'pkexec', 'runuser', 'setpriv',          # privilege pivots
    'env', 'nohup', 'nice', 'timeout', 'xargs', 'find',    # exec wrappers / -exec
    'perl', 'python', 'python3', 'ruby', 'awk', 'gawk',    # interpreters
    'sed', 'dd', 'install', 'psql', 'openssl',             # arbitrary write/exec
    'apt', 'apt-get', 'dnf', 'yum',                        # pkg-mgr hook exec
    'semodule', 'semanage', 'setsebool', 'setcap',         # confinement / caps
    'sysctl',                                              # core_pattern = |cmd
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
    '/opt/tak/',
    '/opt/tak-guarddog/',
    '/usr/local/etc/',
    # NOTE: /usr/local/bin/ deliberately NOT allowed — it is on root's PATH and
    # executable, so a write there is a root-escalation primitive.
    '/var/log/takwerx-broker/',
)

# Exact privileged paths that are read/written but aren't directories.
PATH_ALLOW_EXACT = (
    '/etc/fstab',
    '/etc/os-release',
    '/etc/docker/daemon.json',
    '/swapfile',
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
        if p.startswith(a):
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
    allowed_sub = {
        'ps', 'inspect', 'logs', 'cp', 'exec', 'restart', 'start', 'stop',
        'rm', 'kill', 'network', 'compose', 'images', 'image', 'pull', 'version',
        'info', 'stats', 'system', 'volume', 'port', 'top', 'wait', 'update',
        'create', 'run', 'tag', 'load', 'save', 'container', 'builder', 'buildx',
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
    bad = ('/', '/etc', '/root', '/home', '/boot', '/usr', '/bin', '/sbin',
           '/lib', '/var/run', '/run', '/proc', '/sys', '/dev')
    real = os.path.normpath(src)
    if real in bad or any(real.startswith(b + '/') for b in ('/etc', '/root', '/home', '/boot', '/proc', '/sys')):
        raise Denied(f'docker bind mount of sensitive host path denied: {src}')


def check_exec(argv, cwd=None):
    """Validate an exec request against the rulebook. Returns the argv to run or
    raises Denied. argv must be a non-empty list of strings. `cwd` is the
    request's working directory — path-checked coreutils resolve their path
    args against it so a relative arg + cwd=/etc cannot escape the allowlist."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise Denied('argv must be a non-empty list of strings')
    base = os.path.basename(argv[0])
    if base in EXEC_DENY:
        raise Denied(f'binary is denied: {base}')
    if base not in EXEC_ALLOW:
        raise Denied(f'binary not in allow-list: {base}')
    if base == 'systemctl':
        _check_systemctl(argv)
    if base == 'docker':
        _check_docker(argv)
    if base in PATH_CHECKED_BINS:
        _check_path_args(base, argv, cwd)
    return argv


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
    for a in argv[1:]:
        if a == '--' or a.startswith('-'):
            continue               # flag — coreutils flags here don't take paths
                                   # (sed/dd/install with path-taking flags are denied)
        # Everything else is treated as a path operand and must be allowlisted.
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


def _do_exec(req):
    argv = check_exec(req.get('argv'))
    inp = req.get('input_b64')
    input_bytes = base64.b64decode(inp) if inp else None
    timeout = min(int(req.get('timeout') or DEFAULT_TIMEOUT), DEFAULT_TIMEOUT)
    cwd = req.get('cwd') or None
    if cwd and not (isinstance(cwd, str) and os.path.isdir(cwd)):
        cwd = None
    env = None
    extra_env = req.get('env')
    if isinstance(extra_env, dict):
        env = dict(os.environ)
        for k, v in extra_env.items():
            if isinstance(k, str) and isinstance(v, str):
                env[k] = v
    proc = subprocess.run(argv, input=input_bytes, capture_output=True,
                          timeout=timeout, cwd=cwd, env=env)
    return {
        'ok': True,
        'returncode': proc.returncode,
        'stdout_b64': base64.b64encode(proc.stdout or b'').decode(),
        'stderr_b64': base64.b64encode(proc.stderr or b'').decode(),
    }


def _do_write(req):
    path = _path_allowed(req.get('path'))
    content = base64.b64decode(req.get('content_b64') or '')
    mode = req.get('mode', 'w')
    append = mode in ('a', 'ab')
    # O_NOFOLLOW: refuse to write THROUGH a symlink at the target path (a planted
    # symlink could otherwise redirect an allowlisted write to e.g. /etc/passwd).
    # Only the final component is guarded, so a legit symlinked parent (/opt/tak)
    # still works.
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_APPEND if append else os.O_TRUNC
    fd = os.open(path, flags, 0o644)
    try:
        with os.fdopen(fd, 'ab' if append else 'wb') as f:
            f.write(content)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    perm = req.get('perm')
    if perm is not None:
        os.chmod(path, int(perm))
    return {'ok': True}


def _do_read(req):
    path = _path_allowed(req.get('path'))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        data = f.read(MAX_MSG)
    return {'ok': True, 'content_b64': base64.b64encode(data).decode()}


def _dispatch(req, peer):
    op = req.get('op')
    if op == 'ping':
        audit(peer, 'ping', '', 'ALLOW')
        return {'ok': True, 'pong': True}
    if op == 'exec':
        try:
            argv = req.get('argv') or []
            check_exec(argv, req.get('cwd'))
        except Denied as d:
            audit(peer, 'exec', ' '.join(map(str, req.get('argv') or []))[:200], 'DENY', str(d))
            return {'ok': False, 'code': 'DENIED', 'error': str(d)}
        res = _do_exec(req)
        audit(peer, 'exec', ' '.join(req['argv'])[:200], 'ALLOW', f"rc={res['returncode']}")
        return res
    if op == 'write':
        try:
            _path_allowed(req.get('path'))
        except Denied as d:
            audit(peer, 'write', str(req.get('path'))[:200], 'DENY', str(d))
            return {'ok': False, 'code': 'DENIED', 'error': str(d)}
        res = _do_write(req)
        audit(peer, 'write', str(req.get('path'))[:200], 'ALLOW', f"mode={req.get('mode','w')}")
        return res
    if op == 'read':
        try:
            _path_allowed(req.get('path'))
        except Denied as d:
            audit(peer, 'read', str(req.get('path'))[:200], 'DENY', str(d))
            return {'ok': False, 'code': 'DENIED', 'error': str(d)}
        res = _do_read(req)
        audit(peer, 'read', str(req.get('path'))[:200], 'ALLOW')
        return res
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
        try:
            raw = _recv_all(conn)
            req = json.loads(raw.decode())
            resp = _dispatch(req, peer)
        except Denied as d:
            resp = {'ok': False, 'code': 'DENIED', 'error': str(d)}
        except subprocess.TimeoutExpired:
            resp = {'ok': False, 'code': 'TIMEOUT', 'error': 'command timed out'}
        except Exception as e:  # noqa: BLE001 — broker must never crash a worker thread
            resp = {'ok': False, 'code': 'ERROR', 'error': f'{type(e).__name__}: {e}'}
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

    # 5. DENY: write to sudoers must be refused
    try:
        r = client_send({'op': 'write', 'path': '/etc/sudoers.d/evil',
                         'content_b64': base64.b64encode(b'takwerx ALL=(ALL) NOPASSWD:ALL').decode()})
        check('DENY write(/etc/sudoers.d)', (not r.get('ok')) and r.get('code') == 'DENIED', str(r))
    except Exception as e:
        check('DENY write(/etc/sudoers.d)', False, str(e))

    # 6. DENY: arbitrary shell must be refused
    try:
        r = client_send({'op': 'exec', 'argv': ['bash', '-c', 'id']})
        check('DENY exec(bash -c)', (not r.get('ok')) and r.get('code') == 'DENIED', str(r))
    except Exception as e:
        check('DENY exec(bash -c)', False, str(e))

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
