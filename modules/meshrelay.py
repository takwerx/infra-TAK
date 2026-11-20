"""MeshRelay PTT server (RyanR3/MeshRelayServer) as an infra-TAK module — ops #973.

A Go push-to-talk relay for the MeshRelay phone app: UDP 5000 for the phones, a web
dashboard for the operator. infra-TAK never runs Ryan's `install.sh` and never builds
from source. It installs one pinned release (tag + SHA-256 of each file, held in this
file), runs it as the `ptt` account under a hardened unit, and puts the dashboard behind
Caddy and Authentik.

Security conditions (Security lead, ops #973, Thu Nov 19 2026), each with a test in
tests/test_meshrelay_ops973.py:
  1. config.json is seeded with auth_enabled true before the first start; the health
     check fails the deploy if it ever reads false. config.json.example is never copied.
  2. The dashboard port is loopback-only behind Caddy: a firewall deny rule plus the
     check from outside. (The app has no bind option yet, so it listens on every address.)
  3. Authentik forward_auth covers the dashboard host. The phones use UDP 5000 only (the
     web router has no route they call), so nothing the phones need sits behind it. They
     never touch Caddy, so their brute-force protection is a fail2ban jail on the app's own
     journal (real UDP source address) that blocks UDP 5000 only.
  4. Pinned release, SHA-256 checked here (not only the SHA256SUMS in the release). No git
     pull, no install.sh, no setcap, no chmod o+x on a parent folder. The in-app updater
     cannot write: the binary folder is read-only to `ptt`.
  5. Unit hardening: non-root `ptt`, NoNewPrivileges, ProtectSystem=strict, ProtectHome,
     PrivateTmp, ReadWritePaths for its own data folder only; data files mode 600.
  6. The optional GitHub token (needed while the repo is private) is read-only, kept in the
     console's private settings, sent only to GitHub, and never logged.

This file imports NOTHING from app.py: every seam arrives through the ctx dict.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

from . import register_module, job_log

KEY = 'meshrelay'
UNIT = 'ptt-server'
UNIT_PATH = '/etc/systemd/system/ptt-server.service'
RUN_USER = 'ptt'
INSTALL_DIR = '/opt/meshrelay'            # root-owned: binary + backup, read-only to `ptt`
BIN_PATH = INSTALL_DIR + '/ptt-server'
BACKUP_DIR = INSTALL_DIR + '/backup'
DATA_DIR = '/var/lib/meshrelay'           # `ptt`-owned: config, users, recordings, web files
WEB_DIR = DATA_DIR + '/web'
CONFIG_PATH = DATA_DIR + '/config.json'
PTT_PORT = 5000                           # UDP, public: the phones connect here
# Not Ryan's default 8080: Guard Dog's health agent and Fed Hub already use 8080 on a
# console box. Loopback behind Caddy; closed to the outside by a firewall rule.
WEB_PORT = 8187
REPO = 'RyanR3/MeshRelayServer'

# The pinned release. Nothing installs until every value is filled in: Ryan's repo is
# private and has no tagged release yet (ops #973). Update these in a PR, with the SHA-256
# of each file as built by Ryan's release job and checked by a second person.
RELEASE = {
    'tag': '',
    'assets': {
        # arch -> (file name in the release, sha256)
        'amd64': ('ptt-server-linux', ''),
        'arm64': ('ptt-server-linux-arm64', ''),
    },
    'web': ('web.tar.gz', ''),
}

_SHA_RE = re.compile(r'^[0-9a-f]{64}$')
_TAG_RE = re.compile(r'^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]+)?$')
_MAX_BIN = 120 * 1024 * 1024
_MAX_WEB = 40 * 1024 * 1024


def _plog(msg):
    return job_log(KEY, msg)


# ── pin, config, unit: pure functions (tested without a box) ─────────────────

def pin_problem(release=None, arch='amd64'):
    """Why the pinned release cannot be installed, or '' when it can."""
    rel = release or RELEASE
    tag = rel.get('tag') or ''
    if not _TAG_RE.match(tag):
        return ('MeshRelay has no released version pinned in this infra-TAK yet. '
                'It installs only a tagged release whose SHA-256 is pinned here.')
    asset = (rel.get('assets') or {}).get(arch)
    if not asset:
        return f'No MeshRelay build is pinned for {arch}.'
    for name, sha in (asset, rel.get('web') or ('', '')):
        if not name or not _SHA_RE.match(sha or ''):
            return f'The SHA-256 for {name or "a MeshRelay file"} is not pinned.'
    return ''


def seed_config_text():
    """The first config.json. auth_enabled is true and there is no github_token.
    Ryan's config.json.example sets auth_enabled false; it is never copied."""
    cfg = {
        'ptt_port': PTT_PORT,
        'web_port': WEB_PORT,
        'max_clients': 1000,
        'max_channels': 100,
        'log_level': 'INFO',
        'auth_enabled': True,
        'users_file': 'users.json',
        'web_admins_file': 'web_admins.json',
        'agencies_file': 'agencies.json',
    }
    return json.dumps(cfg, indent=2) + '\n'


def config_problem(text):
    """Why a config.json text is not safe to run, or '' when it is.
    Security condition 1: auth must be on; and no GitHub token inside the app's config."""
    try:
        cfg = json.loads(text or '')
    except ValueError:
        return 'config.json is not valid JSON'
    if not isinstance(cfg, dict):
        return 'config.json is not a JSON object'
    # A missing key means the app's own default, which is true. Only an explicit non-true fails.
    if cfg.get('auth_enabled', True) is not True:
        return 'auth_enabled is not true: anyone could join the relay without an account'
    if (cfg.get('github_token') or '').strip():
        return 'config.json holds a github_token: infra-TAK keeps tokens out of the app'
    if int(cfg.get('web_port') or 0) != WEB_PORT:
        return f'web_port is not {WEB_PORT}: the firewall rule and Caddy point at {WEB_PORT}'
    return ''


def unit_text(selinux=False):
    """The systemd unit (Security condition 5). Only keys the broker allows (ops #645)."""
    lines = [
        '[Unit]',
        'Description=MeshRelay PTT server (managed by infra-TAK)',
        'After=network.target',
        '',
        '[Service]',
        'Type=simple',
        f'User={RUN_USER}',
        f'WorkingDirectory={DATA_DIR}',
        f'ExecStart={BIN_PATH}',
        'Restart=always',
        'RestartSec=5',
        'NoNewPrivileges=yes',
        'ProtectSystem=strict',
        'ProtectHome=yes',
        'PrivateTmp=yes',
        f'ReadWritePaths={DATA_DIR}',
        'UMask=0077',
        'StandardOutput=journal',
        'StandardError=journal',
    ]
    if selinux:
        lines.append('SELinuxContext=system_u:system_r:unconfined_service_t:s0')
    lines += ['', '[Install]', 'WantedBy=multi-user.target', '']
    return '\n'.join(lines)


def append_caddy_vhost(lines, host, authentik, ak_up, strip_header, emit_rescue, root_url):
    """Append the dashboard's Caddy site block to `lines` (Security condition 3).

    Phones use UDP 5000 only (the app's web router has no route a phone calls), so the whole
    HTTP host sits behind Authentik forward_auth. Without Authentik the host answers 503: the
    dashboard is never published bare. The upstream is loopback only."""
    lines.append("# MeshRelay PTT server dashboard (ops #973)")
    lines.append(f"{host} {{")
    if authentik:
        lines.append("    route {")
        lines.append(f"        {strip_header}")
        emit_rescue(root_url)
        lines.append(f"        reverse_proxy /outpost.goauthentik.io/* {ak_up}")
        lines.append(f"        forward_auth {ak_up} {{")
        lines.append("            uri /outpost.goauthentik.io/auth/caddy")
        lines.append("            trusted_proxies private_ranges")
        lines.append("        }")
        lines.append(f"        reverse_proxy 127.0.0.1:{WEB_PORT}")
        lines.append("    }")
    else:
        lines.append('    respond "The MeshRelay dashboard needs Authentik in front of it." 503')
    lines.append("}")
    lines.append("")


# ── download, verify, stage ──────────────────────────────────────────────────

class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """GitHub answers an asset request with a redirect to a signed storage URL. The
    token must not follow it (the storage host refuses it, and it is not GitHub)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header('Authorization')
        return new


def _open(url, token='', accept=None, timeout=60):
    if not url.startswith('https://'):
        raise ValueError('only https downloads are allowed')
    headers = {'User-Agent': 'infra-TAK', 'Accept': accept or '*/*'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    opener = urllib.request.build_opener(_NoAuthOnRedirect())
    return opener.open(urllib.request.Request(url, headers=headers), timeout=timeout)


def _asset_api_url(tag, name, token):
    """The API URL of one release asset (works for a private repo, with a token)."""
    with _open(f'https://api.github.com/repos/{REPO}/releases/tags/{tag}', token,
               'application/vnd.github+json') as r:
        rel = json.load(r)
    for a in rel.get('assets') or []:
        if a.get('name') == name:
            return a['url']
    raise RuntimeError(f'release {tag} has no file named {name}')


def fetch(tag, name, dest, token='', limit=_MAX_BIN):
    """Download one release file to `dest` and return its SHA-256. Never logs the token."""
    url = _asset_api_url(tag, name, token)
    h = hashlib.sha256()
    n = 0
    with _open(url, token, 'application/octet-stream', timeout=120) as r, open(dest, 'wb') as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            n += len(chunk)
            if n > limit:
                raise RuntimeError(f'{name} is larger than {limit} bytes')
            h.update(chunk)
            f.write(chunk)
    return h.hexdigest()


def fetch_verified(tag, name, want_sha, dest, token='', limit=_MAX_BIN, fetcher=None):
    """Download and compare with the pinned SHA-256. Deletes the file on a mismatch."""
    got = (fetcher or fetch)(tag, name, dest, token, limit)
    if got != want_sha:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise RuntimeError(f'SHA-256 of {name} does not match the pinned value; not installing it')
    return got


def safe_web_members(tf):
    """Members of web.tar.gz that may be extracted: plain files and folders under web/,
    no absolute path, no '..', no link, no device."""
    out = []
    for m in tf.getmembers():
        name = m.name
        parts = name.split('/')
        if (name.startswith('/') or '..' in parts or parts[0] != 'web'
                or not (m.isfile() or m.isdir())):
            raise RuntimeError(f'unsafe entry in web.tar.gz: {name[:80]!r}')
        out.append(m)
    return out


def extract_web(archive, stage):
    """Unpack web.tar.gz into `stage`/web. Only vetted members (plain files and folders under
    web/) are written, one by one through extractfile(): no extractall(), no links, and every
    target is checked to stay inside the stage folder."""
    root_abs = os.path.realpath(stage)
    with tarfile.open(archive, 'r:gz') as tf:
        members = safe_web_members(tf)
        for m in members:
            target = os.path.realpath(os.path.join(stage, m.name))
            if target != root_abs and not target.startswith(root_abs + os.sep):
                raise RuntimeError(f'unsafe entry in web.tar.gz: {m.name[:80]!r}')
            if m.isdir():
                os.makedirs(target, mode=0o755, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
            src = tf.extractfile(m)
            with open(target, 'wb') as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, 0o644)
    root = os.path.join(stage, 'web')
    if not os.path.isfile(os.path.join(root, 'index.html')) and not os.path.isdir(root):
        raise RuntimeError('web.tar.gz has no web/ folder')
    return root


# ── privileged helpers (through the broker on a non-root console) ────────────

def _priv(ctx, argv, timeout=120, check=True):
    r = subprocess.run(ctx['_sudo_wrap'](list(argv)), capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{argv[0]} failed: {((r.stderr or '') + (r.stdout or '')).strip()[-200:]}")
    return r


def _install_tree(ctx, src_root, dst_root, owner=None):
    """Copy a staged folder into place file by file (the broker only allows a recursive cp
    from an allow-listed source, and the stage is not one)."""
    _priv(ctx, ['mkdir', '-p', dst_root])
    for base, dirs, files in os.walk(src_root):
        rel = os.path.relpath(base, src_root)
        here = dst_root if rel == '.' else os.path.join(dst_root, rel)
        for d in dirs:
            _priv(ctx, ['mkdir', '-p', os.path.join(here, d)])
        for f in files:
            _priv(ctx, ['cp', os.path.join(base, f), os.path.join(here, f)])
    if owner:
        # -h: never follow a link inside the tree (ops #980); callers stop the service first
        _priv(ctx, ['chown', '-h', '-R', owner, dst_root])


def _active(ctx):
    r = subprocess.run(ctx['_sudo_wrap'](['systemctl', 'is-active', UNIT]),
                       capture_output=True, text=True, timeout=30)
    return (r.stdout or '').strip() == 'active'


def _selinux_enforcing():
    try:
        r = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=10)
        return (r.stdout or '').strip() == 'Enforcing'
    except Exception:
        return False


def read_config(ctx):
    try:
        return ctx['_read_priv'](CONFIG_PATH)
    except Exception:
        return ''


def web_up(timeout=5):
    """The dashboard answers on loopback. /api/session is one of the two routes that need no
    login, and it says nothing about users."""
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{WEB_PORT}/api/session', timeout=timeout) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def health(ctx):
    """(ok, problem). Used by deploy, update and Guard Dog. Fails when auth is off."""
    if not _active(ctx):
        return False, 'the ptt-server service is not running'
    prob = config_problem(read_config(ctx))
    if prob:
        return False, prob
    if not web_up():
        return False, f'the dashboard does not answer on 127.0.0.1:{WEB_PORT}'
    return True, ''


def detect(ctx):
    installed = os.path.exists(BIN_PATH) and os.path.exists(UNIT_PATH)
    running = False
    if installed:
        running = _active(ctx)
    return {'installed': installed, 'running': running}


_PW_RE = re.compile(r'INITIAL ADMIN PASSWORD[^\n]*\n[^\n]*?admin / (\S+)')


def parse_initial_password(journal_text):
    """The one-time admin password the app prints at its first start (server.go), or ''.
    Ryan's README says admin/admin; that is wrong, the real one is random and forced to change."""
    m = _PW_RE.search(journal_text or '')
    return m.group(1) if m else ''


def capture_initial_password(ctx):
    r = subprocess.run(ctx['_sudo_wrap'](['journalctl', '-u', UNIT, '--no-pager', '-o', 'cat', '-n', '400']),
                       capture_output=True, text=True, timeout=30)
    return parse_initial_password(r.stdout)


def get_version_info(ctx):
    """For the console card and the Guard Dog "update pending" email: what is installed
    against the one release this infra-TAK pins. Empty `version` when not installed."""
    have = installed_version(ctx)
    want = RELEASE.get('tag') or ''
    return {'version': have, 'latest': want,
            'update_available': bool(have and want and have != want)}


def installed_version(ctx):
    s = ctx['load_settings']()
    return (s.get('meshrelay') or {}).get('tag', '')


# ── deploy / update / rollback / uninstall ───────────────────────────────────

def deploy_validate(data):
    return {}, None


def _token(ctx):
    return ((ctx['load_settings']() or {}).get('meshrelay_github_token') or '').strip()


def _stage_release(ctx, plog, arch):
    """Download and verify the pinned files into a private temp folder. Returns (dir, bin, web_root)."""
    tag = RELEASE['tag']
    name, want = RELEASE['assets'][arch]
    wname, wwant = RELEASE['web']
    token = _token(ctx)
    stage = tempfile.mkdtemp(prefix='meshrelay-')
    os.chmod(stage, 0o700)
    binpath = os.path.join(stage, 'ptt-server')
    plog(f"⬇ Downloading {name} {tag} ...")
    fetch_verified(tag, name, want, binpath, token, _MAX_BIN, fetcher=ctx.get('meshrelay_fetch'))
    plog("✓ checksum matches the pinned value")
    archive = os.path.join(stage, 'web.tar.gz')
    plog(f"⬇ Downloading {wname} ...")
    fetch_verified(tag, wname, wwant, archive, token, _MAX_WEB, fetcher=ctx.get('meshrelay_fetch'))
    plog("✓ checksum matches the pinned value")
    os.chmod(binpath, 0o755)
    return stage, binpath, extract_web(archive, stage)


def _fix_perms(ctx):
    """Root changes owner and mode inside the `ptt` folder. The service must be stopped first
    (a live `ptt` process could swap a file for a link while root works; Security, ops #980),
    and `-h` keeps chown from following a link that is already there."""
    _priv(ctx, ['chown', '-h', '-R', f'{RUN_USER}:{RUN_USER}', DATA_DIR])
    _priv(ctx, ['chmod', '700', DATA_DIR])
    # data files hold users, TAK client keys and recordings: owner only
    _priv(ctx, ['chmod', '600', CONFIG_PATH], check=False)
    for f in ('users.json', 'web_admins.json', 'agencies.json', 'mutual_aid.json',
              'guest_events.json', 'tak_connections.json'):
        _priv(ctx, ['chmod', '600', f'{DATA_DIR}/{f}'], check=False)


def deploy(ctx, job, params):
    plog = _plog
    stage = None
    try:
        arch = ctx['_host_arch']()
        prob = pin_problem(arch=arch)
        if prob:
            plog(f"✗ {prob}")
            job.update({'running': False, 'error': True})
            return
        if not (ctx['load_settings']().get('fqdn') or '').strip():
            plog("✗ Set a domain name first (Caddy page): the dashboard is served on its own name behind Authentik.")
            job.update({'running': False, 'error': True})
            return
        plog("📡 Step 1/7 — Account and folders")
        if not ctx['_ensure_meshrelay_account'](plog):
            raise RuntimeError('could not create the ptt account')
        # Stop a running service BEFORE root writes anywhere near the `ptt` folder (Security,
        # ops #980: a live `ptt` process could swap a file for a link while root copies or
        # changes modes). It also frees the binary: `cp` onto a running one fails with "Text
        # file busy" (seen on a real box). Step 5 starts it again.
        _priv(ctx, ['systemctl', 'stop', UNIT], check=False)
        for d in (INSTALL_DIR, BACKUP_DIR, DATA_DIR):
            _priv(ctx, ['mkdir', '-p', d])
        _priv(ctx, ['chmod', '755', INSTALL_DIR])
        plog("📡 Step 2/7 — Download the pinned release")
        stage, binpath, web_root = _stage_release(ctx, plog, arch)
        plog("📡 Step 3/7 — Install files")
        _priv(ctx, ['cp', binpath, BIN_PATH])
        _priv(ctx, ['chmod', '755', BIN_PATH])
        _priv(ctx, ['chown', 'root:root', BIN_PATH])
        _install_tree(ctx, web_root, WEB_DIR)
        if not read_config(ctx):
            # seed ONCE, auth on, before the first start (condition 1). Later runs keep the operator's file.
            ctx['_write_priv'](CONFIG_PATH, seed_config_text(), perm=0o600)
            plog("✓ config.json seeded (login required for every phone)")
        _fix_perms(ctx)
        prob = config_problem(read_config(ctx))
        if prob:
            raise RuntimeError(prob)
        plog("📡 Step 4/7 — Service")
        ctx['_write_priv'](UNIT_PATH, unit_text(_selinux_enforcing()), perm=0o644)
        _priv(ctx, ['systemctl', 'daemon-reload'])
        _priv(ctx, ['systemctl', 'enable', UNIT])
        plog("📡 Step 5/7 — Firewall")
        ok, msg = ctx['_fw_allow'](PTT_PORT, 'udp')
        if not ok:
            raise RuntimeError(f'could not open UDP {PTT_PORT}: {msg}')
        ok, msg = ctx['_fw_deny'](WEB_PORT, 'tcp')
        if not ok:
            raise RuntimeError(f'could not close TCP {WEB_PORT}: {msg}')
        _priv(ctx, ['systemctl', 'restart', UNIT])
        plog("📡 Step 6/7 — Health check")
        ok, why = False, ''
        for _ in range(15):
            ok, why = health(ctx)
            if ok:
                break
            time.sleep(2)
        if not ok:
            raise RuntimeError(f'health check failed: {why}')
        s = ctx['load_settings']()
        s['meshrelay'] = {'tag': RELEASE['tag'], 'arch': arch,
                          'sha256': RELEASE['assets'][arch][1]}
        pw = capture_initial_password(ctx)
        if pw:
            s['meshrelay_first_admin_password'] = pw      # shown once on the MeshRelay page, never logged
        ctx['save_settings'](s)
        plog("📡 Step 7/7 — Dashboard behind Caddy and Authentik")
        fqdn = (s.get('fqdn') or '').strip()
        ctx['generate_caddyfile'](s)
        if ctx['_caddy_reload'](plog):
            plog("✓ Caddy reloaded")
        ak_token = (ctx['_get_authentik_env_value'](s, 'AUTHENTIK_TOKEN')
                    or ctx['_get_authentik_env_value'](s, 'AUTHENTIK_BOOTSTRAP_TOKEN'))
        if fqdn and ak_token:
            ctx['_ensure_authentik_meshrelay_app'](fqdn, ak_token, plog=plog, settings=s)
        else:
            plog("⚠ Authentik token not found: the dashboard stays closed (Caddy answers 503) until it is set up")
        ok, msg = ctx['_f2b_arm_meshrelay_jail'](plog)
        plog(f"{'✓' if ok else '⚠'} Phone-login jail: {msg}")
        host = (ctx['_get_service_domain'](s, 'meshrelay') or '').strip()
        plog(f"✅ MeshRelay {RELEASE['tag']} is running. Phones connect to UDP {PTT_PORT}.")
        if host:
            plog(f"   Dashboard: https://{host}/  (first admin password: see the MeshRelay page)")
        job.update({'running': False, 'complete': True, 'error': False})
    except Exception as e:
        plog(f"✗ Deploy failed: {str(e)[:300]}")
        job.update({'running': False, 'error': True})
    finally:
        if stage:
            shutil.rmtree(stage, ignore_errors=True)


def update(ctx, plog=None):
    """Install the pinned release over the running one: back up binary and web, swap,
    restart, check health, and put the backup back if the check fails. The data folder
    (config, users, recordings) is never touched, so auth_enabled stays as it was."""
    plog = plog or _plog
    stage = None
    swapped = False
    stopped = False
    try:
        arch = ctx['_host_arch']()
        prob = pin_problem(arch=arch)
        if prob:
            return {'success': False, 'error': prob}
        if installed_version(ctx) == RELEASE['tag']:
            return {'success': True, 'message': 'already on the pinned version'}
        stage, binpath, web_root = _stage_release(ctx, plog, arch)
        old = installed_version(ctx)
        # Stop first: root reads the web files out of the `ptt` folder for the backup, and a
        # live `ptt` process could swap one for a link meanwhile (Security, ops #980).
        _priv(ctx, ['systemctl', 'stop', UNIT])
        stopped = True
        plog("💾 Backing up the current binary and web files")
        _priv(ctx, ['rm', '-rf', BACKUP_DIR])
        _priv(ctx, ['mkdir', '-p', BACKUP_DIR])
        _priv(ctx, ['cp', BIN_PATH, BACKUP_DIR + '/ptt-server'])
        _install_tree(ctx, WEB_DIR, BACKUP_DIR + '/web')
        swapped = True
        _priv(ctx, ['cp', binpath, BIN_PATH])
        _priv(ctx, ['chmod', '755', BIN_PATH])
        _priv(ctx, ['rm', '-rf', WEB_DIR])
        _install_tree(ctx, web_root, WEB_DIR, owner=f'{RUN_USER}:{RUN_USER}')
        _priv(ctx, ['systemctl', 'start', UNIT])
        ok, why = False, ''
        for _ in range(15):
            ok, why = health(ctx)
            if ok:
                break
            time.sleep(2)
        if not ok:
            plog(f"✗ health check failed after the update: {why}")
            rollback(ctx, plog)
            return {'success': False, 'error': f'update rolled back: {why}'}
        s = ctx['load_settings']()
        s['meshrelay'] = {'tag': RELEASE['tag'], 'arch': arch, 'sha256': RELEASE['assets'][arch][1],
                          'previous': old}
        ctx['save_settings'](s)
        plog(f"✅ MeshRelay updated to {RELEASE['tag']}")
        return {'success': True}
    except Exception as e:
        plog(f"✗ Update failed: {str(e)[:300]}")
        if swapped:
            try:
                rollback(ctx, plog)
            except Exception as e2:
                plog(f"✗ Rollback also failed: {str(e2)[:200]}")
        elif stopped:
            # stopped for the backup, failed before any file was swapped: the old version is
            # still in place, so start it again rather than leave phones with no server
            _priv(ctx, ['systemctl', 'start', UNIT], check=False)
        return {'success': False, 'error': str(e)[:300]}
    finally:
        if stage:
            shutil.rmtree(stage, ignore_errors=True)


def _have_backup():
    return os.path.exists(BACKUP_DIR + '/ptt-server')


def _have_web_backup():
    return os.path.isdir(BACKUP_DIR + '/web')


def rollback(ctx, plog=None):
    """Put the backed-up binary and web files back and restart. Config is never touched."""
    plog = plog or _plog
    if not _have_backup():
        raise RuntimeError('no backup to roll back to')
    _priv(ctx, ['systemctl', 'stop', UNIT], check=False)
    _priv(ctx, ['cp', BACKUP_DIR + '/ptt-server', BIN_PATH])
    _priv(ctx, ['chmod', '755', BIN_PATH])
    if _have_web_backup():
        _priv(ctx, ['rm', '-rf', WEB_DIR])
        _install_tree(ctx, BACKUP_DIR + '/web', WEB_DIR, owner=f'{RUN_USER}:{RUN_USER}')
    _priv(ctx, ['systemctl', 'start', UNIT])
    s = ctx['load_settings']()
    prev = (s.get('meshrelay') or {}).get('previous')
    if prev:
        # tag back to the old one; the recorded checksum and `previous` belonged to the version we left
        s['meshrelay'] = {'tag': prev, 'arch': (s.get('meshrelay') or {}).get('arch', '')}
        ctx['save_settings'](s)
    plog("↩ Rolled back to the previous version")


def uninstall(ctx, job, params):
    steps = []
    _priv(ctx, ['systemctl', 'stop', UNIT], check=False)
    _priv(ctx, ['systemctl', 'disable', UNIT], check=False)
    _priv(ctx, ['rm', '-f', UNIT_PATH], check=False)
    _priv(ctx, ['systemctl', 'daemon-reload'], check=False)
    steps.append('Service stopped and removed')
    ctx['_fw_remove'](PTT_PORT, 'udp')
    steps.append(f'UDP {PTT_PORT} closed')
    _priv(ctx, ['rm', '-rf', INSTALL_DIR], check=False)
    steps.append('Program files removed')
    if (params or {}).get('keep_data'):
        steps.append(f'Data kept in {DATA_DIR}')
    else:
        # users, recordings and TAK client keys: never left behind by default
        _priv(ctx, ['rm', '-rf', DATA_DIR], check=False)
        steps.append('Data removed (users, recordings, TAK connection keys)')
    s = ctx['load_settings']()
    s.pop('meshrelay', None)
    s.pop('meshrelay_first_admin_password', None)
    ctx['save_settings'](s)
    ctx['generate_caddyfile'](s)        # the vhost goes: the module no longer detects as installed
    ctx['_caddy_reload']()
    steps.append('Caddy subdomain removed')
    ctx['_deregister_authentik_proxy_app'](s, 'meshrelay', 'MeshRelay Proxy')
    steps.append('Authentik proxy app deregistered')
    ctx['_f2b_disarm_meshrelay_jail']()
    steps.append('Phone-login jail removed')
    return {'success': True, 'steps': steps}


def register(ctx):
    from flask import jsonify

    def update_view():
        r = update(ctx)
        return jsonify(r), (200 if r.get('success') else 500)

    def rollback_view():
        try:
            rollback(ctx)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)[:300]}), 500

    def forget_password_view():
        s = ctx['load_settings']()
        s.pop('meshrelay_first_admin_password', None)
        ctx['save_settings'](s)
        return jsonify({'success': True})

    def status_view():
        ok, why = health(ctx) if detect(ctx)['installed'] else (False, 'not installed')
        return jsonify({'healthy': ok, 'problem': why, 'version': installed_version(ctx),
                        'pinned': RELEASE['tag'], 'pin_problem': pin_problem(arch=ctx['_host_arch']())})

    register_module({
        'key': KEY,
        'name': 'MeshRelay',
        'description': 'Push-to-talk relay for the MeshRelay phone app',
        'icon': '📻',
        'route': '/meshrelay',
        'template': 'meshrelay.html',
        'priority': 14,
        'detect': detect,
        'deploy': deploy,
        'deploy_validate': deploy_validate,
        'uninstall': uninstall,
        'control_map': {
            'restart': ['systemctl', 'restart', UNIT],
            'stop':    ['systemctl', 'stop', UNIT],
            'start':   ['systemctl', 'start', UNIT],
        },
        'extra_routes': [
            {'url': '/api/meshrelay/update', 'methods': ['POST'],
             'endpoint': 'meshrelay_update', 'view': update_view},
            {'url': '/api/meshrelay/rollback', 'methods': ['POST'],
             'endpoint': 'meshrelay_rollback', 'view': rollback_view},
            {'url': '/api/meshrelay/forget-password', 'methods': ['POST'],
             'endpoint': 'meshrelay_forget_password', 'view': forget_password_view},
            {'url': '/api/meshrelay/status', 'methods': ['GET'],
             'endpoint': 'meshrelay_status', 'view': status_view},
        ],
        'requires_modules': ['authentik'],    # the dashboard is published only behind Authentik
        'ports': [f'{PTT_PORT}/udp'],   # the web port is loopback + Caddy only (firewall deny rule)
        'service_units': [UNIT],
        'settings_keys': ['meshrelay', 'meshrelay_github_token', 'meshrelay_first_admin_password'],
    })
