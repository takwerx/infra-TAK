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
"""Wazuh agent (SIEM, phase 1): the agent on this TAK box, sending logs to a Wazuh server the
operator names. ops #1421; Security review ops #1422 (conditions C1 to C12).

What this file decides, and what it does not:
  * The BROKER is the lock (`wazuh_agent` op in broker/takwerx_broker.py): it installs only the
    four pinned package files, builds ossec.conf itself, and refuses to start an agent whose
    lock-down is not intact. This file never sends config text.
  * This file downloads the pinned file (the console's own copy is checked here too, for a
    plain early message), checks the server's certificate before anything is sent, and shows
    the operator what leaves the box.
  * No Wazuh repository is ever added to the box. Nothing inbound is opened (the agent has no
    listening port; Security verified that on the real 4.14.11 packages).
Module files import nothing from app.py; every seam arrives through `ctx`.
"""

import hashlib
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.request

from . import register_module, job_log, job_start, job_state

KEY = 'wazuh'
UNIT = 'wazuh-agent'
SETTINGS_KEY = 'wazuh'
PIN_VERSION = '4.14.11'
PIN_RELEASE = '4.14.11-1'

# The same four files and hashes as broker/takwerx_broker.py WAZUH_PKG_PINS (Security's table,
# ops #1422). The broker is the authority; a test keeps this copy equal to it.
PINS = {
    'wazuh-agent_4.14.11-1_amd64.deb':
        'af1dd6e83350ecdb3e9c26a6467e3cc701766bf5519f63b3f213148dd5e8e89d',
    'wazuh-agent_4.14.11-1_arm64.deb':
        '28a57d4bb7cb0c441f7b8046b8f15afd37819f0d768663326b4367dd8a8e0318',
    'wazuh-agent-4.14.11-1.x86_64.rpm':
        '17362b1e88be0e53704c9c98664c5a92c560ab0abee8e08fcf6c95d6b7f4f316',
    'wazuh-agent-4.14.11-1.aarch64.rpm':
        '6e53002ecb212d35d13714c4efe87bf37d2ec1f8725852aad2f59346ded82684',
}
URL_APT = 'https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/'
URL_YUM = 'https://packages.wazuh.com/4.x/yum/'
MAX_PKG_BYTES = 64 * 1024 * 1024
ENROLL_PORT = 1515
EVENT_PORT = 1514

# What the card offers. The broker owns the real map from key to file; this is the wording.
# `files` is shown to the operator so they know exactly what is read (C7).
SOURCES = (
    {'key': 'ssh_auth', 'label': 'SSH and sudo logins',
     'files': {'debian': '/var/log/auth.log', 'rhel': '/var/log/secure'}, 'warn': ''},
    {'key': 'fail2ban', 'label': 'Bans from fail2ban',
     'files': {'*': '/var/log/fail2ban.log'}, 'warn': ''},
    {'key': 'caddy_access', 'label': 'TAK Portal web access (Caddy)',
     'files': {'*': '/var/log/caddy/takportal-access.log'},
     'warn': 'Holds client addresses and the pages people open.'},
    {'key': 'takserver_api', 'label': 'TAK Server API log',
     'files': {'*': '/opt/tak/logs/takserver-api.log'},
     'warn': 'Holds user names and client addresses.'},
    {'key': 'takserver_messaging', 'label': 'TAK Server messaging log',
     'files': {'*': '/opt/tak/logs/takserver-messaging.log'},
     'warn': 'Can hold callsigns, client addresses and parts of CoT messages. '
             'Tick it only if your Wazuh server is inside your own network.'},
    {'key': 'broker_audit', 'label': 'infra-TAK admin actions (audit log)',
     'files': {'*': '/var/log/takwerx-broker/audit.log'}, 'warn': ''},
)
SOURCE_KEYS = tuple(s['key'] for s in SOURCES)

CARD_WARNING = ('The Wazuh server you name can read the logs you pick and can reach this '
                'server. Only enter a server you run.')
TRANSPORT_NOTE = ('Events travel on port 1514 with AES and the agent key, not TLS. '
                  'FIPS validation of this channel has not been checked. If the server address '
                  'is on the public internet, send it over a private path (NetBird).')

_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$')
_DNS_RE = re.compile(
    r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
_PW_RE = re.compile(r'^[\x21-\x7e]([\x20-\x7e]{0,126}[\x21-\x7e])?$')
_PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----')
_BUSY = threading.Lock()


# ── pure helpers ─────────────────────────────────────────────────────────────────

def valid_server(v):
    """A host name or an IP address; the same rule as the broker's."""
    if not isinstance(v, str) or not v or len(v) > 253:
        return False
    try:
        ip = ipaddress.ip_address(v)
        return not (ip.is_unspecified or ip.is_multicast)
    except ValueError:
        pass
    return bool(_DNS_RE.fullmatch(v)) and not v.replace('.', '').isdigit()


def clean_pem(pem):
    """(pem_text, '') for exactly one certificate, rebuilt from its base64 body; else (None, why)."""
    if not isinstance(pem, str) or not pem.strip() or len(pem) > 16384:
        return None, 'Paste the Wazuh server certificate (a PEM block, 16 KB at most).'
    blocks = _PEM_RE.findall(pem)
    if len(blocks) != 1 or pem.count('BEGIN') != 1:
        return None, 'The certificate box must hold exactly one certificate.'
    body = ''.join(blocks[0].split())
    if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', body):
        return None, 'That is not a valid PEM certificate.'
    return ('-----BEGIN CERTIFICATE-----\n' + '\n'.join(body[i:i + 64] for i in range(0, len(body), 64))
            + '\n-----END CERTIFICATE-----\n'), ''


def fingerprint(pem):
    """SHA-256 of the certificate, as AA:BB:CC… (what the operator confirms on the card)."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    h = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(h[i:i + 2] for i in range(0, len(h), 2))


def pkg_name(family, arch):
    """The one pinned file name for this box, or ''."""
    for name in PINS:
        if family == 'debian' and name.endswith(f'_{arch}.deb'):
            return name
    for name in PINS:
        if family == 'rhel' and name.endswith({'amd64': '.x86_64.rpm', 'arm64': '.aarch64.rpm'}.get(arch, '.none')):
            return name
    return ''


def pkg_url(name):
    return (URL_APT if name.endswith('.deb') else URL_YUM) + name


def version_tuple(v):
    """'4.14.11-1' -> (4, 14, 11, 1); anything unreadable -> ()."""
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-(\d+))?', str(v or '').strip())
    return tuple(int(x or 0) for x in m.groups()) if m else ()


def default_agent_name():
    host = re.sub(r'[^A-Za-z0-9._-]', '-', socket.gethostname().split('.')[0]).strip('-._') or 'tak'
    return ('infratak-' + host)[:63]


def deploy_validate(data):
    """(params, error). Everything the card sends is checked here and again by the broker."""
    d = data or {}
    server = (d.get('server') or '').strip()
    if not valid_server(server):
        return None, 'Enter the Wazuh server as a host name or an IP address.'
    name = (d.get('agent_name') or default_agent_name()).strip()
    if not _NAME_RE.fullmatch(name):
        return None, 'The agent name may use letters, digits, dot, dash and underscore (2 to 63 characters).'
    pem, why = clean_pem(d.get('ca_pem'))
    if why:
        return None, why
    pw = d.get('password')
    if not isinstance(pw, str) or not _PW_RE.fullmatch(pw):
        return None, 'Enter the enrollment password from your Wazuh server (1 to 128 printable characters).'
    src = d.get('sources') or []
    if not (isinstance(src, list) and all(isinstance(k, str) and k in SOURCE_KEYS for k in src)
            and len(set(src)) == len(src)):
        return None, 'Pick log sources from the list only.'
    try:
        fp = fingerprint(pem)
    except Exception:
        return None, 'That is not a valid PEM certificate.'
    if (d.get('confirm_fingerprint') or '').strip().upper() != fp:
        return None, ('Run "Check server" and confirm the certificate fingerprint first. '
                      'Nothing was installed or sent.')
    return {'server': server, 'agent_name': name, 'ca_pem': pem, 'password': pw,
            'sources': list(src), 'ca_sha256': fp}, ''


def probe_server(server, pem, port=ENROLL_PORT, timeout=10):
    """C3/C4: open a TLS connection to host:1515 and check it against the pasted certificate and
    the typed address. Sends NO password. Returns a dict with ok, and either the facts to show
    or a plain reason."""
    if not valid_server(server):
        return {'ok': False, 'error': 'Enter the Wazuh server as a host name or an IP address.'}
    clean, why = clean_pem(pem)
    if why:
        return {'ok': False, 'error': why}
    try:
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sctx.check_hostname = True
        sctx.verify_mode = ssl.CERT_REQUIRED
        sctx.load_verify_locations(cadata=clean)
        if hasattr(ssl, 'VERIFY_X509_STRICT'):
            sctx.verify_flags &= ~ssl.VERIFY_X509_STRICT   # Wazuh's own certificates lack some strict-mode fields
        with socket.create_connection((server, port), timeout=timeout) as raw:
            with sctx.wrap_socket(raw, server_hostname=server) as tls:
                leaf = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError:
        return {'ok': False, 'error': (
            f'{server} answered on port {port}, but its certificate is not signed by the one you '
            f'pasted, or its name is not {server}. Nothing was sent. Check the address and the certificate.')}
    except ssl.SSLError:
        return {'ok': False, 'error': f'{server} answered on port {port}, but not as a Wazuh enrollment server (no TLS).'}
    except (socket.timeout, TimeoutError):
        return {'ok': False, 'error': f'{server} did not answer on port {port} within {timeout} seconds. '
                                       'Check the address and that this box may reach it.'}
    except OSError as e:
        return {'ok': False, 'error': f'Could not reach {server} on port {port}: {e.__class__.__name__}.'}
    subj = ', '.join('='.join(x) for rdn in (leaf.get('subject') or ()) for x in rdn)
    h = hashlib.sha256(der).hexdigest().upper()
    return {'ok': True, 'server': server, 'port': port, 'subject': subj[:200],
            'not_after': leaf.get('notAfter', ''),
            'server_cert_sha256': ':'.join(h[i:i + 2] for i in range(0, len(h), 2)),
            'confirm_fingerprint': fingerprint(clean)}


# ── on-box facts (read-only, no root needed) ─────────────────────────────────────

def installed_info(ctx):
    """(installed, version) from the real package, never from the folder (C11)."""
    try:
        if ctx['os_type']() == 'debian':
            r = subprocess.run(['dpkg-query', '-W', '-f', '${db:Status-Abbrev}\t${Version}', 'wazuh-agent'],
                               capture_output=True, text=True, timeout=20)
            st, _, ver = (r.stdout or '').partition('\t')
            return (r.returncode == 0 and st[:2] in ('ii', 'hi')), ver.strip()
        r = subprocess.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', 'wazuh-agent'],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0, (r.stdout or '').strip() if r.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        return False, ''


def unit_active(ctx):
    try:
        r = subprocess.run(['systemctl', 'is-active', UNIT], capture_output=True, text=True, timeout=20)
        return (r.stdout or '').strip() == 'active'
    except (OSError, subprocess.SubprocessError):
        return False


def detect(ctx):
    installed, _ver = installed_info(ctx)
    return {'installed': installed, 'running': bool(installed and unit_active(ctx))}


def op(ctx, req, timeout=900):
    """One call to the broker op. Never raises; always a dict with `ok`."""
    try:
        r = ctx['_wazuh_agent_op'](dict(req, op='wazuh_agent'), timeout)
    except Exception as e:      # noqa: BLE001 — the page shows the reason, the journal keeps the type
        return {'ok': False, 'error': f'The broker could not be reached ({e.__class__.__name__}).'}
    return r if isinstance(r, dict) else {'ok': False, 'error': 'The broker gave no answer.'}


def get_version_info(ctx):
    """Shape the console's update sweep reads. Pinned, so a newer Wazuh is never offered until
    Security and the T&E have passed it (C10)."""
    installed, ver = installed_info(ctx)
    cur, tgt = version_tuple(ver), version_tuple(PIN_RELEASE)
    return {'installed': installed, 'version': ver, 'latest': PIN_RELEASE,
            'update_available': bool(installed and cur and cur < tgt)}


def status(ctx):
    """Everything the card shows. `lockdown_ok` is read back from the files by the broker."""
    installed, ver = installed_info(ctx)
    s = (ctx['load_settings']() or {}).get(SETTINGS_KEY) or {}
    out = {'installed': installed, 'version': ver, 'pinned': PIN_RELEASE, 'running': False,
           'enrolled': False, 'connected': False, 'lockdown_ok': None, 'problems': [],
           'update_available': get_version_info(ctx)['update_available'],
           'server': s.get('server', ''), 'agent_name': s.get('agent_name', ''),
           'sources': s.get('sources', []), 'family': ctx['os_type'](),
           'pin_problem': pin_problem(ctx)}
    if not installed:
        return out
    out['running'] = unit_active(ctx)
    v = op(ctx, {'action': 'verify'}, 60)
    if v.get('ok'):
        out['enrolled'] = bool(v.get('enrolled'))
        out['problems'] = list(v.get('problems') or [])
        out['lockdown_ok'] = not out['problems']
        out['connected'] = out['running'] and _connected(v.get('log', ''))
        out['log'] = v.get('log', '')[-2000:]
    return out


def pin_problem(ctx):
    """Why this box cannot install the agent, or ''."""
    fam, arch = ctx['os_type'](), ctx['_host_arch']()
    if not pkg_name(fam, arch):
        return f'There is no checked Wazuh agent package for this server ({fam}, {arch}).'
    return ''


_CONNECTED_RE = re.compile(r'Connected to the server')
_FAIL_RES = (
    (re.compile(r'Invalid password|Wrong password|Incorrect password', re.I),
     'The Wazuh server refused the enrollment password.'),
    (re.compile(r'Duplicate agent name|already exists', re.I),
     'The Wazuh server already has an agent with this name. Pick another agent name.'),
    (re.compile(r'Unable to connect to enrollment service|Could not connect to enrollment', re.I),
     'The agent could not reach the Wazuh enrollment port (1515).'),
    (re.compile(r'verification failed|certificate verify failed|SSL', re.I),
     'The agent did not accept the Wazuh server certificate.'),
)


def _connected(log):
    """Last 'Connected to the server' is newer than the last 'Lost connection' / connect error."""
    last_ok = max((m.start() for m in _CONNECTED_RE.finditer(log or '')), default=-1)
    last_bad = max((m.start() for m in re.finditer(r'Unable to connect to any server|Lost connection', log or '')),
                   default=-1)
    return last_ok > last_bad


def _why_not(log):
    for rx, msg in _FAIL_RES:
        if rx.search(log or ''):
            return msg
    return 'The agent did not report a connection to the server in time.'


# ── download and install ─────────────────────────────────────────────────────────

def _dl_dir(ctx):
    d = os.path.join(ctx['CONFIG_DIR'], 'wazuh')
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def download(ctx, name, plog, opener=None):
    """Fetch the pinned file over HTTPS into the console's own folder and check its SHA-256."""
    if name not in PINS:
        raise RuntimeError('That is not a pinned Wazuh file.')
    dest = os.path.join(_dl_dir(ctx), name)
    want = PINS[name]
    if os.path.isfile(dest):
        try:
            with open(dest, 'rb') as f:
                if hashlib.sha256(f.read(MAX_PKG_BYTES + 1)).hexdigest() == want:
                    plog('✓ The checked package file is already here')
                    return dest
        except OSError:
            pass
    url = pkg_url(name)
    plog(f'Downloading {name} …')
    tmp = dest + '.part'
    h = hashlib.sha256()
    n = 0
    req = urllib.request.Request(url, headers={'User-Agent': 'infra-TAK'})
    with (opener or urllib.request.urlopen)(req, timeout=60) as r, open(tmp, 'wb') as f:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            n += len(b)
            if n > MAX_PKG_BYTES:
                raise RuntimeError('The download is larger than any Wazuh agent package. Stopped.')
            h.update(b)
            f.write(b)
    if h.hexdigest() != want:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise RuntimeError('The downloaded file does not match the checked SHA-256. It was deleted and '
                           'nothing was installed.')
    os.replace(tmp, dest)
    os.chmod(dest, 0o640)
    plog('✓ SHA-256 matches the pinned value')
    return dest


def _need_ok(r, what):
    if not r.get('ok'):
        raise RuntimeError(f"{what}: {r.get('error') or 'refused'}")
    return r


def _audit(ctx, event, detail=''):
    try:
        ctx['audit'](event, detail)
    except Exception:    # noqa: BLE001 — audit must never break the action
        pass


def _wait_connected(ctx, plog, seconds=120):
    """Poll the broker until the agent has enrolled and says it is connected. (ok, why)."""
    end = time.time() + seconds
    last = {}
    while time.time() < end:
        last = op(ctx, {'action': 'verify'}, 60)
        if last.get('ok') and last.get('enrolled') and _connected(last.get('log', '')):
            return True, ''
        time.sleep(4)
    return False, _why_not(last.get('log', ''))


def _enroll(ctx, params, plog):
    """configure, start, wait, then delete the password file. Shared by install and 'change server'."""
    plog('Writing the locked-down agent configuration …')
    r = _need_ok(op(ctx, {'action': 'configure', 'server': params['server'], 'agent_name': params['agent_name'],
                          'sources': params['sources'], 'ca_pem': params['ca_pem'],
                          'password': params['password']}, 120), 'Configuration')
    plog('✓ Lock-down intact (active response off, remote commands off, remote config off, '
         'server certificate required)')
    _need_ok(op(ctx, {'action': 'service', 'verb': 'enable'}, 90), 'Enable at boot')
    _need_ok(op(ctx, {'action': 'service', 'verb': 'restart'}, 90), 'Start')
    plog('Waiting for the agent to enroll and connect (up to 2 minutes) …')
    ok, why = _wait_connected(ctx, plog)
    op(ctx, {'action': 'drop_password'}, 30)       # the password is never kept, success or not
    if not ok:
        raise RuntimeError(why + ' The agent is installed but not connected. Use "Change server" to try again, '
                                  'or uninstall.')
    plog('✓ Enrolled and connected. The enrollment password file was deleted.')
    s = ctx['load_settings']()
    s[SETTINGS_KEY] = {'server': params['server'], 'agent_name': params['agent_name'],
                       'sources': params['sources'], 'ca_sha256': params['ca_sha256'],
                       'version': installed_info(ctx)[1] or PIN_RELEASE,
                       'enrolled_at': int(time.time())}
    ctx['save_settings'](s)
    return r


def deploy(ctx, job, params):
    plog = lambda m: job_log(KEY, m)   # noqa: E731
    problem = pin_problem(ctx)
    if problem:
        raise RuntimeError(problem)
    fam, arch = ctx['os_type'](), ctx['_host_arch']()
    name = pkg_name(fam, arch)
    plog(f'Wazuh agent {PIN_VERSION} for {fam} / {arch}')
    path = download(ctx, name, plog)
    plog('Installing the checked package (no Wazuh repository is added to this server) …')
    _need_ok(op(ctx, {'action': 'install', 'file': path}, 900), 'Install')
    plog('✓ Installed. The agent is stopped until it is configured.')
    _audit(ctx, 'wazuh_install', f'version={PIN_RELEASE} server={params["server"]}')
    try:
        _enroll(ctx, params, plog)
    finally:
        params.pop('password', None)
    _audit(ctx, 'wazuh_enrolled', f'server={params["server"]} sources={",".join(params["sources"]) or "none"}')
    job['complete'] = True


def enroll_job(ctx, job, params):
    plog = lambda m: job_log(KEY, m)   # noqa: E731
    if not installed_info(ctx)[0]:
        raise RuntimeError('The Wazuh agent is not installed.')
    try:
        _enroll(ctx, params, plog)
    finally:
        params.pop('password', None)
    _audit(ctx, 'wazuh_reenrolled', f'server={params["server"]} sources={",".join(params["sources"]) or "none"}')
    job['complete'] = True


def update(ctx, plog=None):
    """Move an infra-TAK-installed agent to the pinned version. Keeps the server, name and sources."""
    plog = plog or (lambda m: job_log(KEY, m))
    info = get_version_info(ctx)
    if not info['installed']:
        return {'success': False, 'error': 'The Wazuh agent is not installed.'}
    if not info['update_available']:
        return {'success': False, 'error': 'The agent is already at the pinned version.'}
    s = (ctx['load_settings']() or {}).get(SETTINGS_KEY) or {}
    if not (s.get('server') and s.get('agent_name')):
        return {'success': False, 'error': 'infra-TAK has no saved server for this agent, so it cannot update it.'}
    name = pkg_name(ctx['os_type'](), ctx['_host_arch']())
    path = download(ctx, name, plog)
    r = op(ctx, {'action': 'install', 'file': path, 'upgrade': True}, 900)
    if not r.get('ok'):
        return {'success': False, 'error': f"Update: {r.get('error') or 'refused'}"}
    r = op(ctx, {'action': 'configure', 'server': s['server'], 'agent_name': s['agent_name'],
                 'sources': s.get('sources', [])}, 120)
    if not r.get('ok'):
        return {'success': False, 'error': f"Lock-down after update: {r.get('error') or 'refused'}"}
    op(ctx, {'action': 'service', 'verb': 'restart'}, 90)
    ok, why = _wait_connected(ctx, plog, 90)
    s['version'] = installed_info(ctx)[1]
    st = ctx['load_settings']()
    st[SETTINGS_KEY] = s
    ctx['save_settings'](st)
    _audit(ctx, 'wazuh_update', f'to={PIN_RELEASE} connected={ok}')
    return {'success': ok, **({} if ok else {'error': why})}


def reassert(ctx):
    """C6: on every console start and Update Now, make sure the lock-down is still in place.
    Writes nothing when it is intact (so the agent is never restarted for nothing). Never raises."""
    try:
        installed, _ver = installed_info(ctx)
        s = (ctx['load_settings']() or {}).get(SETTINGS_KEY) or {}
        if not (installed and s.get('server') and s.get('agent_name')):
            return {'acted': False}
        v = op(ctx, {'action': 'verify'}, 60)
        if v.get('ok') and not v.get('problems'):
            return {'acted': False}
        r = op(ctx, {'action': 'configure', 'server': s['server'], 'agent_name': s['agent_name'],
                     'sources': s.get('sources', [])}, 120)
        if r.get('ok') and unit_active(ctx):
            op(ctx, {'action': 'service', 'verb': 'restart'}, 90)
        _audit(ctx, 'wazuh_lockdown_reasserted', 'problems=' + '; '.join((v.get('problems') or [])[:5])[:300])
        return {'acted': True, 'ok': bool(r.get('ok'))}
    except Exception as e:      # noqa: BLE001
        print(f'[wazuh] re-assert skipped: {e.__class__.__name__}', flush=True)
        return {'acted': False}


def uninstall(ctx, job, params):
    steps = []
    r = op(ctx, {'action': 'uninstall'}, 900)
    if not r.get('ok'):
        return {'success': False, 'error': f"Uninstall: {r.get('error') or 'the package or /var/ossec is still there'}"}
    steps.append('Agent stopped and the package purged')
    steps.append('/var/ossec, the unit limits, the server certificate and the password file removed')
    try:
        d = os.path.join(ctx['CONFIG_DIR'], 'wazuh')
        for f in os.listdir(d):
            os.unlink(os.path.join(d, f))
        steps.append('Downloaded package file removed')
    except OSError:
        pass
    s = ctx['load_settings']()
    s.pop(SETTINGS_KEY, None)
    ctx['save_settings'](s)
    _audit(ctx, 'wazuh_uninstall', '')
    return {'success': True, 'steps': steps}


def register(ctx):
    from flask import jsonify, request

    def _busy():
        if job_state(KEY).get('running') or not _BUSY.acquire(blocking=False):
            return jsonify({'success': False, 'error': 'Wazuh is busy: wait for the running action.'}), 409
        return None

    def status_view():
        return jsonify(status(ctx))

    def probe_view():
        d = request.get_json(silent=True) or {}
        return jsonify(probe_server((d.get('server') or '').strip(), d.get('ca_pem')))

    def service_view():
        d = request.get_json(silent=True) or {}
        verb = d.get('verb')
        if verb not in ('start', 'stop', 'restart'):
            return jsonify({'success': False, 'error': 'Unknown action'}), 400
        r = op(ctx, {'action': 'service', 'verb': verb}, 90)
        _audit(ctx, 'wazuh_service', f'verb={verb} ok={bool(r.get("ok"))}')
        return jsonify({'success': bool(r.get('ok')), 'error': r.get('error', '')})

    def enroll_view():
        d = request.get_json(silent=True) or {}
        params, err = deploy_validate(d)
        if err:
            return jsonify({'success': False, 'error': err})
        if not job_start(KEY, 'enroll', enroll_job, (ctx, job_state(KEY), params)):
            return jsonify({'success': False, 'error': 'A Wazuh action is already running.'})
        return jsonify({'success': True})

    def update_view():
        refused = _busy()
        if refused:
            return refused
        try:
            r = update(ctx)
        finally:
            _BUSY.release()
        return jsonify(r), (200 if r.get('success') else 500)

    register_module({
        'key': KEY,
        'name': 'Wazuh agent',
        'description': 'Sends this server\'s security logs to your Wazuh server',
        'icon': '🛡️',
        'route': '/wazuh',
        'template': 'wazuh.html',
        'priority': 15,
        'detect': detect,
        'deploy': deploy,
        'deploy_validate': deploy_validate,
        'uninstall': uninstall,
        'control_map': {},      # no generic control: start/stop go through the broker op's fixed verbs
        'extra_routes': [
            {'url': '/api/wazuh/status', 'methods': ['GET'], 'endpoint': 'wazuh_status', 'view': status_view},
            {'url': '/api/wazuh/probe', 'methods': ['POST'], 'endpoint': 'wazuh_probe', 'view': probe_view},
            {'url': '/api/wazuh/service', 'methods': ['POST'], 'endpoint': 'wazuh_service', 'view': service_view},
            {'url': '/api/wazuh/enroll', 'methods': ['POST'], 'endpoint': 'wazuh_enroll', 'view': enroll_view},
            {'url': '/api/wazuh/update', 'methods': ['POST'], 'endpoint': 'wazuh_update', 'view': update_view},
        ],
        'ports': [],              # nothing inbound: the agent has no listening port (Security, ops #1422)
        'service_units': [UNIT],
        'settings_keys': [SETTINGS_KEY],
    })
