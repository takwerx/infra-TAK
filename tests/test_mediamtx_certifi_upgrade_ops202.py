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
"""The MediaMTX web editor's certifi drops distrusted roots on Update Now (ops #202).

The MediaMTX deploy upgrades certifi, but Update Now deploys nothing, so two Ubuntu 22.04
boxes kept certifi 2026.02.25 in /usr/local, with emSign ECC Root CA - G3, for root's
python3 and the editor's. The broker op `certifi_upgrade` upgrades a pip copy that still
holds a distrusted root, matched by public key, and the console runs it on every start.
"""

import ast
import base64
import hashlib
import importlib.util
import os
import pathlib
import shutil
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

G3_SPKI = '8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782'
G3_PEM = '''# Issuer: CN=emSign ECC Root CA - G3 O=eMudhra Technologies Limited OU=emSign PKI
-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----
'''


def _broker():
    spec = importlib.util.spec_from_file_location('takwerx_broker_ops202_certifi',
                                                  REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _der(pem):
    body = pem.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0]
    return base64.b64decode(''.join(body.split()))


def _openssl_cert(tmp, name, cn, key='ec'):
    """A self-signed PEM from the openssl CLI, and its SPKI sha256 the way the box check
    computes it (`openssl x509 -pubkey | openssl pkey -pubin -outform DER`)."""
    if not shutil.which('openssl'):
        pytest.skip('no openssl CLI')
    k, c = tmp / f'{name}.key', tmp / f'{name}.pem'
    alg = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-384'] if key == 'ec' else ['-newkey', 'rsa:2048']
    subprocess.run(['openssl', 'req', '-x509', '-nodes', *alg, '-keyout', str(k), '-out', str(c),
                    '-days', '1', '-subj', f'/CN={cn}'], check=True, capture_output=True)
    pub = subprocess.run(['openssl', 'x509', '-in', str(c), '-pubkey', '-noout'],
                         check=True, capture_output=True).stdout
    der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pub,
                         check=True, capture_output=True).stdout
    return c.read_text(), hashlib.sha256(der).hexdigest()


# ── key match ───────────────────────────────────────────────────────────────

def test_g3_is_matched_by_its_public_key():
    m = _broker()
    assert m._cert_spki_sha256(_der(G3_PEM)) == G3_SPKI
    assert m.CERTIFI_DISTRUSTED_SPKI[G3_SPKI] == 'emSign ECC Root CA - G3'


@pytest.mark.parametrize('key', ['ec', 'rsa'])
def test_spki_hash_agrees_with_openssl(tmp_path, key):
    pem, want = _openssl_cert(tmp_path, key, 'infratak test', key)
    assert _broker()._cert_spki_sha256(_der(pem)) == want


def test_bundle_match_is_by_key_not_by_name(tmp_path):
    m = _broker()
    impostor, _ = _openssl_cert(tmp_path, 'impostor', 'emSign ECC Root CA - G3')
    clean = tmp_path / 'clean.pem'
    clean.write_text(impostor)
    assert m._bundle_distrusted(str(clean)) == []
    stale = tmp_path / 'stale.pem'
    stale.write_text(impostor + '\n' + G3_PEM)
    assert m._bundle_distrusted(str(stale)) == ['emSign ECC Root CA - G3']
    assert m._bundle_distrusted(str(tmp_path / 'missing.pem')) is None


def test_garbage_does_not_parse_as_a_key():
    m = _broker()
    assert m._cert_spki_sha256(b'') is None
    assert m._cert_spki_sha256(b'\x30\x82\xff\xff\x30') is None
    assert m._cert_spki_sha256(_der(G3_PEM)[:40]) is None


# ── broker op ───────────────────────────────────────────────────────────────

CLEAN = '# a current certifi\n'


class _Box:
    """Root's and the editor user's python3: which certifi each loads, and a pip that
    rewrites that copy clean. Every call must run from / with a fixed env."""

    def __init__(self, tmp, root_copy='stale', user_copy=None, old_pip=False, pip_fails=False,
                 root_where=None):
        self.local = tmp / 'usr' / 'local'
        self.home = tmp / 'home' / 'takwerx'
        self.editor = tmp / 'opt' / 'mediamtx-webeditor'
        self.editor.mkdir(parents=True)
        self.root_path = self.local / 'lib' / 'python3.10' / 'dist-packages' / 'certifi' / 'cacert.pem'
        self.user_path = self.home / '.local' / 'lib' / 'python3.10' / 'site-packages' / 'certifi' / 'cacert.pem'
        self.root_where = root_where
        if root_copy:
            self._write(self.root_path, root_copy)
        if user_copy:
            self._write(self.user_path, user_copy)
        self.old_pip = old_pip
        self.pip_fails = pip_fails
        self.calls = []
        self.pips = []

    @staticmethod
    def _write(path, which):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CLEAN + (G3_PEM if which == 'stale' else ''))

    def install(self, m):
        m.CERTIFI_EDITOR_DIR = str(self.editor)
        m.CERTIFI_PYTHON = '/bin/sh'                        # any root-owned file
        m.CERTIFI_ROOT_PIP_PREFIX = os.path.realpath(self.local) + '/'
        m._sudoers_safe_binaries = lambda name: ['/usr/sbin/runuser'] if name == 'runuser' else []
        m.pwd = types.SimpleNamespace(getpwnam=self._getpwnam)
        m.subprocess = types.SimpleNamespace(run=self.run, TimeoutExpired=subprocess.TimeoutExpired)
        return m

    def _getpwnam(self, user):
        if user != 'takwerx':
            raise KeyError(user)
        return types.SimpleNamespace(pw_dir=str(self.home))

    def run(self, argv, **kw):
        assert kw.get('cwd') == '/' and 'HOME' in kw['env'], kw
        self.calls.append(argv)
        if argv[0] == '/usr/sbin/runuser':
            assert argv[1:4] == ['-u', 'takwerx', '--'], argv
            user, rest = 'takwerx', argv[4:]
            assert kw['env']['HOME'] == str(self.home)
        else:
            user, rest = 'root', argv
        assert rest[0] == '/bin/sh'
        if '-c' in rest:
            assert rest[1] == ('-I' if user == 'root' else '-E'), rest
            where = self._where(user)
            if where is None:
                return types.SimpleNamespace(returncode=1, stdout='', stderr='No module named certifi')
            return types.SimpleNamespace(returncode=0, stdout=where, stderr='')
        assert rest[1:4] == (['-I'] if user == 'root' else ['-E']) + ['-m', 'pip'], rest
        assert rest[4:6] == ['install', '--upgrade'] and 'certifi' in rest
        assert ('--user' in rest) == (user != 'root'), rest
        assert '--only-binary' in rest
        self.pips.append((user, rest))
        if self.old_pip and '--break-system-packages' in rest:
            return types.SimpleNamespace(returncode=2, stdout='',
                                         stderr='no such option: --break-system-packages')
        if self.pip_fails:
            return types.SimpleNamespace(returncode=1, stdout='',
                                         stderr='Could not find a version that satisfies the requirement certifi')
        self._write(self.root_path if user == 'root' else self.user_path, 'clean')
        return types.SimpleNamespace(returncode=0, stdout='Successfully installed certifi-2026.10.23', stderr='')

    def _where(self, user):
        if user == 'root' and self.root_where is not None:
            return self.root_where or None
        if user == 'takwerx' and self.user_path.exists():
            return str(self.user_path)
        return str(self.root_path) if self.root_path.exists() else None


def test_root_copy_upgraded_and_the_editor_sharing_it_is_then_clean(tmp_path):
    box = _Box(tmp_path)
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r['ok'] and r['still_stale'] == []
    assert [(u['user'], u['removed']) for u in r['upgraded']] == [('root', ['emSign ECC Root CA - G3'])]
    assert [u for u, _ in box.pips] == ['root']
    assert 'BEGIN CERTIFICATE' not in box.root_path.read_text()


def test_editor_users_own_copy_upgraded_with_user(tmp_path):
    box = _Box(tmp_path, root_copy='clean', user_copy='stale')
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r['ok'] and [u['user'] for u in r['upgraded']] == ['takwerx']
    assert [u for u, _ in box.pips] == ['takwerx']
    assert 'BEGIN CERTIFICATE' not in box.user_path.read_text()


def test_both_copies_stale_both_upgraded_root_first(tmp_path):
    box = _Box(tmp_path, root_copy='stale', user_copy='stale')
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r['ok'] and [u['user'] for u in r['upgraded']] == ['root', 'takwerx']


def test_clean_box_runs_no_pip(tmp_path):
    box = _Box(tmp_path, root_copy='clean', user_copy='clean')
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r == {'ok': True, 'upgraded': [], 'still_stale': []}
    assert box.pips == []


def test_no_editor_is_a_skip_and_runs_nothing(tmp_path):
    box = _Box(tmp_path)
    m = box.install(_broker())
    m.CERTIFI_EDITOR_DIR = str(tmp_path / 'nope')
    r = m._do_certifi_upgrade({})
    assert r['ok'] and 'not installed' in r['skipped']
    assert box.calls == []


def test_rhel_without_pip_certifi_is_a_no_op(tmp_path):
    box = _Box(tmp_path, root_copy=None)
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r == {'ok': True, 'upgraded': [], 'still_stale': []}
    assert box.pips == []


def test_distro_certifi_handing_out_the_os_bundle_is_left_alone(tmp_path):
    box = _Box(tmp_path, root_where='/etc/ssl/certs/ca-certificates.crt')
    box.root_path.unlink()
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r['ok'] and r['upgraded'] == [] and box.pips == []


def test_stale_copy_pip_does_not_own_is_reported_not_touched(tmp_path):
    distro = tmp_path / 'usr' / 'lib' / 'python3' / 'dist-packages' / 'certifi' / 'cacert.pem'
    _Box._write(distro, 'stale')
    box = _Box(tmp_path, root_copy=None, root_where=str(distro))
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r['ok'] and box.pips == []
    assert [(s['user'], s['path']) for s in r['still_stale']] == [('root', os.path.realpath(distro))]


def test_old_pip_retried_without_break_system_packages(tmp_path):
    box = _Box(tmp_path, old_pip=True)
    r = box.install(_broker())._do_certifi_upgrade({})
    assert r['ok'] and [u['user'] for u in r['upgraded']] == ['root']
    assert ['--break-system-packages' in a for _, a in box.pips] == [True, False]


def test_pip_failure_is_reported_and_left_for_next_start(tmp_path):
    box = _Box(tmp_path, pip_fails=True)
    r = box.install(_broker())._do_certifi_upgrade({})
    assert not r['ok'] and 'root:' in r['error'] and 'satisfies' in r['error']
    assert {s['user'] for s in r['still_stale']} >= {'root'}
    assert r['upgraded'] == []


def test_python_not_root_owned_is_not_run(tmp_path):
    box = _Box(tmp_path)
    m = box.install(_broker())
    fake = tmp_path / 'python3'
    fake.write_text('')
    m.CERTIFI_PYTHON = str(fake)
    if os.getuid() == 0:
        pytest.skip('running as root: every file is root-owned')
    r = m._do_certifi_upgrade({})
    assert r['ok'] and 'root-owned' in r['skipped'] and box.calls == []


def test_no_editor_user_upgrades_root_only(tmp_path):
    box = _Box(tmp_path)
    m = box.install(_broker())
    m.pwd = types.SimpleNamespace(getpwnam=lambda u: (_ for _ in ()).throw(KeyError(u)))
    r = m._do_certifi_upgrade({})
    assert r['ok'] and [u['user'] for u in r['upgraded']] == ['root']
    assert not any(a[0] == '/usr/sbin/runuser' for a in box.calls)


def test_op_takes_no_arguments_and_is_audited(tmp_path):
    m = _broker()
    assert m._evaluate({'op': 'certifi_upgrade'}) == ('ALLOW', '')
    seen = []
    m.audit = lambda peer, op, summary, verdict, detail='': seen.append((op, summary, verdict))
    m._do_certifi_upgrade = lambda req: {'ok': True, 'upgraded': [{'user': 'root'}], 'still_stale': []}
    assert m._dispatch({'op': 'certifi_upgrade'}, None)['upgraded'] == [{'user': 'root'}]
    assert seen == [('certifi_upgrade', m.CERTIFI_EDITOR_DIR, 'ALLOW')]


def test_editor_constants_match_the_service_unit():
    m = _broker()
    assert 'User=takwerx' in APP and m.CERTIFI_EDITOR_USER == 'takwerx'
    assert f'ExecStart={m.CERTIFI_PYTHON} {m.CERTIFI_EDITOR_DIR}/mediamtx_config_editor.py' in APP


# ── console side ────────────────────────────────────────────────────────────

def _fn(name, tree=None):
    for n in (tree or ast.parse(APP)).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    raise AssertionError(f'{name} was renamed or removed')


def _load(name, ns):
    exec(compile(ast.get_source_segment(APP, _fn(name)), 'app.py', 'exec'), ns)
    return ns[name]


def _os(uid, editor=True):
    return types.SimpleNamespace(getuid=lambda: uid,
                                 path=types.SimpleNamespace(isdir=lambda p: editor))


def _ran(seen):
    return types.SimpleNamespace(run=lambda argv, **kw: seen.append(argv) or
                                 types.SimpleNamespace(returncode=0, stdout='', stderr=''))


def test_console_sends_an_argument_free_request_logs_and_restarts_the_editor():
    sent, logs, ran = [], [], []
    ns = {
        'os': _os(1001),
        '_broker_should_route': lambda: True,
        '_broker_available': lambda: True,
        '_broker_request': lambda req, timeout=600: sent.append(req) or {
            'ok': True, 'still_stale': [],
            'upgraded': [{'user': 'root', 'path': '/usr/local/lib/python3.10/dist-packages/certifi/cacert.pem',
                          'removed': ['emSign ECC Root CA - G3']}]},
        'subprocess': _ran(ran),
        '_sudo_wrap': lambda argv: ['BROKER'] + argv,
    }
    _load('_upgrade_mediamtx_certifi', ns)(log_fn=logs.append)
    assert sent == [{'op': 'certifi_upgrade'}]
    assert len(logs) == 1 and 'root' in logs[0] and 'emSign ECC Root CA - G3' in logs[0]
    # requests holds the bundle it loaded at import: the editor restarts, MediaMTX does not
    assert ran == [['BROKER', 'systemctl', 'try-restart', 'mediamtx-webeditor']]


def test_console_without_the_editor_asks_nothing():
    ns = {'os': _os(1001, editor=False),
          '_broker_should_route': lambda: True, '_broker_available': lambda: True,
          '_broker_request': lambda req, timeout=600: pytest.fail('asked the broker')}
    assert _load('_upgrade_mediamtx_certifi', ns)(log_fn=lambda m: None) is None


def test_console_is_quiet_on_a_clean_or_skipped_box():
    for r in ({'ok': True, 'skipped': 'not installed'}, {'ok': True, 'upgraded': [], 'still_stale': []}):
        logs, ran = [], []
        ns = {'os': _os(1001), '_broker_should_route': lambda: True, '_broker_available': lambda: True,
              '_broker_request': lambda req, timeout=600, r=r: r,
              'subprocess': _ran(ran), '_sudo_wrap': lambda argv: argv}
        _load('_upgrade_mediamtx_certifi', ns)(log_fn=logs.append)
        assert logs == [] and ran == []


def test_console_warns_on_failure():
    logs, ran = [], []
    ns = {'os': _os(1001), '_broker_should_route': lambda: True, '_broker_available': lambda: True,
          '_broker_request': lambda req, timeout=600: {'ok': False, 'error': 'root: offline',
                                                       'upgraded': [], 'still_stale': [{'user': 'root'}]},
          'subprocess': _ran(ran), '_sudo_wrap': lambda argv: argv}
    _load('_upgrade_mediamtx_certifi', ns)(log_fn=logs.append)
    assert len(logs) == 1 and 'offline' in logs[0] and 'next restart' in logs[0]
    assert ran == []


def test_root_console_runs_the_broker_function_in_process():
    calls = []
    mod = types.SimpleNamespace(
        _check_certifi_upgrade=lambda req: calls.append(('check', req)),
        _do_certifi_upgrade=lambda req: calls.append(('do', req)) or {'ok': True, 'upgraded': [], 'still_stale': []})
    ns = {'os': _os(0), '_broker_should_route': lambda: False, '_broker_available': lambda: False,
          '_broker_module': lambda: mod}
    _load('_upgrade_mediamtx_certifi', ns)(log_fn=lambda m: None)
    assert calls == [('check', {}), ('do', {})]


def test_startup_runs_it_off_the_boot_path_after_startup_finishes():
    mig = _fn('_startup_migrations')
    nested =[n for n in ast.walk(mig) if isinstance(n, ast.FunctionDef) and n is not mig
              and any(isinstance(c, ast.Call) and getattr(c.func, 'id', '') == '_upgrade_mediamtx_certifi'
                      for c in ast.walk(n))]
    assert len(nested) == 1, 'must run from a background function, not inline at boot'
    src = ast.get_source_segment(APP, nested[0])
    assert '_STARTUP_IMPORT_DONE.wait' in src
    seg = ast.get_source_segment(APP, mig)
    assert f'target={nested[0].name}' in seg and 'daemon=True' in seg
