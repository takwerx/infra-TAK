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
"""Certificate file handling (ops #831).

1. Browse Certificates (the page, the list and the download route) judges CA private material
   by what a file is, not only by its name. Client and server files download as before.
2. A snapshot download is a POST with the console password, like the full-stack backup.
3. The CA key files are for the TAK Server account only: at deploy, Rotate CA, snapshot,
   restore and console start. Client files and the folder keep their modes.

The folder below is laid out like a box that rotated its intermediate twice.
"""

import ast
import hashlib
import io
import os
import pathlib
import re
import shlex
import shutil
import stat
import struct
import subprocess
import tarfile
import threading

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'takserver.html').read_text(encoding='utf-8')
PASSWORD = 'atakatak'
ADMIN_PASSWORD = 'console-password-831'

# Functions this change adds. Where they do not exist, the route tests run the routes as
# they are, so each test still answers for the behaviour it names.
NEW_FUNCS = ('_ca_cert_fact', '_ca_pem_key_pubs', '_ca_der_key_pub', '_ca_p12_key_pubs', '_ca_jks_key_certs',
             '_ca_file_fact', '_ca_key_stem', '_ca_file_stem', '_ca_private_files', '_is_ca_private_file',
             '_ca_private_verdict_or_refuse_all', '_tak_ca_private_lockdown', '_tak_ca_private_lockdown_all')
OLD_FUNCS = ('_is_ca_private_material', '_cert_file_bytes', '_private_key_pubkey', '_send_cert_file_priv',
             '_validate_snapshot_label', '_require_admin_password',
             'list_cert_files', 'download_cert_file', 'certs_page', 'takserver_snapshot_download_api')
NEW_GLOBALS = ('_CA_SCAN_LOCK', '_CA_SCAN_FACTS', '_CA_SCAN_DIRS', '_CA_CERT_EXTS', '_CA_KEYSTORE_EXTS',
               '_CA_NAME_LEFTOVER_RE', '_CA_SCAN_MAX_BYTES', '_CA_PEM_KEY_RE', '_CA_OID_P7_DATA', '_CA_OID_PBE')


def _func(name, required=True):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    if required:
        raise AssertionError(f'{name} was renamed or removed')
    return None


def _assign(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    return None


def _route_decorator(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ' '.join(ast.get_source_segment(APP, d) for d in n.decorator_list)
    raise AssertionError(f'{name} was renamed or removed')


# ── a certificate folder like TAK's ──────────────────────────────────────────────────────────

def _ssl(*args, cwd, **kw):
    return subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True, **kw)


def _legacy_flag(cwd):
    r = subprocess.run(['openssl', 'pkcs12', '-help'], cwd=cwd, capture_output=True, text=True)
    return ['-legacy'] if '-legacy' in (r.stdout + r.stderr) else []


def _plain_key(d, name):
    _ssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', f'{name}.plain', cwd=d)


def _finish_key(d, name, password=PASSWORD):
    """NAME.plain -> NAME.key, encrypted like makeCert.sh does (`genrsa -aes256`)."""
    _ssl('pkey', '-in', f'{name}.plain', '-aes256', '-passout', f'pass:{password}', '-out', f'{name}.key', cwd=d)
    (d / f'{name}.plain').unlink()


def _ca(d, name, issuer=None):
    _plain_key(d, name)
    (d / 'x.ext').write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    if issuer is None:
        _ssl('req', '-x509', '-new', '-key', f'{name}.plain', '-subj', f'/CN={name}', '-days', '30',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-out', f'{name}.pem', cwd=d)
    else:
        _ssl('req', '-new', '-key', f'{name}.plain', '-subj', f'/CN={name}', '-out', 'x.csr', cwd=d)
        _ssl('x509', '-req', '-in', 'x.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.plain',
             '-CAcreateserial', '-days', '30', '-extfile', 'x.ext', '-out', f'{name}.pem', cwd=d)


def _leaf(d, name, issuer, eku='clientAuth', password=PASSWORD):
    _plain_key(d, name)
    (d / 'x.ext').write_text(f'basicConstraints=CA:FALSE\nextendedKeyUsage={eku}\n')
    _ssl('req', '-new', '-key', f'{name}.plain', '-subj', f'/CN={name}', '-out', 'x.csr', cwd=d)
    _ssl('x509', '-req', '-in', 'x.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.plain',
         '-CAcreateserial', '-days', '30', '-extfile', 'x.ext', '-out', f'{name}.pem', cwd=d)
    # makeCert.sh appends the CA to every certificate it makes
    (d / f'{name}.pem').write_bytes((d / f'{name}.pem').read_bytes() + (d / f'{issuer}.pem').read_bytes())


def _p12(d, out, cert, key):
    _ssl('pkcs12', '-export', *_legacy_flag(d), '-in', cert, '-inkey', key,
         '-passout', f'pass:{PASSWORD}', '-out', out, cwd=d)


def _der(d, pem_name):
    return subprocess.run(['openssl', 'x509', '-in', pem_name, '-outform', 'DER'], cwd=d, check=True,
                          capture_output=True).stdout


def _jks(entries):
    """A real JKS file (Java's own format): entries are ('key' | 'cert', alias, [DER certificates])."""
    out = b'\xfe\xed\xfe\xed' + struct.pack('>II', 2, len(entries))
    for kind, alias, chain in entries:
        a = alias.encode()
        out += struct.pack('>I', 1 if kind == 'key' else 2) + struct.pack('>H', len(a)) + a + struct.pack('>Q', 0)
        if kind == 'key':
            out += struct.pack('>I', 16) + b'sealed-key-bytes' + struct.pack('>I', len(chain))
        for c in chain:
            out += struct.pack('>H', 5) + b'X.509' + struct.pack('>I', len(c)) + c
    return out + b'\0' * 20


def _intermediate(d, name):
    """What `makeCert.sh ca NAME` leaves in the folder."""
    _ca(d, name, issuer='root')
    _p12(d, f'{name}-signing.p12', f'{name}.pem', f'{name}.plain')
    (d / f'{name}-signing.jks').write_bytes((d / f'{name}-signing.p12').read_bytes())   # stand-in bytes
    (d / f'{name}-trusted.pem').write_bytes((d / f'{name}.pem').read_bytes())
    (d / f'{name}.crl').write_bytes(b'crl')
    (d / f'truststore-{name}.jks').write_bytes(_jks([('cert', name.lower(), [_der(d, f'{name}.pem')])]))
    _ssl('pkcs12', '-export', '-nokeys', '-in', f'{name}.pem', '-passout', f'pass:{PASSWORD}',
         '-out', f'truststore-{name}.p12', cwd=d)


# CA private material the file names show (what the file-mode step sets)
CA_BY_NAME = ['INTERMEDIATE-CA-01.key', 'INT-CA-02.key',            # <CA name>.key
              'INT-CA-00.key',                                      # its certificate is gone, the .crl is not
              'ca-do-not-share.key', 'root-ca-do-not-share.key',    # the name rule
              'INTERMEDIATE-CA-01-signing.p12', 'INTERMEDIATE-CA-01-signing.jks',
              'INT-CA-02-signing.p12', 'INT-CA-02-signing.jks']
# CA private material only the content shows: copies under any name or extension
CA_BY_CONTENT = ['key-backup.key', 'INT-CA-02.key.bak', 'notes.txt', 'link.txt',   # PEM copies (one a symlink)
                 'cakey.der', 'x.crt',                               # DER copies
                 'old-ca.p12', 'backup.keystore', 'truststore-copy.p12', 'backup.jks',   # PKCS#12 keystores
                 'java.jks']                                         # a real JKS with the CA's key entry
CA_PRIVATE = CA_BY_NAME + CA_BY_CONTENT
ORPHANS = ['stray.key',                                             # belongs to no certificate here
           'otherpass.p12']                                         # a keystore the console cannot open
SERVED = ['admin.key', 'admin.pem', 'admin.p12', 'admin.jks', 'admin.csr', 'admin-trusted.pem',
          'takserver.key', 'takserver.pem', 'takserver.p12', 'takserver-trusted.pem',
          'svc.key', 'svc.pem', 'svc.p12', 'martiuser.key.pk8', 'martiuser.pem',
          'ca.pem', 'ca-trusted.pem', 'ca.crl', 'root-ca.pem', 'INT-CA-02.pem', 'INT-CA-02-trusted.pem',
          'INTERMEDIATE-CA-01.pem', 'truststore-INT-CA-02.p12', 'truststore-INT-CA-02.jks',
          'truststore-root.p12', 'fed-truststore.jks', 'client-java.jks',
          'INT-CA-02.crl', 'crl_index.txt', 'config-takserver.cfg']


@pytest.fixture
def certs(cert_template, tmp_path):
    """A fresh copy per test (modes kept); the keys are made once per session."""
    d = tmp_path / 'files'
    shutil.copytree(cert_template, d, symlinks=True)
    return d


@pytest.fixture(scope='session')
def cert_template(tmp_path_factory):
    d = tmp_path_factory.mktemp('ops831') / 'files'
    d.mkdir()
    _ca(d, 'root')
    for name in ('INTERMEDIATE-CA-01', 'INT-CA-02'):
        _intermediate(d, name)
    _leaf(d, 'admin', 'INT-CA-02')
    _p12(d, 'admin.p12', 'admin.pem', 'admin.plain')
    (d / 'admin.jks').write_bytes((d / 'admin.p12').read_bytes())      # keytool's .jks is PKCS#12 since Java 9
    (d / 'admin.csr').write_bytes(b'-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n')
    _leaf(d, 'takserver', 'INT-CA-02', eku='serverAuth,clientAuth')
    _p12(d, 'takserver.p12', 'takserver.pem', 'takserver.plain')
    _leaf(d, 'svc', 'INT-CA-02')
    _ssl('pkcs12', '-export', '-in', 'svc.pem', '-inkey', 'svc.plain', '-passout', 'pass:another-password',
         '-out', 'svc.p12', cwd=d)
    # makeCert.sh appends ca-trusted.pem to NAME-trusted.pem for EVERY certificate, so a client's
    # NAME-trusted.pem holds the CA's certificate and nothing of the client's.
    for leaf in ('admin', 'takserver', 'svc'):
        (d / f'{leaf}-trusted.pem').write_bytes((d / 'INT-CA-02-trusted.pem').read_bytes())
    (d / 'ca-trusted.pem').write_bytes((d / 'INT-CA-02-trusted.pem').read_bytes())
    (d / 'ca.crl').write_bytes(b'crl')
    (d / 'crl_index.txt').write_text('V\t271116000000Z\t\t01\tunknown\t/CN=admin\n')
    (d / 'config-takserver.cfg').write_text('[ req ]\ndefault_bits = 2048\n')
    _ssl('pkcs12', '-export', '-nokeys', '-in', 'root.pem', '-passout', f'pass:{PASSWORD}',
         '-out', 'truststore-root.p12', cwd=d)
    (d / 'fed-truststore.jks').write_bytes(_jks([('cert', 'root', [_der(d, 'root.pem')])]))
    (d / 'client-java.jks').write_bytes(_jks([('key', 'admin', [_der(d, 'admin.pem'), _der(d, 'INT-CA-02.pem')])]))
    # copies of CA keys under other names, extensions and formats
    (d / 'java.jks').write_bytes(_jks([('cert', 'root', [_der(d, 'root.pem')]),
                                       ('key', 'int-ca-02', [_der(d, 'INT-CA-02.pem'), _der(d, 'root.pem')])]))
    _p12(d, 'backup.keystore', 'INT-CA-02.pem', 'INT-CA-02.plain')
    _p12(d, 'truststore-copy.p12', 'INT-CA-02.pem', 'INT-CA-02.plain')
    _p12(d, 'backup.jks', 'INT-CA-02.pem', 'INT-CA-02.plain')
    _ssl('pkcs12', '-export', '-in', 'INT-CA-02.pem', '-inkey', 'INT-CA-02.plain',
         '-passout', 'pass:another-password', '-out', 'otherpass.p12', cwd=d)
    _ssl('pkcs8', '-topk8', '-nocrypt', '-outform', 'DER', '-in', 'INT-CA-02.plain', '-out', 'cakey.der', cwd=d)
    (d / 'x.crt').write_bytes((d / 'cakey.der').read_bytes())
    _leaf(d, 'martiuser', 'INT-CA-02')
    _ssl('pkcs8', '-topk8', '-nocrypt', '-outform', 'DER', '-in', 'martiuser.plain',
         '-out', 'martiuser.key.pk8', cwd=d)
    (d / 'martiuser.plain').unlink()
    _p12(d, 'old-ca.p12', 'INTERMEDIATE-CA-01.pem', 'INTERMEDIATE-CA-01.plain')
    # a CA whose certificate was removed: only the key and the makeCert.sh leftovers remain
    _plain_key(d, 'INT-CA-00')
    _finish_key(d, 'INT-CA-00')
    (d / 'INT-CA-00.crl').write_bytes(b'crl')
    _plain_key(d, 'stray')
    _finish_key(d, 'stray')
    _finish_key(d, 'svc', password='another-password')      # the console cannot open this one
    for name in ('admin', 'takserver', 'INTERMEDIATE-CA-01', 'INT-CA-02'):
        _finish_key(d, name)
    # makeRootCa.sh / makeCert.sh ca: the working slot and the root's own names
    (d / 'root-ca.pem').write_bytes((d / 'root.pem').read_bytes())
    _ssl('pkey', '-in', 'root.plain', '-aes256', '-passout', f'pass:{PASSWORD}',
         '-out', 'root-ca-do-not-share.key', cwd=d)
    (d / 'ca.pem').write_bytes((d / 'INT-CA-02.pem').read_bytes())
    (d / 'ca-do-not-share.key').write_bytes((d / 'INT-CA-02.key').read_bytes())
    (d / 'key-backup.key').write_bytes((d / 'INT-CA-02.key').read_bytes())
    (d / 'INT-CA-02.key.bak').write_bytes((d / 'INT-CA-02.key').read_bytes())
    (d / 'notes.txt').write_bytes(b'kept for later\n' + (d / 'INT-CA-02.key').read_bytes())
    os.symlink('INT-CA-02.key', d / 'link.txt')
    for junk in ('root.pem', 'root.plain', 'x.ext', 'x.csr', 'root.srl', 'INT-CA-02.srl'):
        (d / junk).unlink(missing_ok=True)
    for f in d.iterdir():                                   # what makeCert.sh leaves: 0644, keys 0600
        if not f.is_symlink():
            os.chmod(f, 0o600 if f.name.endswith('.key') else 0o644)
    for f in CA_PRIVATE + ORPHANS + SERVED:
        assert (d / f).is_file(), f
    return d


class _Harness:
    def __init__(self, certs, tmp_path, container=False):
        self.audits, self.priv, self.rendered, self.priv_reads = [], [], {}, []
        self.snapshots = tmp_path / 'snapshots'
        self.snapshots.mkdir()
        self.container = container
        self.chmod_works = True
        self.tak_uid = None
        werk = pytest.importorskip('werkzeug.security')
        auth = {'password_hash': werk.generate_password_hash(ADMIN_PASSWORD)}

        def _sudo_wrap(cmd):
            cmd = list(cmd)
            self.priv.append(cmd)
            if cmd[0] == 'chown' or (cmd[0] == 'chmod' and not self.chmod_works):
                return ['true']
            if cmd[0] == 'docker':
                # the in-container fallback: run its script on the folder it mounts
                mount = cmd[cmd.index('-v') + 1].split(':')[0]
                return ['sh', '-c', cmd[-1].replace('/mnt/cakeys', shlex.quote(mount))]
            return cmd

        def _read_priv_bytes(path):
            self.priv_reads.append(path)
            return open(path, 'rb').read()

        def _render(_template, **kw):
            self.rendered.update(kw)
            return 'ok'

        self.ns = {
            'os': os, 're': re, 'subprocess': subprocess, 'hashlib': hashlib, 'threading': threading,
            'shlex': shlex, '_stat': stat, 'jsonify': flask.jsonify, 'request': flask.request,
            'render_template': _render, 'VERSION': 'test',
            '_CERT_FILES_DIR': str(certs), 'SNAPSHOT_DIR': str(self.snapshots),
            '_SNAPSHOT_LABEL_RE': re.compile(r'^[A-Za-z0-9._-]+$'),
            'TAK_CONTAINER': 'takserver',
            '_read_priv_bytes': _read_priv_bytes, '_sudo_wrap': _sudo_wrap,
            'load_settings': lambda: {}, '_get_tak_cert_password': lambda s: PASSWORD,
            '_tak_is_container': lambda: self.container,
            '_tak_container_ids': lambda: (str(os.getuid()), str(os.getgid())),
            '_broker_should_route': lambda: False, '_broker_available': lambda: False,
            'load_auth': lambda: auth, 'check_password_hash': werk.check_password_hash,
            'stored_hash_unusable': lambda h: '',
            'audit': lambda ev, detail='', **kw: self.audits.append((ev, detail)),
        }
        for name in NEW_GLOBALS:
            src = _assign(name)
            if src:
                exec(compile(src, 'app.py', 'exec'), self.ns)
        for name in OLD_FUNCS + NEW_FUNCS:
            src = _func(name, required=name in OLD_FUNCS)
            if src:
                exec(compile(src.replace("'/opt/tak/certs/files'", '_CERT_FILES_DIR'), 'app.py', 'exec'), self.ns)
        self.fixed = all(n in self.ns for n in NEW_FUNCS)
        app = flask.Flask('ops831')
        app.add_url_rule('/api/certs/list', view_func=self.ns['list_cert_files'])
        app.add_url_rule('/api/certs/download/<filename>', view_func=self.ns['download_cert_file'])
        app.add_url_rule('/certs', view_func=self.ns['certs_page'])
        app.add_url_rule('/api/takserver/snapshot/<label>/download',
                         view_func=self.ns['takserver_snapshot_download_api'], methods=['GET', 'POST'])
        self.client = app.test_client()

    def lockdown(self, *a, **kw):
        if not self.fixed:
            pytest.fail('_tak_ca_private_lockdown does not exist')
        return self.ns['_tak_ca_private_lockdown'](lambda m: None, *a, **kw)


@pytest.fixture
def h(certs, tmp_path, monkeypatch):
    """Native TAK Server: the files belong to `tak` (here: the user that runs the tests)."""
    import pwd
    real = pwd.getpwnam
    monkeypatch.setattr(pwd, 'getpwnam',
                        lambda n: type('P', (), {'pw_uid': os.getuid()})() if n == 'tak' else real(n))
    return _Harness(certs, tmp_path)


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


# ── Browse Certificates: CA private material is judged by what the file is ───────────────────

def test_the_list_route_leaves_out_every_ca_private_key(h):
    names = {f['name'] for f in h.client.get('/api/certs/list').get_json()['files']}
    assert not names & set(CA_PRIVATE), sorted(names & set(CA_PRIVATE))
    assert not names & set(ORPHANS)
    assert set(SERVED) <= names, sorted(set(SERVED) - names)


def test_the_certificates_page_leaves_out_every_ca_private_key(h):
    assert h.client.get('/certs').status_code == 200
    names = {f['name'] for f in h.rendered['files']}
    assert not names & set(CA_PRIVATE + ORPHANS), sorted(names & set(CA_PRIVATE + ORPHANS))
    assert set(SERVED) <= names


def test_the_download_route_refuses_ca_private_material(h, certs):
    served = []
    for name in CA_PRIVATE + ORPHANS:
        r = h.client.get(f'/api/certs/download/{name}')
        if r.status_code != 403 or (certs / name).read_bytes() in r.data:
            served.append(f'{name}: HTTP {r.status_code}')
        elif ('cert_download_refused', f'file={name}') not in h.audits:
            served.append(f'{name}: refused without an audit line')
    assert not served, served


def test_the_rotated_and_the_current_intermediate_key_are_the_same_secret_as_do_not_share(h, certs):
    """makeCert.sh copies <CA name>.key to ca-do-not-share.key: one key, two names."""
    assert (certs / 'INT-CA-02.key').read_bytes() == (certs / 'ca-do-not-share.key').read_bytes()
    for name in ('INTERMEDIATE-CA-01.key', 'INT-CA-02.key'):
        assert h.client.get(f'/api/certs/download/{name}').status_code == 403


def test_client_and_server_files_still_download(h, certs):
    refused = []
    for name in SERVED:
        r = h.client.get(f'/api/certs/download/{name}')
        if r.status_code != 200 or r.data != (certs / name).read_bytes():
            refused.append(f'{name}: HTTP {r.status_code}')
    assert not refused, refused


def test_a_new_client_is_served_and_a_new_ca_is_refused_without_a_restart(h, certs):
    """The folder is read again when it changes (Rotate CA, a created client)."""
    assert h.client.get('/api/certs/download/admin.key').status_code == 200
    _ca_src = (certs / 'INT-CA-02.key').read_bytes()
    (certs / 'INT-CA-03.key').write_bytes(_ca_src)
    (certs / 'INT-CA-03.crl').write_bytes(b'crl')
    assert h.client.get('/api/certs/download/INT-CA-03.key').status_code == 403
    names = {f['name'] for f in h.client.get('/api/certs/list').get_json()['files']}
    assert 'INT-CA-03.key' not in names and 'admin.key' in names


def test_a_listing_looks_at_the_folder_once(h):
    if not h.fixed:
        pytest.skip('no folder scan on this branch')
    calls = []
    real = h.ns['_ca_private_files']
    h.ns['_ca_private_files'] = lambda *a, **k: calls.append(a) or real(*a, **k)
    h.client.get('/api/certs/list')
    assert len(calls) == 1
    calls.clear()
    h.client.get('/certs')
    assert len(calls) == 1


def test_a_swap_with_the_same_size_and_time_is_seen(h, certs):
    if not h.fixed:
        pytest.skip('no folder scan on this branch')
    st = os.stat(certs / 'admin.key')
    assert h.client.get('/api/certs/download/admin.key').status_code == 200
    ca = (certs / 'INT-CA-02.key').read_bytes()
    (certs / 'admin.key').write_bytes(ca)
    os.utime(certs / 'admin.key', ns=(st.st_atime_ns, st.st_mtime_ns))
    assert h.client.get('/api/certs/download/admin.key').status_code == 403


def test_a_file_that_cannot_be_read_is_held_back_and_asked_again(h, certs):
    if not h.fixed:
        pytest.skip('no folder scan on this branch')
    real = h.ns['_cert_file_bytes']
    broken = {'on': True}

    def flaky(p):
        if broken['on'] and p.endswith('admin.key'):
            raise OSError('broker not up yet')
        return real(p)
    h.ns['_cert_file_bytes'] = flaky
    assert h.client.get('/api/certs/download/admin.key').status_code == 403
    broken['on'] = False
    assert h.client.get('/api/certs/download/admin.key').status_code == 200


def test_the_folder_is_not_read_again_when_nothing_changed(h, monkeypatch):
    if not h.fixed:
        pytest.skip('no folder scan on this branch')
    h.client.get('/api/certs/list')
    calls = []
    real = subprocess.run
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: calls.append(a) or real(*a, **k))
    h.priv_reads.clear()
    h.client.get('/api/certs/list')
    assert h.client.get('/api/certs/download/INT-CA-02.key').status_code == 403
    assert not calls and not h.priv_reads, 'a second look started openssl or read a key again'


def test_a_folder_that_cannot_be_judged_refuses_every_key(h):
    if not h.fixed:
        pytest.skip('no folder scan on this branch')
    def boom(*a, **k):
        raise RuntimeError('scan broke')
    h.ns['_ca_private_files'] = boom
    for name in ('admin.key', 'admin.p12', 'notes.txt', 'ca.pem'):
        assert h.client.get(f'/api/certs/download/{name}').status_code == 403, name
    assert h.client.get('/api/certs/list').get_json()['files'] == []


def test_the_ca_key_itself_is_never_read_to_judge_it(h):
    """A file that is CA material by name is refused on the name; its bytes are not opened."""
    if not h.fixed:
        pytest.skip('no folder scan on this branch')
    seen = []
    real = h.ns['_cert_file_bytes']
    h.ns['_cert_file_bytes'] = lambda p: seen.append(os.path.basename(p)) or real(p)
    h.ns['_CA_SCAN_DIRS'].clear()
    h.ns['_CA_SCAN_FACTS'].clear()
    h.client.get('/api/certs/list')
    for name in ('ca-do-not-share.key', 'root-ca-do-not-share.key', 'INT-CA-02.key', 'INT-CA-02-signing.p12'):
        assert name not in seen, name


# ── a snapshot download asks for the console password ────────────────────────────────────────

@pytest.fixture
def snapshot(h, certs):
    snap = h.snapshots / 'pre-upgrade-1'
    (snap / 'certs').mkdir(parents=True)
    (snap / 'CoreConfig.xml').write_text('<Configuration/>')
    for f in ('ca-do-not-share.key', 'INT-CA-02.key', 'INT-CA-02-signing.jks', 'INT-CA-02.crl', 'admin.key'):
        (snap / 'certs' / f).write_bytes((certs / f).read_bytes())
        os.chmod(snap / 'certs' / f, 0o644)
    return snap


def test_a_snapshot_download_is_a_post(h):
    assert "methods=['POST']" in _route_decorator('takserver_snapshot_download_api')


@pytest.mark.parametrize('form', [{}, {'admin_password': 'wrong'}, {'password': ADMIN_PASSWORD}])
def test_a_snapshot_download_without_the_console_password_is_refused(h, snapshot, form):
    r = h.client.post('/api/takserver/snapshot/pre-upgrade-1/download', data=form)
    assert r.status_code == 403, f'HTTP {r.status_code}: the console password was not asked for'
    assert b'PRIVATE KEY' not in r.data and not r.data.startswith(b'\x1f\x8b')
    assert ('tak_snapshot_download_refused', 'label=pre-upgrade-1') in h.audits


def test_the_password_check_streams_nothing(h, snapshot):
    r = h.client.post('/api/takserver/snapshot/pre-upgrade-1/download',
                      data={'admin_password': ADMIN_PASSWORD, 'check': '1'})
    assert r.status_code == 200 and r.get_json() == {'ok': True}
    r = h.client.post('/api/takserver/snapshot/pre-upgrade-1/download',
                      data={'admin_password': 'wrong', 'check': '1'})
    assert r.status_code == 403


def test_a_snapshot_download_with_the_password_is_still_a_full_backup(h, snapshot):
    """A backup must still restore: the archive keeps the CA keys."""
    r = h.client.post('/api/takserver/snapshot/pre-upgrade-1/download', data={'admin_password': ADMIN_PASSWORD})
    assert r.status_code == 200
    names = tarfile.open(fileobj=io.BytesIO(r.data), mode='r:gz').getnames()
    for f in ('CoreConfig.xml', 'certs/ca-do-not-share.key', 'certs/INT-CA-02-signing.jks', 'certs/admin.key'):
        assert f'pre-upgrade-1/{f}' in names
    assert ('tak_snapshot_download', 'label=pre-upgrade-1') in h.audits


def test_the_download_staging_folder_is_closed_before_the_copy():
    for fn in ('takserver_snapshot_download_api', 'console_stack_backup_download_api'):
        body = _func(fn)
        assert "['chmod', '700', staging]" in body, fn
        assert body.index("['chmod', '700', staging]") < body.index("'cp', '-rp'"), fn


def test_the_page_asks_for_the_password_and_posts():
    assert 'onclick="downloadSnapshot(' in TEMPLATE
    assert not re.search(r'<a href="/api/takserver/snapshot/[^>]*download', TEMPLATE), 'the plain link is back'
    js = TEMPLATE[TEMPLATE.index('function doDownloadSnapshot'):TEMPLATE.index('function deleteSnapshot')]
    assert "f.method='POST'" in js and "i.name='admin_password'" in js
    assert 'check=1&admin_password=' in js
    assert 'id="snap-dl-password" type="password"' in TEMPLATE


# ── file modes: the CA key files are for the TAK Server account only ─────────────────────────

def _signing(certs):
    return [certs / n for n in ('INTERMEDIATE-CA-01-signing.p12', 'INTERMEDIATE-CA-01-signing.jks',
                                'INT-CA-02-signing.p12', 'INT-CA-02-signing.jks')]


def test_the_folder_starts_like_makecert_left_it(certs):
    """The fixture has the modes makeCert.sh gives the signing keystores."""
    for p in _signing(certs):
        assert _mode(p) == 0o644


def test_native_lockdown_closes_the_signing_keystores_and_every_ca_key(h, certs):
    os.chmod(certs / 'INT-CA-00.key', 0o640)
    before = {f.name: _mode(f) for f in certs.iterdir()}
    fixed, left = h.lockdown()
    assert not left
    for p in [certs / n for n in CA_BY_NAME]:
        assert _mode(p) == 0o600, f'{p.name} is {oct(_mode(p))}'
    assert len(fixed) == 5, fixed            # the 4 signing keystores and INT-CA-00.key
    assert ('ca_private_lockdown', f'dir={certs} files=5') in h.audits
    # nothing else moved: Node-RED reads admin.pem/admin.key as uid 1000, the folder stays open
    for f in certs.iterdir():
        if f.name not in CA_BY_NAME:
            assert _mode(f) == before[f.name], f.name
    assert _mode(certs) & 0o055 == 0o055


@pytest.mark.parametrize('name', ['admin.p12', 'admin.jks', 'admin.pem', 'admin-trusted.pem', 'takserver.p12',
                                  'takserver.pem', 'svc.p12', 'truststore-INT-CA-02.jks', 'ca.pem'])
def test_lockdown_leaves_client_and_server_files_alone(h, certs, name):
    """A client's NAME-trusted.pem holds the CA certificate; it must not make NAME a CA name."""
    h.lockdown()
    assert _mode(certs / name) == 0o644


def test_lockdown_opens_no_file(h, certs):
    seen = []
    real = h.ns['_cert_file_bytes']
    h.ns['_cert_file_bytes'] = lambda p: seen.append(p) or real(p)
    h.lockdown()
    assert not seen and not h.priv_reads


def test_lockdown_never_follows_a_symlink(h, certs, tmp_path):
    """Only regular files are changed: a link in the folder is skipped."""
    outside = tmp_path / 'outside'
    outside.write_text('x')
    os.chmod(outside, 0o644)
    os.symlink(outside, certs / 'evil-do-not-share.key')
    os.symlink(outside, certs / 'EVIL-CA-signing.jks')
    fixed, left = h.lockdown()
    assert _mode(outside) == 0o644
    assert not any(str(outside) in c or 'evil' in ' '.join(c).lower() for c in h.priv), h.priv


def test_node_red_keeps_its_read_on_the_admin_pair(h, certs):
    os.chmod(certs / 'admin.key', 0o644)
    h.lockdown()
    assert _mode(certs / 'admin.key') == 0o644 and _mode(certs / 'admin.pem') == 0o644
    assert _mode(certs / 'stray.key') == 0o600      # an unknown key is refused for download, not re-moded


def test_lockdown_is_idempotent_and_quiet_when_clean(h, certs):
    h.lockdown()
    h.priv.clear()
    h.audits.clear()
    assert h.lockdown() == ([], [])
    assert not h.priv, f'a clean folder ran privileged commands: {h.priv}'
    assert not h.audits


def test_lockdown_only_tightens(h, certs):
    os.chmod(certs / 'INT-CA-02-signing.jks', 0o400)
    h.lockdown()
    assert _mode(certs / 'INT-CA-02-signing.jks') == 0o400


def test_native_a_keystore_tak_does_not_own_is_given_to_tak_first(h, certs, monkeypatch):
    """TAK Server (user tak) read such a file through the bits the lockdown removes."""
    import pwd
    real = pwd.getpwnam
    monkeypatch.setattr(pwd, 'getpwnam', lambda n: type('P', (), {'pw_uid': os.getuid() + 1})() if n == 'tak' else real(n))
    fixed, left = h.lockdown()
    path = str(certs / 'INT-CA-02-signing.jks')
    assert ['chown', '-h', 'tak:tak', path] in h.priv
    # the owner change did not take (the test's chown does nothing): the mode is left as it is,
    # so TAK Server keeps its read, and the file is reported
    assert ['chmod', '600', path] not in h.priv
    assert _mode(path) == 0o644 and 'INT-CA-02-signing.jks' in left


def test_container_lockdown_keeps_the_group_the_container_reads_through(certs, tmp_path):
    h = _Harness(certs, tmp_path, container=True)
    os.chmod(certs / 'INT-CA-02-signing.jks', 0o664)        # _container_own_tree: g+rwX
    fixed, left = h.lockdown()
    assert not left
    assert _mode(certs / 'INT-CA-02-signing.jks') == 0o660
    assert _mode(certs / 'INT-CA-02-signing.p12') == 0o640
    assert not any(c[0] == 'chown' for c in h.priv), 'the container owns the file: no owner change'
    assert not any(c[0] == 'docker' for c in h.priv)


def test_container_falls_back_to_the_image_when_the_host_chmod_changes_nothing(certs, tmp_path):
    h = _Harness(certs, tmp_path, container=True)
    h.chmod_works = False
    fixed, left = h.lockdown()
    assert not left, left
    docker = [c for c in h.priv if c[0] == 'docker']
    assert len(docker) == 1 and docker[0][:5] == ['docker', 'run', '--rm', '--user', '0']
    for p in _signing(certs):
        assert _mode(p) & 0o007 == 0, p.name


def test_what_stays_open_is_reported_not_hidden(h, certs):
    h.chmod_works = False
    said = []
    fixed, left = h.ns['_tak_ca_private_lockdown'](said.append) if h.fixed else pytest.fail('no lockdown')
    assert not fixed and 'INT-CA-02-signing.jks' in left
    assert any('could not be set to the TAK Server account only' in m for m in said)


def test_a_snapshot_copy_is_closed_without_reading_a_key_or_changing_an_owner(h, snapshot):
    h.priv_reads.clear()
    fixed, left = h.lockdown(cert_dir=str(snapshot / 'certs'), live=False)
    assert not left
    for f in ('ca-do-not-share.key', 'INT-CA-02.key', 'INT-CA-02-signing.jks'):
        assert _mode(snapshot / 'certs' / f) == 0o600, f
    assert _mode(snapshot / 'certs' / 'admin.key') == 0o644
    assert not h.priv_reads and not any(c[0] == 'chown' for c in h.priv)


def test_the_startup_converge_covers_the_live_folder_and_every_snapshot(h, certs, snapshot):
    if not h.fixed:
        pytest.fail('_tak_ca_private_lockdown_all does not exist')
    (h.snapshots / '.dl-pre-upgrade-1').mkdir()
    fixed, left = h.ns['_tak_ca_private_lockdown_all'](lambda m: None)
    assert not left
    for p in _signing(certs):
        assert _mode(p) == 0o600
    assert _mode(snapshot / 'certs' / 'INT-CA-02-signing.jks') == 0o600


@pytest.mark.parametrize('fn, call', [
    ('run_takserver_deploy', '_tak_ca_private_lockdown('),              # native deploy
    ('_deploy_takserver_container', '_tak_ca_private_lockdown('),       # Docker deploy
    ('takserver_rotate_intca', '_tak_ca_private_lockdown('),            # Rotate Intermediate CA
    ('takserver_rotate_rootca', '_tak_ca_private_lockdown('),           # Rotate Root CA
    ('_tak_rollback', '_tak_ca_private_lockdown('),                     # snapshot restore
    ('_tak_snapshot', 'live=False'),                                    # the snapshot's own copy
    ('takserver_snapshot_upload_api', 'live=False'),                    # an uploaded archive
    ('_startup_migrations', '_tak_ca_private_lockdown_all('),           # existing boxes
])
def test_every_place_that_makes_or_restores_ca_keys_closes_them(fn, call):
    assert call in _func(fn), f'{fn} no longer closes the CA private keys'


def test_rotate_closes_the_new_keystore_right_after_makecert_wrote_it():
    for fn, made in (('takserver_rotate_intca', 'Intermediate CA {new_ca_name} created'),
                     ('takserver_rotate_rootca', 'Intermediate CA {new_int_name} created')):
        body = _func(fn)
        assert 0 < body.index(made) < body.index('_tak_ca_private_lockdown('), fn


def test_the_blanket_chmod_of_the_cert_folder_did_not_come_back():
    """W7 (v10.1.9) tightened every file under /opt/tak/certs and cut Node-RED off fleet-wide."""
    body = _func('_tak_ca_private_lockdown')
    assert "'-R'" not in body and 'chmod -R' not in body
    assert "kind == 'ca'" in body
