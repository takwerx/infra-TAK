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
"""The integration package never hands out a CA private key (ops #169).

The old Rotate CA bug left a CA:FALSE client leaf INT-CA-NN-signing.pem/.key beside TAK's
INT-CA-NN-signing.p12 — the keystore `makeCert.sh ca` writes, holding the intermediate's own
private key. The leaf passed the client-cert test, so the picker listed INT-CA-01..10-signing and
the package zipped INT-CA-10-signing.p12 as "<name>-legacy.p12". On test8 its key hash matched
the live intermediate.
"""

import ast
import datetime
import html
import io
import os
import pathlib
import re
import subprocess
import zipfile

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
PASSWORD = 'atakatak'

FUNCS = ('_is_ca_private_material', '_cert_file_bytes', '_is_client_cert_pem', '_client_cert_pem_or_none',
         '_cert_pubkey', '_private_key_pubkey', '_modern_p12', '_rotate_coreconfig_truststore',
         '_pem_cn_and_expiry', '_is_int_truststore', '_live_truststore', 'takserver_client_certs',
         'takserver_client_cert_package', 'takserver_create_client_cert')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _ssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


def _legacy_flag(cwd):
    """makeCert.sh writes RC2-40 .p12; OpenSSL 3 needs -legacy to write one."""
    r = subprocess.run(['openssl', 'pkcs12', '-help'], cwd=cwd, capture_output=True, text=True)
    return ['-legacy'] if '-legacy' in (r.stdout + r.stderr) else []


def _key(d, name, encrypt=True):
    _ssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', f'{name}.plain.key', cwd=d)
    if encrypt:
        _ssl('pkey', '-in', f'{name}.plain.key', '-aes256', '-passout', f'pass:{PASSWORD}', '-out', f'{name}.key', cwd=d)
    else:
        os.replace(d / f'{name}.plain.key', d / f'{name}.key')
    (d / f'{name}.plain.key').unlink(missing_ok=True)


def _ext(d, name, text):
    (d / f'{name}.ext').write_text(text)
    return f'{name}.ext'


def _ca(d, name, issuer=None):
    _key(d, name, encrypt=False)
    ext = _ext(d, name, 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    if issuer is None:
        _ssl('req', '-x509', '-new', '-key', f'{name}.key', '-subj', f'/CN={name}', '-days', '30',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-out', f'{name}.pem', cwd=d)
    else:
        _ssl('req', '-new', '-key', f'{name}.key', '-subj', f'/CN={name}', '-out', f'{name}.csr', cwd=d)
        _ssl('x509', '-req', '-in', f'{name}.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.key',
             '-CAcreateserial', '-days', '30', '-extfile', ext, '-out', f'{name}.pem', cwd=d)


def _leaf(d, name, issuer):
    _key(d, name)
    ext = _ext(d, name, 'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n')
    _ssl('req', '-new', '-key', f'{name}.key', '-passin', f'pass:{PASSWORD}', '-subj', f'/CN={name}',
         '-out', f'{name}.csr', cwd=d)
    _ssl('x509', '-req', '-in', f'{name}.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.key',
         '-CAcreateserial', '-days', '30', '-extfile', ext, '-out', f'{name}.pem', cwd=d)


def _p12(d, out, cert, key, key_pass=PASSWORD):
    _ssl('pkcs12', '-export', *_legacy_flag(d), '-in', cert, '-inkey', key, '-passin', f'pass:{key_pass}',
         '-passout', f'pass:{PASSWORD}', '-out', out, cwd=d)


@pytest.fixture
def certs(tmp_path):
    """test8's layout: INT-CA-10 is the live intermediate, its signing keystore holds its key,
    and the Rotate CA bug left a client leaf under the keystore's name."""
    d = tmp_path
    _ca(d, 'root-ca')
    _ca(d, 'INT-CA-10', issuer='root-ca')
    (d / 'ca.pem').write_bytes((d / 'INT-CA-10.pem').read_bytes())
    _p12(d, 'INT-CA-10-signing.p12', 'INT-CA-10.pem', 'INT-CA-10.key', key_pass='')
    (d / 'INT-CA-10-do-not-share.key').write_bytes((d / 'INT-CA-10.key').read_bytes())
    _ssl('pkcs12', '-export', '-nokeys', '-in', 'INT-CA-10.pem', '-passout', f'pass:{PASSWORD}',
         '-out', 'truststore-INT-CA-10.p12', cwd=d)
    _leaf(d, 'INT-CA-10-signing', 'INT-CA-10')          # the leftover leaf
    _leaf(d, 'admin', 'INT-CA-10')
    _p12(d, 'admin.p12', 'admin.pem', 'admin.key')
    for f in d.glob('*.ext'):
        f.unlink()
    return d


@pytest.fixture
def client(certs):
    audits = []
    ns = {'os': os, 're': re, 'html': html, 'subprocess': subprocess, 'datetime': datetime.datetime,
          'jsonify': flask.jsonify, 'request': flask.request, 'VERSION': 'test',
          '_CERT_FILES_DIR': str(certs), '_CLIENT_CERT_NAME_RE': re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
          '_NOT_CLIENT_CERT_NAMES': {'takserver', 'ca', 'root-ca'},
          '_read_priv_bytes': lambda p: open(p, 'rb').read(),
          '_read_priv': lambda p: '',
          'load_settings': lambda: {'server_ip': '203.0.113.5'},
          '_get_tak_cert_password': lambda s: PASSWORD,
          '_get_takserver_host': lambda s: 'tak.example.com',
          'audit': lambda ev, detail='': audits.append((ev, detail))}
    for name in FUNCS:
        src = _func(name).replace("'/opt/tak/certs/files'", '_CERT_FILES_DIR')
        exec(compile(src, 'app.py', 'exec'), ns)
    app = flask.Flask('ops169')
    app.add_url_rule('/api/takserver/client-certs', view_func=ns['takserver_client_certs'])
    app.add_url_rule('/api/takserver/client-cert/<name>/package', view_func=ns['takserver_client_cert_package'])
    app.add_url_rule('/api/takserver/create-client-cert', view_func=ns['takserver_create_client_cert'],
                     methods=['POST'])
    return app.test_client(), audits, certs


def _pub_of_private(pem_bytes):
    return subprocess.run(['openssl', 'pkey', '-pubout'], input=pem_bytes, capture_output=True).stdout.strip()


def _ca_pub(d):
    return subprocess.run(['openssl', 'x509', '-noout', '-pubkey', '-in', str(d / 'INT-CA-10.pem')],
                          capture_output=True).stdout.strip()


def _p12_keys(data):
    """Public keys of every private key in a .p12 from the zip."""
    out = b''
    for extra in ([], ['-legacy']):
        r = subprocess.run(['openssl', 'pkcs12', '-nocerts', '-nodes', '-passin', f'pass:{PASSWORD}', *extra],
                           input=data, capture_output=True)
        if r.returncode == 0:
            out = r.stdout
            break
    blocks = re.findall(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', out, re.S)
    return [_pub_of_private(b) for b in blocks]


def test_the_list_skips_the_leftover_signing_leaf(client):
    c, _a, _d = client
    assert c.get('/api/takserver/client-certs').get_json()['certs'] == ['admin']


def test_the_package_refuses_the_leftover_signing_leaf(client):
    c, _a, _d = client
    r = c.get('/api/takserver/client-cert/INT-CA-10-signing/package')
    assert r.status_code == 404
    assert r.is_json


@pytest.mark.parametrize('name', ['INT-CA-10-do-not-share', 'INT-CA-10', 'root-ca', 'ca', 'truststore-INT-CA-10'])
def test_ca_names_are_never_packaged(client, name):
    c, _a, _d = client
    assert c.get(f'/api/takserver/client-cert/{name}/package').status_code == 404


def test_a_normal_client_package_still_has_every_file(client):
    c, audits, d = client
    r = c.get('/api/takserver/client-cert/admin/package')
    assert r.status_code == 200, r.data[:200]
    z = zipfile.ZipFile(io.BytesIO(r.data))
    names = set(z.namelist())
    assert {'admin.pem', 'admin.key', 'ca-chain.pem', 'README.txt'} <= names
    assert 'admin-legacy.p12' in names, 'the matching makeCert .p12 was dropped'
    admin_pub = subprocess.run(['openssl', 'x509', '-noout', '-pubkey', '-in', str(d / 'admin.pem')],
                               capture_output=True).stdout.strip()
    for fn in names:
        if fn.endswith('.p12') and not fn.startswith('truststore-'):
            assert _p12_keys(z.read(fn)) == [admin_pub], fn
    assert any(ev == 'integration_package' for ev, _ in audits)


def test_no_package_ever_carries_the_ca_key(client):
    c, _a, d = client
    ca_pub = _ca_pub(d)
    for name in c.get('/api/takserver/client-certs').get_json()['certs']:
        z = zipfile.ZipFile(io.BytesIO(c.get(f'/api/takserver/client-cert/{name}/package').data))
        for fn in z.namelist():
            if fn.endswith('.p12'):
                assert ca_pub not in _p12_keys(z.read(fn)), f'{name}: {fn} holds the CA key'


def test_a_p12_holding_a_different_key_is_left_out(client):
    """Defence in depth: even under an ordinary client name, a .p12 whose key is not the leaf's
    key is not zipped."""
    c, audits, d = client
    _p12(d, 'admin.p12', 'INT-CA-10.pem', 'INT-CA-10.key', key_pass='')
    r = c.get('/api/takserver/client-cert/admin/package')
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.data))
    assert 'admin-legacy.p12' not in z.namelist()
    assert ('integration_package_p12_skipped', 'cert=admin reason=key-mismatch') in audits
    for fn in z.namelist():
        if fn.endswith('.p12'):
            assert _ca_pub(d) not in _p12_keys(z.read(fn))


def test_a_key_that_does_not_match_the_cert_refuses_the_package(client):
    c, audits, d = client
    (d / 'admin.key').write_bytes((d / 'INT-CA-10.key').read_bytes())
    r = c.get('/api/takserver/client-cert/admin/package')
    assert r.status_code == 409
    assert ('integration_package_refused', 'cert=admin reason=key-mismatch') in audits


@pytest.mark.parametrize('name', ['INT-CA-11-signing', 'INT-CA-10-signing', 'ca-do-not-share', 'ca',
                                  'root-ca', 'takserver', 'truststore-x', 'INT-CA-10'])
def test_create_refuses_names_that_would_overwrite_ca_files(client, name, monkeypatch):
    c, _a, _d = client
    ran = []
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: ran.append(a) or subprocess.CompletedProcess(a, 1))
    r = c.post('/api/takserver/create-client-cert', json={'name': name})
    assert r.status_code == 400
    assert not ran, 'makeCert.sh ran for a CA name'


def test_the_download_route_still_refuses_signing_material():
    body = _func('download_cert_file')
    assert '_is_ca_private_material(filename)' in body
