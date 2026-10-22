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
"""The integration package and /api/download/truststore hand out the LIVE CA's truststore (ops #170).

Rotate Intermediate CA leaves every earlier truststore-INT-CA-NN.p12 in the cert dir. Both routes
took the first truststore-*.p12 they saw (sorted for the package, raw os.listdir order for the
download), so a box on INT-CA-14 handed out truststore-INT-CA-01.p12. The live one is the
truststore CoreConfig's <security><tls> points at.
"""

import ast
import datetime
import html
import io
import os
import pathlib
import re
import shutil
import subprocess
import zipfile

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
PASSWORD = 'atakatak'
LIVE = 'INT-CA-14'
ROTATED = [f'INT-CA-{n:02d}' for n in range(1, 15)]

FUNCS = ('_is_ca_private_material', '_cert_file_bytes', '_is_client_cert_pem', '_client_cert_pem_or_none',
         '_cert_pubkey', '_private_key_pubkey', '_modern_p12', '_rotate_coreconfig_truststore',
         '_pem_cn_and_expiry', '_is_int_truststore', '_live_truststore',
         'takserver_client_cert_package', 'download_truststore')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _ssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


def _ca(d, name, issuer=None):
    _ssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', f'{name}.key', cwd=d)
    if issuer is None:
        _ssl('req', '-x509', '-new', '-key', f'{name}.key', '-subj', f'/OU=TAK/CN={name}', '-days', '30',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-out', f'{name}.pem', cwd=d)
        return
    (d / 'ca.ext').write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    _ssl('req', '-new', '-key', f'{name}.key', '-subj', f'/OU=TAK/CN={name}', '-out', f'{name}.csr', cwd=d)
    _ssl('x509', '-req', '-in', f'{name}.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.key',
         '-CAcreateserial', '-days', '30', '-extfile', 'ca.ext', '-out', f'{name}.pem', cwd=d)


def _truststore(d, name, *pems):
    (d / 'ts.pem').write_bytes(b''.join((d / p).read_bytes() for p in pems))
    _ssl('pkcs12', '-export', '-nokeys', '-in', 'ts.pem', '-passout', f'pass:{PASSWORD}', '-out', name, cwd=d)


def _coreconfig(truststore):
    return ('<Configuration><network><input _name="stdssl" protocol="tls" port="8089"/></network>'
            '<security><tls keystore="JKS" keystoreFile="certs/files/takserver.jks" keystorePass="atakatak" '
            f'truststore="JKS" truststoreFile="certs/files/{truststore}" truststorePass="atakatak" '
            'context="TLSv1.2" keymanager="SunX509"/></security>'
            '<federation><federation-server port="9000"><tls keystore="JKS" keystoreFile="certs/files/takserver.jks" '
            'truststoreFile="certs/files/fed-truststore.jks" truststorePass="atakatak"/></federation-server>'
            '</federation></Configuration>')


@pytest.fixture(scope='module')
def rotated_template(tmp_path_factory):
    """test8 after 13 Rotate Intermediate CAs: truststore-INT-CA-01..14.p12 all present, the stock
    truststore-root.p12 too, ca.pem and CoreConfig on INT-CA-14."""
    d = tmp_path_factory.mktemp('rotated')
    _ca(d, 'root-ca')
    _truststore(d, 'truststore-root.p12', 'root-ca.pem')
    for name in ROTATED:
        _ca(d, name, issuer='root-ca')
        _truststore(d, f'truststore-{name}.p12', f'{name}.pem', 'root-ca.pem')
    (d / 'ca.pem').write_bytes((d / f'{LIVE}.pem').read_bytes())
    _ssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-aes256',
         '-pass', f'pass:{PASSWORD}', '-out', 'admin.key', cwd=d)
    (d / 'leaf.ext').write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n')
    _ssl('req', '-new', '-key', 'admin.key', '-passin', f'pass:{PASSWORD}', '-subj', '/CN=admin',
         '-out', 'admin.csr', cwd=d)
    _ssl('x509', '-req', '-in', 'admin.csr', '-CA', f'{LIVE}.pem', '-CAkey', f'{LIVE}.key',
         '-CAcreateserial', '-days', '30', '-extfile', 'leaf.ext', '-out', 'admin.pem', cwd=d)
    for f in list(d.iterdir()):
        if f.suffix in ('.csr', '.ext', '.srl') or f.name == 'ts.pem' or (f.suffix == '.key' and f.name != 'admin.key'):
            f.unlink()
    return d


@pytest.fixture
def box(rotated_template, tmp_path):
    """(test client, ns, cert dir, state). state['coreconfig'] is what CoreConfig.xml reads as;
    None makes the read fail like a broker denial."""
    d = tmp_path / 'files'
    shutil.copytree(rotated_template, d)
    state = {'coreconfig': _coreconfig(f'truststore-{LIVE}.jks'), 'sent': []}

    def read_priv(path):
        assert path == '/opt/tak/CoreConfig.xml', path
        if state['coreconfig'] is None:
            raise PermissionError(path)
        return state['coreconfig']

    def send_cert_file_priv(cert_dir, filename):
        state['sent'].append((cert_dir, filename))
        return flask.send_file(io.BytesIO((pathlib.Path(cert_dir) / filename).read_bytes()),
                               as_attachment=True, download_name=filename)

    ns = {'os': os, 're': re, 'html': html, 'subprocess': subprocess, 'datetime': datetime.datetime,
          'jsonify': flask.jsonify, 'request': flask.request, 'VERSION': 'test',
          '_CERT_FILES_DIR': str(d), '_CLIENT_CERT_NAME_RE': re.compile(r'^[A-Za-z0-9._-]{1,64}$'),
          '_NOT_CLIENT_CERT_NAMES': {'takserver', 'ca', 'root-ca'},
          '_read_priv_bytes': lambda p: open(p, 'rb').read(), '_read_priv': read_priv,
          '_send_cert_file_priv': send_cert_file_priv,
          'load_settings': lambda: {'server_ip': '203.0.113.5'},
          '_get_tak_cert_password': lambda s: PASSWORD,
          '_get_takserver_host': lambda s: 'tak.example.com',
          'audit': lambda ev, detail='': None}
    for name in FUNCS:
        src = _func(name).replace("'/opt/tak/certs/files'", '_CERT_FILES_DIR')
        exec(compile(src, 'app.py', 'exec'), ns)
    app = flask.Flask('ops170')
    app.add_url_rule('/api/takserver/client-cert/<name>/package', view_func=ns['takserver_client_cert_package'])
    app.add_url_rule('/api/download/truststore', view_func=ns['download_truststore'])
    return app.test_client(), ns, d, state


def _cns(p12_bytes):
    """Subject CNs of every cert in a truststore .p12."""
    r = subprocess.run(['openssl', 'pkcs12', '-nokeys', '-passin', f'pass:{PASSWORD}'],
                       input=p12_bytes, capture_output=True)
    assert r.returncode == 0, r.stderr
    return sorted(re.findall(rb'^subject=.*?CN\s*=\s*([^,/\n]+)', r.stdout, re.M))


# --- the helper ------------------------------------------------------------------------------

def test_the_live_truststore_is_the_one_coreconfig_points_at(box):
    _c, ns, d, _s = box
    assert ns['_live_truststore'](str(d)) == f'truststore-{LIVE}.p12'


def test_coreconfig_wins_over_ca_pem(box):
    _c, ns, d, state = box
    state['coreconfig'] = _coreconfig('truststore-INT-CA-09.jks')
    assert ns['_live_truststore'](str(d)) == 'truststore-INT-CA-09.p12'


def test_not_the_first_alphabetically_whatever_the_listdir_order(box, monkeypatch):
    _c, ns, d, _s = box
    real = os.listdir
    for order in (sorted, lambda xs: sorted(xs, reverse=True)):
        monkeypatch.setattr(os, 'listdir', lambda p, _o=order: _o(real(p)))
        assert ns['_live_truststore'](str(d)) == f'truststore-{LIVE}.p12'


def test_ca_pem_is_the_fallback_when_coreconfig_cannot_be_read(box):
    _c, ns, d, state = box
    state['coreconfig'] = None
    assert ns['_live_truststore'](str(d)) == f'truststore-{LIVE}.p12'


def test_ca_pem_is_the_fallback_when_coreconfig_names_a_missing_file(box):
    _c, ns, d, state = box
    state['coreconfig'] = _coreconfig('truststore-INT-CA-99.jks')
    assert ns['_live_truststore'](str(d)) == f'truststore-{LIVE}.p12'


def test_stock_root_truststore_in_coreconfig_falls_back_to_ca_pem(box):
    _c, ns, d, state = box
    state['coreconfig'] = _coreconfig('truststore-root.jks')
    assert ns['_live_truststore'](str(d)) == f'truststore-{LIVE}.p12'


def test_the_federation_truststore_is_not_mistaken_for_the_live_one(box):
    _c, ns, d, state = box
    cc = _coreconfig('truststore-INT-CA-03.jks')
    fed = re.search(r'<federation>.*</federation>', cc).group(0)
    state['coreconfig'] = cc.replace(fed, '').replace('<Configuration>', '<Configuration>' + fed)
    assert cc.index('truststore-INT-CA-03') > 0 and state['coreconfig'].index('fed-truststore') < \
        state['coreconfig'].index('truststore-INT-CA-03')
    assert ns['_live_truststore'](str(d)) == 'truststore-INT-CA-03.p12'


def test_several_candidates_and_no_live_ca_is_no_guess(box):
    _c, ns, d, state = box
    state['coreconfig'] = None
    (d / 'ca.pem').unlink()
    assert ns['_live_truststore'](str(d)) == ''


def test_a_single_unrotated_truststore_still_works_without_coreconfig(box):
    _c, ns, d, state = box
    state['coreconfig'] = None
    (d / 'ca.pem').unlink()
    for name in ROTATED[:-1]:
        (d / f'truststore-{name}.p12').unlink()
    assert ns['_live_truststore'](str(d)) == f'truststore-{LIVE}.p12'


# --- the two routes --------------------------------------------------------------------------

def test_the_package_carries_the_live_truststore(box):
    c, _ns, d, _s = box
    r = c.get('/api/takserver/client-cert/admin/package')
    assert r.status_code == 200, r.data[:200]
    z = zipfile.ZipFile(io.BytesIO(r.data))
    trust = [n for n in z.namelist() if n.startswith('truststore-')]
    assert trust == [f'truststore-{LIVE}.p12'], trust
    assert z.read(trust[0]) == (d / f'truststore-{LIVE}.p12').read_bytes()
    assert _cns(z.read(trust[0])) == [LIVE.encode(), b'root-ca']
    assert f'truststore-{LIVE}.p12' in z.read('README.txt').decode()


def test_the_package_leaves_the_truststore_out_rather_than_guess(box):
    c, _ns, d, state = box
    state['coreconfig'] = None
    (d / 'ca.pem').write_bytes((d / 'root-ca.pem').read_bytes())  # ca.pem must stay readable for the chain
    r = c.get('/api/takserver/client-cert/admin/package')
    assert r.status_code == 200, r.data[:200]
    assert not [n for n in zipfile.ZipFile(io.BytesIO(r.data)).namelist() if n.startswith('truststore-')]


def test_the_download_serves_the_live_truststore(box, monkeypatch):
    c, _ns, d, state = box
    real = os.listdir
    monkeypatch.setattr(os, 'listdir', lambda p: sorted(real(p)))  # INT-CA-01 first, as on test8
    r = c.get('/api/download/truststore')
    assert r.status_code == 200
    assert state['sent'] == [(str(d), f'truststore-{LIVE}.p12')]
    assert f'truststore-{LIVE}.p12' in r.headers['Content-Disposition']
    assert _cns(r.data) == [LIVE.encode(), b'root-ca']


def test_the_download_404s_rather_than_guess(box):
    c, _ns, d, state = box
    state['coreconfig'] = None
    (d / 'ca.pem').unlink()
    r = c.get('/api/download/truststore')
    assert r.status_code == 404
    assert state['sent'] == []


def test_neither_route_picks_a_truststore_by_listing_order():
    for name in ('takserver_client_cert_package', 'download_truststore'):
        body = _func(name)
        assert '_live_truststore(' in body, name
        assert "startswith('truststore-')" not in body, f'{name} picks a truststore itself again'
