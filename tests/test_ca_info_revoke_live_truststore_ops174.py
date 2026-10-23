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
"""The CA-info panel and Revoke Old CA use the LIVE truststore .jks (ops #174).

Both took sorted(glob('truststore-*.jks'))[-1]. That is the live one only while CA names sort in
rotation order: after INT-CA-99 the suggested next name is INT-CA-100, which sorts first, so the
panel listed INT-CA-99's truststore and Revoke Old CA deleted from it. Both now ask
_live_truststore(cert_dir, '.jks'): CoreConfig's <security><tls> truststoreFile, then ca.pem's CN,
and never a guess between several.
"""

import ast
import datetime
import html
import os
import pathlib
import re
import shlex
import subprocess

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
PASSWORD = 'atakatak'
LIVE = 'INT-CA-100'
STALE = ['INT-CA-98', 'INT-CA-99']

FUNCS = ('_cert_file_bytes', '_rotate_coreconfig_truststore', '_pem_cn_and_expiry',
         '_is_int_truststore', '_live_truststore', 'takserver_ca_info', 'takserver_revoke_old_ca')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _ssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


def _coreconfig(truststore):
    return ('<Configuration><security><tls keystore="JKS" keystoreFile="certs/files/takserver.jks" '
            f'keystorePass="atakatak" truststore="JKS" truststoreFile="certs/files/{truststore}" '
            'truststorePass="atakatak" context="TLSv1.2"/></security>'
            '<federation><federation-server port="9000"><tls keystore="JKS" keystoreFile="certs/files/takserver.jks" '
            'truststoreFile="certs/files/fed-truststore.jks" truststorePass="atakatak"/></federation-server>'
            '</federation></Configuration>')


@pytest.fixture(scope='module')
def certs(tmp_path_factory):
    """root-ca.pem and an INT-CA-100 ca.pem, the only real certs the routes read."""
    d = tmp_path_factory.mktemp('certs')
    for name in ('root-ca', LIVE):
        _ssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
             '-keyout', f'{name}.key', '-subj', f'/OU=TAK/CN={name}', '-days', '30', '-out', f'{name}.pem', cwd=d)
    return d


@pytest.fixture
def box(certs, tmp_path):
    """(test client, cert dir, state). The cert dir holds truststore-INT-CA-98/99/100.jks and the
    stock truststore-root.jks; sorted()[-1] is INT-CA-99. keytool and every shell-out are
    recorded, not run."""
    d = tmp_path / 'files'
    d.mkdir()
    (d / 'root-ca.pem').write_bytes((certs / 'root-ca.pem').read_bytes())
    (d / 'ca.pem').write_bytes((certs / f'{LIVE}.pem').read_bytes())
    for name in STALE + [LIVE, 'root']:
        (d / f'truststore-{name}.jks').write_bytes(b'jks')
        (d / f'truststore-{name}.p12').write_bytes(b'p12')
    (d / 'takserver-le.jks').write_bytes(b'le')  # Let's Encrypt: Revoke skips the server-cert re-issue
    assert sorted(f for f in os.listdir(d) if f.endswith('.jks') and 'root' not in f
                  and f.startswith('truststore-'))[-1] == 'truststore-INT-CA-99.jks'
    state = {'coreconfig': _coreconfig(f'truststore-{LIVE}.jks'), 'keytool': [], 'shell': []}

    def read_priv(path):
        assert path == '/opt/tak/CoreConfig.xml', path
        if state['coreconfig'] is None:
            raise PermissionError(path)
        return state['coreconfig']

    real_run = subprocess.run

    def run(cmd, *a, **kw):
        if isinstance(cmd, list) and cmd and cmd[0] == 'openssl':
            return real_run(cmd, *a, **kw)
        if isinstance(cmd, list) and cmd and cmd[0] == 'keytool':
            state['keytool'].append(cmd)
            out = (f'{LIVE.lower()}, Oct 1, 2026, trustedCertEntry,\n'
                   'int-ca-99, Sep 1, 2026, trustedCertEntry,\n'
                   'root-ca, Jan 1, 2026, trustedCertEntry,\n')
            return subprocess.CompletedProcess(cmd, 0, out, '')
        state['shell'].append(cmd if isinstance(cmd, str) else shlex.join(cmd))
        return subprocess.CompletedProcess(cmd, 0, '', '')

    sp = type('sp', (), {'run': staticmethod(run), 'PIPE': subprocess.PIPE, 'STDOUT': subprocess.STDOUT,
                         'TimeoutExpired': subprocess.TimeoutExpired, 'CompletedProcess': subprocess.CompletedProcess})
    ns = {'os': os, 're': re, 'html': html, 'shlex': shlex, 'subprocess': sp, 'datetime': datetime.datetime,
          'jsonify': flask.jsonify, 'request': flask.request, '_CERT_FILES_DIR': str(d),
          'TAK_CONTAINER': 'takserver', '_read_priv_bytes': lambda p: open(p, 'rb').read(),
          '_read_priv': read_priv, 'load_settings': lambda: {}, '_get_tak_cert_password': lambda s: PASSWORD,
          '_tak_is_container': lambda: False, '_rotate_tak_cert_cmd': lambda c: c, '_sudo_wrap': lambda a: a,
          '_tak_server_cert_prepare': lambda s: None, '_takportal_sync_certs': lambda restart=False: None}
    for name in FUNCS:
        src = _func(name).replace("'/opt/tak/certs/files'", '_CERT_FILES_DIR')
        exec(compile(src, 'app.py', 'exec'), ns)
    app = flask.Flask('ops174')
    app.add_url_rule('/api/takserver/ca-info', view_func=ns['takserver_ca_info'])
    app.add_url_rule('/api/takserver/revoke-old-ca', view_func=ns['takserver_revoke_old_ca'], methods=['POST'])
    return app.test_client(), d, state


def _no_coreconfig_no_ca_pem(d, state):
    state['coreconfig'] = None
    (d / 'ca.pem').unlink()


# --- CA-info panel ---------------------------------------------------------------------------

def test_ca_info_lists_the_truststore_coreconfig_points_at(box):
    c, d, state = box
    j = c.get('/api/takserver/ca-info').get_json()
    assert j['truststore_file'] == f'truststore-{LIVE}.jks'
    assert [k[k.index('-keystore') + 1] for k in state['keytool']] == [str(d / f'truststore-{LIVE}.jks')]
    assert j['old_cas_in_truststore'] == ['int-ca-99']


def test_ca_info_falls_back_to_ca_pem(box):
    c, d, state = box
    state['coreconfig'] = None
    assert c.get('/api/takserver/ca-info').get_json()['truststore_file'] == f'truststore-{LIVE}.jks'


def test_ca_info_follows_coreconfig_over_ca_pem(box):
    c, d, state = box
    state['coreconfig'] = _coreconfig('truststore-INT-CA-98.jks')
    assert c.get('/api/takserver/ca-info').get_json()['truststore_file'] == 'truststore-INT-CA-98.jks'


def test_ca_info_shows_no_truststore_and_no_revoke_rather_than_guess(box):
    c, d, state = box
    _no_coreconfig_no_ca_pem(d, state)
    j = c.get('/api/takserver/ca-info').get_json()
    assert 'truststore_file' not in j
    assert j['old_cas_in_truststore'] == []
    assert state['keytool'] == []


# --- Revoke Old CA ---------------------------------------------------------------------------

def test_revoke_deletes_from_the_live_truststore(box):
    c, d, state = box
    r = c.post('/api/takserver/revoke-old-ca', json={'old_ca_alias': 'int-ca-99'})
    assert r.status_code == 200, r.get_json()
    delete = [s for s in state['shell'] if 'keytool -delete' in s]
    assert len(delete) == 1 and str(d / f'truststore-{LIVE}.jks') in delete[0]
    assert 'truststore-INT-CA-99' not in ' '.join(state['shell'])
    export = [s for s in state['shell'] if '-importkeystore' in s]
    assert len(export) == 1 and f'-destkeystore {d / f"truststore-{LIVE}.p12"}' in export[0]


def test_revoke_changes_nothing_when_the_live_truststore_cannot_be_told(box):
    c, d, state = box
    _no_coreconfig_no_ca_pem(d, state)
    r = c.post('/api/takserver/revoke-old-ca', json={'old_ca_alias': 'int-ca-99'})
    assert r.status_code == 500
    assert 'Nothing was changed' in r.get_json()['error']
    assert state['shell'] == [] and state['keytool'] == []


def test_neither_route_picks_a_truststore_by_name_order():
    for name in ('takserver_ca_info', 'takserver_revoke_old_ca'):
        body = _func(name)
        assert "_live_truststore(cert_dir, '.jks')" in body, name
        assert 'truststore-*' not in body and 'ts_files' not in body, f'{name} picks a truststore itself again'
