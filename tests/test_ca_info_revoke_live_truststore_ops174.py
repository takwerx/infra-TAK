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
import threading
import types

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
PASSWORD = 'atakatak'
LIVE = 'INT-CA-100'
STALE = ['INT-CA-98', 'INT-CA-99']

FUNCS = ('_cert_file_bytes', '_rotate_coreconfig_truststore', '_pem_cn_and_expiry',
         '_is_int_truststore', '_live_truststore', '_tak_live_trust_entries', 'takserver_ca_info',
         '_pem_dn', '_pem_self_signed', '_pem_key', '_rotate_truststore_entries', '_rotate_client_cert_names',
         '_tak_coreconfig_keystore', '_tak_server_cert_mode', '_tak_cert_job_busy',
         '_tak_root_signed_dependents', '_tak_truststore_drop_roots', '_tak_client_truststore_rebuild',
         'takserver_revoke_old_ca')


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
    """root-ca.pem (self-signed), an INT-CA-100 ca.pem and the stale INT-CA-99 the truststore still
    holds, both signed by the root like TAK's own intermediates (v10.3.5 W6 tells a root from an
    intermediate by subject == issuer)."""
    d = tmp_path_factory.mktemp('certs')
    _ssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
         '-keyout', 'root-ca.key', '-subj', '/OU=TAK/CN=root-ca', '-days', '30', '-out', 'root-ca.pem', cwd=d)
    for name in (LIVE, 'INT-CA-99'):
        _ssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
             '-keyout', f'{name}.key', '-subj', f'/OU=TAK/CN={name}', '-out', f'{name}.csr', cwd=d)
        _ssl('x509', '-req', '-in', f'{name}.csr', '-CA', 'root-ca.pem', '-CAkey', 'root-ca.key',
             '-CAcreateserial', '-days', '30', '-out', f'{name}.pem', cwd=d)
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
    state = {'coreconfig': _coreconfig(f'truststore-{LIVE}.jks'), 'keytool': [], 'shell': [], 'server_cert': []}

    def read_priv(path):
        if path == '/opt/tak/CoreConfig.xml':
            if state['coreconfig'] is None:
                raise PermissionError(path)
            return state['coreconfig']
        return open(path).read()   # root-ca.pem / ca.pem in the (temporary) cert dir

    real_run = subprocess.run

    def run(cmd, *a, **kw):
        if isinstance(cmd, list) and cmd and cmd[0] == 'openssl':
            return real_run(cmd, *a, **kw)
        if isinstance(cmd, list) and cmd and cmd[0] == 'keytool':
            state['keytool'].append(cmd)
            if '-rfc' in cmd:     # v10.3.4 W10: entries judged by the cert subject
                out = ''.join(f'Alias name: {a}\nEntry type: trustedCertEntry\n\n'
                              + (certs / f'{n}.pem').read_text() + '\n\n'
                              for a, n in ((LIVE.lower(), LIVE), ('int-ca-99', 'INT-CA-99'), ('root-ca', 'root-ca')))
                return subprocess.CompletedProcess(cmd, 0, out, '')
            out = (f'{LIVE.lower()}, Oct 1, 2026, trustedCertEntry,\n'
                   'int-ca-99, Sep 1, 2026, trustedCertEntry,\n'
                   'root-ca, Jan 1, 2026, trustedCertEntry,\n')
            return subprocess.CompletedProcess(cmd, 0, out, '')
        state['shell'].append(cmd if isinstance(cmd, str) else shlex.join(cmd))
        return subprocess.CompletedProcess(cmd, 0, '', '')

    sp = type('sp', (), {'run': staticmethod(run), 'PIPE': subprocess.PIPE, 'STDOUT': subprocess.STDOUT,
                         'TimeoutExpired': subprocess.TimeoutExpired, 'CompletedProcess': subprocess.CompletedProcess})
    class _Now:   # the revoke job runs on a thread in the app; here it runs to the end inside the request
        def __init__(self, target=None, **kw):
            self.target = target

        def start(self):
            self.target()

    ns = {'os': os, 're': re, 'html': html, 'shlex': shlex, 'subprocess': sp, 'datetime': datetime.datetime,
          'jsonify': flask.jsonify, 'request': flask.request, '_CERT_FILES_DIR': str(d),
          'threading': types.SimpleNamespace(Thread=_Now), 'time': types.SimpleNamespace(sleep=lambda s: None),
          'mod_registry': types.SimpleNamespace(
              _check_admin_password=lambda ctx, data: None if data.get('password') == PASSWORD else 'Invalid admin password'),
          'load_auth': lambda: {}, 'verify_password': lambda h, p: False,
          'login_required': lambda f: f,
          'tak_server_cert_job': {'running': False}, 'rotate_rootca_status': {}, 'rotate_intca_status': {},
          'revoke_ca_status': {'running': False, 'complete': False, 'error': False, 'message': ''},
          'revoke_ca_log': [], '_rotate_sh': lambda argv, timeout=120: (True, run(argv).stdout),
          '_rotate_tak_live_certs_by_issuer': lambda: {},
          '_ca_rotation_state_load': lambda: {}, '_ca_rotation_state_save': lambda st: None,
          '_tak_server_cert_issue': lambda *a, **k: state['server_cert'].append(a[1]) or True,
          'TAK_CONTAINER': 'takserver', '_read_priv_bytes': lambda p: open(p, 'rb').read(),
          '_read_priv': read_priv, 'load_settings': lambda: {}, '_get_tak_cert_password': lambda s: PASSWORD,
          '_tak_is_container': lambda: False, '_rotate_tak_cert_cmd': lambda c: c, '_sudo_wrap': lambda a: a,
          '_tak_server_cert_prepare': lambda s: None, '_takportal_sync_certs': lambda plog=None, restart=False: (True, 'ok'),
          '_cloudtak_local_with_local_tak': lambda: False}
    for name in FUNCS:
        src = _func(name).replace("'/opt/tak/certs/files'", '_CERT_FILES_DIR')
        exec(compile(src, 'app.py', 'exec'), ns)
    app = flask.Flask('ops174')
    app.add_url_rule('/api/takserver/ca-info', view_func=ns['takserver_ca_info'])
    app.add_url_rule('/api/takserver/revoke-old-ca', view_func=ns['takserver_revoke_old_ca'], methods=['POST'])
    state['ns'] = ns
    return app.test_client(), d, state


def _no_coreconfig_no_ca_pem(d, state):
    state['coreconfig'] = None
    (d / 'ca.pem').unlink()


# --- CA-info panel ---------------------------------------------------------------------------

def test_ca_info_lists_the_truststore_coreconfig_points_at(box):
    c, d, state = box
    j = c.get('/api/takserver/ca-info').get_json()
    assert j['truststore_file'] == f'truststore-{LIVE}.jks'
    assert {k[k.index('-keystore') + 1] for k in state['keytool']} == {str(d / f'truststore-{LIVE}.jks')}
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
    r = c.post('/api/takserver/revoke-old-ca', json={'old_ca_alias': 'int-ca-99', 'password': PASSWORD})
    assert r.status_code == 200, r.get_json()
    assert state['ns']['revoke_ca_status']['complete'] and not state['ns']['revoke_ca_status']['error'], \
        state['ns']['revoke_ca_log']
    live = str(d / f'truststore-{LIVE}.jks')
    # the old intermediate, then (v10.3.5 W6) every self-signed root: always from the live truststore
    delete = [s for s in state['shell'] if 'keytool -delete' in s]
    assert len(delete) == 1 and live in delete[0] and '-alias int-ca-99' in delete[0]
    root_delete = [k for k in state['keytool'] if '-delete' in k]
    assert len(root_delete) == 1 and root_delete[0][root_delete[0].index('-alias') + 1] == 'root-ca'
    assert root_delete[0][root_delete[0].index('-keystore') + 1] == live
    assert 'truststore-INT-CA-99' not in ' '.join(state['shell']) + ' '.join(map(' '.join, state['keytool']))
    # the clients' .p12 is rebuilt fresh from the live .jks and moved over the old one
    export = [s for s in state['shell'] if '-importkeystore' in s]
    p12 = str(d / f'truststore-{LIVE}.p12')
    assert len(export) == 1 and f'-srckeystore {live}' in export[0] and f'-destkeystore {p12}.new' in export[0]
    assert any(s.startswith('mv -f ') and s.endswith(p12) for s in state['shell'])


def test_revoke_changes_nothing_when_the_live_truststore_cannot_be_told(box):
    c, d, state = box
    _no_coreconfig_no_ca_pem(d, state)
    r = c.post('/api/takserver/revoke-old-ca', json={'old_ca_alias': 'int-ca-99', 'password': PASSWORD})
    assert r.status_code == 500
    assert 'Nothing was changed' in r.get_json()['error']
    assert state['shell'] == [] and state['keytool'] == []


def test_neither_route_picks_a_truststore_by_name_order():
    for name in ('takserver_ca_info', 'takserver_revoke_old_ca'):
        body = _func(name)
        assert "_live_truststore(cert_dir, '.jks')" in body, name
        assert 'truststore-*' not in body and 'ts_files' not in body, f'{name} picks a truststore itself again'


# --- Revoke Old CA, v10.3.5 W5-W7, W10 (ops #452: these shipped with no test) -------------------

def _revoke(c, alias='int-ca-99', password=PASSWORD):
    return c.post('/api/takserver/revoke-old-ca', json={'old_ca_alias': alias, 'password': password})


def _nothing_ran(state):
    return state['shell'] == [] and not [k for k in state['keytool'] if '-delete' in k] and state['server_cert'] == []


def _server_pem(certs, d, issuer):
    """takserver.pem in the cert dir, signed by `issuer` (root-ca or INT-CA-100: keys are in `certs`)."""
    _ssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'srv.key',
         '-subj', '/CN=takserver', '-out', 'srv.csr', cwd=certs)
    _ssl('x509', '-req', '-in', 'srv.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.key',
         '-CAcreateserial', '-days', '30', '-out', 'srv.pem', cwd=certs)
    (d / 'takserver.pem').write_bytes((certs / 'srv.pem').read_bytes())


def test_revoke_needs_the_console_password_and_changes_nothing_without_it(box):
    c, d, state = box
    for body in ({'old_ca_alias': 'int-ca-99'}, {'old_ca_alias': 'int-ca-99', 'password': 'wrong'}):
        r = c.post('/api/takserver/revoke-old-ca', json=body)
        assert r.status_code == 403 and r.get_json()['need_password'] is True
    assert _nothing_ran(state) and not state['ns']['revoke_ca_status']['running']


def test_revoke_is_refused_while_another_certificate_job_runs(box):
    c, d, state = box
    state['ns']['rotate_intca_status']['running'] = True
    r = _revoke(c)
    assert r.status_code == 409 and 'already running' in r.get_json()['error']
    assert _nothing_ran(state)


def test_revoke_refuses_the_current_intermediate_a_root_and_an_unknown_alias(box):
    c, d, state = box
    r = _revoke(c, LIVE.lower())
    assert r.status_code == 400 and 'current intermediate' in r.get_json()['error']
    r = _revoke(c, 'root-ca')
    assert r.status_code == 400 and 'is a root CA' in r.get_json()['error']
    r = _revoke(c, 'nope')
    assert r.status_code == 400 and 'is not in' in r.get_json()['error']
    assert _nothing_ran(state)


def test_revoke_is_refused_when_a_client_cert_is_signed_by_the_root_itself(box, certs):
    c, d, state = box
    _ssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'bob.key',
         '-subj', '/CN=bob', '-out', 'bob.csr', cwd=certs)
    _ssl('x509', '-req', '-in', 'bob.csr', '-CA', 'root-ca.pem', '-CAkey', 'root-ca.key',
         '-CAcreateserial', '-days', '30', '-out', 'bob.pem', cwd=certs)
    (d / 'bob.pem').write_bytes((certs / 'bob.pem').read_bytes())
    (d / 'bob.p12').write_bytes(b'p12')
    r = _revoke(c)
    assert r.status_code == 409 and 'Signed directly by the root CA: bob' in r.get_json()['error']
    assert 'Nothing was changed' in r.get_json()['error'] and _nothing_ran(state)


def test_revoke_is_refused_when_tak_holds_live_certs_signed_by_the_root(box):
    c, d, state = box
    state['ns']['_rotate_tak_live_certs_by_issuer'] = lambda: {'root-ca': 2}
    r = _revoke(c)
    assert r.status_code == 409 and '2 live client certs' in r.get_json()['error'] and _nothing_ran(state)


def test_8089_cert_is_reissued_only_when_it_chains_through_the_ca_being_revoked(box, certs):
    c, d, state = box
    _server_pem(certs, d, LIVE)                         # signed by the working intermediate: needs a new one
    assert _revoke(c).status_code == 200
    assert state['server_cert'] == ['intermediate']


def test_8089_cert_signed_by_the_root_is_left_alone(box, certs):
    c, d, state = box
    _server_pem(certs, d, 'root-ca')                    # W1: doesn't depend on the CA being revoked
    assert _revoke(c).status_code == 200
    assert state['server_cert'] == []
    assert 'left as it is' in ' '.join(state['ns']['revoke_ca_log'])
    assert 'Server cert is signed by the root CA' in state['ns']['revoke_ca_status']['message']


def test_8089_cert_from_a_custom_keystore_is_left_alone_even_when_the_file_names_differ(box, certs):
    c, d, state = box
    _server_pem(certs, d, LIVE)                         # takserver.pem alone would say "reissue"
    state['coreconfig'] = state['coreconfig'].replace('certs/files/takserver.jks', 'certs/files/takserver-le.jks', 1)
    assert _revoke(c).status_code == 200
    assert state['server_cert'] == []
    assert 'takserver-le.jks (a custom or Let' in ' '.join(state['ns']['revoke_ca_log'])


def test_revoking_the_windows_old_ca_closes_the_window_and_another_does_not(box):
    c, d, state = box
    saved = []
    state['ns']['_ca_rotation_state_load'] = lambda: {'old_ca_cn': 'INT-CA-99', 'rotated_at': 1}
    state['ns']['_ca_rotation_state_save'] = saved.append
    assert _revoke(c).status_code == 200
    assert saved == [{}]                                # no more reminders for a window that is over
    saved.clear()
    state['ns']['revoke_ca_status']['running'] = False
    state['ns']['_ca_rotation_state_load'] = lambda: {'old_ca_cn': 'INT-CA-77', 'rotated_at': 1}
    assert _revoke(c, 'int-ca-99').status_code == 200
    assert saved == []
