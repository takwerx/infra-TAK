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
"""CloudTAK recovers from a CA rotation/revoke from the console (v10.3.4, W7–W10).

test6, 2026-11-01: after Revoke Old CA, CloudTAK's own cert and all four user certs were from
the revoked intermediate, so every login failed `UND_ERR_SOCKET: other side closed`. The
documented fix needed a CloudTAK login. Now: certs are judged by the LIVE truststore (W7),
Revoke repairs CloudTAK in the background (W8), one button connects or reconnects it (W9),
and Revoke can see the original intermediate under keytool's `mykey` alias (W10).
"""

import ast
import os
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'cloudtak.html').read_text(encoding='utf-8')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    out = [ast.get_source_segment(APP, n) for n in TREE.body
           if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets)]
    assert len(out) == len(names), names
    return '\n'.join(out)


def _ns(consts=(), funcs=(), **extra):
    ns = {'re': re, 'os': os, 'shlex': __import__('shlex'), 'json': __import__('json')}
    ns.update(extra)
    exec(_consts(*consts) if consts else '', ns)
    for f in funcs:
        exec(_func(f), ns)
    return ns


def _done(rc=0, out='', err=''):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


PEM = '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----'
KEYTOOL_RFC = f"""Keystore type: JKS
Keystore provider: SUN

Your keystore contains 3 entries

Alias name: ca-ps-int-ca-02
Creation date: Nov 1, 2026
Entry type: trustedCertEntry

{PEM % 'INT02'}


*******************************************


Alias name: tak-key
Creation date: Nov 1, 2026
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
{PEM % 'LEAF'}


*******************************************


Alias name: root-ca
Creation date: Nov 1, 2026
Entry type: trustedCertEntry

{PEM % 'ROOT'}
"""


# ── W7: what TAK trusts NOW, not what's on disk ──────────────────────────────────────

def _trust_ns(run, ts='truststore-CA-PS-INT-CA-02.jks', container=False):
    return _ns(funcs=('_tak_live_trust_entries', '_tak_live_trust_bundle'),
               _live_truststore=lambda d, ext: ts, load_settings=lambda: {},
               _get_tak_cert_password=lambda s: 'atakatak', _tak_is_container=lambda: container,
               _sudo_wrap=lambda a: a, TAK_CONTAINER='takserver',
               subprocess=types.SimpleNamespace(run=run))


def test_live_trust_entries_are_the_trusted_certs_of_the_live_truststore():
    seen = []
    ns = _trust_ns(lambda cmd, **k: (seen.append(cmd), _done(0, KEYTOOL_RFC))[1])
    assert ns['_tak_live_trust_entries']() == [('ca-ps-int-ca-02', PEM % 'INT02'), ('root-ca', PEM % 'ROOT')]
    assert seen[0][:3] == ['keytool', '-list', '-rfc'] and seen[0][4].endswith('truststore-CA-PS-INT-CA-02.jks')
    assert ns['_tak_live_trust_bundle']() == PEM % 'INT02' + '\n' + PEM % 'ROOT' + '\n'


def test_container_tak_reads_the_truststore_inside_the_container():
    seen = []
    ns = _trust_ns(lambda cmd, **k: (seen.append(cmd), _done(0, KEYTOOL_RFC))[1], container=True)
    assert ns['_tak_live_trust_entries']()
    assert seen[0][:6] == ['docker', 'exec', 'takserver', 'keytool', '-list', '-rfc']


def test_cant_tell_is_none_never_an_empty_trust_list():
    assert _trust_ns(lambda *a, **k: _done(0, KEYTOOL_RFC), ts='')['_tak_live_trust_entries']() is None
    assert _trust_ns(lambda *a, **k: _done(1, '', 'bad password'))['_tak_live_trust_entries']() is None
    ns = _trust_ns(lambda *a, **k: _done(1))
    assert ns['_tak_live_trust_bundle']() == ''


def test_user_cert_reset_judges_by_the_live_truststore_with_the_disk_as_fallback():
    src = _func('_cloudtak_reset_foreign_profile_certs')
    assert 'bundle = _tak_live_trust_bundle() or _tak_ca_bundle()' in src
    assert 'if not bundle:\n        return None' in src                 # can't tell: reset nothing


# ── W8: Revoke Old CA repairs CloudTAK ───────────────────────────────────────────────

def test_revoke_starts_the_cloudtak_repair_after_tak_and_portal_are_back():
    src = _func('takserver_revoke_old_ca')
    i_portal = src.index('_takportal_sync_certs(restart=True)')
    i_gate = src.index('if _cloudtak_local_with_local_tak():')
    i_thread = src.index('target=_cloudtak_heal_after_ca_change')
    assert i_portal < i_gate < i_thread
    assert 'its users get a new certificate at their next login' in src


def test_heal_after_ca_change_heals_the_connection_then_resets_users():
    calls = []
    ns = _ns(funcs=('_cloudtak_heal_after_ca_change',),
             _cloudtak_tak_cert_heal=lambda log=None: calls.append('heal'),
             _cloudtak_local_with_local_tak=lambda: True,
             _cloudtak_reset_foreign_profile_certs=lambda log=None: calls.append('reset'))
    ns['_cloudtak_heal_after_ca_change'](lambda m: None)
    assert calls == ['heal', 'reset']
    ns['_cloudtak_local_with_local_tak'] = lambda: False
    calls.clear()
    ns['_cloudtak_heal_after_ca_change'](lambda m: None)
    assert calls == ['heal']                       # the heal applies its own gate


def test_update_now_uses_the_same_repair():
    i = APP.index("name='ct-cert-heal')")
    assert 'target=_cloudtak_heal_after_ca_change' in APP[i - 300:i]


# ── W9: Connect CloudTAK to TAK Server ───────────────────────────────────────────────

class _CT:
    """CloudTAK as the connect flow sees it: /api/server, its profile table, the API restart."""

    def __init__(self, status='configured', profiles=(), profiles_readable=True):
        self.srv = {'status': status, 'url': 'ssl://custom.example:8089', 'api': 'https://custom.example:8443',
                    'webtak': 'https://custom.example:8446'} if status == 'configured' else {'status': status}
        self.profiles = list(profiles)
        self.readable = profiles_readable
        self.patches, self.restarts, self.certs, self.resets = [], [], [], []

    def request(self, method, url, payload=None, timeout=25, headers=None):
        assert headers and headers['Authorization'].startswith('Bearer ')
        if method == 'PATCH':
            self.patches.append(payload)
            self.srv['status'] = 'configured'
            return True, 200, dict(self.srv)
        return True, 200, dict(self.srv)

    def postgis(self, sql):
        assert 'select coalesce(json_agg(username)' in sql
        return list(self.profiles) if self.readable else None

    def run(self, cmd, **k):
        self.restarts.append(cmd)
        return _done()


def _connect_ns(ct):
    return _ns(consts=('_CLOUDTAK_USERNAME_RE', 'CLOUDTAK_BOOTSTRAP_CERT_CN'),
               funcs=('_cloudtak_connect_urls', '_cloudtak_connect_tak'),
               jsonify=lambda d: d, _cloudtak_signing_secret=lambda: 'sekrit',
               _cloudtak_admin_token=lambda s: 'jwt', _cloudtak_request_json=ct.request,
               _cloudtak_postgis_json=ct.postgis,
               _local_bootstrap_cert_ensure=lambda s: (ct.certs.append(1), {'success': True, 'admin_flip_ok': True})[1],
               _read_priv_bytes=lambda p: b'p12', _get_tak_cert_password=lambda s: 'atakatak',
               _p12_bytes_to_pem=lambda b, pw: ('CERT', 'KEY'),
               _suggest_tak_core_host=lambda s: 'takserver.test6.example',
               _sudo_wrap=lambda c: c, subprocess=types.SimpleNamespace(run=ct.run),
               _cloudtak_reset_foreign_profile_certs=lambda log=None: (ct.resets.append(1), ['test2bse', 'test1bse'])[1])


def _status(r):
    return r[1] if isinstance(r, tuple) else 200


def test_reconnect_keeps_cloudtaks_own_endpoints_restarts_the_api_and_resets_users():
    ct = _CT('configured')
    r = _connect_ns(ct)['_cloudtak_connect_tak']({}, {})
    assert _status(r) == 200 and r['mode'] == 'reconnected' and r['users_reset'] == 2
    assert ct.patches == [{'url': 'ssl://custom.example:8089', 'api': 'https://custom.example:8443',
                           'webtak': 'https://custom.example:8446', 'auth': {'cert': 'CERT', 'key': 'KEY'}}]
    assert ct.restarts == [['docker', 'restart', 'cloudtak-api-1']] and ct.resets == [1]


def test_first_time_setup_asks_for_the_tak_user_first():
    ct = _CT('unconfigured')
    r = _connect_ns(ct)['_cloudtak_connect_tak']({}, {})
    assert _status(r) == 400 and r[0]['needs_credentials']
    assert ct.certs == [] and ct.patches == []


def test_first_time_setup_sends_the_wizards_payload(capsys):
    ct = _CT('unconfigured', profiles=['someone-else'])
    r = _connect_ns(ct)['_cloudtak_connect_tak']({}, {'username': 'cloudtakadmin-ps', 'password': 'S3cret!pw'})
    assert _status(r) == 200 and r['mode'] == 'configured'
    assert ct.patches == [{'url': 'ssl://takserver.test6.example:8089', 'api': 'https://takserver.test6.example:8443',
                           'webtak': 'https://takserver.test6.example:8446', 'auth': {'cert': 'CERT', 'key': 'KEY'},
                           'username': 'cloudtakadmin-ps', 'password': 'S3cret!pw'}]
    assert ct.restarts == [] and ct.resets == []
    assert 'S3cret!pw' not in capsys.readouterr().out and 'S3cret!pw' not in str(r)


def test_a_leftover_profile_row_is_refused_before_anything_changes():
    ct = _CT('unconfigured', profiles=['CloudTAKAdmin-PS'])
    r = _connect_ns(ct)['_cloudtak_connect_tak']({}, {'username': 'cloudtakadmin-ps', 'password': 'x'})
    assert _status(r) == 409 and 'already has a user named' in r[0]['error']
    assert ct.certs == [] and ct.patches == []


def test_an_unreadable_profile_table_changes_nothing():
    ct = _CT('unconfigured', profiles_readable=False)
    r = _connect_ns(ct)['_cloudtak_connect_tak']({}, {'username': 'cloudtakadmin-ps', 'password': 'x'})
    assert _status(r) == 502 and ct.certs == [] and ct.patches == []


def test_odd_usernames_are_refused():
    ct = _CT('unconfigured')
    for bad in ("x' or 1=1 --", 'a b', 'x' * 151):
        r = _connect_ns(ct)['_cloudtak_connect_tak']({}, {'username': bad, 'password': 'x'})
        assert _status(r) == 400, bad
    assert ct.patches == []


def test_the_username_never_enters_sql():
    src = _func('_cloudtak_connect_tak')
    assert "select coalesce(json_agg(username), '[]') from profile\")" in src
    assert 'where username' not in src.lower()


def test_routes_need_a_login_and_remote_cloudtak_is_refused_plainly():
    for path in ("@app.route('/api/cloudtak/connect-tak', methods=['GET'])",
                 "@app.route('/api/cloudtak/connect-tak', methods=['POST'])"):
        i = APP.index(path)
        assert APP[i:i + 200].split('\n')[1] == '@login_required'
    assert 'Not supported on a remote CloudTAK yet' in _func('cloudtak_connect_tak_api')
    assert '_CLOUDTAK_CONNECT_LOCK.acquire(blocking=False)' in _func('cloudtak_connect_tak_api')


def test_the_old_bootstrap_route_and_its_helpers_are_gone():
    assert "'/api/cloudtak/bootstrap-server'" not in APP
    for name in ('cloudtak_bootstrap_server_api', '_cloudtak_bootstrap_preflight', '_cloudtak_api_base_urls',
                 '_ensure_cloudtak_container_connectivity', '_is_ipv4_host'):
        assert f'def {name}(' not in APP, name


def test_page_has_the_button_and_keeps_the_manual_steps_as_fallback():
    assert 'id="ct-connect-btn"' in TEMPLATE and 'onclick="ctConnectTak(this)"' in TEMPLATE
    assert 'id="ct-connect-pass"' in TEMPLATE and 'type="password"' in TEMPLATE
    assert 'Manual Connection (Bootstrap)' in TEMPLATE and 'ctGenBootstrapCert(this)' in TEMPLATE
    js = APP[APP.index("CLOUDTAK_PAGE_JS = r'''"):]
    assert 'window.ctConnectTak = function' in js and "fetch('/api/cloudtak/connect-tak'" in js


# ── W10: Revoke can see the original intermediate ────────────────────────────────────

def _ca_info(entries):
    subjects = {'/opt/tak/certs/files/root-ca.pem': 'CA-PS-ROOT-CA-01', '/opt/tak/certs/files/ca.pem': 'CA-PS-INT-CA-02'}

    def run(cmd, **k):
        if cmd[:2] == ['openssl', 'x509']:
            return _done(0, f'subject=O = PS, CN = {subjects[cmd[-1]]}\nnotAfter=Jan  1 00:00:00 2030 GMT\n')
        return _done(0, ''.join(f'{a}, Nov 1, 2026, trustedCertEntry,\n' for a, _p in entries or []))
    cns = {PEM % 'INT01': 'CA-PS-INT-CA-01', PEM % 'INT02': 'CA-PS-INT-CA-02', PEM % 'ROOT': 'CA-PS-ROOT-CA-01'}
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True, join=os.path.join))
    ns = _ns(funcs=('takserver_ca_info',), os=fake_os, jsonify=lambda d: d, load_settings=lambda: {},
             _get_tak_cert_password=lambda s: 'atakatak', _live_truststore=lambda d, ext: 'truststore-CA-PS-INT-CA-02.jks',
             _tak_is_container=lambda: False, subprocess=types.SimpleNamespace(run=run),
             _tak_live_trust_entries=lambda d: entries, _pem_cn_and_expiry=lambda p: (cns[p], None))
    return ns['takserver_ca_info']()


def test_the_original_intermediate_under_mykey_is_offered_for_revoke():
    info = _ca_info([('mykey', PEM % 'INT01'), ('ca-ps-int-ca-02', PEM % 'INT02'),
                     ('ca-ps-root-ca-01', PEM % 'ROOT'), ('root-ca', PEM % 'ROOT')])
    assert info['old_cas_in_truststore'] == ['mykey']
    assert info['old_ca_names'] == {'mykey': 'CA-PS-INT-CA-01'}


def test_mykey_holding_the_current_intermediate_is_never_offered():
    info = _ca_info([('mykey', PEM % 'INT02'), ('root-ca', PEM % 'ROOT')])
    assert info['old_cas_in_truststore'] == []


def test_unreadable_subjects_fall_back_to_the_alias_rule():
    info = _ca_info(None)
    assert info['old_cas_in_truststore'] == []


# ── Status line: "connected" can still mean nobody can log in ────────────────────────

def _state_ns(srv, user_certs, signed, bundle='B'):
    return _ns(funcs=('_cloudtak_untrusted_user_certs', '_cloudtak_connect_state'),
               _cloudtak_local_with_local_tak=lambda s: True, _cloudtak_signing_secret=lambda: 's',
               _cloudtak_admin_token=lambda s: 'jwt',
               _cloudtak_request_json=lambda *a, **k: (True, 200, srv),
               _cloudtak_postgis_json=lambda sql: user_certs if 'from profile' in sql else '',
               _tak_live_trust_bundle=lambda: bundle, _tak_ca_bundle=lambda: bundle,
               _cert_signed_by=lambda c, b: signed[c])


def test_live_connection_with_revoked_user_certs_is_not_reported_as_fine():
    # test6 2026-11-01: CloudTAK's chain got its own connection through after Revoke while
    # every user cert was refused and logins failed UND_ERR_SOCKET.
    st = _state_ns({'status': 'configured', 'connection_status': 'live'}, ['U1', 'U2', 'U3'],
                   {'U1': False, 'U2': False, 'U3': True})['_cloudtak_connect_state']({})
    assert st['status'] == 'users_untrusted' and '2 user certificate(s)' in st['message']


def test_live_connection_with_trusted_or_unknown_user_certs_is_connected():
    for signed in ({'U1': True}, {'U1': None}):
        st = _state_ns({'status': 'configured', 'connection_status': 'live'}, ['U1'], signed)['_cloudtak_connect_state']({})
        assert st['status'] == 'connected'
    st = _state_ns({'status': 'configured', 'connection_status': 'live'}, ['U1'], {'U1': False},
                   bundle='')['_cloudtak_connect_state']({})
    assert st['status'] == 'connected'          # truststore unreadable: never cry wolf


def test_status_waits_out_the_api_restart_after_a_reconnect():
    js = APP[APP.index("CLOUDTAK_PAGE_JS = r'''"):]
    assert "window.ctLoadConnectState(12);" in js and "d.status === 'unreachable' && (retries || 0) > 0" in js
