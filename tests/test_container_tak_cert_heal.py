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
"""Container TAK after an upgrade: certs keep working, CloudTAK keeps logging in (v10.2.8 W11).

aws-arm, 2026-10-08 — CloudTAK login: `UND_ERR_SOCKET: other side closed`; CloudTAK api log:

    not ok - 0 - admin - failed to refresh channels: UND_ERR_SOCKET: other side closed
    [socket] error: ... ssl3_read_bytes:tlsv1 alert internal error ... SSL alert number 80

The 2026-09-22 container upgrade built a new cert tree. Three faults followed:

  W11a/b  the upgrade carried certs/files, CoreConfig and the UAF but not cert-metadata.sh, so
          the new bundle kept the stock `STATE=${STATE}` placeholders and every console makeCert
          failed "Please set the following variables".
  W11c    admin.p12 is root:root 660 on the hardened tree; the non-root console's open() failed.
  W11d    CloudTAK still held a bootstrap cert signed by the OLD CA, which TAK refuses.
"""

import ast
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

HAVE_OPENSSL = shutil.which('openssl') is not None

STOCK_META = '''#!/bin/bash
COUNTRY=US
STATE=${STATE}
CITY=${CITY}
ORGANIZATION=${ORGANIZATION:-TAK}
ORGANIZATIONAL_UNIT=${ORGANIZATIONAL_UNIT}
CAPASS=${CAPASS:-atakatak}
PASS=${PASS:-$CAPASS}
DIR=/opt/tak/certs/files
'''

OLD_META = '''COUNTRY=US
STATE="CA"
CITY=SAC
ORGANIZATION=TAK
ORGANIZATIONAL_UNIT=FIRE
DIR=/opt/tak/certs/files
'''


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    out = []
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets):
            out.append(ast.get_source_segment(APP, n))
    return '\n'.join(out)


def _load(names, ns=None, consts=('_CERT_META_VARS', '_CERT_META_REQUIRED', '_CERT_META_SAFE',
                                  'CLOUDTAK_BOOTSTRAP_CERT_CN')):
    ns = {} if ns is None else ns
    base = {'re': re, 'os': os, 'json': json, 'time': time, 'hmac': hmac, 'hashlib': hashlib,
            'subprocess': subprocess, 'tempfile': tempfile, '_b64': base64, 'shlex': __import__('shlex')}
    for k, v in base.items():
        ns.setdefault(k, v)
    exec(compile(_consts(*consts), 'app.py', 'exec'), ns)
    exec(compile('\n\n'.join(_func(n) for n in names), 'app.py', 'exec'), ns)
    return ns


def _openssl(*args, **kw):
    return subprocess.run(['openssl', *args], capture_output=True, text=True, check=True, **kw)


def _mkca(d, name, subj):
    _openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{d}/{name}.key',
             '-out', f'{d}/{name}.pem', '-days', '2', '-subj', subj)
    return pathlib.Path(f'{d}/{name}.pem').read_text()


def _mkleaf(d, ca, cn='cloudtak-svc-bootstrap'):
    _openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{d}/{cn}.key', '-out', f'{d}/{cn}.csr',
             '-subj', f'/CN={cn}')
    _openssl('x509', '-req', '-in', f'{d}/{cn}.csr', '-CA', f'{d}/{ca}.pem', '-CAkey', f'{d}/{ca}.key',
             '-set_serial', '0x1234', '-out', f'{d}/{cn}-{ca}.pem', '-days', '1')
    return pathlib.Path(f'{d}/{cn}-{ca}.pem').read_text()


# ---------------------------------------------------------------- W11a/b cert-metadata.sh

def test_placeholders_are_not_literals():
    ns = _load(['_cert_metadata_literals'])
    lit = ns['_cert_metadata_literals'](STOCK_META)
    assert lit == {'COUNTRY': 'US'}
    assert ns['_cert_metadata_literals'](OLD_META) == {
        'COUNTRY': 'US', 'STATE': 'CA', 'CITY': 'SAC', 'ORGANIZATION': 'TAK', 'ORGANIZATIONAL_UNIT': 'FIRE'}


def test_fill_only_touches_placeholders_and_never_a_literal():
    ns = _load(['_cert_metadata_literals', '_cert_metadata_fill'])
    new, changed = ns['_cert_metadata_fill'](STOCK_META, {
        'COUNTRY': 'XX', 'STATE': 'CA', 'CITY': 'SAC', 'ORGANIZATION': 'TAK', 'ORGANIZATIONAL_UNIT': 'FIRE'})
    assert 'COUNTRY=US\n' in new, 'a literal value an operator or the deploy set was overwritten'
    assert 'STATE="CA"\n' in new and 'CITY="SAC"\n' in new and 'ORGANIZATIONAL_UNIT="FIRE"\n' in new
    assert set(changed) == {'STATE', 'CITY', 'ORGANIZATION', 'ORGANIZATIONAL_UNIT'}
    assert 'CAPASS=${CAPASS:-atakatak}' in new and 'DIR=/opt/tak/certs/files' in new
    again, changed2 = ns['_cert_metadata_fill'](new, {'STATE': 'NY'})
    assert again == new and changed2 == []


def test_fill_strips_shell_active_characters():
    """makeCert.sh SOURCES cert-metadata.sh — a CA subject must not become shell."""
    ns = _load(['_cert_metadata_literals', '_cert_metadata_fill'])
    new, _ = ns['_cert_metadata_fill'](STOCK_META, {'STATE': 'CA"; rm -rf / #', 'CITY': '$(id)`x`'})
    assert 'STATE="CA rm -rf"\n' in new
    assert 'CITY="idx"\n' in new
    assert ns['_cert_metadata_fill'](STOCK_META, {'STATE': '$;`"'}) == (STOCK_META, [])


@pytest.mark.skipif(not HAVE_OPENSSL, reason='openssl not installed')
def test_ca_subject_values_reads_the_signing_ca(tmp_path):
    ca = _mkca(tmp_path, 'ca', '/C=US/ST=CA/L=SAC/O=TAK/OU=FIRE/CN=INT-CA-01')
    ns = _load(['_ca_subject_values'])
    assert ns['_ca_subject_values'](ca_pem=ca) == {
        'COUNTRY': 'US', 'STATE': 'CA', 'CITY': 'SAC', 'ORGANIZATION': 'TAK', 'ORGANIZATIONAL_UNIT': 'FIRE'}


def _fs_ns(files, container=True):
    """Stubs for the privileged I/O seams over an in-memory file map."""
    log = []

    def _read_priv(p):
        if p not in files:
            raise FileNotFoundError(p)
        return files[p]

    def _write_priv(p, content, *a, **k):
        files[p] = content
    ns = {'_read_priv': _read_priv, '_write_priv': _write_priv,
          '_tak_is_container': lambda: container,
          '_container_readable': lambda p, l=None: log.append(('readable', p)) or True}
    return ns, log


def test_upgrade_carries_old_literal_values_into_the_new_stock_file():
    files = {'/old/tak/certs/cert-metadata.sh': OLD_META, '/new/tak/certs/cert-metadata.sh': STOCK_META}
    ns, log = _fs_ns(files)
    ns['_ca_subject_values'] = lambda **k: pytest.fail('the old file had every value; CA fallback not needed')
    _load(['_cert_metadata_literals', '_cert_metadata_fill', '_carry_cert_metadata'], ns)
    changed = ns['_carry_cert_metadata']('/old/tak', '/new/tak', lambda m: None)
    out = files['/new/tak/certs/cert-metadata.sh']
    assert set(changed) == {'STATE', 'CITY', 'ORGANIZATION', 'ORGANIZATIONAL_UNIT'}
    assert ns['_cert_metadata_literals'](out)['ORGANIZATIONAL_UNIT'] == 'FIRE'
    assert ('readable', '/new/tak/certs/cert-metadata.sh') in log


def test_upgrade_falls_back_to_the_ca_subject_when_the_old_file_was_stock_too():
    """aws-arm's situation one upgrade later: the old tree ALSO held placeholders."""
    files = {'/old/tak/certs/cert-metadata.sh': STOCK_META, '/new/tak/certs/cert-metadata.sh': STOCK_META}
    ns, _ = _fs_ns(files)
    ns['_ca_subject_values'] = lambda **k: {'STATE': 'CA', 'CITY': 'SAC', 'ORGANIZATIONAL_UNIT': 'FIRE',
                                            'COUNTRY': 'ZZ'}
    _load(['_cert_metadata_literals', '_cert_metadata_fill', '_carry_cert_metadata'], ns)
    ns['_carry_cert_metadata']('/old/tak', '/new/tak', lambda m: None)
    lit = ns['_cert_metadata_literals'](files['/new/tak/certs/cert-metadata.sh'])
    assert lit['STATE'] == 'CA' and lit['CITY'] == 'SAC' and lit['ORGANIZATIONAL_UNIT'] == 'FIRE'
    assert lit['COUNTRY'] == 'US', 'the stock literal COUNTRY must win over the CA fallback'


def test_upgrade_carry_runs_before_the_swap_deletes_the_old_tree():
    body = _func('run_takserver_upgrade_container')
    carry = body.index('_carry_cert_metadata(old_tak, new_tak')
    assert body.index("'UserAuthenticationFile.xml'") < carry < body.index("['rm', '-rf', old_ctx]")


def test_heal_fills_placeholders_from_the_ca_and_leaves_a_complete_file_alone():
    files = {'/opt/tak/certs/cert-metadata.sh': STOCK_META}
    ns, log = _fs_ns(files)
    ns['_ca_subject_values'] = lambda: {'STATE': 'CA', 'CITY': 'SAC', 'ORGANIZATIONAL_UNIT': 'FIRE'}
    _load(['_cert_metadata_literals', '_cert_metadata_fill', '_heal_cert_metadata_placeholders'], ns)
    assert ns['_heal_cert_metadata_placeholders'](lambda m: None) is True
    assert ('readable', '/opt/tak/certs/cert-metadata.sh') in log
    healed = files['/opt/tak/certs/cert-metadata.sh']
    assert ns['_heal_cert_metadata_placeholders'](lambda m: None) is False
    assert files['/opt/tak/certs/cert-metadata.sh'] == healed


def test_heal_never_writes_when_the_ca_cannot_be_read():
    files = {'/opt/tak/certs/cert-metadata.sh': STOCK_META}
    ns, _ = _fs_ns(files)

    def boom():
        raise PermissionError('ca.pem')
    ns['_ca_subject_values'] = boom
    _load(['_cert_metadata_literals', '_cert_metadata_fill', '_heal_cert_metadata_placeholders'], ns)
    assert ns['_heal_cert_metadata_placeholders'](lambda m: None) is None
    assert files['/opt/tak/certs/cert-metadata.sh'] == STOCK_META


def test_post_update_heals_before_reasserting_mode_and_container_gets_group0_640():
    body = APP[APP.index('def _run_post_update():'):]
    body = body[:body.index('# Fix LDAP outpost AUTHENTIK_HOST')]
    assert body.index('_heal_cert_metadata_placeholders(') < body.index("_container_readable(_cm)")
    assert "if _tak_is_container():" in body and "['chown', 'tak:tak', _cm]" in body
    assert "_cloudtak_tak_cert_heal(" in body and 'daemon=True' in body


def test_makecert_sites_no_longer_chmod_500_on_the_container_path():
    """chmod 500 left the file owner-only: the container (uid 1001) could read it only on a box
    whose console uid happened to be 1001."""
    prep = _func('_cert_metadata_prepare_for_makecert')
    assert '_heal_cert_metadata_placeholders(' in prep and '_container_readable(cm' in prep
    assert APP.count("_run_priv_chain([['chmod', '500', '/opt/tak/certs/cert-metadata.sh']], 'and')") == 0
    assert '_cert_metadata_prepare_for_makecert()' in _func('_local_bootstrap_cert_ensure')
    create = APP[APP.index("def takserver_create_client_cert"):]
    create = create[:create.index('makeCert.sh client {cert_name}')]
    assert '_cert_metadata_prepare_for_makecert()' in create


# ---------------------------------------------------------------- W11c admin.p12 read

def test_read_priv_bytes_returns_raw_bytes_through_the_broker():
    raw = b'\x30\x82\x11\x00\xff\xfe binary p12'
    ns = {'_broker_should_route': lambda: True, '_broker_available': lambda: True,
          '_broker_request': lambda req: {'ok': True, 'content_b64': base64.b64encode(raw).decode()},
          'BrokerError': RuntimeError}
    _load(['_read_priv_bytes'], ns)
    assert ns['_read_priv_bytes']('/opt/tak/certs/files/admin.p12') == raw


def test_admin_p12_falls_back_to_the_privileged_read_on_permission_denied(monkeypatch, tmp_path):
    ns = {'_read_priv_bytes': lambda p: b'P12BYTES'}
    _load(['_load_admin_p12_bytes_from_tak_core'], ns)
    real_open = open

    def denied(path, *a, **k):
        if str(path) == '/opt/tak/certs/files/admin.p12':
            raise PermissionError(13, 'Permission denied')
        return real_open(path, *a, **k)
    ns['open'] = denied
    ns['os'] = types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True))
    data, where, err = ns['_load_admin_p12_bytes_from_tak_core']({})
    assert data == b'P12BYTES' and err == ''


# ---------------------------------------------------------------- W11d CloudTAK's TAK cert

@pytest.mark.skipif(not HAVE_OPENSSL, reason='openssl not installed')
def test_signed_by_is_a_signature_check_not_a_dn_compare(tmp_path):
    subj = '/C=US/ST=CA/L=SAC/O=TAK/OU=FIRE/CN=INT-CA-01'
    ca_new = _mkca(tmp_path, 'new', subj)
    ca_old = _mkca(tmp_path, 'old', subj)                       # SAME DN, different key
    ca_other = _mkca(tmp_path, 'other', '/C=US/O=FIRE/OU=TAK/CN=INT-CA-01')
    leaf_old = _mkleaf(tmp_path, 'old')
    leaf_new = _mkleaf(tmp_path, 'new')
    ns = _load(['_cert_signed_by'])
    f = ns['_cert_signed_by']
    assert f(leaf_new, ca_new) is True
    assert f(leaf_old, ca_new) is False, 'same-DN CA replacement must still read as "other CA"'
    assert f(leaf_old, ca_other) is False
    assert f(leaf_new, ca_new + ca_old) is True
    assert f('', ca_new) is None and f(leaf_new, 'not a pem') is None


def test_admin_token_is_hs256_server_minted_and_short_lived():
    ns = _load(['_cloudtak_admin_token'])
    tok = ns['_cloudtak_admin_token']('s3cret', ttl=120)
    h, b, sig = tok.split('.')
    want = base64.urlsafe_b64encode(hmac.new(b's3cret', f'{h}.{b}'.encode(), hashlib.sha256).digest()).rstrip(b'=')
    assert sig.encode() == want
    pad = lambda s: s + '=' * (-len(s) % 4)
    assert json.loads(base64.urlsafe_b64decode(pad(h))) == {'alg': 'HS256', 'typ': 'JWT'}
    claims = json.loads(base64.urlsafe_b64decode(pad(b)))
    assert claims['access'] == 'admin' and claims['email']
    assert 's' not in claims, 'an `s` claim makes CloudTAK look up a session that does not exist'
    assert 0 < claims['exp'] - claims['iat'] <= 300


class _CT:
    """CloudTAK API + docker + TAK seams for _cloudtak_tak_cert_heal."""

    def __init__(self, statuses, signed=False, configured=True, ensure_ok=True):
        self.statuses = list(statuses)
        self.signed, self.configured, self.ensure_ok = signed, configured, ensure_ok
        self.calls, self.ensured, self.logs, self.runs = [], 0, [], []

    def ns(self):
        def req(method, url, payload=None, timeout=25, headers=None):
            self.calls.append((method, url, payload, headers))
            if method == 'GET':
                st = self.statuses.pop(0) if self.statuses else 'live'
                return True, 200, {'status': 'configured' if self.configured else 'unconfigured',
                                   'connection_status': st, 'url': 'ssl://tak:8089',
                                   'api': 'https://tak:8443', 'webtak': 'https://tak:8446'}
            return True, 200, {'status': 'configured'}

        def ensure(settings):
            self.ensured += 1
            return {'success': self.ensure_ok, 'admin_flip_ok': True, 'error': None if self.ensure_ok else 'x'}
        return {
            'load_settings': lambda: {},
            '_get_cloudtak_deployment_config': lambda s: {'target_mode': 'local'},
            '_cloudtak_bootstrap_cert_target': lambda s: ('local', None),
            '_cloudtak_signing_secret': lambda: 'sekret',
            '_cloudtak_admin_token': lambda secret: 'TOKEN',
            '_cloudtak_request_json': req,
            '_sudo_wrap': lambda argv: argv,
            'subprocess': types.SimpleNamespace(run=lambda argv, **k: self.runs.append(list(argv)) or types.SimpleNamespace(
                returncode=0, stdout='-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----', stderr='')),
            '_read_priv': lambda p: 'CA',
            '_cert_signed_by': lambda cert, ca: self.signed,
            '_local_bootstrap_cert_ensure': ensure,
            '_read_priv_bytes': lambda p: b'p12',
            '_p12_bytes_to_pem': lambda b, pw: ('CERT', 'KEY'),
            '_get_tak_cert_password': lambda s: 'atakatak',
            'time': types.SimpleNamespace(sleep=lambda s: None),
        }

    def run(self, **kw):
        ns = _load(['_cloudtak_tak_cert_heal'], self.ns())
        return ns['_cloudtak_tak_cert_heal'](log=self.logs.append, **kw)

    @property
    def patches(self):
        return [c for c in self.calls if c[0] == 'PATCH']


def test_heal_reissues_and_patches_when_dead_and_from_another_ca():
    ct = _CT(['dead'] * 4, signed=False)
    assert ct.run() is True
    assert ct.ensured == 1 and len(ct.patches) == 1
    _, url, body, headers = ct.patches[0]
    assert url == 'http://127.0.0.1:5000/api/server'
    assert body == {'url': 'ssl://tak:8089', 'api': 'https://tak:8443', 'webtak': 'https://tak:8446',
                    'auth': {'cert': 'CERT', 'key': 'KEY'}}
    assert headers == {'Authorization': 'Bearer TOKEN'}
    assert not any('TOKEN' in m or 'sekret' in m or 'KEY' == m for m in ct.logs)
    assert ['docker', 'restart', 'cloudtak-api-1'] in ct.runs, \
        "the old connection's retry loop survives the PATCH until the API restarts"


def test_heal_does_not_restart_cloudtak_when_the_patch_is_refused():
    ct = _CT(['dead'] * 4, signed=False)
    ns = _load(['_cloudtak_tak_cert_heal'], ct.ns())
    real = ns['_cloudtak_request_json']
    ns['_cloudtak_request_json'] = lambda m, u, payload=None, timeout=25, headers=None: (
        (False, 400, {'message': 'Could not connect to TAK Server'}) if m == 'PATCH'
        else real(m, u, payload, timeout, headers))
    assert ns['_cloudtak_tak_cert_heal'](log=ct.logs.append) is False
    assert not any(r[:2] == ['docker', 'restart'] for r in ct.runs)
    assert any('Could not connect to TAK Server' in m for m in ct.logs)


@pytest.mark.parametrize('statuses', [['live'], ['dead', 'live'], ['dead', 'dead', 'dead', 'unknown']])
def test_heal_never_touches_a_connection_that_is_or_becomes_live(statuses):
    """A TAK restart reads dead for a minute; a CA rotation keeps the old CA trusted (live)."""
    ct = _CT(statuses, signed=False)
    assert ct.run() is None
    assert ct.ensured == 0 and ct.patches == []


def test_heal_leaves_a_dead_connection_alone_when_its_cert_is_from_the_current_ca():
    ct = _CT(['dead'] * 4, signed=True)
    assert ct.run() is None and ct.ensured == 0 and ct.patches == []
    ct = _CT(['dead'] * 4, signed=None)
    assert ct.run() is None and ct.ensured == 0 and ct.patches == []


def test_heal_never_bootstraps_an_unconfigured_cloudtak():
    ct = _CT(['dead'] * 4, configured=False)
    assert ct.run() is None and ct.ensured == 0 and ct.patches == []


def test_heal_reports_failure_without_patching_when_the_cert_cannot_be_issued():
    ct = _CT(['dead'] * 4, ensure_ok=False)
    assert ct.run() is False and ct.patches == []


def test_bootstrap_ensure_reissues_a_cert_the_current_ca_did_not_sign():
    ran = []
    ns = {
        '_exists_priv': lambda p: True,
        '_read_priv': lambda p: 'UAF identifier="cloudtak-svc-bootstrap"' if p.endswith('.xml') else 'PEM',
        '_cert_signed_by': lambda cert, ca: False,
        '_patch_openssl_string_mask': lambda: None,
        '_cert_metadata_prepare_for_makecert': lambda: None,
        '_rotate_tak_cert_cmd': lambda c: c,
        '_tak_is_container': lambda: False,
        '_tak_exec': lambda c: c,
        'subprocess': types.SimpleNamespace(run=lambda cmd, **k: ran.append(cmd) or types.SimpleNamespace(
            returncode=0, stdout='', stderr='')),
    }
    _load(['_local_bootstrap_cert_ensure'], ns)
    ns['os'] = types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True, join=os.path.join))
    res = ns['_local_bootstrap_cert_ensure']({})
    assert res['success'] and res['regenerated'] and res['created'] and res['admin_flip_ok']
    assert any('makeCert.sh client cloudtak-svc-bootstrap' in c for c in ran)
    ns['_cert_signed_by'] = lambda cert, ca: True
    ran.clear()
    res = ns['_local_bootstrap_cert_ensure']({})
    assert not res['regenerated'] and not res['created']
    assert not any('makeCert.sh' in c for c in ran), 'a current-CA cert must be reused, not re-issued'


def test_generate_route_uses_the_shared_ensure():
    body = _func('cloudtak_generate_bootstrap_cert_api')
    assert '_local_bootstrap_cert_ensure(settings)' in body and "'regenerated'" in body
    assert 'makeCert.sh client' not in body[body.index('# Local (native or container)'):]
