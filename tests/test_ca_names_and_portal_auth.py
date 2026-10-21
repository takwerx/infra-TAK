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
"""v10.2.20 W1 + W2.

W1 (GH #128): a CA name with `_` is encoded T61String by openssl and UTF8String by TAK's Java
signer, so every enrolled device fails 8089. Deploy and Rotate Intermediate CA must refuse it.

W2: TAK Portal with PORTAL_AUTH_ENABLED off makes every signed-in user a Global admin. The card
must show whenever TAK Portal itself would read the setting as off, and the button may write
that one key and nothing an operator owns.
"""

import ast
import json
import pathlib
import re
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
JS = (REPO / 'static' / 'takserver.js').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    return '\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                     if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets))


def _load(names, ns=None, consts=()):
    ns = {} if ns is None else ns
    ns.setdefault('_re_module', re)
    ns.setdefault('json', json)
    if consts:
        exec(compile(_consts(*consts), 'app.py', 'exec'), ns)
    exec(compile('\n\n'.join(_func(n) for n in names), 'app.py', 'exec'), ns)
    return ns


# ── W1: CA names ────────────────────────────────────────────────────────────────────────

def _validate():
    return _load(['_validate_ca_name'], consts=('_CA_NAME_RE',))['_validate_ca_name']


@pytest.mark.parametrize('name', ['ROOT-CA-01', 'INTERMEDIATE-CA-01', 'INT-CA-09', 'ca.example.2', 'A' * 64])
def test_hyphenated_names_pass(name):
    assert _validate()(f'  {name} ', 'CA') == name


@pytest.mark.parametrize('name', ['ROOT_CA_03', 'INTERMEDIATE_CA_03', 'BAD NAME', '', '-LEADING',
                                  '.LEADING', 'A' * 65, '../etc', 'CA;rm', 'CAé'])
def test_names_that_break_enrollment_or_paths_are_refused(name):
    with pytest.raises(ValueError, match='no underscores'):
        _validate()(name, 'CA')


def test_deploy_and_rotate_both_enforce_it():
    assert "_validate_ca_name(data.get('root_ca_name'" in _func('deploy_takserver')
    assert "_validate_ca_name(data.get('intermediate_ca_name'" in _func('deploy_takserver')
    rot = _func('takserver_rotate_intca')
    assert '_validate_ca_name(new_ca_name' in rot and '._-]' not in rot, 'rotate used to allow underscores'


def test_browser_uses_the_same_rule():
    server = re.search(r"_CA_NAME_RE = _re_module\.compile\(r'(.+?)'\)", APP).group(1)
    assert JS.count(server) == 2, 'rotateIntCA() and startDeploy() must match _CA_NAME_RE'


# ── W2: TAK Portal login off ────────────────────────────────────────────────────────────

def _disabled(existing, fqdn='ops1.example.com'):
    ns = _load(['_takportal_auth_disabled'], {'_takportal_get_existing_settings': lambda: existing})
    return ns['_takportal_auth_disabled']({'fqdn': fqdn}, existing=existing)


# TAK Portal's getBool (services/env.js): 1/true/yes/on (lowercased, not trimmed) is on, all
# else falls back to off — so the card has to treat everything else as off too.
@pytest.mark.parametrize('value', ['true', 'TRUE', 'yes', 'on', '1', True])
def test_values_tak_portal_reads_as_on(value):
    assert _disabled({'PORTAL_AUTH_ENABLED': value}) is False


@pytest.mark.parametrize('value', ['false', '0', 'no', 'off', '', None, False, ' true', 'enabled'])
def test_values_tak_portal_reads_as_off(value):
    assert _disabled({'PORTAL_AUTH_ENABLED': value}) is True


def test_missing_key_is_off_and_no_domain_or_no_portal_is_not_flagged():
    assert _disabled({'TAK_URL': 'x'}) is True
    assert _disabled({'PORTAL_AUTH_ENABLED': 'false'}, fqdn='') is False, 'IP-only boxes install with it off'
    assert _disabled({}) is False, 'no portal settings to read'


OPERATOR = {
    'PORTAL_AUTH_ENABLED': 'false',
    'PORTAL_AUTH_REQUIRED_GROUP': 'agency-admins',
    'TAK_SSH_USER': 'root',
    'TAK_PORTAL_PUBLIC_URL': 'http://149.20.250.162:3000',
    'AUTHENTIK_TOKEN': 'old-token',
}
BUILT = {
    'PORTAL_AUTH_ENABLED': 'true',
    'PORTAL_AUTH_REQUIRED_GROUP': 'authentik Admins',
    'TAK_SSH_USER': 'takwerx',
    'TAK_PORTAL_PUBLIC_URL': 'https://takportal.ops1.example.com',
    'AUTHENTIK_TOKEN': 'new-token',
}


def _merge(existing, adopt):
    ns = _load(['_takportal_template_placeholder_keys', '_takportal_merged_settings_json'], {
        '_takportal_get_existing_settings': lambda: dict(existing),
        '_takportal_build_settings_dict': lambda s: dict(BUILT),
        '_takportal_settings_value_is_blank': lambda v: v is None or (isinstance(v, str) and not v.strip()),
    }, consts=('TAKPORTAL_DOMAIN_KEYS', 'TAKPORTAL_AUTH_ADOPT_KEYS', 'TAKPORTAL_AUTHORITATIVE_KEYS',
               'EMAIL_TRANSPORT_KEYS', 'TAKPORTAL_TEMPLATE_PLACEHOLDERS', 'TAKPORTAL_TEMPLATE_TAK_CONNECTION'))
    return json.loads(ns['_takportal_merged_settings_json']({}, adopt=adopt))


def test_auth_adopt_turns_login_on_and_keeps_every_operator_value():
    out = _merge(OPERATOR, ('PORTAL_AUTH_ENABLED',))
    assert out['PORTAL_AUTH_ENABLED'] == 'true'
    assert out['PORTAL_AUTH_REQUIRED_GROUP'] == 'agency-admins', 'an operator-set group is kept'
    assert out['TAK_SSH_USER'] == 'root' and out['TAK_PORTAL_PUBLIC_URL'] == OPERATOR['TAK_PORTAL_PUBLIC_URL']


def test_a_blanked_group_is_reseeded():
    out = _merge(dict(OPERATOR, PORTAL_AUTH_REQUIRED_GROUP=''), ('PORTAL_AUTH_ENABLED',))
    assert out['PORTAL_AUTH_REQUIRED_GROUP'] == 'authentik Admins'


def test_adopt_still_refuses_keys_outside_the_two_lists():
    out = _merge(OPERATOR, ('TAK_SSH_USER', 'PORTAL_AUTH_REQUIRED_GROUP'))
    assert out['TAK_SSH_USER'] == 'root' and out['PORTAL_AUTH_REQUIRED_GROUP'] == 'agency-admins'


def test_use_domain_cannot_be_used_to_adopt_the_auth_key():
    body = _func('takportal_use_domain_api')
    assert 'keys = [k for k in TAKPORTAL_DOMAIN_KEYS if k in want' in body


class _EnableAuth:
    def __init__(self, existing, keeps=True, write_ok=True):
        self.existing, self.keeps, self.write_ok = dict(existing), keeps, write_ok
        self.adopted, self.writes, self.restarts = None, [], 0

    def call(self):
        def merged(settings, adopt=()):
            self.adopted = tuple(adopt)
            return 'MERGED'

        def write(js, plog=None):
            self.writes.append(js)
            if self.write_ok and self.keeps:
                self.existing['PORTAL_AUTH_ENABLED'] = 'true'
            return self.write_ok, '' if self.write_ok else 'docker cp failed'

        def restart():
            self.restarts += 1
            return True

        ns = _load(['_takportal_auth_disabled', 'takportal_enable_auth_api'], {
            'load_settings': lambda: {'fqdn': 'ops1.example.com'},
            'jsonify': lambda d: d,
            '_takportal_get_existing_settings': lambda: dict(self.existing),
            '_takportal_merged_settings_json': merged,
            '_takportal_write_settings_json': write,
            '_takportal_restart': restart,
            'print': lambda *a, **k: None,
        }, consts=('TAKPORTAL_AUTH_ADOPT_KEYS',))
        r = ns['takportal_enable_auth_api']()
        return r if isinstance(r, tuple) else (r, 200)


def test_enable_auth_writes_only_the_auth_key_through_the_single_writer():
    rt = _EnableAuth(dict(OPERATOR, PORTAL_AUTH_REQUIRED_GROUP='authentik Admins'))
    body, code = rt.call()
    assert code == 200 and body['success'] is True and body['group'] == 'authentik Admins'
    assert rt.adopted == ('PORTAL_AUTH_ENABLED',) and rt.writes == ['MERGED'] and rt.restarts == 1


def test_enable_auth_when_already_on_writes_nothing():
    rt = _EnableAuth(dict(OPERATOR, PORTAL_AUTH_ENABLED='true'))
    body, _ = rt.call()
    assert body['success'] is True and rt.writes == [] and rt.restarts == 0


def test_enable_auth_reports_a_failed_write_or_a_portal_that_did_not_keep_it():
    body, code = _EnableAuth(OPERATOR, write_ok=False).call()
    assert code == 500 and body['success'] is False
    body, _ = _EnableAuth(OPERATOR, keeps=False).call()
    assert body['success'] is False and 'did not keep' in body['error']


def test_enable_auth_route_is_a_login_required_post():
    i = APP.index('def takportal_enable_auth_api(')
    head = APP[APP.rindex('@app.route', 0, i):i]
    assert "/api/takportal/enable-auth', methods=['POST']" in head and '@login_required' in head


def test_enable_auth_is_covered_by_the_same_origin_check():
    """No per-route CSRF token: every state-changing /api/ call goes through _same_origin_ok()."""
    gate = APP[APP.index('# CSRF baseline for state-changing API calls'):]
    gate = gate[:gate.index('@app.after_request')]
    assert "request.path.startswith('/api/')" in gate and '_same_origin_ok()' in gate
    assert '/api/takportal' not in gate, 'TAK Portal routes must not be on the CSRF exemption list'
