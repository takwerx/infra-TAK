# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""A new ATLAS deployment on a Hardened box gets the require-MFA binding (ops #985).

⚠️ **Reported from a real box (test6, Hardened, v10.4.3 T&E):** a new agency
deployment came up with policy mode `any` and only its own `ATLAS access`
binding, so the agency's administrators signed in without the MFA step every
other app asks for. Hardening binds MFA to the apps that exist when it runs;
Remote Assist and NetBird sweep for a late-made app at the end of their deploy,
ATLAS did not.

The first group runs the console's real sweep (`_w1_reassert_app_mfa`, read out
of app.py) against a fake Authentik, through the new ATLAS helper.
"""

import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)

MFA_PK = 'pol-mfa'
ACCESS_PK = 'pol-access-new'


def _func(src, name):
    m = re.search(r'\ndef %s\(.*?(?=\n(?:def |class |@|[A-Za-z_]))' % name, src, re.S)
    assert m, name
    return m.group(0)


class FakeAuthentik:
    """Applications, their bindings and engine mode; enough REST for the sweep."""

    def __init__(self):
        # Two older apps, already hardened; the new agency app, not.
        self.apps = {
            'atlas': {'pk': 'a1', 'slug': 'atlas', 'provider': 11, 'policy_engine_mode': 'all'},
            'atlas-old': {'pk': 'a2', 'slug': 'atlas-old', 'provider': 12, 'policy_engine_mode': 'all'},
            'atlas-tenew': {'pk': 'a3', 'slug': 'atlas-tenew', 'provider': 13, 'policy_engine_mode': 'any'},
        }
        self.bindings = [
            {'pk': 'b1', 'target': 'a1', 'policy': MFA_PK, 'enabled': True},
            {'pk': 'b2', 'target': 'a2', 'policy': MFA_PK, 'enabled': True},
            {'pk': 'b3', 'target': 'a3', 'policy': ACCESS_PK, 'enabled': True},
        ]
        self.ldap_providers = [{'pk': 99}]
        self.calls = []

    def get(self, ak_url, path, ak_headers):
        if path.startswith('providers/ldap/'):
            return {'results': self.ldap_providers}
        if path.startswith('core/applications/?'):
            return {'results': list(self.apps.values())}
        m = re.match(r'core/applications/([^/?]+)/', path)
        if m:
            return self.apps[m.group(1)]
        m = re.match(r'policies/bindings/\?target=([^&]+)', path)
        if m:
            return {'results': [b for b in self.bindings if b['target'] == m.group(1)]}
        raise AssertionError('unexpected GET ' + path)

    def call(self, url, data=None, method='GET', headers=None):
        self.calls.append((method, url))
        body = json.loads(data.decode()) if data else {}
        if method == 'POST' and url.endswith('/policies/bindings/'):
            b = dict(body, pk='new-%d' % len(self.bindings))
            self.bindings.append(b)
            return _Resp(b)
        if method == 'PATCH':
            slug = url.rstrip('/').rsplit('/', 1)[1]
            self.apps[slug].update(body)
            return _Resp(self.apps[slug])
        raise AssertionError('unexpected %s %s' % (method, url))


class _Resp:
    def __init__(self, obj):
        self._b = json.dumps(obj).encode()

    def read(self):
        return self._b


def _bound(ak, slug):
    pk = ak.apps[slug]['pk']
    return [b['policy'] for b in ak.bindings if b['target'] == pk and b['enabled']]


@pytest.fixture
def console(monkeypatch):
    """The console's real `_w1_login_apps` and `_w1_reassert_app_mfa`, over a fake."""
    src = (ROOT / 'app.py').read_text(encoding='utf-8')
    ak = FakeAuthentik()
    hardening = {'applied': {'W1_sso': {
        'ak_mfa_policy_pk': MFA_PK,
        'ak_apps': {'atlas': {'app_pk': 'a1', 'binding_pk': 'b1', 'prior_engine_mode': 'any'},
                    'atlas-old': {'app_pk': 'a2', 'binding_pk': 'b2', 'prior_engine_mode': 'any'}}}}}
    saved = []
    ns = {
        'json': json,
        '_w1_ak_ctx': lambda: ('http://ak', {}, {}),
        '_w1_ak_get': ak.get,
        '_ak_api_call': ak.call,
        'load_hardening': lambda: hardening,
        'save_hardening': lambda h: saved.append(json.dumps(h)),
        '_w1_unbind_recovery_login': lambda h, log: True,
        '_w1_bind_recovery_logout': lambda h, log: True,
    }
    exec(compile(_func(src, '_w1_login_apps') + _func(src, '_w1_reassert_app_mfa'),
                 'app.py', 'exec'), ns)
    ns['ak'] = ak
    ns['hardening'] = hardening
    ns['ctx'] = {'_w1_reassert_app_mfa': ns['_w1_reassert_app_mfa']}
    return ns


def test_a_new_agency_app_gets_the_mfa_binding_and_mode_all(console):
    """⚠️ **The reported case.** Mode `any`, one access binding, no MFA binding
    before; mode `all`, the access binding kept and the MFA binding after."""
    ak = console['ak']
    assert ak.apps['atlas-tenew']['policy_engine_mode'] == 'any'
    assert MFA_PK not in _bound(ak, 'atlas-tenew')

    logged = []
    changed = atlas._reassert_mfa(console['ctx'], logged.append)

    assert changed is True
    assert ak.apps['atlas-tenew']['policy_engine_mode'] == 'all'
    assert sorted(_bound(ak, 'atlas-tenew')) == sorted([ACCESS_PK, MFA_PK])
    assert any('atlas-tenew' in m for m in logged)


def test_the_older_apps_are_left_alone(console):
    ak = console['ak']
    atlas._reassert_mfa(console['ctx'], lambda _m: None)

    assert _bound(ak, 'atlas') == [MFA_PK] and _bound(ak, 'atlas-old') == [MFA_PK]
    assert not [c for c in ak.calls if c[0] == 'PATCH' and c[1].endswith('/atlas/')
                or c[0] == 'PATCH' and c[1].endswith('/atlas-old/')]


def test_it_is_idempotent(console):
    ak = console['ak']
    atlas._reassert_mfa(console['ctx'], lambda _m: None)
    n = len(ak.bindings)
    again = atlas._reassert_mfa(console['ctx'], lambda _m: None)

    assert again is False and len(ak.bindings) == n


def test_a_new_app_is_recorded_so_hardening_can_revert_it(console):
    atlas._reassert_mfa(console['ctx'], lambda _m: None)

    rec = console['hardening']['applied']['W1_sso']['ak_apps']['atlas-tenew']
    assert rec['prior_engine_mode'] == 'any' and rec['binding_pk']


def test_nothing_changes_when_hardening_is_not_applied(console):
    console['hardening']['applied'] = {}
    ak = console['ak']

    assert atlas._reassert_mfa(console['ctx'], lambda _m: None) is False
    assert ak.apps['atlas-tenew']['policy_engine_mode'] == 'any'
    assert MFA_PK not in _bound(ak, 'atlas-tenew')


def test_a_missing_or_failing_sweep_never_fails_the_deploy():
    logged = []
    assert atlas._reassert_mfa({}, logged.append) is False

    def boom(_plog):
        raise RuntimeError('authentik down')

    assert atlas._reassert_mfa({'_w1_reassert_app_mfa': boom}, logged.append) is False
    assert any('MFA' in m for m in logged)


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #

def _body(src, name):
    return re.search(r'\ndef %s\(.*?(?=\ndef )' % name, src, re.S).group(0)


def test_deploy_sweeps_after_the_access_policy_and_the_roster():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    deploy = _body(src, 'deploy')

    assert deploy.count('_reassert_mfa(ctx, plog)') == 1
    assert deploy.index('_reconcile_roster(ctx, _inst') < deploy.index('_reassert_mfa(ctx, plog)')
    # and before Caddy is re-emitted, the last thing the step does
    tail = deploy[deploy.index('_reassert_mfa(ctx, plog)'):]
    assert tail.index("ctx['generate_caddyfile']") < tail.index("ctx['_caddy_reload']")


def test_every_update_sweeps_too():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    access = _body(src, '_reconcile_access')

    assert access.index('_reconcile_agency_group(') < access.index('_reassert_mfa(ctx, plog)')


def test_the_console_hands_the_sweep_to_the_module():
    src = (ROOT / 'app.py').read_text(encoding='utf-8')

    assert "'_w1_reassert_app_mfa': _w1_reassert_app_mfa" in src
