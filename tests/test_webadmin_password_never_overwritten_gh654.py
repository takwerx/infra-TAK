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
"""The console never resets an existing webadmin password by itself (infra-TAK #654, ops #1121).

test12, 2026-11-22: an Authentik redeploy generated a random webadmin password and set it on the
live user, and the LDAP watchdog's role heal set the stored password again. The operator was
locked out of the SSO-protected console.

Rule: only an explicit operator action (Sync webadmin, TAK deploy, Connect LDAP) may set the
password of an EXISTING webadmin. The watchdog heal and the four TAK Server upgrade paths call
`_ensure_authentik_webadmin(..., reset_password=False)`.

The behavior tests run the real function body from app.py against a fake Authentik API.
"""

import ast
import json
import os
import pathlib
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
FUNCS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}

# Callers that run on their own (no operator click): they must not touch the password.
AUTOMATIC = {
    '_authentik_webadmin_role_check_and_heal',
    'run_takserver_upgrade',
    'run_takserver_upgrade_rhel',
    'run_takserver_upgrade_two_server',
    'run_takserver_upgrade_two_server_rhel',
}
# Callers started by an operator (button or deploy): they keep the reset.
EXPLICIT = {'takserver_sync_webadmin', 'takserver_connect_ldap',
            '_deploy_takserver_container', 'run_takserver_deploy'}


# ---- wiring: who passes reset_password=False --------------------------------------------------

def _calls_to_ensure():
    """(enclosing top-level function name, call node) for every _ensure_authentik_webadmin(...) call."""
    out = []
    for fn in TREE.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == '_ensure_authentik_webadmin'):
                out.append((fn.name, node))
    return out


def _reset_kw(call):
    for kw in call.keywords:
        if kw.arg == 'reset_password':
            return ast.literal_eval(kw.value)
    return None


def test_every_automatic_caller_passes_reset_password_false():
    seen = {}
    for owner, call in _calls_to_ensure():
        if owner in AUTOMATIC:
            seen.setdefault(owner, []).append(_reset_kw(call))
    assert set(seen) == AUTOMATIC, f'automatic callers changed: {sorted(seen)}'
    for owner, values in seen.items():
        assert values and all(v is False for v in values), (
            f'{owner} calls _ensure_authentik_webadmin without reset_password=False: {values}')


def test_explicit_operator_callers_keep_the_reset():
    seen = {}
    for owner, call in _calls_to_ensure():
        if owner not in AUTOMATIC and owner != '_ensure_authentik_webadmin':
            seen.setdefault(owner, []).append(_reset_kw(call))
    assert set(seen) == EXPLICIT, f'new caller of _ensure_authentik_webadmin: {sorted(set(seen) ^ EXPLICIT)}'
    for owner, values in seen.items():
        assert all(v is None for v in values), f'{owner} must keep the default (reset_password=True)'


def test_authentik_deploy_step_sets_password_only_on_a_user_it_created():
    """Step 11 of the Authentik deploy: no password for an existing webadmin, no early save."""
    src = APP
    gate = src.index('if webadmin_pk and webadmin_created:')
    # the set_password POST for the deploy sits under that gate
    assert 'users/{webadmin_pk}/set_password/' in src[gate:gate + 600]
    # a generated password is saved only after the user was created
    created = src.index('webadmin_created = True')
    saved = src.index("settings['webadmin_password'] = webadmin_pass", created)
    assert saved - created < 800
    assert "webadmin_pass = secrets.token_urlsafe(16)\n                            webadmin_pass_generated = True" in src
    # the group PATCH merges with the current groups
    assert "list(dict.fromkeys(_cur + [group_pk]))" in src


# ---- behavior: the real function against a fake Authentik -------------------------------------

class _Resp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b


class FakeAuthentik:
    GROUP_TAK = 10
    GROUP_ADMINS = 1

    def __init__(self, webadmin=True, admins_member=False, groups=None):
        self.calls = []
        self.user = None
        if webadmin:
            self.user = {'pk': 7, 'username': 'webadmin', 'is_active': True, 'is_superuser': True,
                         'path': 'users', 'groups': list(groups if groups is not None else [self.GROUP_TAK])}
        self.admins_users = [7] if admins_member else []

    def urlopen(self, req, timeout=None):
        method, url = req.get_method(), req.full_url
        path = url.split('/api/v3/', 1)[1]
        body = json.loads(req.data.decode()) if req.data else None
        self.calls.append((method, path, body))
        if method == 'GET' and path.startswith('core/groups/?search=tak_ROLE_ADMIN'):
            return _Resp({'results': [{'pk': self.GROUP_TAK, 'name': 'tak_ROLE_ADMIN'}]})
        if method == 'GET' and path.startswith('core/groups/?search=authentik+Admins'):
            return _Resp({'results': [{'pk': self.GROUP_ADMINS, 'name': 'authentik Admins',
                                       'users': list(self.admins_users)}]})
        if method == 'GET' and path.startswith('core/users/?search=webadmin'):
            return _Resp({'results': [self.user] if self.user else []})
        if method == 'POST' and path == 'core/users/':
            self.user = {'pk': 99, 'username': 'webadmin', 'is_active': True, 'is_superuser': True,
                         'path': 'users', 'groups': list(body.get('groups') or [])}
            return _Resp(self.user)
        if method == 'PATCH' and path.startswith('core/users/'):
            self.user.update(body)
            return _Resp(self.user)
        if method == 'DELETE':
            self.user = None
            return _Resp({})
        return _Resp({})

    def password_posts(self):
        return [c for c in self.calls if c[0] == 'POST' and c[1].endswith('/set_password/')]

    def deletes(self):
        return [c for c in self.calls if c[0] == 'DELETE']


@pytest.fixture
def ensure(monkeypatch):
    """Returns run(fake, *, stored_password, **kwargs) -> (result, verdict_calls)."""
    import time as _time
    src = ast.get_source_segment(APP, FUNCS['_ensure_authentik_webadmin'])

    def run(fake, stored_password='stored-pw', verdict='fail', **kwargs):
        verdict_calls = []
        glb = {
            'os': os, 'json': json, 'time': _time, 'subprocess': __import__('subprocess'),
            'load_settings': lambda: {'webadmin_password': stored_password, 'fqdn': 'tak.example.org'},
            # GH #687: the function body now asks this helper for a new webadmin's email.
            '_ak_admin_account_email': lambda u, s=None: f'{u}@tak.example.org',
            '_get_authentik_env_value': lambda s, k: 'token',
            '_get_authentik_api_url': lambda s: 'http://authentik.test',
            '_get_module_deployment_config': lambda s, k: {},
            '_self_heal_authentik_compose': lambda: None,
            '_preflight_port_conflicts': lambda *a, **k: None,
            '_wait_ldap_outpost_ready': lambda timeout_secs=0: (True, 'ready'),
            '_ensure_authentik_ldap_outpost_on_fqdn': lambda *a, **k: None,
            '_ak_compose_subprocess': lambda *a, **k: types_ns(returncode=0, stdout='', stderr=''),
            '_sudo_wrap': lambda c: c,
            '_test_ldap_bind_dn_verdict': lambda dn, pw: (verdict_calls.append((dn, pw)), verdict)[1],
        }
        exec(src, glb)
        monkeypatch.setattr(urllib.request, 'urlopen', fake.urlopen)
        real_exists = os.path.exists
        monkeypatch.setattr(os.path, 'exists',
                            lambda p: True if p == '/opt/tak' else (False if 'authentik/docker-compose' in str(p) else real_exists(p)))
        monkeypatch.setattr(_time, 'sleep', lambda s: None)
        return glb['_ensure_authentik_webadmin'](**kwargs), verdict_calls

    return run


def types_ns(**kw):
    import types
    return types.SimpleNamespace(**kw)


def test_watchdog_heal_does_not_reset_an_existing_password(ensure):
    # webadmin lost 'authentik Admins' (the drift the watchdog heals) and has an operator-set password
    fake = FakeAuthentik(webadmin=True, admins_member=False)
    (ok, err), _ = ensure(fake, skip_bind_verify=True, reset_password=False)
    assert (ok, err) == (True, None)
    assert fake.password_posts() == [], 'watchdog heal must not set the password of an existing webadmin'
    # ...but it still heals the role
    assert any(c[0] == 'POST' and c[1] == f'core/groups/{fake.GROUP_ADMINS}/add_user/' for c in fake.calls)


def test_upgrade_path_does_not_reset_password_or_delete_the_user(ensure):
    # TAK Server upgrades call it with skip_bind_verify=False. A 'fail' bind verdict deletes and
    # recreates the user, and the stored password is not the operator's password, so no bind check.
    fake = FakeAuthentik(webadmin=True, admins_member=True)
    (ok, err), verdict_calls = ensure(fake, verdict='fail', skip_bind_verify=False, reset_password=False)
    assert (ok, err) == (True, None)
    assert fake.password_posts() == []
    assert fake.deletes() == []
    assert verdict_calls == []
    assert fake.user is not None


def test_automatic_heal_works_when_no_password_is_stored(ensure):
    fake = FakeAuthentik(webadmin=True, admins_member=True)
    (ok, err), _ = ensure(fake, stored_password='', skip_bind_verify=True, reset_password=False)
    assert (ok, err) == (True, None)
    assert fake.password_posts() == []


def test_automatic_call_still_creates_a_missing_webadmin_with_the_stored_password(ensure):
    fake = FakeAuthentik(webadmin=False)
    (ok, err), _ = ensure(fake, stored_password='stored-pw', skip_bind_verify=True, reset_password=False)
    assert (ok, err) == (True, None)
    posts = fake.password_posts()
    assert len(posts) == 1 and posts[0][2] == {'password': 'stored-pw'}


def test_automatic_call_cannot_create_a_missing_webadmin_without_a_stored_password(ensure):
    fake = FakeAuthentik(webadmin=False)
    (ok, err), _ = ensure(fake, stored_password='', skip_bind_verify=True, reset_password=False)
    assert ok is False and 'not set' in err
    assert fake.password_posts() == []


def test_explicit_sync_still_sets_the_stored_password(ensure):
    fake = FakeAuthentik(webadmin=True, admins_member=True)
    (ok, err), verdict_calls = ensure(fake, verdict='ok', skip_bind_verify=False)
    assert (ok, err) == (True, None)
    posts = fake.password_posts()
    assert len(posts) == 1 and posts[0][2] == {'password': 'stored-pw'}
    assert len(verdict_calls) == 1


def test_explicit_sync_without_a_stored_password_is_refused(ensure):
    fake = FakeAuthentik(webadmin=True, admins_member=True)
    (ok, err), _ = ensure(fake, stored_password='', skip_bind_verify=False)
    assert ok is False and 'not set' in err
    assert fake.password_posts() == []
