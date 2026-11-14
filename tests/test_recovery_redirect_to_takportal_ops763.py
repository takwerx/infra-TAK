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
"""The password-reset flow sends the user on to TAK Portal (ops #763, GH #503).

Field: a new TAK Portal user resets their password, sets up MFA and lands on the Authentik
library page, not on TAK Portal, because the recovery flow had no ending that points back.
The flow now ends: User Write -> Session Logout (110) -> Redirect (120) to the TAK Portal
link. The ending stays SIGNED OUT on purpose (v10.1.28: a trailing User Login would resume
the pre-reset OAuth state and hit the outpost's SameSite=Lax 400). The redirect runs after
the logout, so the user signs in once with the new password, and the login flow carries
next= for the TAK Portal URL.

app.py cannot be imported in a test, so the two functions are cut out of it and run against
an in-memory fake of the Authentik API: the code under test is the shipped text.
"""

import ast
import io
import json
import pathlib
import re
import urllib.error
import urllib.request
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)


def _consts():
    return '\n'.join(ast.get_source_segment(APP, n) for n in _TREE.body
                     if isinstance(n, ast.Assign)
                     and any(getattr(t, 'id', '').startswith('_AK_RECOVERY_BACK_TO_APP') for t in n.targets))


_POLICY_CONSTS = _consts()


def _func(name):
    return next((ast.get_source_segment(APP, n) for n in _TREE.body
                 if isinstance(n, ast.FunctionDef) and n.name == name), '')


class FakeAuthentik:
    """Just enough of /api/v3 for _ensure_authentik_recovery_flow."""

    def __init__(self, portal_external_host=None):
        self.n = 0
        self.objs = {}      # kind -> list of dicts
        self.bindings = []
        self.policy_bindings = []
        self.flows = []
        self.apps = []
        self.providers = {}
        self.id_stages = [{'pk': 'auth-id', 'name': 'default-authentication-identification',
                           'user_fields': ['username'], 'recovery_flow': None}]
        if portal_external_host is not None:
            self.providers['prov-1'] = {'pk': 'prov-1', 'external_host': portal_external_host}
            self.apps.append({'slug': 'tak-portal', 'provider': 'prov-1'})

    def _pk(self):
        self.n += 1
        return f'pk-{self.n}'

    def handle(self, method, path, body):
        path, _, query = path.partition('?')
        parts = [p for p in path.strip('/').split('/') if p]
        q = dict(kv.split('=', 1) for kv in query.split('&') if '=' in kv)
        if parts[0] == 'core' and parts[1] == 'applications':
            # Real Authentik (seen on test12): without superuser_full_list=true the list holds
            # only the apps the token's user may open, so tak-portal is missing from it.
            if q.get('superuser_full_list') != 'true':
                return {'results': []}
            return {'results': [a for a in self.apps if a['slug'] == q.get('slug', a['slug'])]}
        if parts[0] == 'providers':
            return self.providers[parts[2]]
        if parts[0] == 'policies':
            if parts[1] == 'expression':
                lst = self.objs.setdefault('policy', [])
                if len(parts) == 2 and method == 'GET':
                    return {'results': list(lst)}
                if len(parts) == 2:
                    o = dict(body, pk=self._pk())
                    lst.append(o)
                    return o
                o = next(x for x in lst if x['pk'] == parts[2])
                o.update(body)
                return o
            if parts[1] == 'bindings':
                if method == 'GET':
                    return {'results': [b for b in self.policy_bindings
                                        if b['target'] == q.get('target', b['target'])]}
                b = dict(body, pk=self._pk())
                self.policy_bindings.append(b)
                return b
        if parts[0] == 'flows' and parts[1] == 'instances':
            if method == 'GET':
                return {'results': list(self.flows)}
            if method == 'POST':
                f = dict(body, pk=self._pk())
                self.flows.append(f)
                return f
            return {}
        if parts[0] == 'flows' and parts[1] == 'bindings':
            if method == 'GET':
                return {'results': list(self.bindings), 'pagination': {}}
            if method == 'POST':
                b = dict(body, pk=self._pk())
                self.bindings.append(b)
                return b
            if method == 'DELETE':
                self.bindings = [b for b in self.bindings if b['pk'] != parts[2]]
                return {}
        if parts[:2] == ['stages', 'identification']:
            if len(parts) == 2:
                if method == 'POST':
                    o = dict(body, pk=self._pk())
                    self.objs.setdefault('identification', []).append(o)
                    return o
                s = urllib.request.unquote(q.get('search', ''))
                return {'results': [o for o in self.id_stages + self.objs.get('identification', [])
                                    if s in o['name']]}
            pk = parts[2]
            allst = self.id_stages + self.objs.get('identification', [])
            st = next(s for s in allst if s['pk'] == pk)
            if method == 'PATCH':
                st.update(body)
            return st
        # generic stage / prompt kinds: stages/<kind>/ and stages/prompt/{stages,prompts}/
        kind = '/'.join(parts[1:3]) if parts[1] == 'prompt' else parts[1]
        rest = parts[3:] if parts[1] == 'prompt' else parts[2:]
        lst = self.objs.setdefault(kind, [])
        if not rest:
            if method == 'GET':
                s = q.get('search', '')
                s = urllib.request.unquote(s)
                return {'results': [o for o in lst if s in o['name']]}
            o = dict(body, pk=self._pk())
            lst.append(o)
            return o
        o = next(x for x in lst if x['pk'] == rest[0])
        if method == 'PATCH':
            o.update(body)
        return o


def _run(fake):
    assert _func('_ensure_authentik_recovery_flow'), 'function under test was renamed'
    src = _POLICY_CONSTS + '\n\n' + '\n\n'.join(
        _func(n) for n in ('_recovery_takportal_landing_url', '_ensure_authentik_recovery_flow'))
    g = {'json': json, '_AK_SHOWPW_FIELD_HTML': '<label>x</label>',
         '_ensure_authentik_showpw_css': lambda *a, **k: 0}
    exec(src, g)

    class _Resp:
        def __init__(self, data):
            self._d = json.dumps(data).encode()

        def read(self):
            return self._d

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        path = url.split('/api/v3/', 1)[1]
        body = json.loads(req.data.decode()) if req.data else None
        return _Resp(fake.handle(req.get_method(), path, body))

    with mock.patch.object(urllib.request, 'urlopen', fake_urlopen):
        return g['_ensure_authentik_recovery_flow']('http://ak.test', {'Authorization': 'Bearer x'})


def _recovery_binding_stage_names(fake):
    """(order, stage name) of every binding on the recovery flow, in order."""
    names = {}
    for kind, lst in fake.objs.items():
        for o in lst:
            names[o['pk']] = o['name']
    flow_pk = fake.flows[0]['pk']
    return sorted((b['order'], names.get(b['stage'], b['stage'])) for b in fake.bindings
                  if b['target'] == flow_pk)


def test_reset_flow_ends_with_redirect_to_takportal_after_logout():
    fake = FakeAuthentik(portal_external_host='https://takportal.example.com')
    ok, _msg, _slug = _run(fake)
    assert ok
    tail = _recovery_binding_stage_names(fake)[-2:]
    assert tail == [(110, 'Recovery Session Logout'),
                    (120, 'Recovery Redirect to TAK Portal')]
    stage = fake.objs['redirect'][0]
    assert stage['mode'] == 'static'
    assert stage['target_static'] == 'https://takportal.example.com/'


def test_reset_flow_still_ends_signed_out_never_user_login():
    fake = FakeAuthentik(portal_external_host='https://takportal.example.com')
    _run(fake)
    assert 'user_login' not in fake.objs
    names = [n for _o, n in _recovery_binding_stage_names(fake)]
    assert 'Recovery Session Logout' in names
    # the redirect comes AFTER the logout, never before it
    assert names.index('Recovery Redirect to TAK Portal') > names.index('Recovery Session Logout')


def test_redirect_follows_a_changed_takportal_address_and_port():
    fake = FakeAuthentik(portal_external_host='https://takportal.example.com')
    _run(fake)
    fake.providers['prov-1']['external_host'] = 'https://portal.other.org:8443/'
    _run(fake)
    assert len(fake.objs['redirect']) == 1
    assert fake.objs['redirect'][0]['target_static'] == 'https://portal.other.org:8443/'
    redirect_bindings = [b for b in fake.bindings if b['order'] == 120]
    assert len(redirect_bindings) == 1


def test_no_takportal_means_no_redirect_stage_and_an_old_one_is_removed():
    fake = FakeAuthentik(portal_external_host='https://takportal.example.com')
    _run(fake)
    assert any(b['order'] == 120 for b in fake.bindings)
    fake.apps.clear()  # TAK Portal removed from Authentik
    ok, _m, _s = _run(fake)
    assert ok
    assert not any(b['order'] == 120 for b in fake.bindings)
    assert _recovery_binding_stage_names(fake)[-1] == (110, 'Recovery Session Logout')


def test_a_non_https_or_odd_target_is_never_used():
    for bad in ('http://takportal.example.com', 'javascript:alert(1)',
                'https://x.example.com/"><script>', ''):
        fake = FakeAuthentik(portal_external_host=bad)
        ok, _m, _s = _run(fake)
        assert ok
        assert not any(b['order'] == 120 for b in fake.bindings), bad


def test_rerun_is_idempotent():
    fake = FakeAuthentik(portal_external_host='https://takportal.example.com')
    _run(fake)
    before = _recovery_binding_stage_names(fake)
    _run(fake)
    assert _recovery_binding_stage_names(fake) == before


# ---- "go back to the app you came from" (AJ, ops #763): the Redirect stage's policy ----

def test_redirect_binding_has_the_back_to_app_policy_and_reevaluates():
    fake = FakeAuthentik(portal_external_host='https://takportal.example.com')
    _run(fake)
    rb = next(b for b in fake.bindings if b['order'] == 120)
    assert rb['re_evaluate_policies'] is True
    pol = fake.objs['policy'][0]
    assert pol['name'] == 'Recovery Redirect to the app you came from'
    assert [x['policy'] for x in fake.policy_bindings if x['target'] == rb['pk']] == [pol['pk']]
    _run(fake)  # re-run: one policy, one binding
    assert len(fake.objs['policy']) == 1
    assert len(fake.policy_bindings) == 1


class _Prov:
    def __init__(self, application):
        self.application = application


class _App:
    def __init__(self, url):
        self._u = url

    def get_launch_url(self):
        return self._u


def _run_policy(next_param, providers, flow_plan=True):
    """Run the shipped policy expression against stand-ins for Authentik's objects.
    Returns (result, plan.context)."""
    import sys
    import types
    expr = eval(_POLICY_CONSTS.split('_AK_RECOVERY_BACK_TO_APP_EXPR = ', 1)[1])
    body = 'def _policy(request):\n' + ''.join('    ' + ln + '\n' for ln in expr.splitlines())

    class _Qs:
        def __init__(self, d):
            self.d = d

        def filter(self, client_id):
            class _R:
                def __init__(s, v):
                    s.v = v

                def first(s):
                    return s.v
            return _R(self.d.get(client_id))

    mod = types.ModuleType('authentik.providers.oauth2.models')
    mod.OAuth2Provider = types.SimpleNamespace(objects=_Qs(providers))
    sys.modules.update({'authentik': types.ModuleType('authentik'),
                        'authentik.providers': types.ModuleType('authentik.providers'),
                        'authentik.providers.oauth2': types.ModuleType('authentik.providers.oauth2'),
                        'authentik.providers.oauth2.models': mod})
    plan = types.SimpleNamespace(context={})
    request = types.SimpleNamespace(
        context={'flow_plan': plan if flow_plan else None},
        http_request=types.SimpleNamespace(session={'authentik/flows/get': {'next': next_param}}))
    g = {}
    exec(body, g)
    return g['_policy'](request), plan.context


def test_policy_sends_the_user_back_to_the_app_they_started_from():
    provs = {'cid-cloudtak': _Prov(_App('https://map.example.com/')),
             'cid-portal': _Prov(_App('https://takportal.example.com/'))}
    res, ctx = _run_policy('/application/o/authorize/?client_id=cid-cloudtak&state=abc', provs)
    assert res is True
    assert ctx == {'redirect_stage_target': 'https://map.example.com/'}


def test_policy_never_uses_an_address_from_the_url_and_falls_back():
    provs = {'cid-portal': _Prov(_App('https://takportal.example.com/'))}
    # an address in the URL is ignored; unknown client_id -> no override (static TAK Portal)
    for nxt in ('https://evil.example.com/', '/application/o/authorize/?client_id=nope&redirect_uri=https://evil.example.com/',
                '', '/if/user/'):
        res, ctx = _run_policy(nxt, provs)
        assert res is True and ctx == {}, nxt


def test_policy_ignores_app_launch_urls_that_are_not_plain_https():
    for bad in ('http://x.example.com/', 'javascript:alert(1)', '', None, 'https://x.example.com/"><b>'):
        res, ctx = _run_policy('/application/o/authorize/?client_id=c', {'c': _Prov(_App(bad))})
        assert res is True and ctx == {}, bad


def test_policy_never_breaks_the_reset():
    # a lookup that raises must still let the flow continue (policy returns True)
    class _Boom:
        @property
        def application(self):
            raise RuntimeError('db down')
    res, ctx = _run_policy('/application/o/authorize/?client_id=c', {'c': _Boom()})
    assert res is True and ctx == {}
