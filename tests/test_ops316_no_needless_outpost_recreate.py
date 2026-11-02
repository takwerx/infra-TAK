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
"""A console update must not take LDAP down under TAK when nothing about it changed (ops #316).

test6, 2026-10-30: the post-update Authentik Reconfigure recreated the LDAP outpost twice with
nothing changed (the LDAP flow fix at 20:32:08Z, the domain sync's server/worker restart + LDAP
recreate at 20:35:53Z). TAK's HTTPS side then gave cert logins no groups and the heal restarted
TAK at 20:42:29Z. Now the flow fix (recreate='if_changed') and the domain sync recreate only
after a real write.

app.py cannot be imported in a test: the functions are cut out of it and run against a fake
Authentik API.
"""

import ast
import io
import json
import pathlib
import subprocess
import types
import urllib.error
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)


def _src(name):
    return next(ast.get_source_segment(APP, n) for n in _TREE.body
                if isinstance(n, ast.FunctionDef) and n.name == name)


SESSION = 'hours=1'


class FakeAuthentik:
    """Authentik's API as the LDAP flow fix sees it; `writes` = every PATCH/POST/DELETE."""

    def __init__(self, **drift):
        self.flow = {'pk': 'F1', 'slug': 'ldap-authentication-flow', 'authentication': 'none'}
        self.bindings = [
            {'pk': f'B{i}', 'target': 'F1', 'order': o, 'stage_obj': {'name': n, 'pk': p}}
            for i, (o, n, p) in enumerate([(10, 'ldap-identification-stage', 'S1'),
                                           (15, 'ldap-authentication-password', 'S2'),
                                           (20, 'ldap-authentication-login', 'S3')])]
        self.id_stage = {'pk': 'S1', 'name': 'ldap-identification-stage', 'password_stage': None,
                         'user_fields': ['username']}
        self.login_stage = {'pk': 'S3', 'name': 'ldap-authentication-login', 'session_duration': SESSION}
        self.provider = {'pk': 7, 'name': 'LDAP', 'authentication_flow': 'F1', 'authorization_flow': 'F1',
                         'bind_mode': 'cached', 'search_mode': 'cached'}
        for k, v in drift.items():
            obj, field = k.split('__')
            getattr(self, obj)[field] = v
        self.writes = []

    def urlopen(self, req, timeout=None):
        method = req.get_method()
        path = req.full_url.split('/api/v3/', 1)[1]
        if method != 'GET':
            self.writes.append((method, path.split('?')[0]))
            return io.BytesIO(b'{}')
        if path.startswith('flows/instances/?slug=ldap-authentication-flow'):
            body = {'results': [self.flow]}
        elif path.startswith('flows/instances/?slug=default-authentication-flow'):
            body = {'results': [{'pk': 'D1'}]}
        elif path.startswith('flows/bindings/'):
            body = {'results': self.bindings, 'pagination': {'next': 0}}
        elif path.startswith('stages/identification/S1/'):
            body = self.id_stage
        elif path.startswith('stages/identification/'):
            body = {'results': [self.id_stage], 'pagination': {'next': 0}}
        elif path.startswith('stages/user_login/S3/'):
            body = self.login_stage
        elif path.startswith('stages/user_login/'):
            body = {'results': [self.login_stage], 'pagination': {'next': 0}}
        elif path.startswith('stages/password/'):
            body = {'results': [{'pk': 'S2', 'name': 'ldap-authentication-password'}], 'pagination': {'next': 0}}
        elif path.startswith('providers/ldap/'):
            body = {'results': [self.provider]}
        else:
            raise AssertionError(f'unexpected GET {path}')
        return io.BytesIO(json.dumps(body).encode())


def run_flow_fix(monkeypatch, ak, **kw):
    composes = []
    ns = {
        'json': json, 'os': __import__('os'), 'time': types.SimpleNamespace(sleep=lambda s: None),
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: 'tok',
        '_get_module_deployment_config': lambda s, k: {},
        '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
        'AK_LDAP_SESSION_DURATION': SESSION,
        '_ak_compose_run_locked': lambda args, tag, *a, **k: composes.append((args, tag)) or 'ok',
        '_ak_module_compose': lambda *a, **k: composes.append(a),
    }
    monkeypatch.setattr(urllib.request, 'urlopen', ak.urlopen)
    monkeypatch.setattr(ns['os'].path, 'exists', lambda p: True)
    exec(compile(_src('_ensure_ldap_flow_authentication_none'), 'app.py', 'exec'), ns)
    return ns['_ensure_ldap_flow_authentication_none'](**kw), composes


def test_nothing_changed_leaves_the_outpost_running(monkeypatch, capsys):
    ak = FakeAuthentik()
    res, composes = run_flow_fix(monkeypatch, ak, recreate='if_changed')
    assert res == (True, None)
    assert ak.writes == [] and composes == []
    assert 'outpost left running (no recreate)' in capsys.readouterr().out


@pytest.mark.parametrize('drift, written', [
    ({'flow__authentication': 'require_outpost'}, ('PATCH', 'flows/instances/ldap-authentication-flow/')),
    ({'id_stage__password_stage': 'S2'}, ('PATCH', 'stages/identification/S1/')),
    ({'login_stage__session_duration': 'seconds=120'}, ('PATCH', 'stages/user_login/S3/')),
    ({'provider__bind_mode': 'direct'}, ('PATCH', 'providers/ldap/7/')),
    ({'provider__authorization_flow': 'OTHER'}, ('PATCH', 'providers/ldap/7/')),
])
def test_a_real_change_is_written_and_recreates_the_outpost(monkeypatch, drift, written):
    ak = FakeAuthentik(**drift)
    res, composes = run_flow_fix(monkeypatch, ak, recreate='if_changed')
    assert res == (True, None)
    assert written in ak.writes
    assert composes == [(['up', '-d', '--force-recreate', 'ldap'], 'ldap-flow-recreate')]


def test_missing_binding_recreates_the_outpost(monkeypatch):
    ak = FakeAuthentik()
    ak.bindings = ak.bindings[:2]
    _res, composes = run_flow_fix(monkeypatch, ak, recreate='if_changed')
    assert ('POST', 'flows/bindings/') in ak.writes
    assert composes == [(['up', '-d', '--force-recreate', 'ldap'], 'ldap-flow-recreate')]


def test_other_callers_still_always_recreate(monkeypatch):
    # The flow-fix heals outside Reconfigure (LDAP repair buttons, full-stack recreate)
    # keep their recreate: they run because something is already wrong.
    ak = FakeAuthentik()
    _res, composes = run_flow_fix(monkeypatch, ak)
    assert ak.writes == []
    assert composes == [(['up', '-d', '--force-recreate', 'ldap'], 'ldap-flow-recreate')]


def test_reconfigure_asks_for_if_changed_on_both_paths():
    body = _src('run_authentik_deploy')
    assert body.count("_ensure_ldap_flow_authentication_none(recreate='if_changed')") == 2


def test_domain_sync_restarts_only_when_something_differs():
    body = _src('run_authentik_deploy')
    sync = body[body.index('Syncing Authentik domain from Caddy/Domains'):]
    sync = sync[:sync.index('Restarted Authentik (server/worker, then LDAP')]
    gate = sync.index('elif restart_why:')
    # both restarts sit behind the gate, and nothing is written unless it differs
    assert gate < sync.index("['restart', 'server', 'worker']") and gate < sync.index("'--force-recreate', 'ldap'")
    assert 'if new_env != env_lines:' in sync
    assert "brands[0].get('domain') != ak_host" in sync
    assert "cfg.get('authentik_host') != ak_base" in sync
    assert 'Authentik domain unchanged' in sync


def _env_value(stdout, rc=0):
    ns = {'json': json, '_sudo_wrap': lambda c: c,
          'subprocess': types.SimpleNamespace(
              run=lambda cmd, **k: subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=''))}
    exec(compile(_src('_ak_container_env_value'), 'app.py', 'exec'), ns)
    return ns['_ak_container_env_value']('authentik-server-1', 'AUTHENTIK_HOST')


def test_container_env_value():
    assert _env_value(json.dumps(['A=1', 'AUTHENTIK_HOST=https://tak.example.com'])) == 'https://tak.example.com'
    assert _env_value(json.dumps(['A=1'])) == ''
    assert _env_value('', rc=1) is None
    assert _env_value('not json') is None
