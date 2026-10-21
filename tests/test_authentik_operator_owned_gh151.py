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
"""Operator edits in Authentik survive the daily console restart (GH #151).

The console unit has RuntimeMaxSec=24h, and two startup migrations re-asserted Authentik
fields on every boot: `_ensure_authentik_login_copy` put the brand title (and the login
header / MFA button labels) back, and `_heal_authentik_proxy_chain_all_services` put the
infra-TAK application's open_in_new_tab back to False. An operator's change lasted a day.

Both are operator-owned now: the copy is seeded once, and open_in_new_tab is only set when
the healer creates the application. The functions run from the shipped app.py text.
"""

import ast
import io
import json
import pathlib
import types
import urllib.error
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

AK = 'http://ak'


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    return '\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                     if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets))


class FakeAuthentik:
    """Just enough of the Authentik v3 API for the two functions under test."""

    def __init__(self, stock=True):
        self.brand = {'brand_uuid': 'b1', 'branding_title': 'authentik' if stock else 'infra-TAK'}
        self.flow = {'slug': 'default-authentication-flow',
                     'title': 'Welcome to authentik!' if stock else 'Sign in'}
        self.stages = {'totp': [{'pk': 't1', 'friendly_name': None}],
                       'webauthn': [{'pk': 'w1', 'friendly_name': None}]}
        self.apps = {}
        self.providers = [{'pk': 7, 'name': 'infra-TAK', 'external_host': 'https://infratak.example.com',
                           'cookie_domain': '.example.com'}]
        self.writes = []
        self.down = False
        self.fail_patch = False

    def call(self, url, data=None, method='GET', headers=None, **_kw):
        if self.down:
            raise OSError('connection refused')
        path = url[len(AK) + len('/api/v3/'):]
        body = json.loads(data.decode()) if data else None
        if method != 'GET':
            if self.fail_patch:
                raise OSError('timed out')
        out = self._route(method, path, body)
        if method != 'GET':                        # only writes Authentik accepted
            self.writes.append((method, path, body))
        return io.BytesIO(json.dumps(out).encode())

    def _route(self, method, path, body):
        if path == 'core/brands/':
            return {'results': [dict(self.brand)]}
        if path == 'core/brands/b1/':
            self.brand.update(body)
            return self.brand
        if path.startswith('flows/instances/?slug=default-authentication-flow'):
            return {'results': [dict(self.flow)]}
        if path == 'flows/instances/default-authentication-flow/':
            self.flow.update(body)
            return self.flow
        if path.startswith('flows/instances/?designation='):
            return {'results': [{'pk': 'f1', 'slug': 'default-provider-authorization-implicit-consent'}]}
        for kind, stages in self.stages.items():
            if path.startswith(f'stages/authenticator/{kind}/?'):
                return {'results': [dict(s) for s in stages]}
            for s in stages:
                if path == f'stages/authenticator/{kind}/{s["pk"]}/':
                    s.update(body)
                    return s
        if path.startswith('providers/proxy/?'):
            return {'results': self.providers}
        for p in self.providers:
            if path == f'providers/proxy/{p["pk"]}/':
                if method in ('PUT', 'PATCH'):
                    p.update(body)
                return dict(p)
        if path == 'core/applications/' and method == 'POST':
            if body['slug'] in self.apps:          # Authentik: slug must be unique
                raise urllib.error.HTTPError(path, 400, 'slug exists', {}, io.BytesIO(b''))
            self.apps[body['slug']] = dict(body)
            return body
        if path.startswith('core/applications/'):
            slug = path.split('/')[2]
            if slug not in self.apps:
                raise urllib.error.HTTPError(path, 404, 'not found', {}, io.BytesIO(b''))
            if method == 'PATCH':
                self.apps[slug].update(body)
            return self.apps[slug]
        raise AssertionError(f'unexpected Authentik call {method} {path}')


class Box:
    def __init__(self, ak, settings=None):
        self.ak = ak
        self.settings = {'fqdn': 'example.com'} if settings is None else settings
        self.log = []
        self.deployed = {'infratak'}

    def ns(self):
        ns = {
            'json': json, 'urllib': urllib, 'time': types.SimpleNamespace(sleep=lambda s: None),
            'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: True,
                                                                   expanduser=lambda p: p)),
            'load_settings': lambda: dict(self.settings),
            'save_settings': self.settings.update,
            '_ak_api_call': self.ak.call,
            '_w1_ak_ctx': lambda: (AK, {}, dict(self.settings)),
            '_get_authentik_env_value': lambda s, k: 'tok',
            '_get_authentik_api_url': lambda s: AK,
            'detect_modules': lambda fresh=False: {},
            '_is_module_deployed': lambda s, k: k in self.deployed,
            '_get_service_domain': lambda s, k: f'{k}.example.com',
            '_outpost_add_providers_safe': lambda *a, **k: False,
            '_deregister_authentik_proxy_app': lambda *a, **k: None,
            '_get_fedhub_deployment_config': lambda s: {},
        }
        exec(compile(_consts('AK_BRAND_TITLE', 'AK_AUTH_FLOW_TITLE', 'AK_TOTP_FRIENDLY',
                             'AK_WEBAUTHN_FRIENDLY', '_AUTHENTIK_PROXY_CHAIN_SERVICES'), 'app.py', 'exec'), ns)
        exec(compile(_func('_w1_ak_get'), 'app.py', 'exec'), ns)
        exec(compile(_func('_ensure_authentik_login_copy') + '\n\n'
                     + _func('_heal_authentik_proxy_chain_all_services'), 'app.py', 'exec'), ns)
        return ns

    def boot(self):
        """What the startup migrations do on each console start."""
        ns = self.ns()
        ns['_ensure_authentik_login_copy'](self.log.append)
        ns['_heal_authentik_proxy_chain_all_services'](plog=self.log.append, settings=dict(self.settings))

    def update(self, monkeypatch):
        """What a console update does to the apps: the Authentik reconfigure runs
        _ensure_authentik_console_app, then the post-update chain healer, then the console
        restarts onto the new code (a boot)."""
        def urlopen(req, timeout=None):
            return self.ak.call(req.get_full_url(), req.data, req.get_method())
        monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
        ns = self.ns()
        if 'def _authentik_application_open_in_new_tab(' in APP:   # pre-fix app.py
            exec(compile(_func('_authentik_application_open_in_new_tab'), 'app.py', 'exec'), ns)
        exec(compile(_func('_ensure_authentik_console_app'), 'app.py', 'exec'), ns)
        assert ns['_ensure_authentik_console_app']('example.com', 'tok', self.log.append, ak_url=AK)
        ns['_heal_authentik_proxy_chain_all_services'](plog=self.log.append, settings=dict(self.settings))
        self.boot()


# --- login copy: seeded once ---------------------------------------------------------

def test_fresh_box_gets_the_copy_once_and_records_it():
    box = Box(FakeAuthentik(stock=True))
    box.boot()
    assert box.ak.brand['branding_title'] == 'infra-TAK'
    assert box.ak.flow['title'] == 'Sign in'
    assert box.ak.stages['totp'][0]['friendly_name'] == 'Authenticator App - Scan a QR code'
    assert box.ak.stages['webauthn'][0]['friendly_name'] == 'Use a Passkey'
    assert box.settings['authentik_login_copy_seeded'] is True


def test_operator_brand_title_survives_the_daily_restart():
    box = Box(FakeAuthentik(stock=True))
    box.boot()
    box.ak.brand['branding_title'] = 'County SO'          # operator edit in Authentik
    box.ak.flow['title'] = 'County login'
    box.ak.writes.clear()
    for _ in range(3):                                     # RuntimeMaxSec=24h, three days
        box.boot()
    assert box.ak.brand['branding_title'] == 'County SO'
    assert box.ak.flow['title'] == 'County login'
    assert not [w for w in box.ak.writes if w[1].startswith(('core/brands', 'flows/', 'stages/'))]


def test_upgrade_keeps_an_edit_made_since_the_last_boot():
    # Box seeded by an earlier release (copy in place, no marker), then the operator
    # retitled the brand. The first boot on the fixed release must not revert it.
    ak = FakeAuthentik(stock=False)
    ak.brand['branding_title'] = 'County SO'
    box = Box(ak)
    box.boot()
    assert ak.brand['branding_title'] == 'County SO'
    assert box.settings['authentik_login_copy_seeded'] is True
    assert not [w for w in ak.writes if w[1].startswith(('core/brands', 'flows/', 'stages/'))]


def test_unreachable_authentik_is_retried_next_boot():
    ak = FakeAuthentik(stock=True)
    ak.down = True
    box = Box(ak)
    box.ns()['_ensure_authentik_login_copy'](box.log.append)
    assert 'authentik_login_copy_seeded' not in box.settings
    ak.down = False
    box.boot()
    assert ak.brand['branding_title'] == 'infra-TAK'
    assert box.settings['authentik_login_copy_seeded'] is True


def test_failed_write_is_retried_next_boot():
    ak = FakeAuthentik(stock=True)
    ak.fail_patch = True
    box = Box(ak)
    box.ns()['_ensure_authentik_login_copy'](box.log.append)
    assert 'authentik_login_copy_seeded' not in box.settings


# --- chain healer: open_in_new_tab on create only --------------------------------------

def test_healer_creates_app_with_catalog_launch_setting():
    box = Box(FakeAuthentik(stock=False), settings={'fqdn': 'example.com', 'authentik_login_copy_seeded': True})
    box.boot()
    assert box.ak.apps['infratak']['open_in_new_tab'] is False
    assert box.ak.apps['infratak']['provider'] == 7


def test_operator_open_in_new_tab_survives_the_daily_restart():
    box = Box(FakeAuthentik(stock=False), settings={'fqdn': 'example.com', 'authentik_login_copy_seeded': True})
    box.boot()
    box.ak.apps['infratak']['open_in_new_tab'] = True     # operator edit in Authentik
    box.ak.writes.clear()
    for _ in range(3):
        box.boot()
    assert box.ak.apps['infratak']['open_in_new_tab'] is True
    assert not [w for w in box.ak.writes if w[1].startswith('core/applications/')]


def test_healer_still_repairs_a_wrong_provider_link_without_touching_launch_setting():
    box = Box(FakeAuthentik(stock=False), settings={'fqdn': 'example.com', 'authentik_login_copy_seeded': True})
    box.ak.apps['infratak'] = {'slug': 'infratak', 'provider': 99, 'open_in_new_tab': True}
    box.boot()
    assert box.ak.apps['infratak']['provider'] == 7
    assert box.ak.apps['infratak']['open_in_new_tab'] is True
    patches = [w for w in box.ak.writes if w[1] == 'core/applications/infratak/']
    assert patches == [('PATCH', 'core/applications/infratak/', {'provider': 7})]


def test_healer_writes_open_in_new_tab_only_in_the_create_body():
    src = _func('_heal_authentik_proxy_chain_all_services')
    hits = [l.strip() for l in src.splitlines() if "'open_in_new_tab'" in l]
    assert hits == ["'open_in_new_tab': bool(open_new_tab)}"], hits


# --- console update: the Authentik reconfigure step (#151 follow-up) --------------------
#
# A console update runs the Authentik reconfigure, which calls _ensure_authentik_console_app
# for infra-TAK (+ MediaMTX). It PATCHed open_in_new_tab=True onto the existing apps; before
# #153 the healer flipped infra-TAK back to False right after, so an operator who chose
# True kept it, but one who chose False lost it on every update.

def _seeded_box():
    return Box(FakeAuthentik(stock=False), settings={'fqdn': 'example.com', 'authentik_login_copy_seeded': True})


def test_update_creates_console_apps_with_catalog_launch_setting(monkeypatch):
    box = _seeded_box()
    box.deployed.add('mediamtx')
    box.ak.providers.append({'pk': 8, 'name': 'MediaMTX', 'external_host': 'https://mediamtx.example.com',
                             'cookie_domain': '.example.com'})
    box.update(monkeypatch)
    assert box.ak.apps['infratak']['open_in_new_tab'] is False
    assert box.ak.apps['stream']['open_in_new_tab'] is True


@pytest.mark.parametrize('choice', [True, False])
def test_operator_launch_setting_survives_a_console_update(monkeypatch, choice):
    box = _seeded_box()
    box.deployed.add('mediamtx')
    box.ak.providers.append({'pk': 8, 'name': 'MediaMTX', 'external_host': 'https://mediamtx.example.com',
                             'cookie_domain': '.example.com'})
    box.update(monkeypatch)
    box.ak.apps['infratak']['open_in_new_tab'] = choice      # operator edits in Authentik
    box.ak.apps['stream']['open_in_new_tab'] = choice
    box.ak.writes.clear()
    for _ in range(2):
        box.update(monkeypatch)
    assert box.ak.apps['infratak']['open_in_new_tab'] is choice
    assert box.ak.apps['stream']['open_in_new_tab'] is choice
    assert not [w for w in box.ak.writes if 'open_in_new_tab' in (w[2] or {})]


def test_update_still_relinks_a_wrong_provider_without_touching_launch_setting(monkeypatch):
    box = _seeded_box()
    box.ak.apps['infratak'] = {'slug': 'infratak', 'provider': 99, 'open_in_new_tab': True}
    box.update(monkeypatch)
    assert box.ak.apps['infratak']['provider'] == 7
    assert box.ak.apps['infratak']['open_in_new_tab'] is True


def _open_in_new_tab_dicts(path):
    src = path.read_text(encoding='utf-8')
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            if 'open_in_new_tab' in keys:
                yield node.lineno, keys


@pytest.mark.parametrize('rel', ['app.py', *sorted(str(p.relative_to(REPO))
                                                   for p in (REPO / 'modules').glob('*.py'))])
def test_open_in_new_tab_is_only_written_when_an_app_is_created(rel):
    # A create body carries the slug; a PATCH onto an existing app does not. Every deploy,
    # reconfigure and update path used to PATCH it back to True on existing apps.
    bad = [line for line, keys in _open_in_new_tab_dicts(REPO / rel) if 'slug' not in keys]
    assert not bad, f'{rel}: open_in_new_tab written outside a create body at lines {bad}'
    assert '_authentik_application_open_in_new_tab' not in (REPO / rel).read_text(encoding='utf-8')
