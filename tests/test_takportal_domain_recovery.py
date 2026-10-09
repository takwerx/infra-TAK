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
"""A TAK Portal installed before the box had a domain can be moved onto it in one click (v10.2.8 W12).

bcg-tak, 2026-10-09: Delete → "TAK: Unable to list certificates from /api/certadmin/cert;
refusing to proceed"; the invite email's link → Brevo redirect → `http://149.20.250.162:3000/`.
Portal had been seeded while the box had no fqdn (TAK_URL / TAK_PORTAL_PUBLIC_URL /
AUTHENTIK_PUBLIC_URL from the IP); those keys are seed-only since v10.1.42, so adding the domain
never reached them and Update config truthfully changed nothing.

The recovery must not break the operator-owned rule: nothing is inferred from the value to
OVERWRITE anything — the value only decides what the card shows; the write happens on the
operator's press, for the keys they pressed it for.
"""

import ast
import ipaddress
import json
import os
import pathlib
import re
import types
import urllib.parse

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TPL = (REPO / 'templates' / 'takportal.html').read_text(encoding='utf-8')
TREE = ast.parse(APP)

IP_SEEDED = {
    'TAK_URL': 'https://149.20.250.162:8443/Marti',
    'TAK_PORTAL_PUBLIC_URL': 'http://149.20.250.162:3000',
    'AUTHENTIK_PUBLIC_URL': 'http://149.20.250.162:9090',
    'TAK_SSH_USER': 'root',
    'BRAND_LOGO_URL': 'https://example.org/logo.png',
    'AUTHENTIK_TOKEN': 'old-token',
}
BUILT = {
    'TAK_URL': 'https://takserver.ops1.example.com:8443/Marti',
    'TAK_PORTAL_PUBLIC_URL': 'https://takportal.ops1.example.com',
    'AUTHENTIK_PUBLIC_URL': 'https://tak.ops1.example.com',
    'TAK_SSH_USER': 'takwerx',
    'AUTHENTIK_TOKEN': 'new-token',
    'AUTHENTIK_URL': 'http://authentik-server-1:9000',
}


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _consts(*names):
    return '\n'.join(ast.get_source_segment(APP, n) for n in TREE.body
                     if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) in names for t in n.targets))


def _load(names, ns=None, consts=('TAKPORTAL_DOMAIN_KEYS', '_TAKPORTAL_DOMAIN_KEY_INFO',
                                  'TAKPORTAL_AUTHORITATIVE_KEYS', 'EMAIL_TRANSPORT_KEYS')):
    ns = {} if ns is None else ns
    for k, v in {'os': os, 're': re, 'json': json, 'ipaddress': ipaddress, 'urllib': urllib}.items():
        ns.setdefault(k, v)
    exec(compile(_consts(*consts), 'app.py', 'exec'), ns)
    exec(compile('\n\n'.join(_func(n) for n in names), 'app.py', 'exec'), ns)
    return ns


def _detect_ns(tak_local=True):
    ns = {'os': types.SimpleNamespace(path=types.SimpleNamespace(isdir=lambda p: tak_local and p == '/opt/tak'))}
    return _load(['_url_host_is_address', '_takportal_stale_address_fields'], ns)


@pytest.mark.parametrize('url,want', [
    ('https://149.20.250.162:8443/Marti', True), ('http://[2001:db8::1]:3000', True),
    ('https://host.docker.internal:8443/Marti', True), ('http://localhost:3000', True),
    ('https://takportal.ops1.bcg-tak.com', False), ('', False), ('not a url', False),
])
def test_address_hosts(url, want):
    assert _load(['_url_host_is_address'])['_url_host_is_address'](url) is want


def test_ip_seeded_portal_on_a_box_with_a_domain_lists_all_three():
    ns = _detect_ns()
    f = ns['_takportal_stale_address_fields']({'fqdn': 'ops1.example.com'}, existing=IP_SEEDED, built=BUILT)
    assert [x['key'] for x in f] == ['TAK_URL', 'TAK_PORTAL_PUBLIC_URL', 'AUTHENTIK_PUBLIC_URL']
    pub = f[1]
    assert pub['current'] == 'http://149.20.250.162:3000' and pub['suggested'] == 'https://takportal.ops1.example.com'
    assert pub['label'] == 'TAK Portal Public URL' and 'email' in pub['effect']


def test_nothing_is_listed_without_a_domain_or_for_a_domain_the_operator_typed():
    ns = _detect_ns()
    f = ns['_takportal_stale_address_fields']
    assert f({}, existing=IP_SEEDED, built=BUILT) == []
    custom = dict(IP_SEEDED, TAK_PORTAL_PUBLIC_URL='https://portal.agency.gov', TAK_URL='https://tak.agency.gov:8443/Marti')
    assert [x['key'] for x in f({'fqdn': 'ops1.example.com'}, existing=custom, built=BUILT)] == ['AUTHENTIK_PUBLIC_URL']
    blank = dict(IP_SEEDED, TAK_URL='', TAK_PORTAL_PUBLIC_URL='', AUTHENTIK_PUBLIC_URL='')
    assert f({'fqdn': 'ops1.example.com'}, existing=blank, built=BUILT) == [], 'blank is the seed path, not this card'


def test_tak_url_is_left_alone_when_tak_server_is_not_on_this_box():
    """A portal aimed at a REMOTE TAK by IP may mean it, and the container alias covers a local TAK only."""
    ns = _detect_ns(tak_local=False)
    f = ns['_takportal_stale_address_fields']({'fqdn': 'ops1.example.com'}, existing=IP_SEEDED, built=BUILT)
    assert 'TAK_URL' not in [x['key'] for x in f]


def _merge_ns(existing, relay=False):
    ns = {'_takportal_get_existing_settings': lambda: dict(existing),
          '_takportal_build_settings_dict': lambda s: dict(BUILT),
          '_takportal_settings_value_is_blank': lambda v: v is None or (isinstance(v, str) and not v.strip())}
    return _load(['_takportal_merged_settings_json'], ns)


def test_merge_without_adopt_keeps_every_operator_value():
    ns = _merge_ns(IP_SEEDED)
    out = json.loads(ns['_takportal_merged_settings_json']({}))
    for k in ('TAK_URL', 'TAK_PORTAL_PUBLIC_URL', 'AUTHENTIK_PUBLIC_URL', 'TAK_SSH_USER'):
        assert out[k] == IP_SEEDED[k]
    assert out['AUTHENTIK_TOKEN'] == 'new-token', 'authoritative keys still follow infra-TAK'


def test_merge_adopt_moves_only_the_pressed_domain_keys():
    ns = _merge_ns(IP_SEEDED)
    out = json.loads(ns['_takportal_merged_settings_json']({}, adopt=['TAK_PORTAL_PUBLIC_URL', 'TAK_SSH_USER']))
    assert out['TAK_PORTAL_PUBLIC_URL'] == 'https://takportal.ops1.example.com'
    assert out['TAK_SSH_USER'] == 'root', 'adopt is limited to TAKPORTAL_DOMAIN_KEYS (Justin Davis/TN rule)'
    assert out['TAK_URL'] == IP_SEEDED['TAK_URL'], 'a key not pressed stays as it was'
    assert out['BRAND_LOGO_URL'] == IP_SEEDED['BRAND_LOGO_URL']


class _Route:
    def __init__(self, body, stale_keys=('TAK_URL', 'TAK_PORTAL_PUBLIC_URL', 'AUTHENTIK_PUBLIC_URL'),
                 write_ok=True, override_changed=False, keeps=True):
        self.body, self.write_ok, self.override_changed, self.keeps = body, write_ok, override_changed, keeps
        self.stale = [{'key': k, 'suggested': BUILT[k], 'label': k, 'current': IP_SEEDED[k], 'effect': ''}
                      for k in stale_keys]
        self.adopted, self.runs, self.restarts, self.writes = None, [], 0, []

    def ns(self):
        def merged(settings, adopt=()):
            self.adopted = list(adopt)
            return 'MERGED'

        def write(js, plog=None):
            self.writes.append(js)
            return self.write_ok, '' if self.write_ok else 'docker cp failed'

        def restart():
            self.restarts += 1
            return True

        def existing():
            return dict(IP_SEEDED, **({k: BUILT[k] for k in self.adopted or ()} if self.keeps else {}))
        return {
            'load_settings': lambda: {'fqdn': 'ops1.example.com'},
            'request': types.SimpleNamespace(get_json=lambda silent=True: self.body),
            'jsonify': lambda d: d,
            '_takportal_stale_address_fields': lambda s: self.stale,
            '_takportal_merged_settings_json': merged,
            '_takportal_write_settings_json': write,
            '_takportal_dir': lambda: '/home/takwerx/TAK-Portal',
            '_write_takportal_override': lambda: self.override_changed,
            '_takportal_app_services': lambda d: ['tak-portal', 'tak-portal-worker'],
            '_sudo_wrap': lambda a: a,
            'subprocess': types.SimpleNamespace(run=lambda a, **k: self.runs.append(a) or types.SimpleNamespace(returncode=0)),
            '_takportal_restart': restart,
            '_takportal_get_existing_settings': existing,
            'print': lambda *a, **k: None,
        }

    def call(self):
        # ast's FunctionDef segment starts at `def`, so the Flask decorators are not exec'd.
        r = _load(['takportal_use_domain_api'], self.ns())['takportal_use_domain_api']()
        return r if isinstance(r, tuple) else (r, 200)


def test_use_domain_writes_only_requested_stale_keys_through_the_single_writer():
    rt = _Route({'keys': ['TAK_PORTAL_PUBLIC_URL', 'TAK_SSH_USER', 'AUTHENTIK_PUBLIC_URL']})
    body, code = rt.call()
    assert code == 200 and body['success'] is True
    assert rt.adopted == ['TAK_PORTAL_PUBLIC_URL', 'AUTHENTIK_PUBLIC_URL']
    assert rt.writes == ['MERGED'] and rt.restarts == 1 and rt.runs == []
    assert body['changed'] == {'TAK_PORTAL_PUBLIC_URL': BUILT['TAK_PORTAL_PUBLIC_URL'],
                               'AUTHENTIK_PUBLIC_URL': BUILT['AUTHENTIK_PUBLIC_URL']}


def test_use_domain_recreates_app_services_only_when_the_alias_changed_and_never_postgres():
    rt = _Route({'keys': ['TAK_URL']}, override_changed=True)
    body, _ = rt.call()
    assert body['success'] and rt.restarts == 0
    assert rt.runs == [['docker', 'compose', 'up', '-d', '--no-deps', 'tak-portal', 'tak-portal-worker']]
    assert '--force-recreate' not in _func('takportal_use_domain_api'), 'that would recreate Portal\'s Postgres'


@pytest.mark.parametrize('body', [{}, {'keys': []}, {'keys': 'TAK_URL'}, {'keys': [1]}])
def test_use_domain_rejects_malformed_requests(body):
    rt = _Route(body)
    _, code = rt.call()
    assert code == 400 and rt.writes == []


def test_use_domain_with_nothing_stale_writes_nothing():
    rt = _Route({'keys': ['TAK_URL']}, stale_keys=())
    body, code = rt.call()
    assert code == 200 and body['changed'] == {} and rt.writes == []


def test_use_domain_reports_when_portal_did_not_keep_the_values():
    rt = _Route({'keys': ['TAK_URL']}, keeps=False)
    body, _ = rt.call()
    assert body['success'] is False and 'did not keep' in body['error']


def test_routes_are_login_required():
    for name, path in (('takportal_use_domain_api', "/api/takportal/use-domain', methods=['POST']"),
                       ('takportal_address_check_api', "/api/takportal/address-check'")):
        i = APP.index(f'def {name}(')
        head = APP[APP.rindex('@app.route', 0, i):i]
        assert path in head and '@login_required' in head


def test_update_config_names_the_fields_it_does_not_change():
    body = APP[APP.index("elif action == 'reconfigure':"):APP.index("elif action == 'update':")]
    assert '_takportal_stale_address_fields(settings)' in body and 'Use the domain' in body


def test_diagnostics_shows_the_three_addresses_and_never_the_token():
    d = _func('_diag_section_takportal')
    assert 'TAKPORTAL_DOMAIN_KEYS' in d and '_takportal_stale_address_fields(' in d
    assert 'AUTHENTIK_TOKEN' not in d


def test_page_card_builds_values_with_text_nodes_only():
    assert 'id="portal-address-card"' in TPL and "fetch('/api/takportal/address-check')" in TPL
    js = TPL[TPL.index('async function portalAddressCheck'):TPL.index('{% if deploying %}pollDeployLog();')]
    assert 'innerHTML' not in js, 'Portal settings values are operator-controlled text'
    assert "addEventListener('click',portalUseDomain)" in js and 'onclick=' not in js
