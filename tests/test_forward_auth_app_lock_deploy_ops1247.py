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
"""ops #1247: a new module site gets its application compare when its deploy ends.

ops #1108 gives every site behind Authentik two locks. The first is always written. The
second (the application compare) is written only when Authentik already lists the site's
application at the moment the Caddyfile is built. A module that writes its Caddy site first
and makes its Authentik application second (WebODM) left a site with the first lock only,
until the next console restart, update or module deploy: nothing built a Caddyfile after the
application existed.

The fix: a deploy that puts a new provider on the outpost ends with the step the console start
runs (_caddy_app_lock_converge), once Authentik answers again.

app.py cannot be imported in a test, so the helpers are cut out of it and run.
"""
import ast
import json
import os
import pathlib
import re
import threading
import time
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = ('_caddy_forward_auth_lines', '_caddy_app_lock_map', '_caddy_app_lock_saved',
          '_caddy_app_lock_save', '_caddy_app_lock_refresh', '_caddy_app_lock_slug',
          '_caddyfile_app_locks', '_caddy_app_lock_converge', '_caddy_app_lock_after_deploy',
          '_outpost_add_providers_safe')
_CONSTS = ('_CADDY_AK_COPY_HEADERS', '_CADDY_FORWARD_AUTH_URI', '_CADDY_FORWARD_AUTH_PIN',
           'CADDYFILE_USER_BLOCKS_MARKER', '_CADDY_APP_HEADER', '_CADDY_APP_LOCK_MATCHER',
           '_CADDY_APP_LOCK_TEXT', '_CADDY_APP_SLUG_RE', '_CADDY_APP_LOCK_FILE',
           '_caddy_app_lock_cache')
AK = '127.0.0.1:9090'
HOST = 'webodm.example.com'


def _func_src(name):
    found = [ast.get_source_segment(APP, n) for n in ast.walk(TREE)
             if isinstance(n, ast.FunctionDef) and n.name == name]
    assert found, f'{name} is missing from app.py (ops #1247)'
    return found[0]


class _Answer:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body


def _prov(host, slug):
    return {'external_host': f'https://{host}', 'mode': 'forward_single',
            'assigned_application_slug': slug, 'skip_path_regex': ''}


def _deploy_ns(tmp_path, monkeypatch, providers, caddyfile):
    """The deploy helpers with a stand-in Authentik (provider list and outpost), a stand-in
    Caddy and a Caddyfile writer that follows the saved names the way generate_caddyfile does.
    Returns (ns, did, caddyfile path). did['order'] is what happened, in order."""
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / '.env').write_text('X=1\n')
    monkeypatch.setenv('HOME', str(home))
    cfg = tmp_path / 'config'
    cf = tmp_path / 'Caddyfile'
    cf.write_text(caddyfile)
    did = {'order': [], 'patched': [], 'log': [], 'api_up': True, 'providers': providers,
           'on_outpost': [1]}

    ns = {'re': re, 'os': os, 'json': json, 'time': time, 'CONFIG_DIR': str(cfg)}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    ns['_CADDY_APP_LOCK_FILE'] = str(cfg / 'forward_auth_apps.json')

    def api(url, **kw):                     # the provider list the refresh reads
        did['order'].append('ask-authentik')
        return _Answer(json.dumps({'results': did['providers']}).encode())

    def generate(s):
        did['order'].append('caddyfile-built')
        slug = ns['_caddy_app_lock_slug'](ns['_caddy_app_lock_saved'](), HOST, s)
        lines = ns['_caddy_forward_auth_lines'](AK, '        ', app=slug)
        cf.write_text(f'{HOST} {{\n    route {{\n' + '\n'.join(lines) + '\n    }\n}\n')

    def caddy_reload(timeout=0):
        did['order'].append('caddy-reloaded')
        return True, ''

    def reload_outpost(plog=None):
        did['order'].append('authentik-restarted')

    def wait_api(url, headers, max_attempts=90, plog=None, require_200=False):
        did['order'].append('waited-for-authentik')
        return did['api_up']

    ready = threading.Event()
    ready.set()
    ns.update({'load_settings': lambda: {'fqdn': 'example.com'},
               '_get_authentik_env_value': lambda s, k: 'tok' if k == 'AUTHENTIK_BOOTSTRAP_TOKEN' else '',
               '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
               '_ak_api_call': api, 'CADDYFILE_PATH': str(cf),
               '_read_priv': lambda p: pathlib.Path(p).read_text(),
               'generate_caddyfile': generate, '_caddy_reload_if_changed': caddy_reload,
               '_CADDY_REGISTRY_READY': ready, '_reload_embedded_outpost': reload_outpost,
               '_wait_for_authentik_api': wait_api, '_pub_hostport': lambda h, s=None: h})

    def urlopen(req, timeout=0):            # the outpost: list, one instance, the PATCH
        url = req.full_url
        if '/outposts/instances/?search=embedded' in url:
            return _Answer(json.dumps({'results': [{'pk': 'op1', 'name': 'authentik Embedded Outpost',
                                                    'type': 'proxy'}]}).encode())
        if url.endswith('/outposts/instances/op1/') and req.get_method() == 'PATCH':
            body = json.loads(req.data.decode())
            did['patched'].append(body['providers'])
            did['on_outpost'] = body['providers']
            return _Answer(b'{}')
        if url.endswith('/outposts/instances/op1/'):
            return _Answer(json.dumps({'providers': did['on_outpost']}).encode())
        raise AssertionError('unexpected Authentik call: ' + url)
    monkeypatch.setattr(urllib.request, 'urlopen', urlopen)
    return ns, did, cf


# What WebODM leaves after its deploy up to now: the site is written (first lock), and the
# application did not exist yet, so the site has no compare.
_SITE_NO_COMPARE = (f'{HOST} {{\n    route {{\n        forward_auth {AK} {{\n'
                    '            uri /outpost.goauthentik.io/auth/caddy\n        }\n    }\n}\n')
_HEADERS = {'Authorization': 'Bearer x'}


def test_a_deploy_that_adds_a_provider_ends_with_the_compare_in_the_caddyfile(tmp_path, monkeypatch):
    ns, did, cf = _deploy_ns(tmp_path, monkeypatch, [_prov(HOST, 'webodm')], _SITE_NO_COMPARE)
    assert ns['_caddyfile_app_locks'](cf.read_text()) == []              # the hole, as it was
    log = did['log'].append
    assert ns['_outpost_add_providers_safe']('http://127.0.0.1:9090', _HEADERS, [7], plog=log) is True
    assert did['patched'] == [[1, 7]]
    # the new site compares its own application when the deploy is over, with no restart
    assert ns['_caddyfile_app_locks'](cf.read_text()) == ['webodm']
    # in this order: Authentik restarts, answers again, is asked, the file is built, Caddy loads it
    order = did['order']
    assert order.index('authentik-restarted') < order.index('waited-for-authentik') \
        < order.index('ask-authentik') < order.index('caddyfile-built') \
        < order.index('caddy-reloaded')
    assert any('1 site(s) (webodm)' in m for m in did['log']), did['log']


def test_a_deploy_that_adds_nothing_builds_nothing(tmp_path, monkeypatch):
    ns, did, cf = _deploy_ns(tmp_path, monkeypatch, [_prov(HOST, 'webodm')], _SITE_NO_COMPARE)
    did['on_outpost'] = [1, 7]                                           # already on the outpost
    assert ns['_outpost_add_providers_safe']('http://127.0.0.1:9090', _HEADERS, [7]) is False
    assert did['patched'] == []
    assert 'caddyfile-built' not in did['order'] and 'authentik-restarted' not in did['order']


def test_a_deploy_does_not_wait_on_an_authentik_that_does_not_answer(tmp_path, monkeypatch):
    ns, did, cf = _deploy_ns(tmp_path, monkeypatch, [_prov(HOST, 'webodm')], _SITE_NO_COMPARE)
    did['api_up'] = False
    # the provider is on the outpost and the deploy goes on; the next console start adds the compare
    assert ns['_outpost_add_providers_safe']('http://127.0.0.1:9090', _HEADERS, [7],
                                             plog=did['log'].append) is True
    assert 'caddyfile-built' not in did['order']
    assert ns['_caddyfile_app_locks'](cf.read_text()) == []
    assert any('next console start' in m for m in did['log']), did['log']


def test_a_failed_caddyfile_build_never_fails_the_deploy(tmp_path, monkeypatch):
    ns, did, cf = _deploy_ns(tmp_path, monkeypatch, [_prov(HOST, 'webodm')], _SITE_NO_COMPARE)

    def boom(s):
        raise RuntimeError('caddy validate failed')
    ns['generate_caddyfile'] = boom
    assert ns['_outpost_add_providers_safe']('http://127.0.0.1:9090', _HEADERS, [7]) is True


def test_a_site_written_after_the_application_gets_the_compare_too(tmp_path, monkeypatch):
    # The other order (ATLAS, and a module that writes its site last): the converge saved the
    # names, so the site written next compares its application with no second Authentik call.
    ns, did, cf = _deploy_ns(tmp_path, monkeypatch, [_prov(HOST, 'webodm')], '')
    ns['_outpost_add_providers_safe']('http://127.0.0.1:9090', _HEADERS, [7])
    asked = did['order'].count('ask-authentik')
    ns['generate_caddyfile']({})
    assert ns['_caddyfile_app_locks'](cf.read_text()) == ['webodm']
    assert did['order'].count('ask-authentik') == asked


def test_the_tak_portal_deploy_asks_authentik_again_and_ends_with_the_compare():
    src = _func_src('run_takportal_deploy')
    reset = src.index("_caddy_app_lock_cache['ts'] = 0.0")
    build = src.index('generate_caddyfile(settings)', reset)
    apply_ = src.index("_caddy_apply_and_verify(plog, 'TAK Portal'", build)
    end = src.index('_caddy_app_lock_after_deploy(plog)', apply_)
    # the application is made above; the build asks Authentik again; the step comes last
    assert src.index("'slug': 'tak-portal'") < reset < build < apply_ < end


def test_the_authentik_deploy_asks_again_before_it_builds_the_caddyfile():
    src = _func_src('run_authentik_deploy')
    build = src.index('Updating Caddy config...')
    reset = src.index("_caddy_app_lock_cache['ts'] = 0.0", build)
    assert reset < src.index('generate_caddyfile(settings)', build) < reset + 300


def test_every_outpost_provider_add_goes_through_the_one_helper_that_ends_with_the_step():
    src = _func_src('_outpost_add_providers_safe')
    # after the outpost restart, before it returns True
    assert src.index('_reload_embedded_outpost(plog=plog)') \
        < src.index('_caddy_app_lock_after_deploy(plog, ak_url, ak_headers)') \
        < src.index('return True', src.index('_caddy_app_lock_after_deploy('))
