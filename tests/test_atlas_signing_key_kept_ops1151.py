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
"""ops #1151: an ATLAS deployment on Authentik's signed token keeps its signing key.

Authentik takes the signing key off a proxy provider on every save through its proxy
provider API (`ProxyProviderSerializer.update` calls `set_oauth_defaults()`, which sets
`signing_key = None`; authentik/providers/proxy/api.py and models.py at version/2026.8.5).
ATLAS on `jwt` refuses the HS256 token Authentik then sends, so every administrator gets 401.

The fake Authentik below follows that rule. Three things are tested:

1. the console step that runs after every console update writes nothing to a provider
   whose cookie_domain is already right, so the key stays;
2. when something else took the key off, the module finds that and puts it back;
3. a rollback to a release without the signed token puts ATLAS back on headers first.

app.py cannot be imported in a test, so its functions are cut out of it and run.
"""

import ast
import io
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
ATLAS_SRC = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')

PROVIDER = 'ATLAS MDM Proxy (corona)'
KEY_NAME = 'ATLAS token signing — ' + PROVIDER
CORONA = {'slug': 'corona', 'name': 'Corona'}
PUBLIC = 'https://tak.example.org'
HOST = 'atlas.corona.example.org'
CADDY_READY = """
atlas.corona.example.org {
    route {
        forward_auth 127.0.0.1:9090 {
            uri /outpost.goauthentik.io/auth/caddy
            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Jwt
        }
        reverse_proxy 127.0.0.1:8088
    }
}
"""


class Authentik:
    """Proxy providers with Authentik's own rule: a save through the proxy API takes the
    signing key off; the OAuth2 API is the one that can set it."""

    def __init__(self, cookie_domain='.example.org', signing_key='key-1'):
        self.providers = {
            49: {'pk': 49, 'name': PROVIDER, 'client_id': 'cid-49',
                 'cookie_domain': cookie_domain, 'signing_key': signing_key},
            7: {'pk': 7, 'name': 'TAK Portal Proxy', 'client_id': 'cid-7',
                'cookie_domain': cookie_domain, 'signing_key': None},
        }
        self.keys = {'key-1': {'pk': 'key-1', 'name': KEY_NAME}} if signing_key else {}
        # The embedded outpost serves both providers; a second proxy outpost serves only
        # TAK Portal's; the LDAP outpost is not a sign-in service for either.
        self.outposts = {
            'op-emb': {'pk': 'op-emb', 'name': 'authentik Embedded Outpost', 'type': 'proxy',
                       'providers': [7, 49]},
            'op-other': {'pk': 'op-other', 'name': 'Other proxy', 'type': 'proxy',
                         'providers': [7]},
            'op-ldap': {'pk': 'op-ldap', 'name': 'LDAP', 'type': 'ldap', 'providers': [49]},
        }
        self.outposts_fail = False
        self.writes = []
        self.fail = False

    def __call__(self, req, timeout=None):
        if self.fail:
            raise urllib.error.URLError('timed out')
        url = urllib.parse.urlparse(req.full_url)
        path = url.path.split('/api/v3/', 1)[1]
        query = dict(urllib.parse.parse_qsl(url.query))
        method = req.get_method()
        body = json.loads(req.data.decode()) if req.data else None
        if method != 'GET':
            self.writes.append((method, path, body))
        out = self.handle(method, path, query, body)
        return io.BytesIO(json.dumps(out).encode() if out is not None else b'')

    def handle(self, method, path, query, body):
        if path == 'providers/proxy/':
            rows = [dict(p) for p in self.providers.values()
                    if query.get('name', '') in p['name']]
            for row in rows:
                row.pop('signing_key', None)        # not a field of the proxy API
            return {'results': rows}
        if path.startswith('providers/proxy/'):
            pk = int(path.split('/')[2])
            if method in ('PATCH', 'PUT'):
                self.providers[pk].update(body)
                self.providers[pk]['signing_key'] = None      # set_oauth_defaults()
            return dict(self.providers[pk])
        if path.startswith('providers/oauth2/'):
            pk = int(path.split('/')[2])
            if method == 'PATCH':
                self.providers[pk].update(body)
            return dict(self.providers[pk])
        if path == 'crypto/certificatekeypairs/':
            return {'results': [k for k in self.keys.values()
                                if query.get('name', '') in k['name']]}
        if path == 'crypto/certificatekeypairs/generate/':
            key = {'pk': 'key-%d' % (len(self.keys) + 1), 'name': body['common_name']}
            self.keys[key['pk']] = key
            return key
        if path.startswith('outposts/instances/'):
            if self.outposts_fail:
                raise urllib.error.URLError('timed out')
            if path == 'outposts/instances/':
                return {'results': [dict(o) for o in self.outposts.values()]}
            pk = path.split('/')[2]
            if method == 'PATCH':
                self.outposts[pk].update(body)
            return dict(self.outposts[pk])
        raise AssertionError('unexpected %s %s' % (method, path))


def _cookie_domain_step(converged):
    """`_ensure_proxy_providers_cookie_domain` as app.py ships it."""
    ns = {'json': json,
          '_atlas_signed_identity_converge': lambda log=None: converged.append(True)}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and \
                node.name == '_ensure_proxy_providers_cookie_domain':
            exec(ast.get_source_segment(APP, node), ns)
    return ns['_ensure_proxy_providers_cookie_domain']


def ctx():
    return {
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: 'admin-token' if k == 'AUTHENTIK_TOKEN' else None,
        '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
    }


@pytest.fixture
def sid():
    from modules import atlas_signed_identity
    return atlas_signed_identity


@pytest.fixture
def atlas():
    import modules.atlas
    return modules.atlas


# --------------------------------------------------------------------------- #
# 1. The step that runs after every console update
# --------------------------------------------------------------------------- #


def test_the_console_update_step_leaves_the_signing_key_on(monkeypatch):
    """The proof test. Before the fix this step PATCHed cookie_domain on every provider,
    every time, and Authentik took the ATLAS signing key off with it."""
    fake, converged = Authentik(cookie_domain='.example.org'), []
    monkeypatch.setattr(urllib.request, 'urlopen', fake)
    _cookie_domain_step(converged)('http://127.0.0.1:9090', {'Authorization': 'Bearer t'},
                                   'example.org')
    assert fake.providers[49]['signing_key'] == 'key-1', \
        'the console update step took the ATLAS signing key off: %r' % fake.writes
    assert fake.writes == []


def test_a_wrong_cookie_domain_is_still_fixed_and_the_key_check_runs_after(monkeypatch):
    fake, converged = Authentik(cookie_domain='.old.example.net'), []
    monkeypatch.setattr(urllib.request, 'urlopen', fake)
    _cookie_domain_step(converged)('http://127.0.0.1:9090', {'Authorization': 'Bearer t'},
                                   'example.org:8443')
    assert [p['cookie_domain'] for p in fake.providers.values()] == ['.example.org'] * 2
    assert len(fake.writes) == 2
    # The write took the key off, so the ATLAS module is asked to put it back.
    assert converged == [True]


def test_the_key_check_runs_even_when_authentik_does_not_answer(monkeypatch):
    fake, converged = Authentik(), []
    fake.fail = True
    monkeypatch.setattr(urllib.request, 'urlopen', fake)
    _cookie_domain_step(converged)('http://127.0.0.1:9090', {}, 'example.org')
    assert converged == [True]


# --------------------------------------------------------------------------- #
# 2. Finding a lost key, and putting it back
# --------------------------------------------------------------------------- #


def test_a_save_through_the_proxy_api_is_seen_as_a_lost_key(sid):
    fake = Authentik()
    assert sid.key_lost(ctx(), CORONA, opener=fake) is False
    # What a cookie_domain PATCH, a host fix or Save in Authentik's admin page does.
    fake.handle('PATCH', 'providers/proxy/49/', {}, {'cookie_domain': '.example.org'})
    assert sid.key_lost(ctx(), CORONA, opener=fake) is True
    assert fake.writes == []                       # looking never writes


def test_a_deleted_key_pair_is_a_lost_key(sid):
    fake = Authentik()
    fake.keys.clear()
    assert sid.key_lost(ctx(), CORONA, opener=fake) is True


def test_could_not_look_is_not_a_lost_key(sid):
    fake = Authentik()
    fake.fail = True
    assert sid.key_lost(ctx(), CORONA, opener=fake) is False
    no_provider = Authentik()
    no_provider.providers.pop(49)
    assert sid.key_lost(ctx(), CORONA, opener=no_provider) is False
    no_token = dict(ctx(), _get_authentik_env_value=lambda s, k: None)
    assert sid.key_lost(no_token, CORONA, opener=Authentik()) is False


def test_the_switch_puts_a_lost_key_back_and_stays_on_the_signed_token(sid, monkeypatch):
    monkeypatch.setattr('modules.atlas_roster.authentik_public_url', lambda c, s: PUBLIC)
    fake = Authentik()
    fake.handle('PATCH', 'providers/proxy/49/', {}, {'cookie_domain': '.example.org'})
    env = {sid.ENV_SOURCE: 'jwt', sid.ENV_AUDIENCE: 'cid-49',
           sid.ENV_JWKS: PUBLIC + '/application/o/atlas-corona/jwks/'}

    def write(path, key, value):
        changed = env.get(key) != value
        env[key] = value
        return changed

    def jwks(req, timeout=None):
        published = bool(fake.providers[49]['signing_key'])
        return io.BytesIO(json.dumps({'keys': [{'kid': 'k'}]} if published else {}).encode())

    result = sid.ensure(ctx(), CORONA, '/opt/atlas-corona', write, lambda m: None, HOST,
                        opener=fake, jwks_opener=jwks, caddyfile=CADDY_READY,
                        compose_passes=lambda d: {sid.ENV_SOURCE})
    assert result == {'env_changed': False, 'source': 'jwt'}
    assert fake.providers[49]['signing_key'] == 'key-1'
    # ops #1151: the key, then the outpost that serves this provider is told (below).
    assert fake.writes == [
        ('PATCH', 'providers/oauth2/49/', {'signing_key': 'key-1'}),
        ('PATCH', 'outposts/instances/op-emb/', {'name': 'authentik Embedded Outpost'})]
    assert sid.key_lost(ctx(), CORONA, opener=fake) is False


# ---------------------------------------------------------------------------
# Authentik's sign-in service is told about a new key (ops #1151)
#
# ✅ Seen on a box, Nov 24, 2026 (Rocky 9, Authentik 2026.8.5): the key was set through the
# OAuth2 endpoint at 08:36:18 and every ATLAS sign-in ended in a redirect loop until the
# embedded outpost's own five-minute refresh at 08:40:53. A save of the outpost with the
# name it already has made it refresh one second later.
# ---------------------------------------------------------------------------

def _switch(sid, monkeypatch, fake, log=None):
    monkeypatch.setattr('modules.atlas_roster.authentik_public_url', lambda c, s: PUBLIC)
    env = {}

    def write(path, key, value):
        changed = env.get(key) != value
        env[key] = value
        return changed

    def jwks(req, timeout=None):
        published = bool(fake.providers[49]['signing_key'])
        return io.BytesIO(json.dumps({'keys': [{'kid': 'k'}]} if published else {}).encode())

    lines = log if log is not None else []
    return sid.ensure(ctx(), CORONA, '/opt/atlas-corona', write, lines.append, HOST,
                      opener=fake, jwks_opener=jwks, caddyfile=CADDY_READY,
                      compose_passes=lambda d: {sid.ENV_SOURCE})


def test_a_new_key_is_told_to_the_outpost_that_serves_the_provider(sid, monkeypatch):
    fake = Authentik(signing_key=None)

    result = _switch(sid, monkeypatch, fake)

    assert result['source'] == 'jwt'
    told = [w for w in fake.writes if w[1].startswith('outposts/')]
    # ⚠️ The name it already has, and nothing else: never its provider list.
    assert told == [('PATCH', 'outposts/instances/op-emb/',
                     {'name': 'authentik Embedded Outpost'})]
    # After the key is on the provider, or the outpost would read the old state again.
    order = [w[1] for w in fake.writes]
    assert order.index('providers/oauth2/49/') < order.index('outposts/instances/op-emb/')
    assert fake.outposts['op-emb']['providers'] == [7, 49]


def test_telling_the_outpost_never_saves_a_proxy_provider(sid, monkeypatch):
    """A save through the proxy provider API is what takes the key off."""
    fake = Authentik(signing_key=None)

    _switch(sid, monkeypatch, fake)

    assert not [w for w in fake.writes if w[1].startswith('providers/proxy/')]
    assert fake.providers[49]['signing_key'] == 'key-1'


def test_a_key_that_is_already_on_the_provider_tells_nobody(sid, monkeypatch):
    """The usual Update: two reads, no write. The outpost already knows this key."""
    fake = Authentik()

    result = _switch(sid, monkeypatch, fake)

    assert result['source'] == 'jwt'
    assert fake.writes == []


def test_an_outpost_that_cannot_be_told_does_not_stop_the_switch(sid, monkeypatch):
    """Its own five-minute refresh still comes; the log says what to expect."""
    fake, log = Authentik(signing_key=None), []
    fake.outposts_fail = True

    result = _switch(sid, monkeypatch, fake, log)

    assert result['source'] == 'jwt'
    assert any('was not told' in line and 'five minutes' in line for line in log)


def test_no_outpost_for_the_provider_is_said(sid, monkeypatch):
    fake, log = Authentik(signing_key=None), []
    fake.outposts['op-emb']['providers'] = [7]

    result = _switch(sid, monkeypatch, fake, log)

    assert result['source'] == 'jwt'
    assert not [w for w in fake.writes if w[1].startswith('outposts/')]
    assert any('No Authentik outpost serves this provider' in line for line in log)


def test_env_source_reads_the_line(sid, tmp_path):
    assert sid.env_source(str(tmp_path)) == ''
    (tmp_path / '.env').write_text('A=1\nTAKMDM_ADMIN_IDENTITY_SOURCE=jwt\n', encoding='utf-8')
    assert sid.env_source(str(tmp_path)) == 'jwt'
    (tmp_path / '.env').write_text('# TAKMDM_ADMIN_IDENTITY_SOURCE=jwt\nB=2\n', encoding='utf-8')
    assert sid.env_source(str(tmp_path)) == ''


class Box:
    """One built deployment in a temp folder, with the module's seams replaced."""

    def __init__(self, atlas, monkeypatch, tmp_path, source='jwt', built=True):
        self.dir = tmp_path
        (tmp_path / '.env').write_text(
            'TAKMDM_ADMIN_GROUP=x\n' + ('TAKMDM_ADMIN_IDENTITY_SOURCE=%s\n' % source
                                        if source else ''), encoding='utf-8')
        self.lost = [True, False]          # answers of key_lost, in order
        self.looked = 0
        self.reconciled = 0
        self.reconcile_changes_env = False
        self.compose = []
        self.log = []
        monkeypatch.setattr(atlas, 'load_instances', lambda c: [CORONA])
        monkeypatch.setattr(atlas, 'instance_paths', lambda c=None, i=None: {
            'dir': str(tmp_path), 'compose_project': 'takmdm-corona'})
        monkeypatch.setattr(atlas, 'compose_projects_present',
                            lambda c=None: {'takmdm-corona'} if built else set())
        monkeypatch.setattr(atlas.atlas_signed_identity, 'key_lost', self._key_lost)
        monkeypatch.setattr(atlas, '_reconcile_signed_identity', self._reconcile)
        monkeypatch.setattr(atlas, '_compose',
                            lambda c, action, timeout=180, inst=None: self.compose.append(action))

    def _key_lost(self, c, inst, opener=None):
        self.looked += 1
        return self.lost.pop(0) if self.lost else False

    def _reconcile(self, c, inst, plog, regenerate=False):
        self.reconciled += 1
        return self.reconcile_changes_env

    def source(self):
        return (self.dir / '.env').read_text(encoding='utf-8')


def test_a_lost_key_is_put_back(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)
    out = atlas.converge_signed_identity({}, box.log.append)
    assert list(out.values()) == ['healed']
    assert box.reconciled == 1
    assert box.compose == []                       # .env did not change: no restart
    assert any('putting it back' in line for line in box.log)


def test_a_key_that_is_there_needs_nothing(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)
    box.lost = [False]
    assert atlas.converge_signed_identity({}, box.log.append) == {}
    assert (box.looked, box.reconciled, box.compose, box.log) == (1, 0, [], [])


@pytest.mark.parametrize('source', ['headers', ''])
def test_a_deployment_on_headers_is_not_looked_at(atlas, monkeypatch, tmp_path, source):
    """The move to the signed token stays with Deploy and Update."""
    box = Box(atlas, monkeypatch, tmp_path, source=source)
    assert atlas.converge_signed_identity({}, box.log.append) == {}
    assert (box.looked, box.reconciled) == (0, 0)


def test_a_deployment_that_is_not_built_is_not_looked_at(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path, built=False)
    assert atlas.converge_signed_identity({}, box.log.append) == {}
    assert (box.looked, box.reconciled) == (0, 0)


def test_a_repair_that_ends_on_headers_restarts_api_and_says_so(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)
    box.reconcile_changes_env = True

    def to_headers(c, inst, plog, regenerate=False):
        (tmp_path / '.env').write_text('TAKMDM_ADMIN_IDENTITY_SOURCE=headers\n',
                                       encoding='utf-8')
        return True
    monkeypatch.setattr(atlas, '_reconcile_signed_identity', to_headers)
    out = atlas.converge_signed_identity({}, box.log.append)
    assert list(out.values()) == ['headers']
    assert box.compose == ['up -d api']


def test_a_key_that_does_not_come_back_is_reported(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)
    box.lost = [True, True]
    assert list(atlas.converge_signed_identity({}, box.log.append).values()) == ['failed']


def test_the_repair_never_raises(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)

    def boom(*a, **k):
        raise RuntimeError('docker is away')
    monkeypatch.setattr(atlas, '_reconcile_signed_identity', boom)
    assert list(atlas.converge_signed_identity({}, box.log.append).values()) == ['failed']
    monkeypatch.setattr(atlas, 'load_instances', boom)
    assert atlas.converge_signed_identity({}, box.log.append) == {}


# --------------------------------------------------------------------------- #
# 3. Rollback to a release without the signed token
# --------------------------------------------------------------------------- #


def test_rollback_to_an_older_release_puts_atlas_back_on_headers(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)
    out = atlas.before_console_rollback({}, box.log.append, False)
    assert list(out.values()) == ['headers']
    assert 'TAKMDM_ADMIN_IDENTITY_SOURCE=headers' in box.source()
    assert 'TAKMDM_ADMIN_GROUP=x' in box.source()          # the other lines stay
    assert box.compose == ['up -d api']


def test_rollback_to_a_release_that_reads_the_token_changes_nothing(atlas, monkeypatch,
                                                                    tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)
    assert atlas.before_console_rollback({}, box.log.append, True) == {}
    assert 'TAKMDM_ADMIN_IDENTITY_SOURCE=jwt' in box.source()
    assert box.compose == []


def test_rollback_leaves_a_deployment_on_headers_alone(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path, source='headers')
    assert atlas.before_console_rollback({}, box.log.append, False) == {}
    assert box.compose == []


def test_a_failed_rollback_step_is_reported_and_does_not_raise(atlas, monkeypatch, tmp_path):
    box = Box(atlas, monkeypatch, tmp_path)

    def boom(*a, **k):
        raise RuntimeError('docker is away')
    monkeypatch.setattr(atlas, '_compose', boom)
    assert list(atlas.before_console_rollback({}, box.log.append, False).values()) == ['failed']


def _app_func(name):
    found = [ast.get_source_segment(APP, n) for n in TREE.body
             if isinstance(n, ast.FunctionDef) and n.name == name]
    assert found, '%s is missing from app.py (ops #1151)' % name
    return found[0]


def test_the_console_can_tell_whether_a_release_has_a_file():
    import os
    import re
    import subprocess
    ns = {'re': re, 'subprocess': subprocess, 'os': os}
    exec(_app_func('_console_release_has_file'), ns)
    has = ns['_console_release_has_file']
    assert has(str(ROOT), 'HEAD', 'modules/atlas.py') is True
    assert has(str(ROOT), 'HEAD', 'modules/no_such_file.py') is False
    # A stored value never reaches git as an option, and "cannot say" is False.
    assert has(str(ROOT), '--help', 'modules/atlas.py') is False
    assert has(str(ROOT), 'no-such-tag-ops1151', 'modules/atlas.py') is False


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #


def test_the_module_offers_both_calls_to_the_console():
    assert "'converge_signed_identity': converge_signed_identity," in ATLAS_SRC
    assert "'before_console_rollback': before_console_rollback," in ATLAS_SRC


def test_a_loop_of_the_module_checks_the_key():
    """ops #1186 moved the check from the five-minute loop to its own minute loop;
    tests/test_atlas_key_check_minute_ops1186.py holds the timing."""
    loop = ATLAS_SRC[ATLAS_SRC.index('def _start_signing_key_loop(ctx):'):]
    loop = loop[:loop.index('\ndef ', 10)]
    assert 'converge_signed_identity(ctx,' in loop
    assert loop.index('converge_signed_identity(ctx,') < loop.index(
        'time.sleep(SIGNING_KEY_CHECK_INTERVAL_S)')


def test_rollback_asks_atlas_before_the_checkout():
    route = _app_func('console_rollback_api')
    assert "get('before_console_rollback')" in route
    assert "'modules/atlas_signed_identity.py'" in route
    assert route.index("get('before_console_rollback')") < route.index("'checkout', '--force'")


def test_every_console_step_that_saves_the_providers_asks_for_the_key_check():
    helper = _app_func('_atlas_signed_identity_converge')
    assert "get('converge_signed_identity')" in helper
    for name in ('_ensure_proxy_providers_cookie_domain',      # after every console update
                 '_authentik_sync_all_domain_refs',            # a domain change
                 '_startup_app_access_policy_converge'):       # every console start
        assert '_atlas_signed_identity_converge(' in _app_func(name), name


def test_a_new_key_says_what_an_administrator_already_signed_in_must_do(sid, monkeypatch):
    """✅ Seen on a box, Nov 24, 2026: a session made before the key was set gets 401 from
    ATLAS on every page ("your sign-in could not be verified") until it ends. The update
    log is where the operator who pressed Update is looking."""
    fake, log = Authentik(signing_key=None), []

    _switch(sid, monkeypatch, fake, log)

    said = [line for line in log if 'already signed in' in line]
    assert len(said) == 1
    assert 'sign out of Authentik and sign in again' in said[0]


def test_a_key_that_was_already_there_says_nothing_about_sessions(sid, monkeypatch):
    fake, log = Authentik(), []

    _switch(sid, monkeypatch, fake, log)

    assert not [line for line in log if 'already signed in' in line]
