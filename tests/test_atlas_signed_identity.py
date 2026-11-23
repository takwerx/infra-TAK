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
"""ATLAS reads its administrator from Authentik's signed token (ATLAS W504).

Facts read from Authentik 2026.5.6 on a live box and its source:
* a proxy provider has no signing key by default, so its token is HS256 with
  the client secret, and its JWKS is `{}`;
* the proxy provider API has no `signing_key` field; the OAuth2 provider
  endpoint does, and lists proxy providers too;
* `crypto/certificatekeypairs/generate/` makes a key pair (`common_name`).
"""

import io
import json
import pathlib
import sys
import urllib.error
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import atlas_instances as ai  # noqa: E402
from modules import atlas_signed_identity as sid  # noqa: E402
import modules.atlas as atlas  # noqa: E402

PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)
CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
PUBLIC = 'https://tak.example.org'
HOST = 'atlas.corona.example.org'

CADDY_READY = f"""
tak.example.org {{
    reverse_proxy 127.0.0.1:9000
}}
{HOST} {{
    route {{
        forward_auth 127.0.0.1:9090 {{
            uri /outpost.goauthentik.io/auth/caddy
            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid X-Authentik-Jwt
        }}
        reverse_proxy 127.0.0.1:8761
    }}
}}
"""

CADDY_OLD = CADDY_READY.replace(' X-Authentik-Jwt', '')

CADDY_ONLY_PORTAL = CADDY_OLD + """
portal.example.org {
    route {
        forward_auth 127.0.0.1:9090 {
            copy_headers X-Authentik-Username X-Authentik-Jwt
        }
    }
}
"""


class FakeAuthentik:
    """Providers, OAuth2 view of them, and key pairs."""

    def __init__(self, provider_name='ATLAS MDM Proxy (corona)'):
        self.providers = {49: {'pk': 49, 'name': provider_name, 'client_id': 'cid-49',
                               'signing_key': None}}
        self.keys = {}
        self.calls = []
        self.fail_on = None

    def __call__(self, req, timeout=None):
        url = urllib.parse.urlparse(req.full_url)
        path = url.path.split('/api/v3/', 1)[1]
        query = dict(urllib.parse.parse_qsl(url.query))
        method = req.get_method()
        body = json.loads(req.data.decode()) if req.data else None
        self.calls.append((method, path, body))
        if self.fail_on and self.fail_on in path:
            raise urllib.error.URLError('timed out')
        out = self.handle(method, path, query, body)
        return io.BytesIO(json.dumps(out).encode() if out is not None else b'')

    def handle(self, method, path, query, body):
        if path == 'providers/proxy/':
            rows = [dict(p) for p in self.providers.values() if query.get('name', '') in p['name']]
            for r in rows:
                r.pop('signing_key', None)   # not a proxy API field
            return {'results': rows}
        if path.startswith('providers/oauth2/'):
            pk = int(path.split('/')[2])
            if method == 'PATCH':
                assert set(body) == {'signing_key'}, body
                self.providers[pk]['signing_key'] = body['signing_key']
            return dict(self.providers[pk])
        if path == 'crypto/certificatekeypairs/':
            return {'results': [k for k in self.keys.values() if query.get('name', '') in k['name']]}
        if path == 'crypto/certificatekeypairs/generate/':
            k = {'pk': 'key-%d' % (len(self.keys) + 1), 'name': body['common_name']}
            self.keys[k['pk']] = k
            return k
        if path.startswith('crypto/certificatekeypairs/') and method == 'DELETE':
            self.keys.pop(path.split('/')[2])
            return None
        raise AssertionError('unexpected %s %s' % (method, path))


def jwks(has_key=True):
    def opener(req, timeout=None):
        assert req.full_url == PUBLIC + '/application/o/atlas-corona/jwks/', req.full_url
        return io.BytesIO(json.dumps({'keys': [{'kid': 'k'}]} if has_key else {}).encode())
    return opener


def ctx():
    return {
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: 'admin-token' if k == 'AUTHENTIK_TOKEN' else None,
        '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
    }


class Env:
    def __init__(self):
        self.values = {}

    def write(self, path, key, value):
        changed = self.values.get(key) != value
        self.values[key] = value
        return changed


NEW_COMPOSE = {sid.ENV_SOURCE, sid.ENV_AUDIENCE, sid.ENV_JWKS, 'TAKMDM_ADMIN_GROUP'}


def passes_new(dirpath):
    return NEW_COMPOSE


def run(fake, env, *, caddy=CADDY_READY, has_key=True, inst=CORONA, monkeypatch=None,
        passes=passes_new):
    log = []
    if monkeypatch is not None:
        monkeypatch.setattr('modules.atlas_roster.authentik_public_url', lambda c, s: PUBLIC)
    result = sid.ensure(ctx(), inst, '/opt/atlas-corona', env.write, log.append, HOST,
                        opener=fake, jwks_opener=jwks(has_key), caddyfile=caddy,
                        compose_passes=passes)
    return result, log


# --------------------------------------------------------------------------- #
# The switch
# --------------------------------------------------------------------------- #


def test_a_ready_deployment_is_switched_to_the_signed_token(monkeypatch):
    fake, env = FakeAuthentik(), Env()
    result, log = run(fake, env, monkeypatch=monkeypatch)
    assert result == {'env_changed': True, 'source': 'jwt'}
    assert env.values == {
        sid.ENV_AUDIENCE: 'cid-49',
        sid.ENV_JWKS: PUBLIC + '/application/o/atlas-corona/jwks/',
        sid.ENV_SOURCE: 'jwt',
    }
    key = fake.keys['key-1']
    assert key['name'] == 'ATLAS token signing — ATLAS MDM Proxy (corona)'
    assert fake.providers[49]['signing_key'] == 'key-1'
    assert any('signed token' in line for line in log)


def test_the_key_goes_on_through_the_oauth2_endpoint_only():
    """The proxy API has no signing_key field: a PATCH there is ignored."""
    fake, env = FakeAuthentik(), Env()
    import pytest
    mp = pytest.MonkeyPatch()
    try:
        run(fake, env, monkeypatch=mp)
    finally:
        mp.undo()
    patches = [(m, p) for m, p, b in fake.calls if m == 'PATCH']
    assert patches == [('PATCH', 'providers/oauth2/49/')]


def test_a_second_run_changes_nothing(monkeypatch):
    fake, env = FakeAuthentik(), Env()
    run(fake, env, monkeypatch=monkeypatch)
    calls_before = len(fake.calls)
    result, _ = run(fake, env, monkeypatch=monkeypatch)
    assert result == {'env_changed': False, 'source': 'jwt'}
    new = fake.calls[calls_before:]
    assert not [c for c in new if c[0] in ('POST', 'PATCH')]
    assert len(fake.keys) == 1


def test_the_jwt_line_is_written_last(monkeypatch):
    fake, order = FakeAuthentik(), []
    env = Env()
    original = env.write

    def write(path, key, value):
        order.append(key)
        return original(path, key, value)

    monkeypatch.setattr('modules.atlas_roster.authentik_public_url', lambda c, s: PUBLIC)
    sid.ensure(ctx(), CORONA, '/d', write, lambda m: None, HOST,
               opener=fake, jwks_opener=jwks(), caddyfile=CADDY_READY,
               compose_passes=passes_new)
    assert order[-1] == sid.ENV_SOURCE


# --------------------------------------------------------------------------- #
# Stays on headers when it cannot be proven
# --------------------------------------------------------------------------- #


def test_no_published_key_keeps_headers(monkeypatch):
    env = Env()
    result, log = run(FakeAuthentik(), env, has_key=False, monkeypatch=monkeypatch)
    assert result['source'] == 'headers'
    assert env.values == {sid.ENV_SOURCE: 'headers'}
    assert any('publishes no key' in line for line in log)


def test_a_caddyfile_that_does_not_pass_the_token_keeps_headers(monkeypatch):
    for caddy in (CADDY_OLD, CADDY_ONLY_PORTAL, ''):
        env = Env()
        result, log = run(FakeAuthentik(), env, caddy=caddy, monkeypatch=monkeypatch)
        assert result['source'] == 'headers', caddy
        assert env.values == {sid.ENV_SOURCE: 'headers'}


def test_a_deployment_that_lost_its_caddy_line_goes_back_to_headers(monkeypatch):
    """jwt with no token passed would refuse every administrator."""
    fake, env = FakeAuthentik(), Env()
    run(fake, env, monkeypatch=monkeypatch)
    result, _ = run(fake, env, caddy=CADDY_OLD, monkeypatch=monkeypatch)
    assert result == {'env_changed': True, 'source': 'headers'}
    assert env.values[sid.ENV_SOURCE] == 'headers'


def test_an_older_atlas_stays_on_headers_and_authentik_is_not_touched(monkeypatch):
    """ATLAS before 2.10.0 does not read the setting; its compose would drop it."""
    for passes in (lambda d: {'TAKMDM_ADMIN_GROUP'}, lambda d: None):
        fake, env = FakeAuthentik(), Env()
        result, log = run(fake, env, monkeypatch=monkeypatch, passes=passes)
        assert result['source'] == 'headers'
        assert env.values == {sid.ENV_SOURCE: 'headers'}
        assert fake.calls == []
        assert any('2.10.0' in line for line in log)


def test_no_provider_keeps_headers(monkeypatch):
    env = Env()
    result, _ = run(FakeAuthentik(provider_name='something else'), env, monkeypatch=monkeypatch)
    assert result['source'] == 'headers'


def test_an_unexpected_error_leaves_env_alone(monkeypatch):
    """A timeout says nothing about the key or Caddy: never undo a working switch."""
    fake, env = FakeAuthentik(), Env()
    run(fake, env, monkeypatch=monkeypatch)
    fake.fail_on = 'providers/proxy/'
    result, log = run(fake, env, caddy=CADDY_READY, monkeypatch=monkeypatch)
    assert result == {'env_changed': False, 'source': 'unchanged'}
    assert env.values[sid.ENV_SOURCE] == 'jwt'
    assert any('left as it was' in line for line in log)


def test_no_authentik_token_keeps_headers(monkeypatch):
    env = Env()
    c = ctx()
    c['_get_authentik_env_value'] = lambda s, k: None
    result = sid.ensure(c, CORONA, '/d', env.write, lambda m: None, HOST,
                        opener=FakeAuthentik(), jwks_opener=jwks(), caddyfile=CADDY_READY,
                        compose_passes=passes_new)
    assert result['source'] == 'headers'


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_caddy_check_reads_only_the_deployment_vhost():
    assert sid.caddy_copies_token(CADDY_READY, HOST)
    assert not sid.caddy_copies_token(CADDY_OLD, HOST)
    assert not sid.caddy_copies_token(CADDY_ONLY_PORTAL, HOST)
    assert not sid.caddy_copies_token(CADDY_READY, 'atlas.other.example.org')
    # A prefix of the host is not the host.
    assert not sid.caddy_copies_token(CADDY_READY, 'corona.example.org')
    assert not sid.caddy_copies_token(None, HOST)


def test_the_key_address_is_authentik_s_public_one():
    assert sid.jwks_url('https://tak.example.org/', 'atlas-corona') == \
        'https://tak.example.org/application/o/atlas-corona/jwks/'


def test_removal_deletes_only_this_provider_s_key():
    fake = FakeAuthentik()
    fake.keys = {'key-1': {'pk': 'key-1', 'name': 'ATLAS token signing — ATLAS MDM Proxy (corona)'},
                 'key-2': {'pk': 'key-2', 'name': 'ATLAS token signing — ATLAS MDM Proxy (corona2)'}}
    note = sid.remove(ctx(), CORONA, opener=fake)
    assert 'deleted' in note
    assert list(fake.keys) == ['key-2']
    assert sid.remove(ctx(), CORONA, opener=fake) == ''


# --------------------------------------------------------------------------- #
# Wiring in modules/atlas.py and the generated Caddyfile
# --------------------------------------------------------------------------- #


def test_the_atlas_vhost_copies_and_strips_the_token():
    src = (ROOT / 'app.py').read_text(encoding='utf-8')
    start = src.index('# ATLAS MDM — administration console (443)')
    block = src[start:src.index('# ATLAS MDM — agent package', start)]
    copy = [line for line in block.splitlines() if 'copy_headers' in line]
    assert len(copy) == 1 and 'X-Authentik-Jwt' in copy[0]
    strip = src[src.index('_AK_FWD_HEADERS = ('):]
    strip = strip[:strip.index(')')]
    assert "'X-Authentik-Jwt'" in strip


def test_every_path_that_regenerates_the_vhost_then_checks_the_switch():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    calls = src.count('_reconcile_signed_identity(')
    # definition + deploy + update + update with nothing to install
    assert calls == 4, calls
    assert '_reconcile_signed_identity(\n                    ctx, inst, plog, regenerate=True)' in src
    assert 'atlas_signed_identity.remove(ctx, inst)' in src


def test_reconcile_never_raises(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('no settings')
    c = {'load_settings': boom}
    assert atlas._reconcile_signed_identity(c, CORONA, lambda m: None) is False
