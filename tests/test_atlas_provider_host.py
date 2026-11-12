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
"""An update corrects an Authentik provider that names the wrong host.

⚠️ **Reported from a real box (2026-11-12):** an agency console answered 404
after an update. Caddy served `atlas.yfd.<domain>`; the provider still said
`atlas.<domain>`, so the outpost had no provider for the host Caddy asked
about. Only deploy ever set the host, so no update could repair it.
"""

import io
import json
import pathlib
import sys
import urllib.error

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


YFD = ai.make('yfd', ai.MODE_DYNAMIC, 50, 8760)
PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)


class FakeProviders:
    """Authentik's proxy provider list, and the PATCHes sent to it."""

    def __init__(self, providers, fail=False):
        self.providers = providers
        self.fail = fail
        self.patched = []

    def open(self, req, timeout=None):
        if self.fail:
            raise OSError('boom')
        if getattr(req, 'method', None) == 'PATCH':
            body = json.loads(req.data.decode())
            # ⚠️ What Authentik 2026.8.5 really does (ops #708, seen on a box):
            # a partial update is validated as if `mode` were its default,
            # `proxy`, so a body without `mode` is refused with a 400.
            if 'mode' not in body:
                raise urllib.error.HTTPError(
                    req.full_url, 400, 'Bad Request', {},
                    io.BytesIO(b'{"internal_host":["Internal host cannot be '
                               b'empty when forward auth is disabled."]}'))
            self.patched.append((req.full_url, body))
            return _Response({})
        assert 'providers/proxy/?search=' in req.full_url, req.full_url
        return _Response({'results': self.providers})


class _Response:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload


def make_ctx(token='tok'):
    return {
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda _s, key: token if key == 'AUTHENTIK_TOKEN' else None,
        '_get_authentik_api_url': lambda _s: 'http://ak',
        '_get_service_domain': lambda _s, _key: 'atlas.example.com',
    }


@pytest.fixture
def authentik(monkeypatch):
    import urllib.request

    def install(fake):
        monkeypatch.setattr(urllib.request, 'urlopen', fake.open)
        return fake

    return install


@pytest.fixture(autouse=True)
def console_url(monkeypatch):
    """The host Caddy serves, from the same function deploy uses."""
    def identity(_ctx, inst, _settings):
        host = ai.agency_host('atlas.example.com', (inst or {}).get('slug'))
        return {'console_url': 'https://' + host}
    monkeypatch.setattr(atlas, 'deployment_identity', identity)


def provider(name, host, pk=13, **more):
    return dict({'pk': pk, 'name': name, 'external_host': host,
                 'mode': 'forward_single'}, **more)


def test_a_plain_host_on_an_agency_provider_is_corrected(authentik):
    """The box that reported it."""
    fake = authentik(FakeProviders([
        provider('ATLAS MDM Proxy', 'https://atlas.example.com', pk=1),
        provider('ATLAS MDM Proxy (yfd)', 'https://atlas.example.com', pk=13),
    ]))
    log = []

    assert atlas._reconcile_provider_host(make_ctx(), YFD, log.append) == 'fixed'
    assert fake.patched == [('http://ak/api/v3/providers/proxy/13/',
                             {'external_host': 'https://atlas.yfd.example.com',
                              'mode': 'forward_single'})]
    assert 'corrected' in log[-1]


def test_the_cookie_domain_is_not_sent(authentik):
    """⚠️ The cookie domain decides who stays signed in; it is not ours to
    change on a running box. Only the host, and the `mode` Authentik needs to
    accept the update, go out."""
    fake = authentik(FakeProviders([
        provider('ATLAS MDM Proxy (yfd)', 'https://atlas.example.com',
                 cookie_domain='.example.com')]))

    atlas._reconcile_provider_host(make_ctx(), YFD, lambda _m: None)

    assert sorted(fake.patched[0][1]) == ['external_host', 'mode']


def test_the_patch_carries_mode_or_authentik_refuses_it(authentik):
    """⚠️ The bug the first version of this repair had (ops #708). Authentik
    2026.8.5 answers HTTP 400 to a PATCH of `external_host` alone, so the repair
    reported 'failed' and the console kept answering 404. The fake refuses such
    a body as the real one does; the repair must get past it, whatever `mode`
    the provider listing happens to omit."""
    listing = provider('ATLAS MDM Proxy (yfd)', 'https://atlas.example.com')
    del listing['mode']
    fake = authentik(FakeProviders([listing]))
    log = []

    assert atlas._reconcile_provider_host(make_ctx(), YFD, log.append) == 'fixed'
    assert fake.patched[0][1]['mode'] == 'forward_single'
    assert 'Could not check' not in ' '.join(log)


def test_a_providers_own_mode_and_internal_host_are_kept(authentik):
    """A provider in `proxy` mode needs its internal host to pass the same
    validation; both are sent back unchanged."""
    fake = authentik(FakeProviders([
        provider('ATLAS MDM Proxy (yfd)', 'https://atlas.example.com',
                 mode='proxy', internal_host='http://127.0.0.1:8760')]))

    assert atlas._reconcile_provider_host(make_ctx(), YFD, lambda _m: None) == 'fixed'
    assert fake.patched[0][1] == {'external_host': 'https://atlas.yfd.example.com',
                                  'mode': 'proxy',
                                  'internal_host': 'http://127.0.0.1:8760'}


def test_a_correct_provider_is_left_alone(authentik):
    fake = authentik(FakeProviders([
        provider('ATLAS MDM Proxy (yfd)', 'https://atlas.yfd.example.com/')]))

    assert atlas._reconcile_provider_host(make_ctx(), YFD, lambda _m: None) == 'ok'
    assert fake.patched == []


def test_the_plain_deployment_is_matched_by_its_exact_name(authentik):
    """⚠️ `search` is a substring match: the agency's provider comes back for
    the plain name too, and must not be the one repointed."""
    fake = authentik(FakeProviders([
        provider('ATLAS MDM Proxy (yfd)', 'https://atlas.yfd.example.com', pk=13),
        provider('ATLAS MDM Proxy', 'https://old.example.com', pk=1),
    ]))

    assert atlas._reconcile_provider_host(make_ctx(), PLAIN, lambda _m: None) == 'fixed'
    assert fake.patched == [('http://ak/api/v3/providers/proxy/1/',
                             {'external_host': 'https://atlas.example.com',
                              'mode': 'forward_single'})]


def test_a_missing_provider_is_said_not_made(authentik):
    fake = authentik(FakeProviders([]))
    log = []

    assert atlas._reconcile_provider_host(make_ctx(), YFD, log.append) == 'missing'
    assert fake.patched == []
    assert 'redeploy' in log[-1]


def test_no_token_is_said(authentik):
    authentik(FakeProviders([]))
    log = []

    assert atlas._reconcile_provider_host(make_ctx(token=None), YFD, log.append) == 'skipped'
    assert 'not checked' in log[-1]


def test_an_unreachable_authentik_does_not_fail_the_update(authentik):
    authentik(FakeProviders([], fail=True))
    log = []

    assert atlas._reconcile_provider_host(make_ctx(), YFD, log.append) == 'failed'
    assert 'Could not check' in log[-1]


def test_every_update_runs_it(monkeypatch):
    """⚠️ Through `_reconcile_access`, which runs on every update, including
    one with nothing to install."""
    calls = []
    monkeypatch.setattr(atlas, '_verify_access_control', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_reconcile_agency_group', lambda *a: None)
    monkeypatch.setattr(atlas, '_reconcile_provider_host',
                        lambda ctx, inst, plog: calls.append(inst))

    atlas._reconcile_access({}, YFD, lambda _m: None)

    assert calls == [YFD]
