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
"""ATLAS certificate renewal: the account InfraTAK makes for it.

⚠️ Measured on the box (authentik 2026.5.6) before this was written: a
superuser-group service account's API token made an `app_password` for another
user (HTTP 201), and TAK Server 8446 signed a certificate with it.
"""

import io
import json
import os
import pathlib
import stat
import sys
import urllib.parse

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import atlas_instances as ai  # noqa: E402
from modules import atlas_renewal as ar  # noqa: E402
import modules.atlas as atlas  # noqa: E402

PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)
CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
CA = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
COMPOSE_WITH = 'services:\n  api:\n    build: .\n  renewal:\n    build: .\n'
COMPOSE_WITHOUT = 'services:\n  api:\n    build: .\n'


class FakeAuthentik:
    """Just enough of /api/v3 for the account, its group and its tokens."""

    def __init__(self):
        self.groups, self.users, self.tokens = {}, {}, {}
        self.calls = []
        self._pk = 100

    def pk(self):
        self._pk += 1
        return self._pk

    def __call__(self, req, timeout=None):
        url = urllib.parse.urlparse(req.full_url)
        path = url.path.split('/api/v3/', 1)[1]
        query = dict(urllib.parse.parse_qsl(url.query))
        method = req.get_method()
        body = json.loads(req.data.decode()) if req.data else None
        self.calls.append((method, path))
        out = self.handle(method, path, query, body)
        return io.BytesIO(json.dumps(out).encode() if out is not None else b'')

    def handle(self, method, path, query, body):
        parts = [p for p in path.split('/') if p]
        if parts[:2] == ['core', 'groups']:
            if len(parts) == 2 and method == 'GET':
                return {'results': [g for g in self.groups.values()
                                    if g['name'] == query.get('name')]}
            if len(parts) == 2 and method == 'POST':
                g = dict(body, pk=str(self.pk()), users=[])
                self.groups[g['pk']] = g
                return g
            g = self.groups[parts[2]]
            if len(parts) == 4 and parts[3] == 'add_user':
                if body['pk'] not in g['users']:
                    g['users'].append(body['pk'])
                return None
            if method == 'PATCH':
                g.update(body)
                return g
            if method == 'DELETE':
                del self.groups[parts[2]]
                return None
        if parts[:2] == ['core', 'users']:
            if len(parts) == 2 and method == 'GET':
                return {'results': [u for u in self.users.values()
                                    if u['username'] == query.get('username')]}
            if len(parts) == 2 and method == 'POST':
                u = dict(body, pk=self.pk())
                self.users[u['pk']] = u
                return u
            pk = int(parts[2])
            if method == 'PATCH':
                self.users[pk].update(body)
                return self.users[pk]
            if method == 'DELETE':
                del self.users[pk]
                for g in self.groups.values():
                    if pk in g['users']:
                        g['users'].remove(pk)
                return None
        if parts[:2] == ['core', 'tokens']:
            if len(parts) == 2 and method == 'GET':
                return {'results': [t for t in self.tokens.values()
                                    if str(t['user']) == query.get('user')
                                    and t['intent'] == query.get('intent')]}
            if len(parts) == 2 and method == 'POST':
                t = dict(body, key='key-for-' + body['identifier'])
                self.tokens[t['identifier']] = t
                return t
            ident = urllib.parse.unquote(parts[2])
            if len(parts) == 4 and parts[3] == 'view_key':
                return {'key': self.tokens[ident]['key']}
            if method == 'DELETE':
                del self.tokens[ident]
                return None
        raise AssertionError('unexpected call %s %s' % (method, path))


@pytest.fixture
def ak():
    return FakeAuthentik()


@pytest.fixture
def deployment(tmp_path):
    (tmp_path / 'docker-compose.yml').write_text(COMPOSE_WITH)
    (tmp_path / '.env').write_text('TAKMDM_DB_PASSWORD=x\n')
    ca = tmp_path / 'root-ca.pem'
    ca.write_text(CA)
    return tmp_path


def _ctx(token='admin-token', domain='auth.example.com', port=None):
    # The box's shape: Authentik's .env has the token but no AUTHENTIK_FQDN; the
    # console names Authentik with _get_service_domain and _pub_hostport.
    env = {'AUTHENTIK_TOKEN': token}
    return {
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: env.get(k),
        '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
        '_get_service_domain': lambda s, key: domain if key == 'authentik' else '',
        '_pub_hostport': lambda host, s=None: host if port is None else '%s:%d' % (host, port),
    }


def _ensure(deployment, ak, inst=PLAIN, ctx=None, log=None):
    log = [] if log is None else log
    result = ar.ensure(ctx or _ctx(), inst, str(deployment), atlas.write_env_value,
                       log.append, opener=ak, ca_path=str(deployment / 'root-ca.pem'))
    return result, log


# --------------------------------------------------------------------------- #
# The account
# --------------------------------------------------------------------------- #

def test_each_deployment_has_its_own_account():
    assert ar.names(PLAIN)['username'] == 'atlas-renewal'
    assert ar.names(CORONA)['username'] == 'atlas-renewal-corona'


def test_the_account_is_a_superuser_service_account(deployment, ak):
    _ensure(deployment, ak)
    [user] = ak.users.values()
    assert user['type'] == 'service_account'
    assert user['path'] == ar.SERVICE_ACCOUNT_PATH
    [group] = ak.groups.values()
    assert group['name'] == ar.GROUP_NAME and group['is_superuser'] is True
    assert group['users'] == [user['pk']]


def test_a_group_someone_unticked_is_made_superuser_again(deployment, ak):
    ak.groups['g1'] = {'pk': 'g1', 'name': ar.GROUP_NAME, 'is_superuser': False, 'users': []}
    _ensure(deployment, ak)
    assert ak.groups['g1']['is_superuser'] is True


def test_every_update_rotates_the_token_and_deletes_the_old_one(deployment, ak):
    clock = iter([1000, 2000])
    ar_ensure = ar.ensure_account
    try:
        ar.ensure_account = lambda api, inst: ar_ensure(api, inst, now=lambda: next(clock))
        _ensure(deployment, ak)
        _, log = _ensure(deployment, ak)
    finally:
        ar.ensure_account = ar_ensure
    assert list(ak.tokens) == ['atlas-renewal-api-2000']
    token = deployment / ar.SECRETS_DIR / ar.TOKEN_FILE
    assert token.read_text() == 'key-for-atlas-renewal-api-2000'
    assert '1 old one deleted' in log[-1]


def test_the_new_token_is_on_disk_before_the_old_one_is_deleted(deployment, ak):
    order = []
    real_write, real_retire = ar.write_files, ar.retire_old_tokens
    try:
        ar.write_files = lambda *a, **k: (order.append('write'), real_write(*a, **k))
        ar.retire_old_tokens = lambda *a, **k: (order.append('retire'), real_retire(*a, **k))[1]
        _ensure(deployment, ak)
    finally:
        ar.write_files, ar.retire_old_tokens = real_write, real_retire
    assert order == ['write', 'retire']


def test_tokens_of_other_deployments_are_left_alone(deployment, ak):
    _ensure(deployment, ak, inst=CORONA)
    _ensure(deployment, ak, inst=PLAIN)
    owners = sorted(t['identifier'].rsplit('-', 1)[0] for t in ak.tokens.values())
    assert owners == ['atlas-renewal-api', 'atlas-renewal-corona-api']


# --------------------------------------------------------------------------- #
# The files
# --------------------------------------------------------------------------- #

def test_the_files_are_private_and_complete(deployment, ak):
    _ensure(deployment, ak)
    sdir = deployment / ar.SECRETS_DIR
    assert (sdir / ar.URL_FILE).read_text() == 'https://auth.example.com'
    assert (sdir / ar.CA_FILE).read_text() == CA
    if os.name == 'posix':
        assert stat.S_IMODE(sdir.stat().st_mode) == 0o700
        for name in (ar.TOKEN_FILE, ar.URL_FILE, ar.CA_FILE, ar.CLIENT_KEY_FILE):
            assert stat.S_IMODE((sdir / name).stat().st_mode) == 0o400


def test_the_client_key_and_uid_reach_env_and_the_key_is_kept(deployment, ak):
    result, _ = _ensure(deployment, ak)
    assert result == {'env_changed': True, 'ready': True}
    env = (deployment / '.env').read_text()
    key = (deployment / ar.SECRETS_DIR / ar.CLIENT_KEY_FILE).read_text()
    assert '%s=%s' % (ar.ENV_CLIENT_KEY, key) in env
    assert '%s=%d' % (ar.ENV_UID, ar.container_uid()) in env
    result, _ = _ensure(deployment, ak)
    assert result['env_changed'] is False, 'a second update must keep the same client key'


def test_the_token_is_never_logged(deployment, ak):
    _, log = _ensure(deployment, ak)
    assert not any('key-for-' in line for line in log)


# --------------------------------------------------------------------------- #
# When it does nothing
# --------------------------------------------------------------------------- #

def test_an_atlas_release_without_the_container_gets_no_account(deployment, ak):
    (deployment / 'docker-compose.yml').write_text(COMPOSE_WITHOUT)
    result, log = _ensure(deployment, ak)
    assert result['ready'] is False and ak.calls == [] and log == []


def test_no_authentik_says_so_and_does_not_fail(deployment, ak):
    result, log = _ensure(deployment, ak, ctx=_ctx(token=None))
    assert result['ready'] is False and ak.calls == []
    assert 'Authentik is not configured' in log[0]


def test_no_tak_server_says_so(deployment, ak):
    (deployment / 'root-ca.pem').unlink()
    result, log = _ensure(deployment, ak)
    assert result['ready'] is False and 'no TAK Server root CA' in log[0]


def test_an_authentik_error_is_reported_not_raised(deployment):
    def broken(req, timeout=None):
        raise OSError('connection refused')
    result, log = _ensure(deployment, broken)
    assert result['ready'] is False and 'connection refused' in log[0]


# --------------------------------------------------------------------------- #
# Removal
# --------------------------------------------------------------------------- #

def test_removal_deletes_the_account_its_tokens_and_the_empty_group(deployment, ak):
    _ensure(deployment, ak)
    note = ar.remove(_ctx(), PLAIN, opener=ak)
    assert note == "renewal account 'atlas-renewal' removed"
    assert ak.users == {} and ak.tokens == {} and ak.groups == {}


def test_removal_keeps_the_group_while_another_deployment_uses_it(deployment, ak):
    _ensure(deployment, ak, inst=PLAIN)
    _ensure(deployment, ak, inst=CORONA)
    ar.remove(_ctx(), CORONA, opener=ak)
    assert [u['username'] for u in ak.users.values()] == ['atlas-renewal']
    assert len(ak.groups) == 1


def test_deploy_update_and_removal_all_call_it():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    # deploy, update, update with nothing to install, and the on/off switch
    assert src.count('atlas_renewal.ensure(ctx,') == 4
    assert src.count('atlas_renewal.start(') == 4
    assert 'atlas_renewal.remove(ctx, inst)' in src


def test_the_container_is_started_by_name_and_never_as_a_dependency():
    # api must not pull it up before its files exist: Docker would create the
    # bind-mount source as a root-owned directory nobody could write again.
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    for line in src.splitlines():
        if "atlas_renewal.start(" in line:
            assert "_renewal['ready']" in src
    calls = []

    class R:
        returncode, stderr = 0, ''
    log = []
    ar.start(lambda action: (calls.append(action), R())[1], log.append)
    assert calls == ['up -d --build renewal'] and 'running' in log[0]


def test_a_container_that_fails_to_start_is_reported_not_raised():
    class R:
        returncode, stderr = 1, 'no such service: renewal'
    log = []
    ar.start(lambda action: R(), log.append)
    assert 'did not start' in log[0] and 'no such service' in log[0]


# --------------------------------------------------------------------------- #
# The off switch
# --------------------------------------------------------------------------- #

OFF = dict(PLAIN, renewal_disabled=True)


def test_renewal_is_on_unless_turned_off():
    assert ar.enabled(PLAIN) is True and ar.enabled(None) is True
    assert ar.enabled(OFF) is False


def test_an_update_with_renewal_off_makes_no_account(deployment, ak):
    result, log = _ensure(deployment, ak, inst=OFF)
    assert result == {'env_changed': False, 'ready': False}
    assert ak.users == {} and ak.tokens == {}
    assert 'Certificate renewal is off' in log[0]


def test_an_update_with_renewal_off_removes_what_was_there(deployment, ak):
    _ensure(deployment, ak)
    token = deployment / ar.SECRETS_DIR / ar.TOKEN_FILE
    assert token.exists()
    _ensure(deployment, ak, inst=OFF)
    assert not token.exists()
    assert ak.users == {} and ak.tokens == {} and ak.groups == {}


def test_turning_it_off_stops_the_container_and_deletes_token_and_account(deployment, ak):
    _ensure(deployment, ak)
    calls, log = [], []

    class R:
        returncode, stderr = 0, ''
    ar.disable(_ctx(), OFF, str(deployment), lambda a: (calls.append(a), R())[1],
               log.append, opener=ak)
    assert calls == ['rm -s -f renewal']
    assert not (deployment / ar.SECRETS_DIR / ar.TOKEN_FILE).exists()
    assert ak.users == {} and ak.tokens == {}
    assert log == ['Renewal container stopped', 'Token file deleted',
                   "Renewal account 'atlas-renewal' removed"]


def test_turning_it_off_twice_is_harmless(deployment, ak):
    class R:
        returncode, stderr = 0, ''
    log = []
    ar.disable(_ctx(), OFF, str(deployment), lambda a: R(), log.append, opener=ak)
    assert log[-1] == 'No renewal account to remove'


def test_the_page_offers_the_switch_and_the_route_exists():
    page = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    assert "toggleRenewal(i)" in page and "/renewal'" in page
    assert 'renewal_enabled' in atlas.INSTANCE_FIELDS
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    assert "/instances/<slug>/renewal" in src


# --------------------------------------------------------------------------- #
# Authentik's public address (found on the box, 2026-11-05)
# --------------------------------------------------------------------------- #

def test_the_public_address_comes_from_the_console_not_authentiks_env(deployment, ak):
    # The first box update said "Authentik is not configured": AUTHENTIK_FQDN is
    # not in Authentik's .env on an InfraTAK box.
    result, _ = _ensure(deployment, ak)
    assert result['ready'] is True
    assert (deployment / ar.SECRETS_DIR / ar.URL_FILE).read_text() == 'https://auth.example.com'


def test_a_moved_caddy_port_is_in_the_address(deployment, ak):
    _ensure(deployment, ak, ctx=_ctx(port=8443))
    assert (deployment / ar.SECRETS_DIR / ar.URL_FILE).read_text() == 'https://auth.example.com:8443'


def test_no_fqdn_says_so_plainly(deployment, ak):
    result, log = _ensure(deployment, ak, ctx=_ctx(domain=''))
    assert result['ready'] is False and ak.calls == []
    assert "public name is unknown" in log[0]
