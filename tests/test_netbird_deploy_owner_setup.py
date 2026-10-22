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
"""NetBird deploy: a redeploy must create a real owner, or fail loudly (GH #72).

Field (GH #72): after deploying NetBird the dashboard login ended in "Error: Unauthenticated",
and later the NetBird address offered to create the admin account. The management log showed
NetBird asking for setup (no owner) and no PAT stored by the console.

Reproduced on a test box (NetBird 0.74.4): a redeploy that still had a PAT in settings (an
uninstall that never reached its settings cleanup, or a hand-removed ~/netbird) wrote the
bootstrap compose WITHOUT NB_SETUP_PAT_ENABLED. The fresh store's /api/setup then created the
owner in the embedded IdP only (no account, no PAT), registering Authentik failed with the old
PAT, and the deploy still printed "NetBird deployed successfully!".

app.py cannot be imported in a test, so the two functions are cut out of it and run: the code
under test is the shipped text.
"""

import ast
import io
import json
import pathlib
import subprocess
import types
import urllib.error

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_WANT = {'_netbird_complete_setup', '_run_netbird_deploy'}


class FakeNetBird:
    """The management API as seen from the console during a deploy."""

    def __init__(self, setup_required=True, pat_on_setup='new-pat', idp_ok=True):
        self.setup_required = setup_required
        self.pat_on_setup = pat_on_setup
        self.idp_ok = idp_ok
        self.valid_pats = set()
        self.compose_writes = []  # setup_pat_enabled of every compose write
        self.setup_env = None     # NB_SETUP_PAT_ENABLED when /api/setup ran

    def request(self, path, method='GET', data=None, token=None, timeout=15):
        if path == '/api/instance':
            return io.BytesIO(json.dumps({'setup_required': self.setup_required}).encode())
        if path == '/api/setup':
            if not self.setup_required:
                raise urllib.error.HTTPError(path, 412, 'setup already completed', {}, io.BytesIO(b''))
            self.setup_required = False
            self.setup_env = self.compose_writes[-1]
            body = {'email': 'akadmin@x', 'user_id': 'u1'}
            if self.setup_env and self.pat_on_setup:
                body['personal_access_token'] = self.pat_on_setup
                self.valid_pats.add(self.pat_on_setup)
            return io.BytesIO(json.dumps(body).encode())
        if path == '/api/users':
            if token in self.valid_pats:
                return io.BytesIO(b'[]')
            raise urllib.error.HTTPError(path, 401, 'invalid token', {}, io.BytesIO(b''))
        raise AssertionError(path)


def _load(nb, settings, tmp_path, monkeypatch):
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name in _WANT]
    assert len(parts) == len(_WANT), 'a function under test was renamed or removed'
    status = {'running': True, 'complete': False, 'error': False, 'log': []}
    registered = []

    def register_idp(pat, *a, **k):
        registered.append(pat)
        return nb.idp_ok and pat in nb.valid_pats

    def write_compose(nb_dir, domain, secret, setup_pat_enabled=True, store_key=None):
        nb.compose_writes.append(setup_pat_enabled)

    ns = {
        'os': __import__('os'), 'json': json, 'time': types.SimpleNamespace(time=lambda: 0, sleep=lambda s: None),
        'NETBIRD_INSTALL_DIR': str(tmp_path / 'netbird'),
        '_netbird_deploy_status': status,
        '_netbird_deploy_log': lambda m, status=None: status_log(m),
        '_netbird_wait_instance': lambda plog, timeout_sec=120: json.loads(nb.request('/api/instance').read()),
        '_netbird_mgmt_request': nb.request,
        '_netbird_pat_is_valid': lambda p: p in nb.valid_pats,
        '_netbird_admin_credentials': lambda s: ('akadmin@x', 'akadmin', 'pw-long-enough'),
        '_netbird_register_authentik_idp': register_idp,
        '_netbird_write_compose': write_compose,
        '_netbird_read_auth_secret': lambda d: 'secret',
        '_netbird_recreate_containers': lambda d, plog: None,
        '_netbird_finalize_account_store': lambda plog=None: True,
        '_netbird_store_key_needed': lambda img: True,
        '_ensure_netbird_store_key_setting': lambda s: 'key',
        '_get_netbird_target_images': lambda settings=None: ('netbirdio/netbird-server:0.74.4', 'netbirdio/dashboard:v2.90.4'),
        '_docker_probe': lambda: (0, 'Docker version 29'),
        '_install_docker_engine': lambda plog: True,
        '_ensure_authentik_netbird_app': lambda s, plog=None: ('client-id-123456', 'secret'),
        '_w1_reassert_app_mfa': lambda plog: None,
        '_get_service_domain': lambda s, name: f'{name}.example.com',
        '_pub_hostport': lambda h, s=None: h,
        '_get_authentik_api_url': lambda s: 'http://ak',
        '_get_authentik_env_value': lambda s, k: None,
        '_ensure_app_access_policies': lambda *a: None,
        '_sudo_wrap': lambda argv: argv,
        'save_settings': lambda s: None,
        'generate_caddyfile': lambda s: None,
        '_caddy_reload': lambda timeout=90: None,
    }

    def status_log(m):
        status['log'].append(m)

    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    ns['_run_netbird_deploy'](settings)
    return status, registered


def test_redeploy_with_leftover_pat_still_creates_owner_with_pat(tmp_path, monkeypatch):
    """The #72 path: an old PAT is still in settings, the store is fresh."""
    nb = FakeNetBird(setup_required=True, pat_on_setup='new-pat')
    settings = {'netbird_pat': 'old-dead-pat', 'fqdn': 'example.com'}
    status, registered = _load(nb, settings, tmp_path, monkeypatch)
    assert nb.setup_env is True, 'bootstrap compose must allow the setup PAT even when settings carry an old one'
    assert settings['netbird_pat'] == 'new-pat'
    assert registered == ['new-pat']
    assert status['complete'] and not status['error'], status['log']


def test_fresh_deploy_succeeds(tmp_path, monkeypatch):
    nb = FakeNetBird(setup_required=True)
    settings = {'fqdn': 'example.com'}
    status, registered = _load(nb, settings, tmp_path, monkeypatch)
    assert registered == ['new-pat']
    assert status['complete'] and not status['error'], status['log']
    assert nb.compose_writes[-1] is False, 'final compose must not keep the setup PAT switch on'


def test_setup_without_pat_fails_the_deploy(tmp_path, monkeypatch):
    nb = FakeNetBird(setup_required=True, pat_on_setup=None)
    status, registered = _load(nb, {'fqdn': 'example.com'}, tmp_path, monkeypatch)
    assert status['error'] and not status['complete']
    assert not any('deployed successfully' in m for m in status['log'])
    assert registered == []


def test_authentik_registration_failure_fails_the_deploy(tmp_path, monkeypatch):
    nb = FakeNetBird(setup_required=True, idp_ok=False)
    status, _ = _load(nb, {'fqdn': 'example.com'}, tmp_path, monkeypatch)
    assert status['error'] and not status['complete']
    assert not any('deployed successfully' in m for m in status['log'])


def test_already_set_up_box_with_valid_pat_redeploys(tmp_path, monkeypatch):
    nb = FakeNetBird(setup_required=False)
    nb.valid_pats.add('good-pat')
    settings = {'netbird_pat': 'good-pat', 'fqdn': 'example.com'}
    status, registered = _load(nb, settings, tmp_path, monkeypatch)
    assert registered == ['good-pat']
    assert status['complete'] and not status['error'], status['log']


def _register(idps, put_error=None):
    src = next(ast.get_source_segment(APP, n) for n in ast.parse(APP).body
               if isinstance(n, ast.FunctionDef) and n.name == '_netbird_register_authentik_idp')
    calls = []

    def mgmt(path, method='GET', data=None, token=None, timeout=15):
        calls.append((method, path))
        if method == 'GET':
            return io.BytesIO(json.dumps(idps).encode())
        if method == 'PUT' and put_error:
            raise urllib.error.HTTPError(path, put_error, 'boom', {}, io.BytesIO(b'{}'))
        return io.BytesIO(json.dumps({'id': 'new', 'name': 'Authentik'}).encode())

    ns = {'json': json, '_netbird_mgmt_request': mgmt,
          '_get_service_domain': lambda s, name: 'netbird.example.com',
          '_pub_hostport': lambda h, s=None: h,
          '_netbird_patch_authentik_idp_redirect': lambda *a, **k: None}
    exec(compile(src, 'app.py', 'exec'), ns)
    ok = ns['_netbird_register_authentik_idp']('pat', 'https://ak/application/o/netbird/', 'cid', 'sec', {}, lambda m: None)
    return ok, [c for c in calls if c[0] != 'GET']


def test_redeploy_updates_authentik_idp_instead_of_adding_another():
    """Each POST is another Authentik button on the login page (a redeploy-tested box reached 3 connectors)."""
    ok, writes = _register([{'id': 'idp1', 'name': 'Authentik', 'type': 'oidc'}])
    assert ok and writes == [('PUT', '/api/identity-providers/idp1')]


def test_first_deploy_creates_authentik_idp():
    ok, writes = _register([])
    assert ok and writes == [('POST', '/api/identity-providers')]


def test_failed_update_of_existing_idp_is_not_a_failed_deploy():
    ok, writes = _register([{'id': 'idp1', 'name': 'Authentik'}], put_error=500)
    assert ok and writes == [('PUT', '/api/identity-providers/idp1')]


def test_already_set_up_box_with_lost_pat_still_redeploys(tmp_path, monkeypatch):
    """A working install whose PAT was lost keeps its earlier Authentik registration; a redeploy
    must not be turned into a failure (nothing to register with, nothing broken)."""
    nb = FakeNetBird(setup_required=False)
    settings = {'netbird_pat': 'lost-pat', 'fqdn': 'example.com'}
    status, registered = _load(nb, settings, tmp_path, monkeypatch)
    assert 'netbird_pat' not in settings
    assert registered == []
    assert status['complete'] and not status['error'], status['log']
