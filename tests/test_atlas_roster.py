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
"""ATLAS standard admins: the group and the read-only roster account (W495).

⚠️ Measured on a live box (Authentik 2026.5.6) with a temporary account set up
the same way: the token listed only its two groups, with members; another group
by pk answered 404; the user list answered 403.
"""

import io
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import atlas_instances as ai  # noqa: E402
from modules import atlas_roster as roster  # noqa: E402
import modules.atlas as atlas  # noqa: E402

PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)
CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)


class FakeAuthentik:
    """Enough of /api/v3 for groups, users, tokens, roles and role permissions."""

    def __init__(self):
        self.groups, self.users, self.tokens, self.roles = {}, {}, {}, {}
        self.object_perms = []   # (role_pk, codename, object_pk)
        self.model_perms = []    # (role_pk, codename)
        self.applications = {}   # slug -> row
        self.bindings = []
        self.calls = []
        self._pk = 100

    def add_application(self, slug):
        app = {'pk': 'app-%s' % slug, 'slug': slug}
        self.applications[slug] = app
        return app

    def bindings_of(self, group_name):
        pks = {g['pk'] for g in self.groups.values() if g['name'] == group_name}
        return [b for b in self.bindings if b['group'] in pks]

    def pk(self):
        self._pk += 1
        return self._pk

    def add_group(self, name, superuser=False, users=()):
        g = {'pk': 'g%d' % self.pk(), 'name': name, 'is_superuser': superuser,
             'users': list(users)}
        self.groups[g['pk']] = g
        return g

    def __call__(self, req, timeout=None):
        url = urllib.parse.urlparse(req.full_url)
        path = url.path.split('/api/v3/', 1)[1]
        query = dict(urllib.parse.parse_qsl(url.query))
        method = req.get_method()
        body = json.loads(req.data.decode()) if req.data else None
        self.calls.append((method, path, body))
        if path.startswith('core/applications/'):
            slug = path.split('/')[2]
            if slug not in self.applications:
                raise urllib.error.HTTPError(req.full_url, 404, 'Not Found', {}, None)
        out = self.handle(method, path, query, body)
        return io.BytesIO(json.dumps(out).encode() if out is not None else b'')

    def handle(self, method, path, query, body):
        parts = [p for p in path.split('/') if p]
        if parts[:2] == ['core', 'applications'] and method == 'GET':
            return self.applications[parts[2]]
        if parts[:2] == ['policies', 'bindings']:
            if method == 'GET':
                return {'results': [b for b in self.bindings
                                    if b['target'] == query.get('target')]}
            if method == 'POST':
                b = dict(body, pk='b%d' % self.pk())
                self.bindings.append(b)
                return b
        if parts[:2] == ['core', 'groups']:
            if len(parts) == 2 and method == 'GET':
                return {'results': [g for g in self.groups.values()
                                    if g['name'] == query.get('name')]}
            if len(parts) == 2 and method == 'POST':
                return self.add_group(body['name'], body.get('is_superuser', False))
            g = self.groups[parts[2]]
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
                u = dict(body, pk=self.pk(), roles=[])
                self.users[u['pk']] = u
                return u
            pk = int(parts[2])
            if method == 'PATCH':
                self.users[pk].update(body)
                return self.users[pk]
            if method == 'DELETE':
                del self.users[pk]
                # Authentik deletes a user's tokens with the user.
                self.tokens = {k: t for k, t in self.tokens.items() if t['user'] != pk}
                return None
        if parts[:2] == ['core', 'tokens']:
            if len(parts) == 2 and method == 'GET':
                want = query.get('user__username')
                return {'results': [t for t in self.tokens.values()
                                    if self.users.get(t['user'], {}).get('username') == want
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
        if parts[:2] == ['rbac', 'roles']:
            if len(parts) == 2 and method == 'GET':
                return {'results': [r for r in self.roles.values()
                                    if r['name'] == query.get('name')]}
            if len(parts) == 2 and method == 'POST':
                r = {'pk': 'r%d' % self.pk(), 'name': body['name'], 'users': []}
                self.roles[r['pk']] = r
                return r
            r = self.roles[parts[2]]
            if len(parts) == 4 and parts[3] == 'add_user':
                if body['pk'] not in r['users']:
                    r['users'].append(body['pk'])
                return None
            if method == 'DELETE':
                del self.roles[parts[2]]
                self.object_perms = [p for p in self.object_perms if p[0] != parts[2]]
                self.model_perms = [p for p in self.model_perms if p[0] != parts[2]]
                return None
        if parts[:3] == ['rbac', 'permissions', 'assigned_by_roles']:
            if len(parts) == 3 and method == 'GET':
                assert query.get('model') == 'authentik_core.group'
                rows = {}
                for role_pk, codename, _obj in self.object_perms:
                    rows.setdefault(role_pk, {'role_pk': role_pk, 'model_permissions': []})
                for role_pk, codename in self.model_perms:
                    rows.setdefault(role_pk, {'role_pk': role_pk, 'model_permissions': []})
                    rows[role_pk]['model_permissions'].append({'codename': codename})
                return {'results': list(rows.values())}
            role_pk = parts[3]
            codenames = [p.split('.', 1)[1] for p in body['permissions']]
            if parts[4] == 'assign':
                for c in codenames:
                    # Like Authentik: an object that is not there means global.
                    if body.get('object_pk') in self.groups:
                        if (role_pk, c, body['object_pk']) not in self.object_perms:
                            self.object_perms.append((role_pk, c, body['object_pk']))
                    else:
                        self.model_perms.append((role_pk, c))
                return []
            if parts[4] == 'unassign':
                self.model_perms = [p for p in self.model_perms
                                    if not (p[0] == role_pk and p[1] in codenames)]
                return None
        raise AssertionError('unexpected call %s %s' % (method, path))

    def visible_groups(self, role_pk):
        return {obj for r, _c, obj in self.object_perms if r == role_pk}


@pytest.fixture
def ak():
    fake = FakeAuthentik()
    fake.add_group('atlas-corona-admins', users=[1])
    fake.add_application('atlas-corona')
    fake.add_application('atlas')
    return fake


@pytest.fixture
def deployment(tmp_path):
    (tmp_path / '.env').write_text('TAKMDM_DB_PASSWORD=x\nTAKMDM_ADMIN_GROUP=atlas-corona-admins,authentik Admins\n')
    return tmp_path


def _ctx(token='admin-token', domain='auth.example.com'):
    env = {'AUTHENTIK_TOKEN': token}
    return {
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: env.get(k),
        '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
        '_get_service_domain': lambda s, key: domain if key == 'authentik' else '',
        '_pub_hostport': lambda host, s=None: host,
    }


def _ensure(deployment, ak, inst=CORONA, ctx=None, installed=None):
    log = []
    result = roster.ensure(ctx or _ctx(), inst, str(deployment), atlas.write_env_value,
                           log.append, opener=ak, installed=installed)
    return result, log


def _env(deployment):
    return dict(line.split('=', 1) for line in
                (deployment / '.env').read_text().splitlines() if '=' in line)


def _by_name(ak, name):
    return next(g for g in ak.groups.values() if g['name'] == name)


# --------------------------------------------------------------------------- #
# Names
# --------------------------------------------------------------------------- #

def test_an_agency_gets_its_own_names():
    assert roster.names(CORONA) == {
        'admin_group': 'atlas-corona-admins',
        'standard_group': 'atlas-corona-standard-admins',
        'username': 'atlas-roster-corona',
        'role': 'atlas-roster-corona',
        'token': 'atlas-roster-corona-api',
        'application': 'atlas-corona',
    }


def test_the_plain_deployment_gets_its_own_names_and_no_admin_group():
    """⚠️ Its super admins are the box's Authentik administrators: the roster
    must never be scoped to them."""
    assert roster.names(PLAIN) == {
        'admin_group': None,
        'standard_group': 'atlas-standard-admins',
        'username': 'atlas-roster',
        'role': 'atlas-roster',
        'token': 'atlas-roster-api',
        'application': 'atlas',
    }


def test_an_agency_named_standard_is_refused():
    """⚠️ Its admin group would be the plain deployment's standard group."""
    slug, error = ai.validate_slug('standard')
    assert slug is None and 'reserved' in error
    assert ai.derive({'slug': 'standard'})['admin_group'] == roster.names(PLAIN)['standard_group']


def test_a_standard_group_can_never_be_another_agencys_admin_group():
    # A slug is lowercase letters only, so no hyphen can make the names meet.
    assert not ai._SLUG_RE.match('corona-standard')


def test_the_standard_group_is_never_an_administrator_group():
    """⚠️ In TAKMDM_ADMIN_GROUP it would make standard admins full admins on
    today's ATLAS, which does not know the role."""
    for inst in (PLAIN, CORONA):
        assert not any('standard' in g for g in atlas.admin_groups_for(inst, 'authentik Admins'))


# --------------------------------------------------------------------------- #
# Setting it up
# --------------------------------------------------------------------------- #

def test_the_group_is_made_empty_and_not_a_superuser(deployment, ak):
    _ensure(deployment, ak)
    group = _by_name(ak, 'atlas-corona-standard-admins')
    assert group['is_superuser'] is False and group['users'] == []


def test_the_account_is_a_service_account(deployment, ak):
    _ensure(deployment, ak)
    [user] = [u for u in ak.users.values() if u['username'] == 'atlas-roster-corona']
    assert user['type'] == 'service_account'
    assert user['path'] == 'goauthentik.io/service-accounts'


def test_the_role_sees_the_two_agency_groups_and_nothing_else(deployment, ak):
    ak.add_group('authentik Admins', superuser=True)
    ak.add_group('atlas-other-admins')
    _ensure(deployment, ak)
    [role] = ak.roles.values()
    wanted = {_by_name(ak, 'atlas-corona-admins')['pk'],
              _by_name(ak, 'atlas-corona-standard-admins')['pk']}
    assert ak.visible_groups(role['pk']) == wanted
    assert ak.model_perms == []
    [user] = ak.users.values()
    assert role['users'] == [user['pk']], 'the role is given to the account directly'


@pytest.mark.parametrize('installed', [None, '', '2.2.2', 'v2.2.9', '2.3', 'garbage'])
def test_an_older_or_unknown_atlas_does_not_admit_the_group(deployment, ak, installed):
    """⚠️ Before 2.3.0 a box with a blank TAKMDM_ADMIN_GROUP would make the
    group's members full administrators."""
    result, log = _ensure(deployment, ak, installed=installed)
    assert not [c for c in ak.calls if c[1].startswith(('policies', 'core/applications'))]
    assert 'predates the standard role (2.3.0)' in log[-1]
    assert result == {'env_changed': True}, 'the roster is still set up'


@pytest.mark.parametrize('installed', ['2.3.0', 'v2.3.0', '2.10.1', '3.0.0'])
def test_atlas_2_3_0_or_newer_admits_the_group_to_its_own_application(deployment, ak, installed):
    _ensure(deployment, ak, installed=installed)
    [binding] = ak.bindings_of('atlas-corona-standard-admins')
    assert binding['target'] == 'app-atlas-corona', 'this deployment only'
    assert binding['order'] == 20 and binding['enabled'] is True and binding['negate'] is False
    assert len(ak.bindings) == 1, 'nothing else bound or replaced'


def test_the_binding_is_made_once(deployment, ak):
    _ensure(deployment, ak, installed='2.3.0')
    _result, log = _ensure(deployment, ak, installed='2.3.0')
    assert len(ak.bindings_of('atlas-corona-standard-admins')) == 1
    assert log[-1].endswith('admitted to ATLAS')


def test_a_disabled_binding_is_left_alone_and_reported(deployment, ak):
    """⚠️ Somebody switched it off in Authentik; that is theirs to undo."""
    _ensure(deployment, ak, installed='2.3.0')
    [binding] = ak.bindings_of('atlas-corona-standard-admins')
    binding['enabled'] = False
    _result, log = _ensure(deployment, ak, installed='2.3.0')
    assert len(ak.bindings) == 1 and binding['enabled'] is False
    assert log[-1].startswith('  ⚠') and 'disabled or negated' in log[-1]


def test_a_failed_binding_still_leaves_the_roster_working(deployment, ak):
    del ak.applications['atlas-corona']
    result, log = _ensure(deployment, ak, installed='2.3.0')
    assert result == {'env_changed': True}
    assert _env(deployment)['TAKMDM_AUTHENTIK_ROSTER_TOKEN'] == 'key-for-atlas-roster-corona-api'
    assert 'not admitted to ATLAS' in log[-1] and log[-1].startswith('  ⚠')


@pytest.mark.parametrize('installed,admits', [
    ('2.3.0', True), ('V2.3.1', True), (' 2.4.0 ', True), ('2.2.99', False),
    ('1.99.0', False), (None, False), ('2.3.0-rc1', False), ('2.3.0.1', False),
])
def test_which_atlas_versions_know_the_role(installed, admits):
    assert roster.admits_role(installed) is admits


# --------------------------------------------------------------------------- #
# The plain deployment
# --------------------------------------------------------------------------- #

def test_the_plain_deployment_gets_a_group_a_roster_and_on_2_3_0_a_binding(deployment, ak):
    admins = ak.add_group('authentik Admins', superuser=True)
    result, log = _ensure(deployment, ak, inst=PLAIN, installed='2.3.0')
    standard = _by_name(ak, 'atlas-standard-admins')
    assert standard['is_superuser'] is False and standard['users'] == []
    [role] = ak.roles.values()
    assert role['name'] == 'atlas-roster'
    assert ak.visible_groups(role['pk']) == {standard['pk']}, 'never authentik Admins'
    assert admins['pk'] not in ak.visible_groups(role['pk'])
    [binding] = ak.bindings_of('atlas-standard-admins')
    assert binding['target'] == 'app-atlas'
    env = _env(deployment)
    assert env['TAKMDM_STANDARD_ADMIN_GROUP'] == 'atlas-standard-admins'
    assert env['TAKMDM_AUTHENTIK_ROSTER_TOKEN'] == 'key-for-atlas-roster-api'
    assert result == {'env_changed': True}
    assert 'roster account atlas-roster can read it' in log[-2]


def test_the_plain_deployment_on_an_older_atlas_is_not_admitted(deployment, ak):
    _ensure(deployment, ak, inst=PLAIN, installed='2.2.2')
    assert ak.bindings == []


def test_the_plain_deployment_stands_aside_for_an_agency_named_standard(deployment, ak):
    """⚠️ A box that deployed agency 'standard' before the slug was reserved:
    `atlas-standard-admins` is that agency's admin group."""
    ak.add_application('atlas-standard')
    theirs = ak.add_group('atlas-standard-admins', users=[5])
    result, log = _ensure(deployment, ak, inst=PLAIN, installed='2.3.0')
    assert result == {'env_changed': False}
    assert ak.roles == {} and ak.users == {} and ak.bindings == []
    assert 'agency deployment "standard"' in log[-1]
    note = roster.remove(_ctx(), PLAIN, opener=ak)
    assert theirs['pk'] in ak.groups and 'not removed' in note


def test_atlas_gets_the_group_the_address_and_the_token(deployment, ak):
    result, _log = _ensure(deployment, ak)
    env = _env(deployment)
    assert env['TAKMDM_STANDARD_ADMIN_GROUP'] == 'atlas-corona-standard-admins'
    assert env['TAKMDM_AUTHENTIK_URL'] == 'https://auth.example.com'
    assert env['TAKMDM_AUTHENTIK_ROSTER_TOKEN'] == 'key-for-atlas-roster-corona-api'
    assert env['TAKMDM_ADMIN_GROUP'] == 'atlas-corona-admins,authentik Admins', 'untouched'
    assert result == {'env_changed': True}


def test_the_token_is_stable_across_updates(deployment, ak):
    """⚠️ ATLAS reads it at start: rotating it would break the roster until a
    restart, so it is kept and nothing changes on a second run."""
    _ensure(deployment, ak)
    result, _log = _ensure(deployment, ak)
    assert result == {'env_changed': False}
    assert list(ak.tokens) == ['atlas-roster-corona-api']
    assert ak.tokens['atlas-roster-corona-api']['expiring'] is False
    assert len(ak.roles) == 1 and len(ak.users) == 1


def test_a_deleted_token_is_made_again(deployment, ak):
    _ensure(deployment, ak)
    ak.tokens.clear()
    result, _log = _ensure(deployment, ak)
    assert list(ak.tokens) == ['atlas-roster-corona-api']
    assert result == {'env_changed': False}, 'same identifier, same fake key'


def test_a_superuser_flag_on_the_group_is_taken_off(deployment, ak):
    ak.add_group('atlas-corona-standard-admins', superuser=True)
    _result, log = _ensure(deployment, ak)
    assert _by_name(ak, 'atlas-corona-standard-admins')['is_superuser'] is False
    assert 'superuser flag removed' in log[-2]


def test_a_missing_agency_group_sets_nothing_up(deployment, ak):
    """⚠️ Never scope a role to a group that is not there: Authentik would
    grant the permission on every group instead."""
    ak.groups.clear()
    result, log = _ensure(deployment, ak)
    assert result == {'env_changed': False}
    assert ak.roles == {} and ak.users == {} and ak.model_perms == []
    assert 'atlas-corona-admins" is missing' in log[-1]


def test_a_grant_on_every_group_is_taken_away_and_reported(deployment, ak, monkeypatch):
    real = roster.ensure_role

    def scoped_to_a_ghost(api, n, user, groups):
        return real(api, n, user, groups + [{'pk': 'gone'}])
    monkeypatch.setattr(roster, 'ensure_role', scoped_to_a_ghost)

    result, log = _ensure(deployment, ak)
    assert ak.model_perms == [], 'the global grant was removed'
    assert 'permission on every group' in log[-1]
    assert result == {'env_changed': False}
    assert 'TAKMDM_AUTHENTIK_ROSTER_TOKEN' not in _env(deployment), 'no token for that role'


def test_a_person_with_the_accounts_name_is_refused(deployment, ak):
    ak.users[7] = {'pk': 7, 'username': 'atlas-roster-corona', 'type': 'internal',
                   'is_active': True, 'roles': []}
    result, log = _ensure(deployment, ak)
    assert result == {'env_changed': False}
    assert ak.roles == {} and ak.tokens == {}
    assert 'not a service account' in log[-1]


def test_the_token_is_never_logged(deployment, ak):
    _r, log = _ensure(deployment, ak)
    assert not any('key-for-' in line for line in log)
    assert 'atlas-corona-standard-admins' in log[-1]


def test_no_authentik_says_so_and_does_not_fail(deployment, ak):
    result, log = _ensure(deployment, ak, ctx=_ctx(token=None))
    assert result == {'env_changed': False} and ak.calls == []
    assert 'Authentik is not configured' in log[-1]


def test_an_authentik_error_is_reported_not_raised(deployment):
    def broken(req, timeout=None):
        raise OSError('connection refused')
    result, log = _ensure(deployment, broken)
    assert result == {'env_changed': False}
    assert 'connection refused' in log[-1]


# --------------------------------------------------------------------------- #
# Removal
# --------------------------------------------------------------------------- #

def test_removal_deletes_token_account_role_and_group(deployment, ak):
    _ensure(deployment, ak)
    _by_name(ak, 'atlas-corona-standard-admins')['users'] = [1, 2]
    note = roster.remove(_ctx(), CORONA, opener=ak)
    assert ak.tokens == {} and ak.roles == {}
    assert [u for u in ak.users.values() if u['username'] == 'atlas-roster-corona'] == []
    assert 'atlas-corona-standard-admins' not in {g['name'] for g in ak.groups.values()}
    assert 'atlas-corona-admins' in {g['name'] for g in ak.groups.values()}, 'not ours to remove here'
    assert '(it had 2 members)' in note


def test_removal_never_deletes_a_person_with_the_accounts_name(ak):
    ak.users[7] = {'pk': 7, 'username': 'atlas-roster-corona', 'type': 'internal'}
    roster.remove(_ctx(), CORONA, opener=ak)
    assert 7 in ak.users


def test_removal_of_the_plain_deployment_removes_its_own_and_nothing_else(deployment, ak):
    ak.add_group('authentik Admins', superuser=True)
    _ensure(deployment, ak, inst=PLAIN, installed='2.3.0')
    note = roster.remove(_ctx(), PLAIN, opener=ak)
    names = {g['name'] for g in ak.groups.values()}
    assert 'atlas-standard-admins' not in names
    assert {'authentik Admins', 'atlas-corona-admins'} <= names
    assert ak.roles == {} and ak.users == {} and ak.tokens == {}
    assert "account 'atlas-roster'" in note


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #

def _body(src, name):
    return re.search(r'\ndef %s\(.*?(?=\ndef )' % name, src, re.S).group(0)


def test_deploy_and_every_update_reconcile_it_after_the_agency_group():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    access = _body(src, '_reconcile_access')
    assert access.index('_reconcile_agency_group(') < access.index('_reconcile_roster(')
    deploy = _body(src, 'deploy')
    assert deploy.index('_reconcile_agency_group(ctx, _inst') < deploy.index('_reconcile_roster(ctx, _inst')
    assert 'atlas_roster.remove(ctx, inst)' in src


def test_a_changed_env_restarts_api():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    helper = _body(src, '_reconcile_roster')
    assert "['env_changed']" in helper and "'up -d api'" in helper


def test_the_installed_version_decides_the_binding():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    assert 'installed=_installed_version(ctx, inst)' in _body(src, '_reconcile_roster')
