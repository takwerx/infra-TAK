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
        self.policies = {}       # pk -> expression policy row
        self.calls = []
        self._pk = 100

    def add_application(self, slug):
        app = {'pk': 'app-%s' % slug, 'slug': slug}
        self.applications[slug] = app
        return app

    def bindings_of(self, group_name):
        pks = {g['pk'] for g in self.groups.values() if g['name'] == group_name}
        return [b for b in self.bindings if b.get('group') in pks]

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
                if b.get('policy') in self.policies:
                    b['policy_obj'] = {'name': self.policies[b['policy']]['name']}
                self.bindings.append(b)
                return b
            if method == 'DELETE':
                self.bindings = [b for b in self.bindings if b['pk'] != parts[2]]
                return None
        if parts[:2] == ['policies', 'expression']:
            if len(parts) == 2 and method == 'GET':
                return {'results': [p for p in self.policies.values()
                                    if p['name'] == query.get('name')]}
            if len(parts) == 2 and method == 'POST':
                pol = dict(body, pk='p%d' % self.pk())
                self.policies[pol['pk']] = pol
                return pol
            if method == 'PATCH':
                self.policies[parts[2]].update(body)
                return self.policies[parts[2]]
            if method == 'DELETE':
                del self.policies[parts[2]]
                self.bindings = [b for b in self.bindings if b.get('policy') != parts[2]]
                return None
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

    def bind_policy(self, slug, name, expression='', order=0):
        """A policy bound to an application, as app.py and Hardened leave them."""
        pol = {'pk': 'p%d' % self.pk(), 'name': name, 'expression': expression}
        self.policies[pol['pk']] = pol
        b = {'pk': 'b%d' % self.pk(), 'target': self.applications[slug]['pk'],
             'policy': pol['pk'], 'policy_obj': {'name': name}, 'order': order,
             'enabled': True, 'negate': False}
        self.bindings.append(b)
        return b

    def bind_group(self, slug, group_name, order=10):
        b = {'pk': 'b%d' % self.pk(), 'target': self.applications[slug]['pk'],
             'group': _by_name(self, group_name)['pk'], 'order': order,
             'enabled': True, 'negate': False}
        self.bindings.append(b)
        return b

    def can_open(self, slug, groups, mode):
        """Authentik's decision for a user in `groups` (MFA always passed).

        Its documented rule: `any` admits when one binding passes, `all` only
        when every one does, and an application with no binding admits every
        signed-in user.
        """
        target = self.applications[slug]['pk']
        live = [b for b in self.bindings
                if b['target'] == target and b.get('enabled', True)]
        if not live:
            return True
        names = {g['pk']: g['name'] for g in self.groups.values()}
        results = []
        for b in live:
            name = (b.get('policy_obj') or {}).get('name')
            if b.get('group'):
                ok = names.get(b['group']) in groups
            elif name == 'Allow authentik Admins':
                ok = 'authentik Admins' in groups
            elif name and name.startswith('ATLAS access: '):
                pol = self.policies[b['policy']]
                ok = any(json.loads(q) in groups for q in
                         re.findall(r'name=("(?:[^"\\]|\\.)*")', pol['expression']))
            elif mode == 'any':
                continue  # the Standard posture has no MFA binding
            else:
                ok = True  # the Hardened MFA binding; the user has a device
            results.append(ok != bool(b.get('negate')))
        return all(results) if mode == 'all' else any(results)


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


def _ensure(deployment, ak, inst=CORONA, ctx=None, installed=None, running='same',
            restarted=True):
    """`ensure`, then (when `installed` is given) `admit`, as `_reconcile_roster` does."""
    log = []
    result = roster.ensure(ctx or _ctx(), inst, str(deployment), atlas.write_env_value,
                           log.append, opener=ak)
    if installed != 'skip':
        roster.admit(ctx or _ctx(), inst, str(deployment), installed,
                     installed if running == 'same' else running, log.append,
                     restarted=restarted, opener=ak)
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


# --------------------------------------------------------------------------- #
# Who gets in (ops #919): one access policy, under `any` and under `all`
# --------------------------------------------------------------------------- #

GLOBAL = {'authentik Admins'}
AGENCY = {'atlas-corona-admins'}
STANDARD = {'atlas-corona-standard-admins'}
NOBODY = {'someone-else'}
MODES = ['all', 'any']   # Hardened posture (MFA step), Standard posture


@pytest.fixture
def box(ak):
    """An agency deployment as dev leaves it on a Hardened box before this change.

    "Allow authentik Admins" at 0 (app.py), the MFA binding (Hardened), and the
    agency group's access policy made by the agency reconcile (ops #979).
    """
    ak.add_group('authentik Admins', superuser=True)
    ak.bind_policy('atlas-corona', 'Allow authentik Admins', order=0)
    ak.bind_policy('atlas-corona', 'infratak-require-mfa', order=10)
    from modules import atlas_access
    api = roster.AuthentikAdmin('http://127.0.0.1:9090', 't', ak)
    assert atlas_access.ensure(api, 'atlas-corona',
                               add=['atlas-corona-admins'])['status'] == 'created'
    return ak


@pytest.mark.parametrize('mode', MODES)
def test_on_2_3_0_every_kind_of_admin_gets_in_and_nobody_else(deployment, box, mode):
    """The customer's question. The first form of this change bound the group
    beside the others, and on a Hardened box (`all`) that locked the global and
    agency admins out (test6, ops #919)."""
    _ensure(deployment, box, installed='2.3.0')
    assert box.can_open('atlas-corona', GLOBAL, mode), 'global admin'
    assert box.can_open('atlas-corona', AGENCY, mode), 'agency admin'
    assert box.can_open('atlas-corona', STANDARD, mode), 'standard admin'
    assert not box.can_open('atlas-corona', NOBODY, mode), 'no group'
    assert not box.can_open('atlas-corona', {'atlas-other-standard-admins'}, mode)


def test_the_group_is_a_name_in_the_policy_not_a_binding(deployment, box):
    _ensure(deployment, box, installed='2.3.0')
    assert box.bindings_of('atlas-corona-standard-admins') == []
    [pol] = [p for p in box.policies.values() if p['name'] == 'ATLAS access: atlas-corona']
    assert 'atlas-corona-standard-admins' in pol['expression']
    assert 'atlas-corona-admins' in pol['expression'], 'the agency group is kept'


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('installed', [None, '', '2.2.2', 'v2.2.9', '2.3', 'garbage'])
def test_an_older_or_unknown_atlas_keeps_the_group_out(deployment, box, mode, installed):
    """⚠️ Before 2.3.0 a box with a blank TAKMDM_ADMIN_GROUP would make the
    group's members full administrators."""
    result, log = _ensure(deployment, box, installed=installed)
    assert not box.can_open('atlas-corona', STANDARD, mode)
    assert box.can_open('atlas-corona', AGENCY, mode)
    assert box.can_open('atlas-corona', GLOBAL, mode)
    assert 'predates the standard role (2.3.0)' in log[-1]
    assert result == {'env_changed': True}, 'the roster is still set up'


@pytest.mark.parametrize('running', [None, '2.2.2'])
def test_the_running_atlas_must_be_2_3_0_too(deployment, box, running):
    """Security read, ops #978: a failed rebuild leaves 2.3.0 on disk and the
    old ATLAS serving."""
    _result, log = _ensure(deployment, box, installed='2.3.0', running=running)
    assert not box.can_open('atlas-corona', STANDARD, 'any')
    assert 'the running ATLAS reports' in log[-1]


@pytest.mark.parametrize('installed,running', [
    ('2.2.2', '2.2.2'),     # Deploy run again checked out the main channel's tag
    ('2.3.0', '2.2.2'),     # an update whose rebuild failed
    ('2.3.0', None),        # api not answering
])
def test_a_group_let_in_before_is_taken_out_again(deployment, box, installed, running):
    """Security read, ops #978, change 1: the old code never took it off."""
    _ensure(deployment, box, installed='2.3.0')
    assert box.can_open('atlas-corona', STANDARD, 'any')
    _result, log = _ensure(deployment, box, installed=installed, running=running)
    assert not box.can_open('atlas-corona', STANDARD, 'any')
    assert box.can_open('atlas-corona', AGENCY, 'all')
    assert box.can_open('atlas-corona', GLOBAL, 'all')
    assert 'taken out of ATLAS access' in log[-1]


def test_a_failed_restart_keeps_the_group_out(deployment, box):
    """Security read, ops #978, change 2: ATLAS must know the group's name
    before anyone in it is let in."""
    _result, log = _ensure(deployment, box, installed='2.3.0', restarted=False)
    assert not box.can_open('atlas-corona', STANDARD, 'any')
    assert 'could not be restarted' in log[-1]


def test_an_env_without_the_group_keeps_the_group_out(deployment, box, monkeypatch):
    monkeypatch.setattr(roster, 'ensure_token',
                        lambda *a: (_ for _ in ()).throw(RuntimeError('boom')))
    _result, log = _ensure(deployment, box, installed='2.3.0')
    assert 'TAKMDM_STANDARD_ADMIN_GROUP' not in _env(deployment)
    assert not box.can_open('atlas-corona', STANDARD, 'any')
    assert '.env does not name the group' in log[-1]


def test_admitting_twice_changes_nothing(deployment, box):
    _ensure(deployment, box, installed='2.3.0')
    before = ([dict(b) for b in box.bindings], {k: dict(v) for k, v in box.policies.items()})
    _result, log = _ensure(deployment, box, installed='2.3.0')
    assert ([dict(b) for b in box.bindings], box.policies) == before
    assert 'admitted to ATLAS' in log[-1]


@pytest.mark.parametrize('installed', ['2.2.2', '2.3.0'])
def test_a_direct_binding_from_the_first_form_is_removed(deployment, box, installed):
    """PR 596 as first written bound the group directly. Under `any` that is a
    door of its own, under `all` a lock on everybody else."""
    box.add_group('atlas-corona-standard-admins')
    box.bind_group('atlas-corona', 'atlas-corona-standard-admins', order=20)
    _ensure(deployment, box, installed=installed)
    assert box.bindings_of('atlas-corona-standard-admins') == []
    assert box.can_open('atlas-corona', AGENCY, 'all')
    assert box.can_open('atlas-corona', STANDARD, 'any') is (installed == '2.3.0')


def test_a_direct_binding_that_is_the_only_way_in_is_left_and_reported(deployment, ak):
    """⚠️ Deleting it would leave the application with no binding, which
    Authentik opens to every signed-in user."""
    ak.add_group('atlas-corona-standard-admins')
    ak.bind_group('atlas-corona', 'atlas-corona-standard-admins')
    _result, log = _ensure(deployment, ak, installed='2.2.2')
    assert len(ak.bindings_of('atlas-corona-standard-admins')) == 1
    assert not ak.can_open('atlas-corona', NOBODY, 'any')
    assert 'left in place' in log[-1] and log[-1].startswith('  ⚠')


def test_a_disabled_access_binding_is_left_alone_and_reported(deployment, box):
    """⚠️ Somebody switched it off in Authentik; that is theirs to undo."""
    [ours] = [b for b in box.bindings
              if (b.get('policy_obj') or {}).get('name', '').startswith('ATLAS access')]
    ours['enabled'] = False
    _result, log = _ensure(deployment, box, installed='2.3.0')
    assert ours in box.bindings and ours['enabled'] is False
    assert log[-1].startswith('  ⚠') and 'disabled or negated' in log[-1]


def test_a_failed_admit_still_leaves_the_roster_working(deployment, ak):
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

@pytest.fixture
def plain_box(ak):
    """The plain deployment as dev leaves it on a Hardened box."""
    ak.add_group('authentik Admins', superuser=True)
    ak.bind_policy('atlas', 'Allow authentik Admins', order=0)
    ak.bind_policy('atlas', 'infratak-require-mfa', order=10)
    return ak


@pytest.mark.parametrize('mode', MODES)
def test_the_plain_deployment_on_2_3_0_lets_global_and_standard_admins_in(
        deployment, plain_box, mode):
    ak = plain_box
    result, log = _ensure(deployment, ak, inst=PLAIN, installed='2.3.0')
    standard = _by_name(ak, 'atlas-standard-admins')
    assert standard['is_superuser'] is False and standard['users'] == []
    [role] = ak.roles.values()
    assert role['name'] == 'atlas-roster'
    assert ak.visible_groups(role['pk']) == {standard['pk']}, 'never authentik Admins'
    env = _env(deployment)
    assert env['TAKMDM_STANDARD_ADMIN_GROUP'] == 'atlas-standard-admins'
    assert env['TAKMDM_AUTHENTIK_ROSTER_TOKEN'] == 'key-for-atlas-roster-api'
    assert result == {'env_changed': True}
    assert ak.can_open('atlas', GLOBAL, mode)
    assert ak.can_open('atlas', {'atlas-standard-admins'}, mode)
    assert not ak.can_open('atlas', NOBODY, mode)
    assert not ak.can_open('atlas', AGENCY, mode), 'an agency admin is not a plain admin'
    assert ak.bindings_of('atlas-standard-admins') == []


def test_the_plain_deployment_on_an_older_atlas_is_left_as_it_was(deployment, plain_box):
    """No policy is made just to keep a group out of it."""
    before = [dict(b) for b in plain_box.bindings]
    _ensure(deployment, plain_box, inst=PLAIN, installed='2.2.2')
    assert [dict(b) for b in plain_box.bindings] == before
    assert not plain_box.can_open('atlas', {'atlas-standard-admins'}, 'any')
    assert plain_box.can_open('atlas', GLOBAL, 'all')


def test_the_plain_deployment_takes_the_group_out_after_a_downgrade(deployment, plain_box):
    _ensure(deployment, plain_box, inst=PLAIN, installed='2.3.0')
    _ensure(deployment, plain_box, inst=PLAIN, installed='2.2.2')
    assert not plain_box.can_open('atlas', {'atlas-standard-admins'}, 'any')
    assert plain_box.can_open('atlas', GLOBAL, 'all')


def test_the_plain_deployment_stands_aside_for_an_agency_named_standard(deployment, ak):
    """⚠️ A box that deployed agency 'standard' before the slug was reserved:
    `atlas-standard-admins` is that agency's admin group."""
    ak.add_application('atlas-standard')
    theirs = ak.add_group('atlas-standard-admins', users=[5])
    result, log = _ensure(deployment, ak, inst=PLAIN, installed='2.3.0')
    assert result == {'env_changed': False}
    assert ak.roles == {} and ak.users == {} and ak.bindings == [] and ak.policies == {}
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
    result, log = _ensure(deployment, ak, installed='skip')
    assert result == {'env_changed': False}
    assert ak.roles == {} and ak.users == {} and ak.model_perms == []
    assert 'atlas-corona-admins" is missing' in log[-1]


def test_a_grant_on_every_group_is_taken_away_and_reported(deployment, ak, monkeypatch):
    real = roster.ensure_role

    def scoped_to_a_ghost(api, n, user, groups):
        return real(api, n, user, groups + [{'pk': 'gone'}])
    monkeypatch.setattr(roster, 'ensure_role', scoped_to_a_ghost)

    result, log = _ensure(deployment, ak, installed='skip')
    assert ak.model_perms == [], 'the global grant was removed'
    assert 'permission on every group' in log[-1]
    assert result == {'env_changed': False}
    assert 'TAKMDM_AUTHENTIK_ROSTER_TOKEN' not in _env(deployment), 'no token for that role'


def test_a_person_with_the_accounts_name_is_refused(deployment, ak):
    ak.users[7] = {'pk': 7, 'username': 'atlas-roster-corona', 'type': 'internal',
                   'is_active': True, 'roles': []}
    result, log = _ensure(deployment, ak, installed='skip')
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


class _Ran:
    def __init__(self, code):
        self.returncode = code


@pytest.mark.parametrize('env_changed,code,restarted', [
    (True, 0, True), (True, 1, False), (False, None, True)])
def test_reconcile_restarts_api_before_it_admits(monkeypatch, tmp_path, env_changed,
                                                 code, restarted):
    """Security read, ops #978, change 2: the group is let in only after ATLAS
    restarted with its name, and on both the file's and the container's version."""
    order = []
    monkeypatch.setattr(atlas, 'instance_paths', lambda ctx, inst: {'dir': str(tmp_path)})
    monkeypatch.setattr(atlas.atlas_roster, 'ensure',
                        lambda *a, **k: order.append('ensure') or {'env_changed': env_changed})
    monkeypatch.setattr(atlas, '_compose',
                        lambda ctx, action, timeout=None, inst=None:
                        order.append(action) or _Ran(code))
    monkeypatch.setattr(atlas, '_installed_version', lambda ctx, inst: '2.3.0')
    monkeypatch.setattr(atlas, '_settled_running_version',
                        lambda ctx, inst: order.append('version') or '2.3.0')
    seen = {}

    def admit(ctx, inst, dirpath, installed, running, plog, restarted=True):
        order.append('admit')
        seen.update(installed=installed, running=running, restarted=restarted)
    monkeypatch.setattr(atlas.atlas_roster, 'admit', admit)
    atlas._reconcile_roster({}, CORONA, lambda m: None)
    want = ['ensure'] + (['up -d api'] if env_changed else []) + ['version', 'admit']
    assert order == want
    assert seen == {'installed': '2.3.0', 'running': '2.3.0', 'restarted': restarted}


def test_reconcile_does_not_wait_for_an_atlas_that_cannot_admit(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'instance_paths', lambda ctx, inst: {'dir': str(tmp_path)})
    monkeypatch.setattr(atlas.atlas_roster, 'ensure', lambda *a, **k: {'env_changed': False})
    monkeypatch.setattr(atlas, '_installed_version', lambda ctx, inst: '2.2.2')
    monkeypatch.setattr(atlas, '_settled_running_version',
                        lambda ctx, inst: pytest.fail('waited for nothing'))
    monkeypatch.setattr(atlas, '_running_version', lambda ctx, inst: '2.2.2')
    monkeypatch.setattr(atlas.atlas_roster, 'admit', lambda *a, **k: None)
    atlas._reconcile_roster({}, CORONA, lambda m: None)


def test_the_running_version_is_waited_for(monkeypatch):
    answers = iter([None, None, '2.3.0'])
    monkeypatch.setattr(atlas, '_running_version', lambda ctx, inst: next(answers))
    monkeypatch.setattr(atlas.time, 'sleep', lambda s: None)
    assert atlas._settled_running_version({}, CORONA) == '2.3.0'
    monkeypatch.setattr(atlas, '_running_version', lambda ctx, inst: None)
    assert atlas._settled_running_version({}, CORONA, tries=3) is None


def test_removal_of_the_plain_deployment_removes_its_access_policy(deployment, ak):
    ak.add_group('authentik Admins', superuser=True)
    _ensure(deployment, ak, inst=PLAIN, installed='2.3.0')
    assert any(p['name'] == 'ATLAS access: atlas' for p in ak.policies.values())
    note = roster.remove(_ctx(), PLAIN, opener=ak)
    assert ak.policies == {}
    assert 'access policy "ATLAS access: atlas"' in note
