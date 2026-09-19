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
"""An admin group per deployment (W221).

Operator: a credential in Authentik per ATLAS, so users can be designated into
that role and reach **only** their own deployment, while the global admin
reaches all.

⚠️ **Measured on the box before any of this was written**, because the whole
design rests on it: the ATLAS applications run with `policy_engine_mode: any`,
so policy bindings are **alternatives**. A group bound beside
`Allow authentik Admins` *adds* a way in rather than narrowing the existing one.
Had the mode been `all`, the same code would have locked every global
administrator out of every agency console.

⚠️ **And ATLAS itself already checked a group.** `_arm_admin_gates` writes
`TAKMDM_ADMIN_GROUP=authentik Admins`, confirmed live in corona's container —
so without widening that to a list, an agency administrator would pass
Authentik's binding and then be refused by ATLAS with a 403. The proxy says yes
and the application says no, which is the most confusing shape a lockout takes.
"""

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from atlas_pin import pin_at_least  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)


# --------------------------------------------------------------------------- #
# Which groups administer a deployment
# --------------------------------------------------------------------------- #


def test_an_agency_is_administered_by_its_own_group_and_the_global_one():
    assert atlas.admin_groups_for(CORONA) == \
        ['atlas-corona-admins', 'authentik Admins']


def test_the_agency_group_comes_first():
    """Most specific first — it is the one an operator is looking for when they
    read the line, and the one they have to create people in."""
    assert atlas.admin_groups_for(CORONA)[0] == 'atlas-corona-admins'


def test_the_plain_deployment_keeps_only_the_global_group():
    """⚠️ Its "agency" is the box. Inventing `atlas-admins` for it would name a
    group nobody is in, and every deployed box would start requiring it."""
    assert atlas.admin_groups_for(PLAIN) == ['authentik Admins']
    assert atlas.admin_groups_for(None) == ['authentik Admins']


def test_a_renamed_superuser_group_is_honoured():
    """⚠️ `authentik Admins` is a default an operator may change. Requiring a
    group that does not exist would lock every administrator out of the console
    they would use to fix it."""
    assert atlas.admin_groups_for(CORONA, 'Platform Owners') == \
        ['atlas-corona-admins', 'Platform Owners']


def test_no_two_deployments_share_an_admin_group():
    """⚠️ **The separation the operator asked for.** A shared group would let
    every agency administrator into every agency's console — the bleedover the
    whole parallel-deployment design exists to prevent."""
    groups = [atlas.admin_groups_for(ai.make(slug, ai.MODE_DYNAMIC, 50, 8761))[0]
              for slug in ('corona', 'redlands', 'pd')]

    assert len(set(groups)) == 3, groups


# --------------------------------------------------------------------------- #
# Resolving the global group
# --------------------------------------------------------------------------- #


class FakeAuthentik:
    """Enough of Authentik's API to answer and record."""

    def __init__(self, groups=(), apps=None, bindings=(), fail=()):
        self.groups = list(groups)
        self.apps = apps or {'atlas-corona': {'pk': 'app-pk'}}
        self.bindings = list(bindings)
        self.fail = set(fail)
        self.posted = []

    def open(self, req, timeout=None):
        url = req.full_url
        for token in self.fail:
            if token in url:
                raise OSError('boom')
        # ⚠️ `getattr`, not `req.method`. A `urllib.request.Request` built
        # without an explicit method has **no `method` attribute at all** on this
        # Python — measured, not assumed. Reading it raised AttributeError, the
        # module's own `except` swallowed it, and every test here passed against
        # the fallback path instead of the one it was written for.
        if getattr(req, 'method', None) == 'POST' or req.data:
            body = json.loads(req.data.decode())
            self.posted.append((url, body))
            if 'core/groups/' in url:
                created = dict(body, pk='group-pk')
                self.groups.append(created)
                return _Response(created)
            return _Response({'pk': 'binding-pk'})
        if 'core/groups/' in url:
            return _Response({'results': list(self.groups)})
        if 'core/applications/' in url:
            slug = url.rstrip('/').rsplit('/', 1)[-1]
            return _Response(self.apps[slug])
        if 'policies/bindings/' in url:
            return _Response({'results': list(self.bindings)})
        raise AssertionError('unexpected call: ' + url)


class _Response:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload


@pytest.fixture
def authentik(monkeypatch):
    import urllib.request

    def install(fake):
        monkeypatch.setattr(urllib.request, 'urlopen', fake.open)
        return fake

    return install


def test_the_superuser_group_is_resolved_by_what_it_is(authentik):
    """⚠️ Not by its name. An operator who renamed it would otherwise have every
    deployment on the box requiring a group that no longer exists."""
    authentik(FakeAuthentik(groups=[
        {'name': 'Platform Owners', 'is_superuser': True, 'pk': 'g1'},
        {'name': 'authentik Read-only', 'is_superuser': False, 'pk': 'g2'},
    ]))

    assert atlas.global_admin_group('http://ak', {}) == 'Platform Owners'


def test_an_unreachable_authentik_falls_back_to_the_default_name(authentik):
    """⚠️ A deploy must not fail because the identity provider was briefly
    unreachable, and the default is right on every box nobody has renamed."""
    authentik(FakeAuthentik(fail=('core/groups',)))

    assert atlas.global_admin_group('http://ak', {}) == atlas.ADMIN_GROUP


def test_a_box_with_no_superuser_group_falls_back_too(authentik):
    authentik(FakeAuthentik(groups=[
        {'name': 'authentik Read-only', 'is_superuser': False, 'pk': 'g2'}]))

    assert atlas.global_admin_group('http://ak', {}) == atlas.ADMIN_GROUP


# --------------------------------------------------------------------------- #
# Creating the group and letting it in
# --------------------------------------------------------------------------- #


def test_the_group_is_created_for_an_agency(authentik):
    fake = authentik(FakeAuthentik())

    name = atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {})

    assert name == 'atlas-corona-admins'
    created = [b for url, b in fake.posted if 'core/groups/' in url]
    assert created == [{'name': 'atlas-corona-admins', 'is_superuser': False}]


def test_the_group_is_never_a_superuser_group(authentik):
    """⚠️ It administers one ATLAS, not Authentik. A superuser group would hand
    every one of its members the identity provider itself — and with it, every
    other agency's console."""
    fake = authentik(FakeAuthentik())

    atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {})

    body = [b for url, b in fake.posted if 'core/groups/' in url][0]

    assert body['is_superuser'] is False


def test_the_group_is_bound_to_that_deployment_s_application(authentik):
    fake = authentik(FakeAuthentik())

    atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {})

    bindings = [b for url, b in fake.posted if 'policies/bindings/' in url]

    assert len(bindings) == 1
    assert bindings[0]['target'] == 'app-pk'
    assert bindings[0]['group'] == 'group-pk'
    assert bindings[0]['enabled'] is True
    assert bindings[0]['negate'] is False


def test_the_existing_admins_binding_is_left_alone(authentik):
    """⚠️ **The load-bearing property.** `policy_engine_mode` is `any`, so the
    two bindings are alternatives. Replacing the admins policy — rather than
    adding beside it — would lock the global administrator out of every agency
    console at once."""
    fake = authentik(FakeAuthentik(bindings=[
        {'pk': 'b0', 'policy': 'p1', 'group': None, 'order': 0}]))

    atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {})

    assert not any(b.get('_delete') for _u, b in fake.posted)
    assert all('DELETE' not in url for url, _b in fake.posted)


def test_an_existing_group_is_reused_not_duplicated(authentik):
    """Deploy and update both call this; a second group with the same name would
    be a second place to add people, one of which does nothing."""
    fake = authentik(FakeAuthentik(groups=[
        {'name': 'atlas-corona-admins', 'is_superuser': False, 'pk': 'g9'}]))

    name = atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {})

    assert name == 'atlas-corona-admins'
    assert not [b for url, b in fake.posted if 'core/groups/' in url]


def test_an_existing_binding_is_not_added_twice(authentik):
    """Reconciled on every update, so this runs many times over a deployment's
    life."""
    fake = authentik(
        FakeAuthentik(groups=[{'name': 'atlas-corona-admins',
                               'is_superuser': False, 'pk': 'g9'}],
                      bindings=[{'pk': 'b1', 'group': 'g9', 'order': 10}]))

    atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {})

    assert not [b for url, b in fake.posted if 'policies/bindings/' in url]


def test_the_plain_deployment_gets_no_group_of_its_own(authentik):
    """It has no agency, and a group nobody is in would be a lockout waiting to
    be enforced."""
    fake = authentik(FakeAuthentik())

    assert atlas.ensure_agency_admin_group(None, PLAIN, 'http://ak', {}) is None
    assert fake.posted == []


def test_a_failure_reports_itself_rather_than_raising(authentik):
    """⚠️ Step 7 of a deploy. An exception here would fail a deployment that is
    otherwise complete and running, over a group an operator can add by hand."""
    authentik(FakeAuthentik(fail=('core/groups',)))

    assert atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {}) is None


def test_the_operator_is_told_what_to_add_people_to(authentik):
    """⚠️ Nobody is put in the group here — that is the operator's decision and
    the only part of this that should be manual. The deploy log is where they
    find out the name."""
    authentik(FakeAuthentik())
    said = []

    atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {},
                                    plog=said.append)

    assert any('atlas-corona-admins' in line for line in said), said
    assert any('administrators to it' in line for line in said), said


# --------------------------------------------------------------------------- #
# What ATLAS is told to require
# --------------------------------------------------------------------------- #


def test_the_env_line_lists_both_groups(tmp_path, monkeypatch):
    """⚠️ Without this an agency administrator passes Authentik and is refused
    by ATLAS with a 403 — the proxy says yes and the application says no."""
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    env = tmp_path / '.env'
    env.write_text('TAKMDM_ADMIN_GROUP=authentik Admins\n', encoding='utf-8')

    atlas._arm_admin_gates(None, str(tmp_path), lambda _m: None, inst=CORONA)

    assert 'TAKMDM_ADMIN_GROUP=atlas-corona-admins,authentik Admins' in \
        env.read_text(encoding='utf-8')


def test_the_plain_deployment_s_line_does_not_change(tmp_path, monkeypatch):
    """Every deployed box has exactly this, and a change it did not ask for is
    a restart it did not ask for."""
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    env = tmp_path / '.env'
    env.write_text('TAKMDM_ADMIN_GROUP=authentik Admins\n', encoding='utf-8')

    changed = atlas._arm_admin_gates(None, str(tmp_path), lambda _m: None)

    assert changed is False
    assert env.read_text(encoding='utf-8') == \
        'TAKMDM_ADMIN_GROUP=authentik Admins\n'


def test_only_one_admin_group_line_survives(tmp_path, monkeypatch):
    """Two would be one setting with two values, and `.env` takes the last —
    which is not the one anybody would read first."""
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    env = tmp_path / '.env'
    env.write_text('TAKMDM_ADMIN_GROUP=authentik Admins\n', encoding='utf-8')

    atlas._arm_admin_gates(None, str(tmp_path), lambda _m: None, inst=CORONA)
    body = env.read_text(encoding='utf-8')

    assert body.count('TAKMDM_ADMIN_GROUP=') == 1, body


def test_a_renamed_superuser_group_reaches_the_env_line(tmp_path, monkeypatch):
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    env = tmp_path / '.env'
    env.write_text('TAKMDM_ADMIN_GROUP=\n', encoding='utf-8')

    atlas._arm_admin_gates(None, str(tmp_path), lambda _m: None, inst=CORONA,
                           global_group='Platform Owners')

    assert 'TAKMDM_ADMIN_GROUP=atlas-corona-admins,Platform Owners' in \
        env.read_text(encoding='utf-8')


def test_the_pin_is_the_release_that_accepts_a_list():
    """⚠️ A list written into an ATLAS older than 1.49.0 is compared as one
    literal group name and matches nobody — every administrator locked out. The
    pin is what keeps a fresh install on a release that understands it.

    ⚠️ **At least, not exactly.** This used to assert equality, which made
    it fail on every promotion for a reason it had nothing to say about.
    """
    ok, why = pin_at_least('v1.49.0')

    assert ok, why


# --------------------------------------------------------------------------- #
# The group goes with the deployment (2026-09-19)
# --------------------------------------------------------------------------- #
#
# ⚠️ Found on the box, not here: `atlas-testing-admins` was still in Authentik
# long after that deployment was torn down. `remove_instance` deregistered the
# application and the provider and never touched the group.


class FakeAk:
    """Authentik's group API, as far as this needs it."""

    def __init__(self, groups):
        self.groups = list(groups)
        self.deleted = []

    def __call__(self, url, timeout=None):
        import io as _io
        import json as _json
        from urllib.parse import unquote

        method = getattr(url, 'method', None) or 'GET'
        full = url.full_url
        if method == 'DELETE':
            pk = full.rstrip('/').rsplit('/', 1)[-1]
            self.deleted.append(pk)
            self.groups = [g for g in self.groups if g['pk'] != pk]
            return _io.BytesIO(b'')
        wanted = unquote(full.split('name=', 1)[1]) if 'name=' in full else None
        # ⚠️ A *filter*, like the real API — it returns prefix matches too,
        # which is the whole reason the caller checks the name exactly.
        hits = [g for g in self.groups
                if wanted is None or wanted in g['name']]
        return _io.BytesIO(_json.dumps({'results': hits}).encode())


def _ctx_with_ak(monkeypatch, fake):
    import urllib.request as urlreq
    monkeypatch.setattr(urlreq, 'urlopen', fake)
    return {
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: 'tok' if 'TOKEN' in k else None,
        '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
    }


def test_the_agency_group_is_deleted_with_its_deployment(monkeypatch):
    fake = FakeAk([{'pk': 'g1', 'name': 'atlas-corona-admins', 'users': []}])
    ctx = _ctx_with_ak(monkeypatch, fake)

    note = atlas.remove_agency_admin_group(ctx, CORONA)

    assert fake.deleted == ['g1'], fake.deleted
    assert 'atlas-corona-admins' in note


def test_a_group_with_members_is_removed_and_the_count_reported(monkeypatch):
    """⚠️ The group goes with the deployment either way — but an operator who
    did not mean to do that needs to know how many people were in it."""
    fake = FakeAk([{'pk': 'g1', 'name': 'atlas-corona-admins',
                    'users': [1, 2, 3]}])
    ctx = _ctx_with_ak(monkeypatch, fake)

    note = atlas.remove_agency_admin_group(ctx, CORONA)

    assert fake.deleted == ['g1']
    assert '3 members' in note, note


def test_a_prefix_match_is_not_deleted(monkeypatch):
    """⚠️ **The trap this module keeps walking into.** Authentik's `?name=` is
    a filter, not an identity, and `atlas-test-admins` is a prefix of
    `atlas-testing-admins`. Tearing one down must not take the other."""
    fake = FakeAk([
        {'pk': 'g1', 'name': 'atlas-testing-admins', 'users': []},
        {'pk': 'g2', 'name': 'atlas-test-admins', 'users': []},
    ])
    ctx = _ctx_with_ak(monkeypatch, fake)

    atlas.remove_agency_admin_group(
        ctx, ai.make('test', ai.MODE_DYNAMIC, 50, 8761))

    assert fake.deleted == ['g2'], fake.deleted
    assert [g['name'] for g in fake.groups] == ['atlas-testing-admins']


def test_the_plain_deployment_has_no_group_to_remove(monkeypatch):
    """⚠️ It uses the global administrators. Deleting anything here would take
    the group every agency relies on."""
    fake = FakeAk([{'pk': 'g1', 'name': 'authentik Admins', 'users': []}])
    ctx = _ctx_with_ak(monkeypatch, fake)

    assert atlas.remove_agency_admin_group(ctx, None) is None
    assert fake.deleted == []


def test_an_unreachable_authentik_does_not_fail_the_teardown(monkeypatch):
    """The deployment's files are already gone by this point; refusing to
    finish over an identity server that is down would strand the record."""
    def boom(url, timeout=None):
        raise OSError('connection refused')

    import urllib.request as urlreq
    monkeypatch.setattr(urlreq, 'urlopen', boom)
    ctx = {
        'load_settings': lambda: {},
        '_get_authentik_env_value': lambda s, k: 'tok',
        '_get_authentik_api_url': lambda s: 'http://127.0.0.1:9090',
    }

    assert atlas.remove_agency_admin_group(ctx, CORONA) is None


def test_removal_calls_it(monkeypatch):
    """⚠️ The wiring, not just the helper. The helper existing and never being
    called is exactly the state the box was found in."""
    import inspect

    source = inspect.getsource(atlas.remove_instance)

    assert 'remove_agency_admin_group(' in source
