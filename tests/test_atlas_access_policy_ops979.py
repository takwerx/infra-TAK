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
"""ATLAS agency administrators can sign in on a Hardened box (ops #979).

⚠️ **The reported failure.** The Hardened posture's MFA step sets
`policy_engine_mode: all` on every login application. The agency group used to
be bound *beside* "Allow authentik Admins", and under `all` each binding is a
requirement, so a user needed `authentik Admins` AND `atlas-<slug>-admins` AND
an MFA device. An agency administrator who was not also an Authentik
administrator got "Permission denied" (measured on test6).

Every test here asks the question the customer asks, not whether a call was
made: **who gets in?** `can_open` is Authentik's decision, modelled from its
documented rule: bindings are evaluated, `any` admits when one passes, `all`
admits only when every one passes.
"""

import ast
import json
import pathlib
import re
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

from test_atlas_agency_admins import FakeAuthentik  # noqa: E402

CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
APP = 'atlas-corona'
ALLOW = 'Allow authentik Admins'
MFA = 'infratak-require-mfa'
_MEMBER = re.compile(r'name=("(?:[^"\\]|\\.)*")')


# --------------------------------------------------------------------------- #
# Authentik's decision, modelled
# --------------------------------------------------------------------------- #


def can_open(fake, mode, groups, mfa):
    """Would Authentik let this user into the application?

    A binding passes by what its policy is: the admins policy and our access
    policy test group membership, the MFA policy tests for a device, a direct
    group binding tests that group. `negate`/`enabled` are honoured.
    """
    names = {g['pk']: g['name'] for g in fake.groups}
    passed = []
    live = [b for b in fake.bindings if b.get('enabled', True)]
    if not live:
        return True  # ⚠️ Authentik shows an unbound application to everyone.
    for b in sorted(live, key=lambda b: b.get('order', 0)):
        pol = (b.get('policy_obj') or {}).get('name')
        if b.get('group'):
            ok = names.get(b['group']) in groups
        elif pol == ALLOW:
            ok = 'authentik Admins' in groups
        elif pol == MFA:
            ok = mfa
        else:
            policy = next(p for p in fake.policies if p['pk'] == b['policy'])
            wanted = [json.loads(q) for q in _MEMBER.findall(policy['expression'])]
            ok = any(w in groups for w in wanted)
        passed.append(ok != bool(b.get('negate')))
    return all(passed) if mode == 'all' else any(passed)


def hardened_box():
    """The state test6 was in: app mode `all`, admins binding, MFA binding."""
    return FakeAuthentik(
        groups=[{'name': 'authentik Admins', 'is_superuser': True, 'pk': 'g-root'}],
        policies=[{'pk': 'p-allow', 'name': ALLOW, 'expression': ''},
                  {'pk': 'p-mfa', 'name': MFA, 'expression': ''}],
        bindings=[
            {'pk': 'b-allow', 'policy': 'p-allow', 'group': None, 'order': 0,
             'enabled': True, 'negate': False, 'policy_obj': {'name': ALLOW}},
            {'pk': 'b-mfa', 'policy': 'p-mfa', 'group': None, 'order': 10,
             'enabled': True, 'negate': False, 'policy_obj': {'name': MFA}}])


def standard_box():
    """The Standard posture: mode `any`, the admins binding only."""
    fake = hardened_box()
    fake.bindings = [b for b in fake.bindings if b['pk'] != 'b-mfa']
    return fake


@pytest.fixture
def authentik(monkeypatch):
    def install(fake):
        monkeypatch.setattr(urllib.request, 'urlopen', fake.open)
        return fake
    return install


def update(ctx_fake):
    """What an Update does to the access, in its order: the binding check first,
    then the agency group (`_reconcile_access`)."""
    headers = {'Authorization': 'Bearer t', 'Content-Type': 'application/json'}
    say = []
    atlas._restrict_to_admins('http://ak', headers, plog=say.append, app_slug=APP)
    atlas.agency_admin_group_outcome(None, CORONA, 'http://ak', headers,
                                     plog=say.append)
    return atlas._restrict_to_admins('http://ak', headers, plog=say.append,
                                     app_slug=APP), say


# --------------------------------------------------------------------------- #
# Who gets in
# --------------------------------------------------------------------------- #


def test_an_agency_admin_alone_gets_in_on_a_hardened_box(authentik):
    """⚠️ **The reported case.** Agency group only, with an MFA device, on an
    application in `all` mode. It was "Permission denied"."""
    fake = authentik(hardened_box())
    update(fake)

    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)


def test_a_global_admin_still_gets_in_on_a_hardened_box(authentik):
    """The global administrators keep their access: the old "Allow authentik
    Admins" binding is gone, and the access policy admits them."""
    fake = authentik(hardened_box())
    update(fake)

    assert can_open(fake, 'all', {'authentik Admins'}, mfa=True)


def test_a_stranger_is_still_refused_on_a_hardened_box(authentik):
    fake = authentik(hardened_box())
    update(fake)

    assert not can_open(fake, 'all', {'some-other-group'}, mfa=True)
    assert not can_open(fake, 'all', set(), mfa=True)


def test_another_agency_s_admin_is_refused(authentik):
    """One agency's administrators must not reach another agency's console."""
    fake = authentik(hardened_box())
    update(fake)

    assert not can_open(fake, 'all', {'atlas-redlands-admins'}, mfa=True)


def test_the_mfa_requirement_is_not_weakened(authentik):
    """⚠️ Hardened means MFA: an agency admin with no device is still refused,
    and so is a global admin. The MFA binding was left exactly as it was."""
    fake = authentik(hardened_box())
    update(fake)

    assert not can_open(fake, 'all', {'atlas-corona-admins'}, mfa=False)
    assert not can_open(fake, 'all', {'authentik Admins'}, mfa=False)
    assert any(b['pk'] == 'b-mfa' for b in fake.bindings)


def test_the_standard_posture_gives_the_same_answers(authentik):
    """The policy means the same under `any`, so a box that is not hardened
    (the default) is unchanged for everyone."""
    fake = authentik(standard_box())
    update(fake)

    assert can_open(fake, 'any', {'atlas-corona-admins'}, mfa=False)
    assert can_open(fake, 'any', {'authentik Admins'}, mfa=False)
    assert not can_open(fake, 'any', {'atlas-redlands-admins'}, mfa=False)
    assert not can_open(fake, 'any', set(), mfa=False)


def test_a_second_update_changes_nothing(authentik):
    """Run on every Update, so it has to settle."""
    fake = authentik(hardened_box())
    update(fake)
    before = (json.dumps(fake.bindings, sort_keys=True),
              json.dumps(fake.policies, sort_keys=True))
    fake.posted.clear()
    fake.deleted.clear()

    ok, _said = update(fake)

    assert ok is True
    assert fake.posted == [] and fake.deleted == []
    assert (json.dumps(fake.bindings, sort_keys=True),
            json.dumps(fake.policies, sort_keys=True)) == before


def test_the_binding_check_does_not_put_the_admins_binding_back(authentik):
    """⚠️ Every Update runs the binding check *before* the group reconcile. It
    must read the access policy as the restriction, or it re-adds "Allow
    authentik Admins" each time and the agency admins are locked out again."""
    fake = authentik(hardened_box())
    update(fake)
    headers = {'Authorization': 'Bearer t'}

    assert atlas._restrict_to_admins('http://ak', headers, app_slug=APP) is True

    assert not any((b.get('policy_obj') or {}).get('name') == ALLOW
                   for b in fake.bindings)
    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)


def test_the_application_is_never_left_unbound(authentik):
    """⚠️ At no point between the first call and the last does the application
    have no binding: Authentik shows an unbound application to every signed-in
    user, and this one is an MDM console."""
    fake = authentik(hardened_box())
    seen = []
    real = fake.open

    def watch(req, timeout=None):
        out = real(req, timeout)
        seen.append(len(fake.bindings))
        return out

    urllib.request.urlopen = watch
    try:
        update(fake)
    finally:
        urllib.request.urlopen = real

    assert min(seen) >= 1


# --------------------------------------------------------------------------- #
# What it leaves alone
# --------------------------------------------------------------------------- #


def test_an_operator_s_own_binding_is_left_alone(authentik):
    """Only the admins binding and the agency group's own direct binding are
    replaced. Anything else on the application belongs to the operator."""
    fake = hardened_box()
    fake.groups.append({'name': 'night-shift', 'is_superuser': False, 'pk': 'g-ns'})
    fake.bindings.append({'pk': 'b-ns', 'policy': None, 'group': 'g-ns',
                          'order': 5, 'enabled': True, 'negate': True,
                          'policy_obj': None})
    authentik(fake)

    update(fake)

    assert any(b['pk'] == 'b-ns' for b in fake.bindings)


def test_the_old_direct_group_binding_is_replaced(authentik):
    """A box updated from before this fix has the agency group bound directly.
    It goes, once the policy is in, because under `all` it is a requirement."""
    fake = hardened_box()
    fake.groups.append({'name': 'atlas-corona-admins', 'is_superuser': False,
                        'pk': 'g-corona'})
    fake.bindings.append({'pk': 'b-old', 'policy': None, 'group': 'g-corona',
                          'order': 10, 'enabled': True, 'negate': False,
                          'policy_obj': None})
    authentik(fake)

    update(fake)

    assert not any(b['pk'] == 'b-old' for b in fake.bindings)
    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)


def test_a_group_added_later_is_kept_by_the_next_reconcile(authentik):
    """Two callers add groups to one policy (the agency's, and the standard
    group of a later release). Each must keep what the other added."""
    from modules import atlas_access
    fake = authentik(hardened_box())
    update(fake)
    api = atlas_access.Api('http://ak', {})

    atlas_access.ensure(api, APP, add=['atlas-corona-standard-admins'])
    update(fake)

    assert can_open(fake, 'all', {'atlas-corona-standard-admins'}, mfa=True)
    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)


def test_a_group_can_be_taken_out_again(authentik):
    from modules import atlas_access
    fake = authentik(hardened_box())
    update(fake)
    api = atlas_access.Api('http://ak', {})
    atlas_access.ensure(api, APP, add=['atlas-corona-standard-admins'])

    atlas_access.ensure(api, APP, remove=['atlas-corona-standard-admins'])

    assert not can_open(fake, 'all', {'atlas-corona-standard-admins'}, mfa=True)
    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)


def test_the_global_admins_cannot_be_taken_out(authentik):
    from modules import atlas_access
    fake = authentik(hardened_box())
    api = atlas_access.Api('http://ak', {})

    atlas_access.ensure(api, APP, remove=['authentik Admins'])

    assert can_open(fake, 'all', {'authentik Admins'}, mfa=True)


def test_group_names_with_odd_characters_stay_inside_their_quotes():
    """The expression is code Authentik runs. A name is data, never code."""
    from modules import atlas_access
    nasty = 'x") or True or ("'

    built = atlas_access.build_expression(['authentik Admins', nasty])

    assert atlas_access.parse_groups(built) == ['authentik Admins', nasty]
    ast.parse(built.replace('return ', '', 1), mode='eval')
    assert built.count('ak_is_group_member') == 2


def test_removing_a_deployment_removes_its_policy(authentik):
    """A later deployment on the same slug must not inherit this one's groups."""
    from modules import atlas_access
    fake = authentik(hardened_box())
    update(fake)
    api = atlas_access.Api('http://ak', {})
    fake.apps.pop(APP)  # `remove_instance` deregisters the application first

    assert atlas_access.remove(api, APP) is True
    assert not [p for p in fake.policies if p['name'].startswith('ATLAS access')]
    assert atlas_access.remove(api, APP) is False


def test_removing_an_agency_removes_its_policy_and_group(authentik):
    """The removal path (`remove_agency_admin_group`) takes the policy with the
    group, so a later agency on the same name starts from the admins alone."""
    from test_atlas_agency_group_reconcile import make_ctx
    fake = authentik(hardened_box())
    update(fake)
    assert [p for p in fake.policies if p['name'] == 'ATLAS access: ' + APP]
    fake.apps.pop(APP)

    note = atlas.remove_agency_admin_group(make_ctx(), CORONA)

    assert not [p for p in fake.policies if p['name'].startswith('ATLAS access')]
    assert 'removed' in (note or '')
    assert any('core/groups/group-pk/' in url for url in fake.deleted)


# --------------------------------------------------------------------------- #
# Security read of the merged rework (ops #978, follow-up item 3)
# --------------------------------------------------------------------------- #


def test_the_policy_stays_while_its_application_is_still_there(authentik):
    """⚠️ Deleting the policy deletes its binding. If the application's
    deregistration failed, it would be left with no binding at all, which
    Authentik opens to every signed-in user."""
    from modules import atlas_access
    fake = authentik(hardened_box())
    update(fake)
    api = atlas_access.Api('http://ak', {})

    with pytest.raises(RuntimeError, match='still in Authentik'):
        atlas_access.remove(api, APP)

    assert [p for p in fake.policies if p['name'] == 'ATLAS access: ' + APP]
    assert not can_open(fake, 'all', {'nobody'}, mfa=True)


def test_the_policy_stays_when_the_application_lookup_fails(authentik):
    """Only a 404 means "gone". An Authentik that answers 500, or not at all,
    says nothing about the application."""
    from modules import atlas_access
    fake = authentik(hardened_box())
    update(fake)
    api = atlas_access.Api('http://ak', {})
    fake.fail.add('core/applications/')

    with pytest.raises(OSError):
        atlas_access.remove(api, APP)

    assert [p for p in fake.policies if p['name'] == 'ATLAS access: ' + APP]


def test_an_agency_removal_keeps_the_policy_of_an_application_still_there(authentik):
    from test_atlas_agency_group_reconcile import make_ctx
    fake = authentik(hardened_box())
    update(fake)
    logged = []

    atlas.remove_agency_admin_group(make_ctx(), CORONA, plog=logged.append)

    assert [p for p in fake.policies if p['name'] == 'ATLAS access: ' + APP]
    assert any('could not be removed' in m and 'still in Authentik' in m
               for m in logged)


HAND_WRITTEN = ('return ak_is_group_member(request.user, name="authentik Admins") '
                'and request.context.get("geoip", {}).get("country") == "US"')


@pytest.mark.parametrize('change', [
    {'add': ['atlas-corona-standard-admins']},
    {'remove': ['atlas-corona-standard-admins']},
    {}])
def test_a_hand_written_policy_is_reported_and_left_as_it_is(authentik, change):
    """⚠️ `parse_groups` finds names in any text. Rebuilding from them would
    drop the operator's extra condition (here: the country check) and could let
    in a group they never meant to."""
    from modules import atlas_access
    fake = authentik(hardened_box())
    update(fake)
    [pol] = [p for p in fake.policies if p['name'] == 'ATLAS access: ' + APP]
    pol['expression'] = HAND_WRITTEN
    api = atlas_access.Api('http://ak', {})
    before = [dict(b) for b in fake.bindings]
    logged = []

    result = atlas_access.ensure(api, APP, plog=logged.append, **change)

    assert result['status'] == 'failed'
    assert 'changed by hand' in result['detail']
    assert pol['expression'] == HAND_WRITTEN
    assert [dict(b) for b in fake.bindings] == before
    assert not any(m == 'PATCH' for m, _url in fake.calls)


def test_our_own_expression_is_still_updated(authentik):
    """The check must not freeze a policy this module wrote."""
    from modules import atlas_access
    fake = authentik(hardened_box())
    update(fake)
    api = atlas_access.Api('http://ak', {})

    result = atlas_access.ensure(api, APP, add=['atlas-corona-standard-admins'])

    assert result['status'] == 'created'
    assert can_open(fake, 'all', {'atlas-corona-standard-admins'}, mfa=True)


@pytest.mark.parametrize('expression,ours', [
    ('return ak_is_group_member(request.user, name="authentik Admins")', True),
    ('return ak_is_group_member(request.user, name="authentik Admins") or '
     'ak_is_group_member(request.user, name="atlas-corona-admins")', True),
    (HAND_WRITTEN, False),
    ('return True', False),
    ('', False),
    ('return ak_is_group_member(request.user, name="authentik Admins")\n', False),
])
def test_is_ours_matches_only_what_build_expression_writes(expression, ours):
    from modules import atlas_access
    assert atlas_access.is_ours(expression) is ours


# --------------------------------------------------------------------------- #
# The boot converge must not add the admins binding back
# --------------------------------------------------------------------------- #

_APP_SRC = (ROOT / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(_APP_SRC)


def _converge():
    """`_ensure_app_access_policies`, cut out of app.py (which cannot be
    imported in a test) and run against the fake."""
    src = next(ast.get_source_segment(_APP_SRC, n) for n in _TREE.body
               if isinstance(n, ast.FunctionDef)
               and n.name == '_ensure_app_access_policies')
    from modules import atlas_access
    ns = {'json': json, '_atlas_access': atlas_access,
          'REMOTE_ASSIST_OIDC_SLUG': 'eud-remote-assist',
          'W1_MFA_POLICY_NAME': MFA}
    exec(src, ns)
    return ns['_ensure_app_access_policies']


class ConvergeAuthentik(FakeAuthentik):
    """The extra reads the boot converge makes."""

    def open(self, req, timeout=None):
        url = req.full_url
        if 'policies/all/' in url:
            return super().open(_Req(
                url.replace('policies/all/', 'policies/expression/')), timeout)
        if 'core/applications/?' in url:
            self.calls.append(('GET', url))
            return _Resp({'results': [
                {'pk': 'app-pk', 'slug': APP, 'name': 'ATLAS corona',
                 'provider': 7}]})
        if 'providers/ldap/' in url:
            self.calls.append(('GET', url))
            return _Resp({'results': []})
        return super().open(req, timeout)


class _Req:
    def __init__(self, url):
        self.full_url = url
        self.data = None
        self.method = 'GET'


class _Resp:
    def __init__(self, payload):
        self._p = json.dumps(payload).encode()

    def read(self):
        return self._p


def test_the_boot_converge_does_not_add_the_admins_binding_beside_the_policy(
        authentik):
    """⚠️ It runs on every console start and binds "Allow authentik Admins" to
    every application it considers admin-only, ATLAS included. Beside the access
    policy that is one more requirement under `all`, and it put the agency
    admins' lockout back at the next restart."""
    fake = ConvergeAuthentik(
        groups=[{'name': 'authentik Admins', 'is_superuser': True, 'pk': 'g-root'}],
        policies=[{'pk': 'p-allow', 'name': ALLOW, 'expression': ''},
                  {'pk': 'p-mfa', 'name': MFA, 'expression': ''}],
        bindings=[{'pk': 'b-mfa', 'policy': 'p-mfa', 'group': None, 'order': 10,
                   'enabled': True, 'negate': False,
                   'policy_obj': {'name': MFA}}])
    authentik(fake)
    update(fake)
    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)

    _converge()('http://ak', {}, plog=lambda _m: None)

    assert not any((b.get('policy_obj') or {}).get('name') == ALLOW
                   for b in fake.bindings)
    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)


def test_the_boot_converge_still_restricts_an_application_with_no_binding(
        authentik):
    """The default-deny is unchanged: an application with no access binding at
    all still gets "Allow authentik Admins"."""
    fake = ConvergeAuthentik(
        groups=[{'name': 'authentik Admins', 'is_superuser': True, 'pk': 'g-root'}],
        policies=[{'pk': 'p-allow', 'name': ALLOW, 'expression': ''}],
        bindings=[])
    authentik(fake)

    _converge()('http://ak', {}, plog=lambda _m: None)

    assert [b['policy_obj']['name'] for b in fake.bindings] == [ALLOW]
