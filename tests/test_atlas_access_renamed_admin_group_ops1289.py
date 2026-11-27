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
"""A renamed Authentik superuser group still opens ATLAS (ops #1289).

⚠️ **The reported failure.** An operator renamed Authentik's superuser group
(`authentik Admins` -> `Platform Owners`). An ATLAS Update wrote the new name
into ATLAS's own admin line, but the Authentik access policy kept naming the
constant `authentik Admins`: the policy was "already in place", so members of
the renamed group got Authentik's "Permission denied" and could not open ATLAS.

Every test asks the customer's question, **who gets in?**, with `can_open` from
the ops #979 tests (Authentik's decision, modelled).
"""

import pathlib
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_access, atlas_roster  # noqa: E402

from test_atlas_agency_admins import FakeAuthentik  # noqa: E402
from test_atlas_access_policy_ops979 import MFA, can_open  # noqa: E402
from test_atlas_access_converge_ops919 import (  # noqa: E402
    CORONA, HEADERS, PLAIN, boot_converge)

NEW = 'Platform Owners'
OLD = 'authentik Admins'
POLICY = 'ATLAS access: atlas'


@pytest.fixture
def authentik(monkeypatch):
    def install(fake):
        monkeypatch.setattr(urllib.request, 'urlopen', fake.open)
        return fake
    return install


def renamed_box(slug_app='atlas', agency=False, keep_old_group=False):
    """A Hardened box, one ATLAS, its access policy already made, and the
    superuser group renamed afterwards. This is what the Update found."""
    app = slug_app
    groups = [{'name': NEW, 'is_superuser': True, 'pk': 'g-root'}]
    expression_groups = [OLD]
    if agency:
        groups.append({'name': 'atlas-corona-admins', 'is_superuser': False,
                       'pk': 'g-corona'})
        expression_groups.append('atlas-corona-admins')
    if keep_old_group:
        groups.append({'name': OLD, 'is_superuser': False, 'pk': 'g-old'})
    fake = FakeAuthentik(
        groups=groups,
        apps={app: {'pk': 'app-pk'}},
        policies=[
            {'pk': 'p-atlas', 'name': 'ATLAS access: ' + app,
             'expression': atlas_access.build_expression(expression_groups)},
            {'pk': 'p-mfa', 'name': MFA, 'expression': ''}],
        bindings=[
            {'pk': 'b-atlas', 'policy': 'p-atlas', 'group': None, 'order': 0,
             'enabled': True, 'negate': False,
             'policy_obj': {'name': 'ATLAS access: ' + app}},
            {'pk': 'b-mfa', 'policy': 'p-mfa', 'group': None, 'order': 10,
             'enabled': True, 'negate': False, 'policy_obj': {'name': MFA}}])
    return fake


def expression_of(fake, name=POLICY):
    return next(p['expression'] for p in fake.policies if p['name'] == name)


# --------------------------------------------------------------------------- #
# Who gets in
# --------------------------------------------------------------------------- #


def test_members_of_the_renamed_group_open_atlas_after_update(authentik):
    """⚠️ **The reported case.** Red on dev: the policy stays "already in
    place" and still names `authentik Admins`."""
    fake = authentik(renamed_box())
    assert not can_open(fake, 'all', {NEW}, mfa=True)

    out = boot_converge([PLAIN])

    assert out == {'atlas': 'created'}
    assert can_open(fake, 'all', {NEW}, mfa=True)


def test_a_stranger_and_the_missing_mfa_are_still_refused(authentik):
    fake = authentik(renamed_box())

    boot_converge([PLAIN])

    assert not can_open(fake, 'all', set(), mfa=True)
    assert not can_open(fake, 'all', {'someone-elses-group'}, mfa=True)
    assert not can_open(fake, 'all', {NEW}, mfa=False)


def test_the_old_default_name_no_longer_admits_anyone(authentik):
    """The group of that name is gone. Left in the policy, a group someone
    makes under it later would be handed ATLAS administration."""
    fake = authentik(renamed_box())

    boot_converge([PLAIN])

    assert atlas_access.parse_groups(expression_of(fake)) == [NEW]
    assert not can_open(fake, 'all', {OLD}, mfa=True)


def test_the_old_default_name_stays_while_a_group_of_that_name_exists(authentik):
    """Not ours to take away: a group still called `authentik Admins` (an
    ordinary one, after the rename) keeps what it had."""
    fake = authentik(renamed_box(keep_old_group=True))

    boot_converge([PLAIN])

    assert atlas_access.parse_groups(expression_of(fake)) == [NEW, OLD]


def test_the_agency_keeps_its_own_group_beside_the_renamed_one(authentik):
    fake = authentik(renamed_box(slug_app='atlas-corona', agency=True))

    boot_converge([CORONA])

    assert atlas_access.parse_groups(
        expression_of(fake, 'ATLAS access: atlas-corona')
    ) == [NEW, 'atlas-corona-admins']
    assert can_open(fake, 'all', {NEW}, mfa=True)
    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)


def test_an_agency_update_opens_atlas_to_the_renamed_group(authentik):
    """The Update path (`agency_admin_group_outcome`), not only the boot converge."""
    fake = authentik(renamed_box(slug_app='atlas-corona', agency=True))

    out = atlas.agency_admin_group_outcome(None, CORONA, 'http://ak', HEADERS,
                                           plog=lambda m: None)

    assert out['status'] in ('present', 'created')
    assert can_open(fake, 'all', {NEW}, mfa=True)
    assert OLD not in atlas_access.parse_groups(
        expression_of(fake, 'ATLAS access: atlas-corona'))


def test_the_standard_group_step_keeps_the_renamed_group(authentik):
    """`atlas_roster.ensure_access` also rewrites the policy; it must not put
    the old name back or drop the new one."""
    fake = authentik(renamed_box(slug_app='atlas-corona', agency=True))
    roster_names = {'standard_group': 'atlas-corona-standard',
                    'application': 'atlas-corona'}

    mark, _note = atlas_roster.ensure_access(
        atlas_access.Api('http://ak', HEADERS), roster_names, '2.3.0', '2.3.0',
        lambda m: None, admin_group=NEW)

    assert mark == '✓'
    groups = atlas_access.parse_groups(
        expression_of(fake, 'ATLAS access: atlas-corona'))
    assert groups[0] == NEW
    assert OLD not in groups
    assert 'atlas-corona-standard' in groups


# --------------------------------------------------------------------------- #
# Nothing changes where nothing was renamed
# --------------------------------------------------------------------------- #


def test_a_box_that_never_renamed_the_group_changes_nothing(authentik):
    fake = FakeAuthentik(
        groups=[{'name': OLD, 'is_superuser': True, 'pk': 'g-root'}],
        apps={'atlas': {'pk': 'app-pk'}},
        policies=[{'pk': 'p-atlas', 'name': POLICY,
                   'expression': atlas_access.build_expression([OLD])}],
        bindings=[{'pk': 'b-atlas', 'policy': 'p-atlas', 'group': None,
                   'order': 0, 'enabled': True, 'negate': False,
                   'policy_obj': {'name': POLICY}}])
    authentik(fake)

    out = boot_converge([PLAIN])

    assert out == {'atlas': 'present'}
    assert fake.deleted == []
    assert atlas_access.parse_groups(expression_of(fake)) == [OLD]


def test_authentik_that_cannot_be_asked_does_not_drop_the_default_name(authentik):
    """The group lookup fails, so the name falls back to the default and
    nothing is pruned: a failed question is never a reason to narrow access."""
    fake = authentik(renamed_box())
    fake.fail = {'core/groups/?page_size=200'}

    boot_converge([PLAIN])

    assert OLD in atlas_access.parse_groups(expression_of(fake))
