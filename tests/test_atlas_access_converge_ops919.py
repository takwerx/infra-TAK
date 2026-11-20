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
"""Update Now alone moves every ATLAS application to its one access policy (ops #919).

⚠️ **The T&E finding (10.4.3, ops #984).** A Hardened box with an agency ATLAS,
console on 10.4.2, then Update Now: the agency admin was still refused until
somebody pressed Update on the ATLAS page. The boot converge and the ATLAS
binding check both read the old "Allow authentik Admins" binding as "already
restricted" and left it; only ATLAS Update ran the swap.

The state below is what a 10.4.2 box has on test6 and test12: the application
in `all` mode with "Allow authentik Admins" at 0, the MFA policy at 10 and (for
an agency) the agency group bound directly. Each test asks who gets in after the
boot converge, with `can_open` from the ops #979 tests.
"""

import ast
import json
import pathlib
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

from test_atlas_access_policy_ops979 import (  # noqa: E402
    ALLOW, MFA, can_open, hardened_box)

CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)
HEADERS = {'Authorization': 'Bearer t', 'Content-Type': 'application/json'}


def make_ctx(instances):
    settings = {ai.INSTANCES_KEY: [dict(i) for i in instances]}
    return {'load_settings': lambda: dict(settings),
            'save_settings': lambda s: None}


def agency_box_on_10_4_2():
    """Hardened, agency `corona`: admins + MFA + the agency group bound directly."""
    fake = hardened_box()
    fake.groups.append({'name': 'atlas-corona-admins', 'is_superuser': False,
                        'pk': 'g-corona'})
    fake.bindings.append({'pk': 'b-corona', 'policy': None, 'group': 'g-corona',
                          'order': 0, 'enabled': True, 'negate': False,
                          'policy_obj': None})
    return fake


def plain_box_on_10_4_2():
    fake = hardened_box()
    fake.apps = {'atlas': {'pk': 'app-pk'}}
    return fake


@pytest.fixture
def authentik(monkeypatch):
    def install(fake):
        monkeypatch.setattr(urllib.request, 'urlopen', fake.open)
        return fake
    return install


def boot_converge(instances, log=None):
    """What the console's boot converge runs for ATLAS after Update Now."""
    hook = getattr(atlas, 'converge_access', None)
    assert hook is not None, 'no ATLAS access swap after a console update'
    return hook(make_ctx(instances), 'http://ak', HEADERS,
                log if log is not None else (lambda m: None))


def names_bound(fake):
    return [(b.get('policy_obj') or {}).get('name') for b in fake.bindings]


# --------------------------------------------------------------------------- #
# The reported case: who gets in after Update Now
# --------------------------------------------------------------------------- #


def test_update_now_lets_the_agency_admin_in_on_a_hardened_box(authentik):
    """⚠️ **The T&E finding.** Red on dev: the agency admin stays refused."""
    fake = authentik(agency_box_on_10_4_2())
    assert not can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)

    boot_converge([CORONA])

    assert can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)
    assert can_open(fake, 'all', {'authentik Admins'}, mfa=True)
    assert not can_open(fake, 'all', {'atlas-redlands-admins'}, mfa=True)
    assert not can_open(fake, 'all', set(), mfa=True)


def test_the_old_binding_is_replaced_by_the_one_policy(authentik):
    """The application ends with our policy and the MFA binding, nothing else."""
    fake = authentik(agency_box_on_10_4_2())

    out = boot_converge([CORONA])

    assert out == {'atlas-corona': 'created'}
    assert sorted(n or '' for n in names_bound(fake)) == sorted(
        ['ATLAS access: atlas-corona', MFA])
    assert not any(b.get('group') for b in fake.bindings)


def test_mfa_is_still_required(authentik):
    fake = authentik(agency_box_on_10_4_2())

    boot_converge([CORONA])

    assert not can_open(fake, 'all', {'atlas-corona-admins'}, mfa=False)
    assert not can_open(fake, 'all', {'authentik Admins'}, mfa=False)


def test_the_plain_deployment_is_swapped_too(authentik):
    """The plain deployment has no group of its own: the policy admits the
    global admins only, the same people the old binding let in."""
    fake = authentik(plain_box_on_10_4_2())

    out = boot_converge([PLAIN])

    assert out == {'atlas': 'created'}
    assert ALLOW not in names_bound(fake)
    assert 'ATLAS access: atlas' in names_bound(fake)
    assert can_open(fake, 'all', {'authentik Admins'}, mfa=True)
    assert not can_open(fake, 'all', {'atlas-corona-admins'}, mfa=True)
    assert not can_open(fake, 'all', set(), mfa=True)


def test_the_standard_group_is_not_let_in_by_the_converge(authentik):
    """Only an ATLAS Update admits the standard group, after it has checked the
    running container. The converge must not."""
    fake = authentik(agency_box_on_10_4_2())

    boot_converge([CORONA])

    pol = next(p for p in fake.policies
               if p['name'] == 'ATLAS access: atlas-corona')
    assert 'standard' not in pol['expression']
    assert pol['expression'] == atlas.atlas_access.build_expression(
        ['authentik Admins', 'atlas-corona-admins'])


# --------------------------------------------------------------------------- #
# Safe to run on every boot
# --------------------------------------------------------------------------- #


def test_a_second_boot_changes_nothing(authentik):
    fake = authentik(agency_box_on_10_4_2())
    boot_converge([CORONA])
    before = (json.dumps(fake.bindings, sort_keys=True),
              json.dumps(fake.policies, sort_keys=True))
    fake.posted.clear()
    fake.deleted.clear()

    out = boot_converge([CORONA])

    assert out == {'atlas-corona': 'present'}
    assert fake.posted == [] and fake.deleted == []
    assert (json.dumps(fake.bindings, sort_keys=True),
            json.dumps(fake.policies, sort_keys=True)) == before


def test_a_hand_written_policy_is_left_and_reported(authentik):
    """PR 600's rule: a policy somebody changed by hand is reported and left,
    and the bindings it would replace stay."""
    fake = agency_box_on_10_4_2()
    fake.policies.append({
        'pk': 'p-own', 'name': 'ATLAS access: atlas-corona',
        'expression': 'return ak_is_group_member(request.user, '
                      'name="authentik Admins") and request.http_request is not None'})
    authentik(fake)
    said = []

    out = boot_converge([CORONA], said.append)

    assert out == {'atlas-corona': 'failed'}
    assert ALLOW in names_bound(fake)
    assert fake.policies[-1]['expression'].endswith('is not None')
    assert any('changed by hand' in line for line in said)


def test_a_failed_bind_leaves_the_old_bindings(authentik):
    """⚠️ Never wider: a bind that fails must not remove the old way in."""
    fake = agency_box_on_10_4_2()
    fake.fail_post = {'policies/bindings/'}
    authentik(fake)

    out = boot_converge([CORONA])

    assert out == {'atlas-corona': 'failed'}
    assert ALLOW in names_bound(fake)
    assert not can_open(fake, 'all', set(), mfa=True)


def test_a_deployment_with_no_application_is_skipped(authentik):
    """A deployment still being built has no application: nothing is written."""
    fake = authentik(agency_box_on_10_4_2())
    fake.apps = {}

    out = boot_converge([CORONA])

    assert out == {'atlas-corona': 'skipped'}
    assert fake.posted == [] and fake.deleted == []


def test_one_deployment_failing_does_not_stop_the_next(authentik):
    fake = authentik(plain_box_on_10_4_2())
    fake.fail = {'core/applications/atlas-corona/'}

    out = boot_converge([CORONA, PLAIN])

    assert out == {'atlas-corona': 'failed', 'atlas': 'created'}
    assert ALLOW not in names_bound(fake)


def test_a_box_with_no_atlas_does_nothing(authentik):
    fake = authentik(plain_box_on_10_4_2())

    assert boot_converge([]) == {}
    assert fake.calls == []


# --------------------------------------------------------------------------- #
# Wired into the boot converge
# --------------------------------------------------------------------------- #


def _function(path, name):
    tree = ast.parse(path.read_text())
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == name)


def test_the_module_offers_the_swap_to_the_console():
    src = (ROOT / 'modules' / 'atlas.py').read_text()
    assert "'converge_access': converge_access" in src


def test_the_boot_converge_runs_the_swap_after_the_admins_binding():
    """Update Now restarts the console, and every boot runs this converge. The
    swap comes after `_ensure_app_access_policies`, so the admins binding it
    may add to a new application is swapped in the same boot."""
    fn = _function(ROOT / 'app.py', '_startup_app_access_policy_converge')
    src = ast.get_source_segment((ROOT / 'app.py').read_text(), fn)

    assert "'converge_access'" in src
    assert src.index('_ensure_app_access_policies(') < src.index("'converge_access'")
