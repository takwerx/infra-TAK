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
"""An ATLAS update keeps the admin groups an operator added (ops #1288).

Field report (TAK-MDM #14): updating ATLAS 2.5.0 to 2.11.0 through infra-TAK
replaced the operator's `TAKMDM_ADMIN_GROUP` with the managed default, so their
own admin group was gone and ATLAS answered 403 after Authentik had let them in.
It happened on every update, so a hand repair lasted until the next one.

The managed groups are guaranteed. Every other group on the line stays. Only
this module's own non-administrator groups (certificate renewal, standard
admins) are taken off, by name.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402
from modules import atlas_renewal  # noqa: E402

CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
KEY = 'TAKMDM_ADMIN_GROUP='


@pytest.fixture(autouse=True)
def _no_proxy_auth(monkeypatch):
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    monkeypatch.setattr(atlas, '_caddyfile_injects_proxy_auth', lambda: False)


def _arm(tmp_path, body, inst=None, global_group=None):
    env = tmp_path / '.env'
    env.write_text(body, encoding='utf-8')
    said = []
    changed = atlas._arm_admin_gates(None, str(tmp_path), said.append,
                                     inst=inst, global_group=global_group)
    return changed, env.read_text(encoding='utf-8'), said


def _groups(body):
    """The names on the (single) admin group line."""
    lines = [l for l in body.splitlines() if l.startswith(KEY)]
    assert len(lines) == 1, body
    return lines[0][len(KEY):].split(',')


def test_a_group_the_operator_added_survives_the_update(tmp_path):
    """The field report: the line held the operator's group only."""
    changed, body, _ = _arm(tmp_path, KEY + 'ATLAS-Admins\n')

    assert changed is True
    assert set(_groups(body)) == {'authentik Admins', 'ATLAS-Admins'}


def test_the_workaround_line_is_left_alone(tmp_path):
    """What the reporter wrote by hand must not be rewritten (no restart)."""
    original = KEY + 'ATLAS-Admins,authentik Admins\n'

    changed, body, _ = _arm(tmp_path, original)

    assert changed is False
    assert body == original


def test_a_second_update_changes_nothing(tmp_path):
    _, first, _ = _arm(tmp_path, KEY + 'ATLAS-Admins\n')

    changed, second, _ = _arm(tmp_path, first)

    assert changed is False
    assert second == first


def test_an_agency_keeps_the_added_group_after_its_own_two(tmp_path):
    """Most specific first, then the operator's, in the order written."""
    _, body, _ = _arm(tmp_path, KEY + 'Ops One,Ops Two\n', inst=CORONA)

    assert _groups(body) == ['atlas-corona-admins', 'authentik Admins',
                             'Ops One', 'Ops Two']


def test_a_renamed_superuser_group_is_added_beside_the_added_one(tmp_path):
    _, body, _ = _arm(tmp_path, KEY + 'ATLAS-Admins\n',
                      global_group='Platform Owners')

    assert set(_groups(body)) == {'Platform Owners', 'ATLAS-Admins'}


def test_a_quoted_line_is_read_without_its_quotes(tmp_path):
    _, body, _ = _arm(tmp_path, KEY + '"ATLAS-Admins"\n')

    assert set(_groups(body)) == {'ATLAS-Admins', 'authentik Admins'}


def test_a_quoted_line_that_is_complete_is_left_alone(tmp_path):
    original = KEY + '"ATLAS-Admins,authentik Admins"\n'

    changed, body, _ = _arm(tmp_path, original)

    assert changed is False
    assert body == original


def test_the_last_line_wins_as_it_does_in_dotenv(tmp_path):
    _, body, _ = _arm(tmp_path, KEY + 'Old One\n' + KEY + 'ATLAS-Admins\n')

    assert set(_groups(body)) == {'authentik Admins', 'ATLAS-Admins'}


def test_a_blank_line_gets_only_the_managed_group(tmp_path):
    _, body, _ = _arm(tmp_path, KEY + '\n')

    assert _groups(body) == ['authentik Admins']


def test_no_line_at_all_gets_the_managed_group(tmp_path):
    _, body, _ = _arm(tmp_path, 'TAKMDM_DB_PASSWORD=x\n')

    assert _groups(body) == ['authentik Admins']
    assert 'TAKMDM_DB_PASSWORD=x' in body


@pytest.mark.parametrize('inst, standard', [
    (None, 'atlas-standard-admins'),
    (CORONA, 'atlas-corona-standard-admins'),
])
def test_our_own_non_administrator_groups_are_still_taken_off(tmp_path, inst,
                                                              standard):
    """⚠️ The renewal group once became every deployment's admin group (ops
    #510) and the standard group would make standard admins full admins. They
    are named; the operator's own groups are not."""
    line = KEY + ','.join([atlas_renewal.GROUP_NAME, standard, 'ATLAS-Admins']) + '\n'

    changed, body, _ = _arm(tmp_path, line, inst=inst)

    assert changed is True
    names = _groups(body)
    assert atlas_renewal.GROUP_NAME not in names
    assert standard not in names
    assert 'ATLAS-Admins' in names


def test_the_log_says_what_was_kept(tmp_path):
    _, _, said = _arm(tmp_path, KEY + 'ATLAS-Admins\n')

    assert any('ATLAS-Admins' in line and 'Kept' in line for line in said), said


def test_the_comment_block_is_not_repeated(tmp_path):
    _, once, _ = _arm(tmp_path, KEY + 'ATLAS-Admins\n')
    _, twice, _ = _arm(tmp_path, once.replace('ATLAS-Admins', 'Other'))

    assert twice.count('# SEC_AUDIT (ATLAS) H-1.') == 1, twice


def test_merge_keeps_order_and_drops_duplicates():
    groups, kept = atlas.merge_admin_groups(
        'b, a ,b,authentik Admins', ['x', 'authentik Admins'], never={'a'})

    assert groups == ['x', 'authentik Admins', 'b']
    assert kept == ['b']
