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
"""The update's admin-only re-check runs on a box with no AUTHENTIK_FQDN (ops #512).

⚠️ `_verify_access_control` used to return None unless Authentik's `.env` held
`AUTHENTIK_FQDN`. infra-TAK never writes that key, so on a real box the check
never ran: an update did not re-bind "Allow authentik Admins" to ATLAS, and the
tile's "checked" time stayed at the deploy.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

from test_atlas_agency_group_reconcile import make_ctx  # noqa: E402


CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)


def _stub(monkeypatch, restricted=True):
    asked = []

    def restrict(ak_url, headers, plog=None, app_slug='atlas'):
        asked.append((ak_url, headers['Authorization'], app_slug))
        return restricted

    monkeypatch.setattr(atlas, '_restrict_to_admins', restrict)
    monkeypatch.setattr(atlas, '_record_access_state',
                        lambda _ctx, ok, plog=None, inst=None: ok)
    return asked


def test_check_runs_when_env_has_a_token_but_no_fqdn(monkeypatch):
    asked = _stub(monkeypatch)
    ctx = make_ctx(env={'AUTHENTIK_TOKEN': 'tok'})  # no AUTHENTIK_FQDN, like a real box

    assert atlas._verify_access_control(ctx, inst=CORONA) is True
    assert asked == [('http://ak', 'Bearer tok', 'atlas-corona')]


def test_a_missing_binding_is_reported_not_skipped(monkeypatch):
    _stub(monkeypatch, restricted=False)
    ctx = make_ctx(env={'AUTHENTIK_TOKEN': 'tok'})

    assert atlas._verify_access_control(ctx, inst=CORONA) is False


def test_no_token_is_still_none(monkeypatch):
    asked = _stub(monkeypatch)
    ctx = make_ctx(env={})

    assert atlas._verify_access_control(ctx, inst=CORONA) is None
    assert asked == []
