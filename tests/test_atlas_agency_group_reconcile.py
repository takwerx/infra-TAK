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
"""The agency admin group is checked on every update, and the answer shows.

⚠️ **Reported from a real box (2026-10-07):** an agency ATLAS was deployed
with no `atlas-<slug>-admins` group, and pressing Update did not make one.
Three things let that happen without a word:

- `_run_update` returned at "already on the newest release" **before** the
  access checks, so the press an operator makes to repair it checked nothing;
- `_reconcile_agency_group` returned in silence when it found no token;
- a failure was one `⚠` line in a log that otherwise read as success, and the
  tile said nothing.
"""

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

from test_atlas_agency_admins import FakeAuthentik  # noqa: E402


CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)


def make_ctx(env=None, settings=None):
    """A console context holding settings in memory and an Authentik `.env`."""
    store = {'s': dict(settings or {})}
    env = dict(env if env is not None else {'AUTHENTIK_TOKEN': 'tok'})
    return {
        'load_settings': lambda: dict(store['s']),
        'save_settings': lambda s: store.__setitem__('s', dict(s)),
        '_get_authentik_env_value': lambda _s, key: env.get(key),
        '_get_authentik_api_url': lambda _s: 'http://ak',
        '_store': store,
    }


@pytest.fixture
def authentik(monkeypatch):
    import urllib.request

    def install(fake):
        monkeypatch.setattr(urllib.request, 'urlopen', fake.open)
        return fake

    return install


def recorded(ctx, inst=CORONA):
    return ctx['_store']['s'].get(atlas.agency_group_key(inst))


# --------------------------------------------------------------------------- #
# An update with nothing to install still checks
# --------------------------------------------------------------------------- #


@pytest.fixture
def update_at(monkeypatch, tmp_path):
    """Run `_run_update` with the installed and offered versions given."""
    (tmp_path / '.git').mkdir()
    calls = []

    def run(installed, offered):
        monkeypatch.setattr(atlas, 'deployment_identity', lambda *_a: {
            'settings_prefix': 'atlas_corona_', 'name': 'atlas-corona',
            'dir': str(tmp_path), 'compose_project': 'takmdm-corona'})
        monkeypatch.setattr(atlas, '_channel_of', lambda _ctx: 'main')
        monkeypatch.setattr(atlas, '_latest_version',
                            lambda use_cache=False, channel=None: offered)
        monkeypatch.setattr(atlas, '_installed_version',
                            lambda _ctx, _inst=None: installed)
        monkeypatch.setattr(atlas, '_reconcile_access',
                            lambda ctx, inst, plog: calls.append(inst))
        ctx = make_ctx()
        atlas._run_update(ctx, CORONA)
        return calls, atlas._update_slot(CORONA)

    return run


def test_an_update_with_nothing_to_install_still_checks_access(update_at):
    """⚠️ **The reported case.** Update is the button an operator presses to
    repair a missing group; on a deployment already current it used to return
    at "nothing to do" and check nothing."""
    calls, slot = update_at('1.79.0', '1.79.0')

    assert calls == [CORONA]
    assert slot['complete'] and not slot['error']


def test_a_refused_downgrade_still_checks_access(update_at):
    """The other early return. Refusing to move backwards is no reason to skip
    a check that changes nothing in the deployment."""
    calls, _slot = update_at('1.80.0', '1.79.0')

    assert calls == [CORONA]


def test_no_early_return_skips_the_check():
    """Every `return` in the version comparison is preceded by the check, and
    the rebuild path calls the same helper rather than its own copy."""
    src = pathlib.Path(atlas.__file__).read_text(encoding='utf-8')
    body = src[src.index('def _run_update('):src.index('def _run_update_all(')]

    assert body.count('_reconcile_access(ctx, inst, plog)') == 3
    assert '_reconcile_agency_group(' not in body
    assert '_verify_access_control(' not in body


def test_the_helper_runs_both_checks(monkeypatch):
    seen = []
    monkeypatch.setattr(atlas, '_verify_access_control',
                        lambda ctx, plog=None, inst=None: seen.append('binding'))
    monkeypatch.setattr(atlas, '_reconcile_agency_group',
                        lambda ctx, inst, plog: seen.append('group'))

    atlas._reconcile_access({}, CORONA, lambda _m: None)

    assert seen == ['binding', 'group']


# --------------------------------------------------------------------------- #
# Never silent
# --------------------------------------------------------------------------- #


def test_no_token_is_said_and_recorded(authentik):
    """⚠️ It used to `return` with no log line, so the update read as a clean
    success over a group nobody had checked."""
    fake = authentik(FakeAuthentik())
    ctx = make_ctx(env={})
    said = []

    outcome = atlas._reconcile_agency_group(ctx, CORONA, said.append)

    assert outcome['status'] == 'skipped'
    assert any('No Authentik API token' in line and 'atlas-corona-admins' in line
               for line in said), said
    assert recorded(ctx)['status'] == 'skipped'
    assert fake.posted == []


def test_a_failure_is_recorded_with_its_reason(authentik):
    authentik(FakeAuthentik(fail=('core/groups',)))
    ctx = make_ctx()

    outcome = atlas._reconcile_agency_group(ctx, CORONA, lambda _m: None)

    assert outcome['status'] == 'failed'
    assert 'look up' in recorded(ctx)['detail']
    assert 'boom' in recorded(ctx)['detail']


def test_a_failed_binding_is_a_failure_even_though_the_group_was_made(authentik):
    """A group nobody can use to get in is not a working group."""
    authentik(FakeAuthentik(fail=('core/applications',)))
    ctx = make_ctx()

    outcome = atlas._reconcile_agency_group(ctx, CORONA, lambda _m: None)

    assert outcome['status'] == 'failed'
    assert 'admit' in outcome['detail']


def test_creating_the_group_is_recorded_as_created(authentik):
    authentik(FakeAuthentik())
    ctx = make_ctx()

    atlas._reconcile_agency_group(ctx, CORONA, lambda _m: None)

    assert recorded(ctx)['status'] == 'created'
    assert recorded(ctx)['group'] == 'atlas-corona-admins'
    assert recorded(ctx)['checked_at'] > 0


def test_an_existing_group_and_binding_are_recorded_as_present(authentik):
    authentik(FakeAuthentik(
        groups=[{'name': 'atlas-corona-admins', 'is_superuser': False,
                 'pk': 'g9'}],
        bindings=[{'pk': 'b1', 'group': 'g9', 'order': 10}]))
    ctx = make_ctx()

    atlas._reconcile_agency_group(ctx, CORONA, lambda _m: None)

    assert recorded(ctx)['status'] == 'present'


def test_an_exception_anywhere_is_recorded_not_raised():
    """An update must not fail over this; the containers are already serving."""
    ctx = make_ctx()
    ctx['_get_authentik_api_url'] = lambda _s: 1 / 0

    outcome = atlas._reconcile_agency_group(ctx, CORONA, lambda _m: None)

    assert outcome['status'] == 'failed'
    assert recorded(ctx)['status'] == 'failed'


def test_the_plain_deployment_is_left_alone(authentik):
    """It has no group of its own: nothing to check, nothing to record, and
    nothing to warn about."""
    fake = authentik(FakeAuthentik())
    ctx = make_ctx()
    said = []

    assert atlas._reconcile_agency_group(ctx, PLAIN, said.append) is None
    assert ctx['_store']['s'] == {}
    assert said == []
    assert fake.posted == []


# --------------------------------------------------------------------------- #
# One token lookup
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('env, settings', [
    ({'AUTHENTIK_TOKEN': 'tok'}, {}),
    ({'AUTHENTIK_BOOTSTRAP_TOKEN': 'tok'}, {}),
    ({}, {'authentik_api_token': 'tok'}),
])
def test_every_place_a_box_keeps_its_token_is_found(env, settings):
    """⚠️ The binding check and the group reconcile each knew two of these
    three, and not the same two."""
    ctx = make_ctx(env=env, settings=settings)

    assert atlas._authentik_token(ctx, ctx['load_settings']()) == 'tok'


def test_the_primary_token_wins():
    ctx = make_ctx(env={'AUTHENTIK_TOKEN': 'a', 'AUTHENTIK_BOOTSTRAP_TOKEN': 'b'},
                   settings={'authentik_api_token': 'c'})

    assert atlas._authentik_token(ctx, ctx['load_settings']()) == 'a'


def test_no_token_anywhere_is_none():
    ctx = make_ctx(env={})

    assert atlas._authentik_token(ctx, ctx['load_settings']()) is None


# --------------------------------------------------------------------------- #
# The tile says so
# --------------------------------------------------------------------------- #


def state(status, detail=''):
    return {atlas.agency_group_key(CORONA): {
        'status': status, 'group': 'atlas-corona-admins', 'detail': detail,
        'checked_at': 1}}


@pytest.mark.parametrize('status', ['failed', 'skipped'])
def test_a_failed_or_skipped_check_is_a_problem(status):
    """⚠️ Skipped is not a pass: a check that could not run has not shown the
    group exists."""
    said = atlas.agency_group_problem(state(status, 'why it went wrong'), CORONA)

    assert 'atlas-corona-admins' in said
    assert 'why it went wrong' in said
    assert 'Update' in said


@pytest.mark.parametrize('status', ['present', 'created'])
def test_a_working_group_is_not_a_problem(status):
    assert atlas.agency_group_problem(state(status), CORONA) is None


def test_never_checked_is_not_shouted_about():
    """Every agency deployed before this record existed has none. The next
    update writes it; a warning on every row until then would be noise."""
    assert atlas.agency_group_problem({}, CORONA) is None
    assert atlas.agency_group_problem(None, CORONA) is None


def test_the_plain_deployment_never_has_a_group_problem():
    assert atlas.agency_group_problem(
        {atlas.agency_group_key(PLAIN): {'status': 'failed'}}, PLAIN) is None


def test_each_deployment_has_its_own_record():
    """One agency's group being fine says nothing about another's."""
    keys = {atlas.agency_group_key(ai.make(s, ai.MODE_DYNAMIC, 50, 8761))
            for s in ('corona', 'redlands')}

    assert len(keys) == 2


def test_the_row_carries_the_problem():
    assert 'admin_group_problem' in atlas.INSTANCE_FIELDS


def test_the_page_shows_it_on_the_row():
    page = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    row = page[page.index('function instanceRow('):page.index('function controlInstance(')]

    assert 'i.admin_group_problem' in row
    # ⚠️ `textContent`, not `innerHTML`: the detail carries Authentik's error
    # text, which this page does not control.
    assert 'warn.textContent' in row
    assert 'innerHTML' not in row


def test_the_page_route_passes_settings_to_the_row(monkeypatch):
    """The field is computed from settings handed in by `instances_payload`;
    without them every row would say None whatever was recorded."""
    monkeypatch.setattr(atlas, 'compose_projects_present', lambda _ctx: set())
    monkeypatch.setattr(atlas, '_latest_version', lambda **_k: '1.79.0')
    monkeypatch.setattr(atlas, '_channel_of', lambda _ctx: 'main')
    monkeypatch.setattr(atlas, 'load_instances', lambda _ctx: [CORONA])
    monkeypatch.setattr(atlas, 'instance_is_built', lambda *_a: False)
    monkeypatch.setattr(atlas, 'instance_is_stranded', lambda *_a: False)
    monkeypatch.setattr(atlas, '_installed_version', lambda *_a: '1.79.0')
    monkeypatch.setattr(atlas, 'instance_paths', lambda *_a: {
        'dir': '/x', 'vhost': '/y', 'compose_project': 'p'})
    monkeypatch.setattr(atlas, 'capacity_facts', lambda *_a, **_k: {})
    monkeypatch.setattr(atlas, 'root_key_holders', lambda *_a: [])
    ctx = make_ctx(settings=state('failed', 'boom'))

    row = atlas.instances_payload(ctx)['instances'][0]

    assert 'boom' in row['admin_group_problem']


# --------------------------------------------------------------------------- #
# Deploy
# --------------------------------------------------------------------------- #


def test_deploy_checks_the_group_outside_the_app_registration():
    """⚠️ `ensure_authentik_app` returns early — no flow yet, a provider it
    could not resolve — without reaching the group, and said nothing. The
    deploy's own step checks again after it."""
    src = pathlib.Path(atlas.__file__).read_text(encoding='utf-8')
    step = src[src.index('Step 7/7: Administrator sign-in'):]
    step = step[:step.index('Authentik not configured')]

    register = step.index('ensure_authentik_app(')
    reconcile = step.index('_reconcile_agency_group(ctx, _inst, plog)')
    assert register < reconcile


def test_the_name_returning_wrapper_keeps_its_contract(authentik):
    """`ensure_agency_admin_group` is still a name or None, for its callers."""
    authentik(FakeAuthentik(fail=('core/applications',)))

    assert atlas.ensure_agency_admin_group(None, CORONA, 'http://ak', {}) is None


# --------------------------------------------------------------------------- #
# v10.2.8 (PR #89 review): a binding that admits nobody is not "present"
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('binding', [
    {'pk': 'b1', 'group': 'g9', 'order': 10, 'enabled': False},
    {'pk': 'b1', 'group': 'g9', 'order': 10, 'negate': True},
    {'pk': 'b1', 'group': 'g9', 'order': 10, 'enabled': False, 'negate': True},
])
def test_a_disabled_or_negated_binding_is_a_problem_not_a_pass(authentik, binding):
    """⚠️ It passed before: any binding naming the group counted, so the tile
    said OK while every member of the group was turned away."""
    fake = authentik(FakeAuthentik(
        groups=[{'name': 'atlas-corona-admins', 'is_superuser': False, 'pk': 'g9'}],
        bindings=[binding]))
    ctx = make_ctx()

    atlas._reconcile_agency_group(ctx, CORONA, lambda _m: None)

    assert recorded(ctx)['status'] == 'failed'
    assert 'disabled or negated' in recorded(ctx)['detail']
    # ⚠️ Never repaired from here: somebody switched it off in Authentik.
    assert fake.posted == []
    said = atlas.agency_group_problem(ctx['_store']['s'], CORONA)
    assert said and 'disabled or negated' in said


def test_one_live_binding_beside_a_disabled_one_is_present(authentik):
    authentik(FakeAuthentik(
        groups=[{'name': 'atlas-corona-admins', 'is_superuser': False, 'pk': 'g9'}],
        bindings=[{'pk': 'b1', 'group': 'g9', 'order': 10, 'enabled': False},
                  {'pk': 'b2', 'group': 'g9', 'order': 11, 'enabled': True}]))
    ctx = make_ctx()

    atlas._reconcile_agency_group(ctx, CORONA, lambda _m: None)

    assert recorded(ctx)['status'] == 'present'
