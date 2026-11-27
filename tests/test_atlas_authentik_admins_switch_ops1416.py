"""The ATLAS switch "Authentik administrators are also ATLAS administrators" (ops #1416).

TAK-MDM issue 14: an operator wants ATLAS administration to be a list they own,
not something every Authentik superuser gets. The switch is per deployment, on
by default (absent = on), and turning it off takes `authentik Admins` out of
both gates: Authentik's access policy for ATLAS and `TAKMDM_ADMIN_GROUP`.

Every test asks what the operator cares about: **who gets in, and can the
switch lock everyone out?**
"""

import json
import pathlib
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_access, atlas_roster  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

from test_atlas_agency_admins import FakeAuthentik  # noqa: E402

PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)
PLAIN_OFF = dict(PLAIN, **{atlas_access.OFF_KEY: True})
CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
CORONA_OFF = dict(CORONA, **{atlas_access.OFF_KEY: True})

SUPER = {'name': 'authentik Admins', 'is_superuser': True, 'pk': 'g-root'}
OURS = {'name': 'ATLAS-Admins', 'pk': 'g-ours', 'is_superuser': False,
        'users_obj': [{'pk': 7, 'username': 'alice', 'is_active': True}]}
EMPTY = {'name': 'ATLAS-Admins', 'pk': 'g-ours', 'is_superuser': False,
         'users_obj': []}
DISABLED = {'name': 'ATLAS-Admins', 'pk': 'g-ours', 'is_superuser': False,
            'users_obj': [{'pk': 7, 'username': 'alice', 'is_active': False}]}


def policy(app, groups, pk='p-atlas'):
    return {'pk': pk, 'name': atlas_access.POLICY_PREFIX + app,
            'expression': atlas_access.build_expression(groups)}


def bound(pk='b-1', policy_pk='p-atlas', name=None):
    return {'pk': pk, 'policy': policy_pk, 'group': None, 'order': 0,
            'enabled': True, 'negate': False,
            'policy_obj': {'name': name or atlas_access.POLICY_PREFIX + 'atlas'}}


@pytest.fixture
def authentik(monkeypatch):
    def install(fake):
        monkeypatch.setattr(urllib.request, 'urlopen', fake.open)
        return fake
    return install


def api():
    return atlas_access.Api('http://ak', {})


# --------------------------------------------------------------------------- #
# The default: nothing changes for anyone who never touches the switch
# --------------------------------------------------------------------------- #


def test_the_switch_is_on_unless_somebody_turned_it_off():
    assert atlas_access.global_admins_wanted(PLAIN) is True
    assert atlas_access.global_admins_wanted(None) is True
    assert atlas_access.global_admins_wanted(PLAIN_OFF) is False


def test_a_box_that_never_touched_it_keeps_the_global_group_everywhere():
    assert atlas.admin_groups_for(CORONA) == ['atlas-corona-admins', 'authentik Admins']
    assert atlas.admin_groups_for(PLAIN) == ['authentik Admins']
    assert atlas_access.global_admins_in_force({}, PLAIN) is True


def test_off_leaves_the_global_group_out_of_the_managed_names():
    assert atlas.admin_groups_for(PLAIN, include_global=False) == []
    assert atlas.admin_groups_for(CORONA, include_global=False) == ['atlas-corona-admins']


def test_off_that_the_guard_never_confirmed_is_not_in_force_yet_in_the_safe_direction():
    """A recorded wish with no guard answer keeps the global administrators in."""
    assert atlas_access.global_admins_in_force({}, PLAIN_OFF) is True
    state = {atlas_access.state_key('atlas_'): {'global_in': False}}
    assert atlas_access.global_admins_in_force(state, PLAIN_OFF) is False
    back = {atlas_access.state_key('atlas_'): {'global_in': True}}
    assert atlas_access.global_admins_in_force(back, PLAIN_OFF) is True


# --------------------------------------------------------------------------- #
# The Authentik policy
# --------------------------------------------------------------------------- #


def test_off_takes_the_global_group_out_of_the_policy_and_keeps_the_operator_s(authentik):
    fake = authentik(FakeAuthentik(
        groups=[SUPER, OURS], apps={'atlas': {'pk': 'app-pk'}},
        policies=[policy('atlas', ['authentik Admins', 'ATLAS-Admins'])],
        bindings=[bound()]))

    out = atlas_access.ensure(api(), 'atlas', include_global=False)

    assert out['status'] == 'created'
    assert atlas_access.parse_groups(fake.policies[0]['expression']) == ['ATLAS-Admins']


def test_off_with_nobody_else_to_admit_is_refused_and_changes_nothing(authentik):
    """⚠️ An empty policy is invalid in Authentik and means nobody: the lockout."""
    fake = authentik(FakeAuthentik(
        groups=[SUPER], apps={'atlas': {'pk': 'app-pk'}},
        policies=[policy('atlas', ['authentik Admins'])], bindings=[bound()]))

    out = atlas_access.ensure(api(), 'atlas', include_global=False)

    assert out['status'] == 'failed'
    assert atlas_access.parse_groups(fake.policies[0]['expression']) == ['authentik Admins']
    assert not [c for c in fake.calls if c[0] in ('POST', 'PATCH', 'DELETE')]


def test_on_is_the_old_behaviour_exactly(authentik):
    fake = authentik(FakeAuthentik(
        groups=[SUPER, OURS], apps={'atlas': {'pk': 'app-pk'}},
        policies=[policy('atlas', ['ATLAS-Admins'])], bindings=[bound()]))

    atlas_access.ensure(api(), 'atlas')

    assert atlas_access.parse_groups(fake.policies[0]['expression']) == \
        ['authentik Admins', 'ATLAS-Admins']


def test_off_does_not_put_the_global_group_back_through_the_standard_role(authentik):
    """The roster writer rewrites the same policy: it must honour the switch."""
    fake = authentik(FakeAuthentik(
        groups=[SUPER, OURS], apps={'atlas': {'pk': 'app-pk'}},
        policies=[policy('atlas', ['ATLAS-Admins'])], bindings=[bound()]))
    n = atlas_roster.names(None)

    atlas_roster.ensure_access(api(), dict(n, application='atlas'), '2.3.0', '2.3.0',
                               lambda m: None, include_global=False)

    groups = atlas_access.parse_groups(fake.policies[0]['expression'])
    assert 'authentik Admins' not in groups
    assert 'ATLAS-Admins' in groups


# --------------------------------------------------------------------------- #
# The lockout guard
# --------------------------------------------------------------------------- #


def test_guard_passes_for_a_group_in_both_gates_with_a_member(authentik):
    authentik(FakeAuthentik(groups=[SUPER, OURS]))
    ok, why = atlas_access.guard(api(), ['authentik Admins', 'ATLAS-Admins'],
                                 ['authentik Admins', 'ATLAS-Admins'])
    assert ok, why


@pytest.mark.parametrize('groups, policy_groups, env_groups', [
    ([SUPER], ['authentik Admins', 'ATLAS-Admins'], ['authentik Admins', 'ATLAS-Admins']),  # group missing
    ([SUPER, EMPTY], ['authentik Admins', 'ATLAS-Admins'], ['authentik Admins', 'ATLAS-Admins']),  # no member
    ([SUPER, DISABLED], ['authentik Admins', 'ATLAS-Admins'], ['authentik Admins', 'ATLAS-Admins']),  # disabled member
    ([SUPER, OURS], ['authentik Admins', 'ATLAS-Admins'], ['authentik Admins']),  # not on the admin line
    ([SUPER, OURS], ['authentik Admins'], ['authentik Admins', 'ATLAS-Admins']),  # not in the policy
    ([SUPER, OURS], ['authentik Admins'], ['authentik Admins']),  # none at all
])
def test_guard_refuses_every_way_the_operator_could_be_locked_out(
        authentik, groups, policy_groups, env_groups):
    authentik(FakeAuthentik(groups=groups))
    ok, why = atlas_access.guard(api(), policy_groups, env_groups)
    assert ok is False
    assert why


def test_guard_never_counts_the_global_group_as_your_own(authentik):
    authentik(FakeAuthentik(groups=[dict(SUPER, users_obj=[{'is_active': True}])]))
    ok, _ = atlas_access.guard(api(), ['authentik Admins'], ['authentik Admins'])
    assert ok is False


def test_guard_treats_an_unanswered_question_as_a_no(authentik):
    authentik(FakeAuthentik(groups=[SUPER, OURS], fail=['core/groups/']))
    ok, why = atlas_access.guard(api(), ['ATLAS-Admins'], ['ATLAS-Admins'])
    assert ok is False
    assert 'could not ask' in why


# --------------------------------------------------------------------------- #
# The `.env` line, and an update after the switch is off
# --------------------------------------------------------------------------- #


class Ctx(dict):
    """The few things the module reads from the console."""


def make_ctx(settings, fake_token='t'):
    store = {'s': settings}
    ctx = Ctx(
        load_settings=lambda: store['s'],
        save_settings=lambda s: store.update(s=s),
        _get_authentik_env_value=lambda s, k: fake_token if k == 'AUTHENTIK_TOKEN' else '',
        _get_authentik_api_url=lambda s: 'http://ak')
    ctx.store = store
    return ctx


def arm(tmp_path, monkeypatch, ctx, inst, env_text):
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    (tmp_path / '.env').write_text(env_text, encoding='utf-8')
    said = []
    atlas._arm_admin_gates(ctx, str(tmp_path), said.append, inst=inst)
    body = (tmp_path / '.env').read_text(encoding='utf-8')
    line = [l for l in body.splitlines() if l.startswith('TAKMDM_ADMIN_GROUP=')]
    return line, said


def settings_for(instances):
    return {ai.INSTANCES_KEY: instances, 'atlas_enabled': True}


def test_update_with_the_switch_off_keeps_your_group_and_leaves_the_global_one_out(
        tmp_path, monkeypatch, authentik):
    authentik(FakeAuthentik(groups=[SUPER, OURS],
                            policies=[policy('atlas', ['ATLAS-Admins'])],
                            apps={'atlas': {'pk': 'app-pk'}}))
    ctx = make_ctx(settings_for([PLAIN_OFF]))

    line, said = arm(tmp_path, monkeypatch, ctx, PLAIN_OFF,
                     'TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins\n')

    assert line == ['TAKMDM_ADMIN_GROUP=ATLAS-Admins']
    assert atlas_access.global_admins_in_force(ctx['load_settings'](), PLAIN_OFF) is False


def test_update_with_the_switch_off_and_the_group_emptied_brings_the_global_group_back(
        tmp_path, monkeypatch, authentik):
    """⚠️ The lockout guard runs on every update, not only when the switch is pressed."""
    authentik(FakeAuthentik(groups=[SUPER, EMPTY],
                            policies=[policy('atlas', ['ATLAS-Admins'])],
                            apps={'atlas': {'pk': 'app-pk'}}))
    ctx = make_ctx(settings_for([PLAIN_OFF]))

    line, said = arm(tmp_path, monkeypatch, ctx, PLAIN_OFF,
                     'TAKMDM_ADMIN_GROUP=ATLAS-Admins\n')

    assert line == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']
    assert any('stay ATLAS administrators' in s for s in said), said
    assert atlas.authentik_admins_problem(ctx['load_settings'](), PLAIN_OFF)


def test_update_that_cannot_ask_authentik_keeps_the_last_answer(
        tmp_path, monkeypatch, authentik):
    authentik(FakeAuthentik(groups=[SUPER, OURS], fail=['policies/expression/']))
    s = settings_for([PLAIN_OFF])
    s[atlas_access.state_key('atlas_')] = {'global_in': False}
    ctx = make_ctx(s)

    line, _ = arm(tmp_path, monkeypatch, ctx, PLAIN_OFF, 'TAKMDM_ADMIN_GROUP=ATLAS-Admins\n')

    assert line == ['TAKMDM_ADMIN_GROUP=ATLAS-Admins']


def test_a_blank_admin_line_is_never_written(tmp_path, monkeypatch, authentik):
    """⚠️ ATLAS reads an empty line as "not armed". Every name on it was one that
    may never be an admin group here, so the global group stays."""
    authentik(FakeAuthentik(groups=[SUPER, OURS],
                            policies=[policy('atlas', ['ATLAS certificate renewal'])],
                            apps={'atlas': {'pk': 'app-pk'}}))
    ctx = make_ctx(settings_for([PLAIN_OFF]))

    line, _ = arm(tmp_path, monkeypatch, ctx, PLAIN_OFF,
                  'TAKMDM_ADMIN_GROUP=ATLAS certificate renewal\n')

    assert line and line[0] != 'TAKMDM_ADMIN_GROUP='


def test_the_default_update_is_byte_for_byte_what_it_was(tmp_path, monkeypatch):
    """No switch recorded: nothing is asked of Authentik, and the line is the old one."""
    ctx = make_ctx(settings_for([PLAIN]))
    ctx['_get_authentik_env_value'] = lambda s, k: (_ for _ in ()).throw(
        AssertionError('Authentik must not be asked while the switch is on'))

    line, _ = arm(tmp_path, monkeypatch, ctx, PLAIN, 'TAKMDM_ADMIN_GROUP=ATLAS-Admins\n')

    assert line == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']


# --------------------------------------------------------------------------- #
# The switch itself
# --------------------------------------------------------------------------- #


def switch_box(tmp_path, monkeypatch, authentik, groups, instance=PLAIN, pol_groups=None):
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    monkeypatch.setattr(atlas, 'instance_paths', lambda ctx=None, inst=None: {'dir': str(tmp_path)})
    restarts = []
    monkeypatch.setattr(atlas, '_compose', lambda ctx, action, timeout=180, inst=None:
                        restarts.append(action))
    (tmp_path / '.env').write_text(
        'TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins\n', encoding='utf-8')
    fake = authentik(FakeAuthentik(
        groups=groups, apps={'atlas': {'pk': 'app-pk'}},
        policies=[policy('atlas', pol_groups or ['authentik Admins', 'ATLAS-Admins'])],
        bindings=[bound()]))
    ctx = make_ctx(settings_for([instance]))
    return ctx, fake, restarts


def line_of(tmp_path):
    body = (tmp_path / '.env').read_text(encoding='utf-8')
    return [l for l in body.splitlines() if l.startswith('TAKMDM_ADMIN_GROUP=')]


def test_turning_it_off_with_a_good_group_changes_both_gates(tmp_path, monkeypatch, authentik):
    ctx, fake, restarts = switch_box(tmp_path, monkeypatch, authentik, [SUPER, OURS])

    steps, err = atlas.set_authentik_admins(ctx, PLAIN, False)

    assert err is None, steps
    assert atlas_access.parse_groups(fake.policies[0]['expression']) == ['ATLAS-Admins']
    assert line_of(tmp_path) == ['TAKMDM_ADMIN_GROUP=ATLAS-Admins']
    assert restarts == ['up -d api']
    assert atlas.load_instances(ctx)[0].get(atlas_access.OFF_KEY) is True


@pytest.mark.parametrize('groups', [[SUPER], [SUPER, EMPTY], [SUPER, DISABLED]])
def test_turning_it_off_is_refused_without_a_group_that_has_a_member(
        tmp_path, monkeypatch, authentik, groups):
    ctx, fake, restarts = switch_box(tmp_path, monkeypatch, authentik, groups)

    steps, err = atlas.set_authentik_admins(ctx, PLAIN, False)

    assert err and 'nobody is locked out' in err
    assert atlas_access.parse_groups(fake.policies[0]['expression']) == \
        ['authentik Admins', 'ATLAS-Admins']
    assert line_of(tmp_path) == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']
    assert restarts == []
    assert not atlas.load_instances(ctx)[0].get(atlas_access.OFF_KEY)


def test_a_failed_policy_write_puts_the_record_back_and_leaves_env_alone(
        tmp_path, monkeypatch, authentik):
    ctx, fake, restarts = switch_box(tmp_path, monkeypatch, authentik, [SUPER, OURS])
    fake.fail_post = {'policies/bindings/'}
    fake.policies[0]['expression'] = 'return ak_is_group_member(request.user, name="x") and True'

    steps, err = atlas.set_authentik_admins(ctx, PLAIN, False)

    assert err
    assert not atlas.load_instances(ctx)[0].get(atlas_access.OFF_KEY)
    assert line_of(tmp_path) == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']
    assert restarts == []


def test_turning_it_back_on_restores_both_gates(tmp_path, monkeypatch, authentik):
    ctx, fake, restarts = switch_box(tmp_path, monkeypatch, authentik, [SUPER, OURS])
    atlas.set_authentik_admins(ctx, PLAIN, False)
    inst = atlas.load_instances(ctx)[0]

    steps, err = atlas.set_authentik_admins(ctx, inst, True)

    assert err is None, steps
    assert atlas_access.parse_groups(fake.policies[0]['expression']) == \
        ['authentik Admins', 'ATLAS-Admins']
    assert line_of(tmp_path) == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']
    assert not atlas.load_instances(ctx)[0].get(atlas_access.OFF_KEY)
    assert atlas.authentik_admins_problem(ctx['load_settings'](), inst) is None


def test_the_agency_group_alone_does_not_pass_the_guard_while_empty(
        tmp_path, monkeypatch, authentik):
    """An agency's own group is empty on purpose, so it cannot be the reason it is safe."""
    agency = {'name': 'atlas-corona-admins', 'pk': 'g-a', 'users_obj': []}
    ctx, fake, _ = switch_box(tmp_path, monkeypatch, authentik, [SUPER, agency],
                              instance=CORONA)
    fake.apps = {'atlas-corona': {'pk': 'app-pk'}}
    fake.policies[0]['name'] = atlas_access.POLICY_PREFIX + 'atlas-corona'
    (tmp_path / '.env').write_text(
        'TAKMDM_ADMIN_GROUP=atlas-corona-admins,authentik Admins\n', encoding='utf-8')
    fake.policies[0]['expression'] = atlas_access.build_expression(
        ['authentik Admins', 'atlas-corona-admins'])

    _, err = atlas.set_authentik_admins(ctx, CORONA, False)

    assert err and 'nobody is locked out' in err


# --------------------------------------------------------------------------- #
# The page and the route
# --------------------------------------------------------------------------- #


def test_the_row_says_what_the_switch_is():
    html = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    assert 'authentik_admins_on' in html
    assert '/authentik-admins' in html


def test_the_route_is_registered_for_post_only():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    assert "instances/<slug>/authentik-admins', 'methods': ['POST']" in src


# --------------------------------------------------------------------------- #
# The other writers of the same policy read what is in force
# --------------------------------------------------------------------------- #


def test_the_boot_converge_does_not_put_the_global_group_back(authentik):
    """A console restart must keep an off switch off (it reads the stored answer)."""
    fake = authentik(FakeAuthentik(
        groups=[SUPER, OURS], apps={'atlas': {'pk': 'app-pk'}},
        policies=[policy('atlas', ['ATLAS-Admins'])], bindings=[bound()]))
    s = settings_for([PLAIN_OFF])
    s[atlas_access.state_key('atlas_')] = {'global_in': False}
    ctx = make_ctx(s)

    out = atlas.converge_access(ctx, 'http://ak', {}, lambda m: None)

    assert out == {'atlas': 'present'}
    assert atlas_access.parse_groups(fake.policies[0]['expression']) == ['ATLAS-Admins']


def test_the_boot_converge_keeps_the_global_group_when_the_guard_never_confirmed_off(authentik):
    fake = authentik(FakeAuthentik(
        groups=[SUPER, OURS], apps={'atlas': {'pk': 'app-pk'}},
        policies=[policy('atlas', ['ATLAS-Admins'])], bindings=[bound()]))
    ctx = make_ctx(settings_for([PLAIN_OFF]))      # a wish, no guard answer

    atlas.converge_access(ctx, 'http://ak', {}, lambda m: None)

    assert atlas_access.parse_groups(fake.policies[0]['expression']) == \
        ['authentik Admins', 'ATLAS-Admins']


def test_the_agency_group_writer_honours_an_off_switch(authentik):
    fake = authentik(FakeAuthentik(
        groups=[SUPER, {'name': 'atlas-corona-admins', 'pk': 'g-a'}],
        apps={'atlas-corona': {'pk': 'app-pk'}},
        policies=[policy('atlas-corona', ['atlas-corona-admins'])],
        bindings=[bound(policy_pk='p-atlas', name=atlas_access.POLICY_PREFIX + 'atlas-corona')]))
    s = settings_for([CORONA_OFF])
    s[atlas_access.state_key('atlas_corona_')] = {'global_in': False}
    ctx = make_ctx(s)

    out = atlas.agency_admin_group_outcome(ctx, CORONA_OFF, 'http://ak', {})

    assert out['status'] in ('present', 'created')
    assert atlas_access.parse_groups(fake.policies[0]['expression']) == ['atlas-corona-admins']
