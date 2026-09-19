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
"""The instance list and the capacity it is judged against (W216, chunk 4).

⚠️ **The migration is the important part.** Every ATLAS installation that exists
today predates `atlas_instances`, so there is no record of it anywhere — only
`atlas_enabled` and a store on disk. A console that read `[]` there would tell
the operator nothing is installed, offer a *plain* deployment that is already
running, and let a second one be built on top of the first.

The rest is arithmetic for the deploy screen, which has one job beyond adding up:
**naming which constraint bites first.** On the box measured, disk allowed four
or five more instances and memory about twelve, and an operator shown only the
larger figure would plan for twice what fits.
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402
from atlas_layout import deployment_dir  # noqa: E402

GIB = ai.GIB


class _Probe:
    """What `probe_run` hands back: stdout and nothing else."""

    def __init__(self, stdout=''):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = 0


class Ctx(dict):
    """Just enough console to hold settings."""

    def __init__(self, settings=None):
        super().__init__()
        self.settings = dict(settings or {})
        self['load_settings'] = lambda: dict(self.settings)
        self['save_settings'] = self._save
        # ⚠️ Present and answering "not running". Left out, the liveness probe
        # raised KeyError inside a bare `except Exception` and *looked* like a
        # stopped container — so a test could pass for the wrong reason.
        self['probe_run'] = lambda argv, **k: _Probe('false')

    def _save(self, s):
        self.settings = dict(s)


# --------------------------------------------------------------------------- #
# The list, and the deployment that predates it
# --------------------------------------------------------------------------- #


def test_a_box_with_nothing_installed_has_no_instances():
    assert atlas.load_instances(Ctx()) == []


def test_a_deployment_made_before_the_list_still_appears(monkeypatch, tmp_path):
    """⚠️ **The migration.** Without this an upgraded console would report an
    installed ATLAS as absent — and then offer to deploy a second plain one over
    the top of it."""
    image = tmp_path / 'store.img'
    image.write_bytes(bytes(1024))
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(image))

    found = atlas.load_instances(Ctx({'atlas_enabled': True}))

    assert len(found) == 1
    assert found[0]['slug'] is None
    assert found[0]['mode'] == ai.MODE_FIXED


def test_the_migrated_instance_blocks_a_second_plain_deployment(monkeypatch, tmp_path):
    """The consequence that matters: the rule from chunk 1 has to see it."""
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'absent.img'))

    found = atlas.load_instances(Ctx({'atlas_enabled': True}))

    assert ai.may_deploy_plain(found) is False


def test_the_migrated_instance_is_sized_from_the_store_on_disk(monkeypatch, tmp_path):
    """⚠️ Byte-scale, because `truncate` allocates for real on NTFS — the
    145 GB lesson. The path matters, not the magnitude."""
    image = tmp_path / 'store.img'
    image.write_bytes(bytes(3 * 1024))
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(image))

    found = atlas.load_instances(Ctx({'atlas_enabled': True}))

    assert found[0]['size_gb'] == 0  # 3 KB rounds to nothing; it was read


def test_the_migration_is_not_written_back(monkeypatch, tmp_path):
    """⚠️ Derived on every read, so it stays true if the store is resized, and
    nothing is persisted about a deployment the operator has not touched."""
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'absent.img'))
    ctx = Ctx({'atlas_enabled': True})

    atlas.load_instances(ctx)

    assert ai.INSTANCES_KEY not in ctx.settings


def test_an_explicit_list_wins_over_the_migration(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'absent.img'))
    recorded = [ai.make('agencya', ai.MODE_DYNAMIC, 50, 8761)]

    found = atlas.load_instances(
        Ctx({'atlas_enabled': True, ai.INSTANCES_KEY: recorded}))

    assert [i['slug'] for i in found] == ['agencya']


def test_saving_replaces_rather_than_merges():
    """⚠️ Removing an instance has to be expressible, and a merge cannot say
    'this one is gone'."""
    ctx = Ctx()
    atlas.save_instances(ctx, [ai.make('a', ai.MODE_FIXED, 10, 8760),
                               ai.make('b', ai.MODE_FIXED, 10, 8761)])

    atlas.save_instances(ctx, [ai.make('a', ai.MODE_FIXED, 10, 8760)])

    assert [i['slug'] for i in atlas.load_instances(ctx)] == ['a']


def test_dropping_an_instance_forgets_only_that_one():
    ctx = Ctx()
    atlas.save_instances(ctx, [ai.make(None, ai.MODE_FIXED, 10, 8760),
                               ai.make('a', ai.MODE_DYNAMIC, 10, 8761)])

    atlas.drop_instance(ctx, 'a')

    assert [i['slug'] for i in atlas.load_instances(ctx)] == [None]


# --------------------------------------------------------------------------- #
# Creating one
# --------------------------------------------------------------------------- #


@pytest.fixture
def roomy(monkeypatch, tmp_path):
    """A box with plenty of disk and nothing listening."""
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(tmp_path / 'store.img'))
    monkeypatch.setattr(atlas, '_disk_free', lambda _p: (500 * GIB, 400 * GIB))
    monkeypatch.setattr(atlas, '_run_root', lambda *a, **k: (1, ''))
    monkeypatch.setattr(atlas, '_memory_bytes', lambda: (32 * GIB, 20 * GIB))
    return None


def test_the_first_deployment_may_be_plain(roomy):
    ctx = Ctx()

    inst, err = atlas.add_instance(ctx, False, None, ai.MODE_FIXED, 50)

    assert err is None
    assert inst['slug'] is None
    assert atlas.load_instances(ctx)[0]['slug'] is None


def test_a_second_plain_deployment_is_refused_with_a_reason(roomy):
    ctx = Ctx()
    atlas.add_instance(ctx, False, None, ai.MODE_FIXED, 50)

    inst, err = atlas.add_instance(ctx, False, None, ai.MODE_FIXED, 50)

    assert inst is None
    assert 'agency-specific' in err


def test_an_agency_deployment_records_its_slug_and_mode(roomy):
    ctx = Ctx()

    inst, err = atlas.add_instance(ctx, True, 'AgencyA', ai.MODE_DYNAMIC, 50)

    assert err is None
    assert inst['slug'] == 'agencya', 'the slug was not normalised'
    assert inst['mode'] == ai.MODE_DYNAMIC


def test_a_fixed_and_a_dynamic_instance_can_coexist(roomy):
    """The operator's requirement, end to end through the registry."""
    ctx = Ctx()
    atlas.add_instance(ctx, False, None, ai.MODE_FIXED, 50)
    atlas.add_instance(ctx, True, 'agencya', ai.MODE_DYNAMIC, 50)

    modes = {i['mode'] for i in atlas.load_instances(ctx)}

    assert modes == {ai.MODE_FIXED, ai.MODE_DYNAMIC}


def test_each_instance_gets_its_own_port(roomy):
    ctx = Ctx()
    atlas.add_instance(ctx, False, None, ai.MODE_FIXED, 50)
    atlas.add_instance(ctx, True, 'agencya', ai.MODE_DYNAMIC, 50)

    ports = [i['port'] for i in atlas.load_instances(ctx)]

    assert len(set(ports)) == 2


def test_a_duplicate_slug_is_refused(roomy):
    ctx = Ctx()
    atlas.add_instance(ctx, True, 'agencya', ai.MODE_FIXED, 50)

    inst, err = atlas.add_instance(ctx, True, 'agencya', ai.MODE_FIXED, 50)

    assert inst is None and 'already' in err


def test_the_instance_is_recorded_before_anything_is_built(roomy):
    """⚠️ So the slug is claimed while the first deploy is still running. A
    half-built instance with no record is the shape of leak W212 was about."""
    ctx = Ctx()

    atlas.add_instance(ctx, True, 'agencya', ai.MODE_FIXED, 50)

    assert ai.INSTANCES_KEY in ctx.settings


def test_a_bad_mode_is_refused(roomy):
    inst, err = atlas.add_instance(Ctx(), True, 'agencya', 'elastic', 50)

    assert inst is None and 'sizing mode' in err


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #


def test_the_budget_leaves_the_floor_alone():
    budget = ai.budget_bytes(473 * GIB, 69 * GIB, 25 * GIB)

    assert round(budget / GIB) == 379


def test_only_fixed_deployments_commit_budget():
    """⚠️ **This counted both modes until the operator settled the design.**
    Their rule is that a dynamic deployment shares the available space and is
    never asked for a size, so its ceiling is not a commitment — it *is* the
    pool. Counting it would exhaust the budget the moment one existed."""
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760),
                 ai.make('a', ai.MODE_DYNAMIC, 200, 8761)]

    assert round(ai.committed_bytes(instances) / GIB) == 100


def test_the_pool_is_what_is_left_after_the_fixed_ones():
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760)]

    assert round(ai.pool_bytes(379 * GIB, instances) / GIB) == 279


def test_dynamic_ceilings_may_exceed_the_disk():
    """⚠️ Deliberate over-commitment: several dynamic deployments can each be
    capped at the whole pool, so their ceilings sum to more than the box holds.
    That is what "share the same available space" means, and the cost is a
    correlated failure if they all fill at once — which is why
    `deliverable_free` exists and why a dynamic store mounts
    `errors=remount-ro`."""
    instances = [ai.make('a', ai.MODE_DYNAMIC, 300, 8761),
                 ai.make('b', ai.MODE_DYNAMIC, 300, 8762)]

    assert ai.committed_bytes(instances) == 0
    assert round(ai.pool_bytes(300 * GIB, instances) / GIB) == 300


def test_a_pool_never_goes_negative():
    """A box over its budget has no pool, not a negative one."""
    instances = [ai.make(None, ai.MODE_FIXED, 500, 8760)]

    assert ai.pool_bytes(100 * GIB, instances) == 0


def test_a_request_past_the_budget_is_refused_with_the_spare_named():
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760)]

    ok, err = ai.fits(400, instances, 379 * GIB)

    assert ok is False
    assert '279' in err


def test_a_request_inside_the_budget_is_allowed():
    ok, err = ai.fits(50, [ai.make(None, ai.MODE_FIXED, 100, 8760)], 379 * GIB)

    assert ok is True and err is None


def test_a_sizeless_request_is_refused():
    ok, err = ai.fits(0, [], 379 * GIB)

    assert ok is False and 'size' in err


def test_the_screen_says_how_many_more_fit():
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760)]

    assert ai.instances_that_fit(50, instances, 379 * GIB) == 5


def test_memory_headroom_uses_the_measured_peak():
    """⚠️ The peak, not the steady state: N instances restarting together spike
    together, and the steady figure promises room a restart would not find."""
    allowed = ai.instances_that_ram_allows(20 * GIB, 4 * GIB)

    assert allowed == int((16 * GIB) // ai.INSTANCE_RAM_PEAK_BYTES)


def test_the_binding_constraint_is_named_not_just_computed():
    """⚠️ The whole point of the panel. Disk 4, memory 12 — an operator shown
    only 12 would plan for three times what fits."""
    assert ai.binding_constraint(4, 12) == ('disk', 4)
    assert ai.binding_constraint(30, 12) == ('memory', 12)


def test_a_tie_reports_disk_because_it_is_the_harder_one_to_add():
    assert ai.binding_constraint(5, 5)[0] == 'disk'


def test_the_facts_carry_everything_the_screen_shows(roomy):
    ctx = Ctx()
    atlas.add_instance(ctx, False, None, ai.MODE_FIXED, 100)

    facts = atlas.capacity_facts(ctx, size_gb=50)

    assert facts['instances'] == 1
    assert facts['committed_gb'] == 100.0
    assert facts['floor_gb'] == 25
    assert facts['binding'] in ('disk', 'memory')
    assert facts['may_deploy_plain'] is False
    assert facts['per_instance_peak_gb'] > 1


def test_the_facts_say_a_plain_deployment_is_still_available(roomy):
    facts = atlas.capacity_facts(Ctx(), size_gb=50)

    assert facts['may_deploy_plain'] is True


def test_memory_is_read_as_available_not_free(tmp_path):
    """⚠️ **`MemAvailable`, not `MemFree`.** On a box running eight stacks free
    memory is near zero because the page cache holds the rest — planning against
    it would refuse every instance the box could comfortably run. These are the
    real proportions from the measured box: 32 GB total, 19.7 GB free, 20.5 GB
    available."""
    meminfo = tmp_path / 'meminfo'
    meminfo.write_text(chr(10).join([
        'MemTotal:       32862208 kB',
        'MemFree:        20193280 kB',
        'MemAvailable:   21027840 kB',
        'Buffers:          102400 kB',
        '',
    ]), encoding='utf-8')

    total, available = atlas._memory_bytes(str(meminfo))

    assert total == 32862208 * 1024
    assert available == 21027840 * 1024, 'planning read MemFree, not MemAvailable'


def test_unreadable_memory_is_zero_rather_than_a_guess(tmp_path):
    """A fabricated figure here would offer instances the box cannot run."""
    assert atlas._memory_bytes(str(tmp_path / 'absent')) == (0, 0)


# --------------------------------------------------------------------------- #
# Per-instance jobs and version drift (chunk 5)
# --------------------------------------------------------------------------- #


def test_each_instance_gets_its_own_job_key():
    """⚠️ Separate slots mean separate locks, so one agency's update cannot
    block or clobber another's."""
    plain = atlas.instance_job_key(ai.make(None, ai.MODE_FIXED, 50, 8760))
    agency = atlas.instance_job_key(ai.make('agencya', ai.MODE_FIXED, 50, 8761))

    assert plain == 'atlas'
    assert agency == 'atlas-agencya'
    assert plain != agency


def test_a_job_key_is_acceptable_to_the_registry():
    """⚠️ `[a-z0-9_-]` only — `atlas:agencya` was the obvious first shape and
    the descriptor validator rejects it at import."""
    key = atlas.instance_job_key(ai.make('agencya', ai.MODE_FIXED, 50, 8761))

    assert all(c.isalnum() or c in '-_' for c in key)


#: Compose projects the fixture pretends exist. ⚠️ A checkout alone is not a
#: deployment — that is what `test_a_checkout_alone_is_not_a_deployment` pins —
#: so a fixture that only writes VERSION describes an *unfinished* deploy. Every
#: version test below means a finished one, so `_checkout` records the project
#: too, and the one test about an unfinished deployment opts out.
_BUILT = set()


def _project_for(name):
    return 'takmdm' if name == 'atlas' else 'takmdm-' + name.split('-', 1)[1]


def _checkout(base, name, version, built=True):
    d = deployment_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    (d / 'VERSION').write_text(version, encoding='utf-8')
    if built:
        _BUILT.add(_project_for(name))


@pytest.fixture
def deployed(monkeypatch, tmp_path):
    _BUILT.clear()
    monkeypatch.setattr(atlas, 'install_base', lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    monkeypatch.setattr(atlas, 'compose_projects_present',
                        lambda ctx=None: set(_BUILT))
    return tmp_path


def test_a_version_is_read_from_the_checkout_not_from_settings(deployed):
    """⚠️ Settings record what was *intended*. After a half-finished update the
    two disagree, and that is exactly when someone looks."""
    _checkout(deployed, 'atlas', '1.47.3')

    assert atlas._installed_version(Ctx(), None) == '1.47.3'


def test_each_instance_reports_its_own_version(deployed):
    _checkout(deployed, 'atlas', '1.47.3')
    _checkout(deployed, 'atlas-agencya', '1.48.0')
    ctx = Ctx({ai.INSTANCES_KEY: [
        ai.make(None, ai.MODE_FIXED, 100, 8760),
        ai.make('agencya', ai.MODE_DYNAMIC, 50, 8761),
    ]})

    drift = atlas.version_drift(ctx)

    assert {r['slug']: r['version'] for r in drift['instances']} == {
        None: '1.47.3', 'agencya': '1.48.0'}


def test_drift_is_reported_when_deployments_disagree(deployed):
    """⚠️ Expected, not a fault: updates are manual by design and will not all
    happen on the same day. Showing it makes a staged rollout deliberate rather
    than something discovered later."""
    _checkout(deployed, 'atlas', '1.47.3')
    _checkout(deployed, 'atlas-agencya', '1.48.0')
    ctx = Ctx({ai.INSTANCES_KEY: [
        ai.make(None, ai.MODE_FIXED, 100, 8760),
        ai.make('agencya', ai.MODE_DYNAMIC, 50, 8761),
    ]})

    assert atlas.version_drift(ctx)['drifted'] is True


def test_agreement_is_not_reported_as_drift(deployed):
    _checkout(deployed, 'atlas', '1.47.3')
    _checkout(deployed, 'atlas-agencya', '1.47.3')
    ctx = Ctx({ai.INSTANCES_KEY: [
        ai.make(None, ai.MODE_FIXED, 100, 8760),
        ai.make('agencya', ai.MODE_DYNAMIC, 50, 8761),
    ]})

    drift = atlas.version_drift(ctx)

    assert drift['drifted'] is False
    assert drift['versions'] == ['1.47.3']


def test_an_unreadable_checkout_is_none_rather_than_a_guess(deployed):
    """A fabricated version would make an update badge lie in both directions."""
    ctx = Ctx({ai.INSTANCES_KEY: [ai.make('gone', ai.MODE_FIXED, 50, 8761)]})

    assert atlas.version_drift(ctx)['instances'][0]['version'] is None


def test_drift_carries_what_is_available(deployed):
    _checkout(deployed, 'atlas', '1.47.3')

    assert atlas.version_drift(Ctx({'atlas_enabled': True}))['available'] == '1.48.0'


def test_the_facts_carry_the_real_hostname(roomy, monkeypatch):
    """⚠️ So the confirmation can name the box's actual domain instead of
    `<your-domain>`. The *rule* for where a slug sits stays in `agency_host`:
    the template is built here and the page only substitutes, so the two cannot
    drift into disagreeing about the shape of an agency hostname."""
    ctx = Ctx()
    ctx['_get_service_domain'] = lambda s, key: 'atlas.leckliter.net'

    facts = atlas.capacity_facts(ctx, size_gb=50)

    assert facts['plain_host'] == 'atlas.leckliter.net'
    assert facts['host_template'] == 'atlas.{slug}.leckliter.net'
    assert facts['host_template'].replace('{slug}', 'corona') ==         'atlas.corona.leckliter.net'


def test_a_box_without_a_domain_offers_no_hostname(roomy):
    """⚠️ Empty, not invented. A guessed domain in a confirmation is worse than
    an obvious placeholder, because it looks like it was checked."""
    facts = atlas.capacity_facts(Ctx(), size_gb=50)

    assert facts['plain_host'] == ''
    assert facts['host_template'] == ''


# --------------------------------------------------------------------------- #
# A dynamic deployment is not a reservation
# --------------------------------------------------------------------------- #


def test_a_dynamic_deployment_is_not_held_to_the_reservation_ceiling(monkeypatch):
    """⚠️ **The bug that stopped a real deploy.** The 85% ceiling limits how much
    disk ATLAS may *take*, and a dynamic deployment takes none — its size is a
    ceiling on a pool. Applying the reservation cap refused a deployment sized at
    the pool (354.6 GB against a 322.7 GB cap), so the deploy never started while
    the instance had already been recorded."""
    monkeypatch.setattr(atlas, '_disk_free',
                        lambda _p: (473 * GIB, int(379.6 * GIB)))

    params, err = atlas.deploy_validate(
        {'store_gb': 354.6, 'mode': 'dynamic', 'slug': 'corona'})

    assert err is None, err
    assert params['mode'] == 'dynamic'
    assert params['slug'] == 'corona'


def test_a_fixed_deployment_is_still_held_to_it(monkeypatch):
    """The other half: a reservation that big really would take the disk."""
    monkeypatch.setattr(atlas, '_disk_free',
                        lambda _p: (473 * GIB, int(379.6 * GIB)))

    params, err = atlas.deploy_validate({'store_gb': 354.6, 'mode': 'fixed'})

    assert err and '85%' in err


def test_a_dynamic_deployment_with_no_pool_left_is_refused(monkeypatch):
    monkeypatch.setattr(atlas, '_disk_free',
                        lambda _p: (473 * GIB, int(379.6 * GIB)))

    params, err = atlas.deploy_validate({'store_gb': 0, 'mode': 'dynamic'})

    assert err and 'budget' in err


def test_the_mode_is_read_before_the_size_is_judged(monkeypatch):
    """⚠️ Order matters here: the mode decides *which* question to ask of the
    size, so judging the size first asks the wrong one."""
    monkeypatch.setattr(atlas, '_disk_free',
                        lambda _p: (473 * GIB, int(379.6 * GIB)))

    params, err = atlas.deploy_validate({'store_gb': 354.6, 'mode': 'elastic'})

    assert err and 'sizing mode' in err, err


# --------------------------------------------------------------------------- #
# Recorded is not deployed
# --------------------------------------------------------------------------- #


def test_a_checkout_alone_is_not_a_deployment(monkeypatch, tmp_path):
    """⚠️ **The check that was too weak.** The first version asked only whether
    the install directory existed — true the moment the clone succeeds — so a
    deploy that cloned and then failed at `docker compose up` reported itself as
    built, and the page offered no way to finish it. That is precisely the state
    a failed deploy leaves behind, so it is the one case the check has to get
    right."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    (tmp_path / 'atlas' / 'corona').mkdir(parents=True)

    assert atlas.instance_is_built(None, inst, projects=set()) is False


def test_containers_make_it_a_deployment(monkeypatch, tmp_path):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    (tmp_path / 'atlas' / 'corona').mkdir(parents=True)

    assert atlas.instance_is_built(
        None, inst, projects={'takmdm-corona'}) is True


def test_another_deployment_s_containers_do_not_count(monkeypatch, tmp_path):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    (tmp_path / 'atlas' / 'corona').mkdir(parents=True)

    assert atlas.instance_is_built(
        None, inst, projects={'takmdm', 'takmdm-other'}) is False


def test_no_checkout_is_not_a_deployment_whatever_is_running(monkeypatch, tmp_path):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))

    assert atlas.instance_is_built(
        None, inst, projects={'takmdm-corona'}) is False


def test_the_projects_are_read_once_for_every_deployment(monkeypatch):
    """⚠️ Read on every poll of the instances route, so a subprocess per agency
    would make the page slower the more agencies a box has."""
    calls = []
    monkeypatch.setattr(atlas, '_run_root',
                        lambda argv, **k: calls.append(argv) or (0, 'takmdm'))

    atlas.compose_projects_present(None)

    assert len(calls) == 1
    assert 'docker' in calls[0][0]


def test_a_failing_docker_call_reports_no_projects(monkeypatch):
    """⚠️ **The error text is not a project name.** `_run_root` returns the
    command's output whether it succeeded or not, so a docker daemon that is
    down hands back something like
    `Cannot connect to the Docker daemon at unix:///var/run/docker.sock`.
    Parsing that as a list of compose projects would invent a project named
    after the error — and on a box whose deployment happened to be called
    `Cannot` it would claim the deployment is built while docker is not even
    running. An empty set is the honest answer: nothing is known to exist, so
    every recorded deployment shows as unfinished until docker answers again.
    """
    monkeypatch.setattr(
        atlas, '_run_root',
        lambda argv, **k: (1, 'Cannot connect to the Docker daemon'))

    assert atlas.compose_projects_present(None) == set()


def test_docker_being_down_never_claims_a_deployment_is_built(monkeypatch, tmp_path):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    (tmp_path / 'atlas' / 'corona').mkdir(parents=True)
    monkeypatch.setattr(atlas, '_run_root',
                        lambda argv, **k: (1, 'takmdm-corona: no such thing'))

    assert atlas.instance_is_built(None, inst) is False
