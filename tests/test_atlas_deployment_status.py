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
"""What the console reports about each deployment, and how it updates them (W216 chunk 8).

⚠️ **Everything the console said about ATLAS answered about `takmdm-api-1`.**
With an agency deployed and no plain ATLAS the tile reported ATLAS down while
its console was serving, the logs card was empty, the version read as the plain
checkout's, and the one *"Update ATLAS"* button rebuilt a directory that does
not exist. Same half-threading as chunk 7, in the half it did not reach.
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai
from atlas_layout import deployment_dir  # noqa: E402


class Probe:
    def __init__(self, stdout=''):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = 0


@pytest.fixture(autouse=True)
def clean_slots():
    """⚠️ `_update_slots` is module state and outlives a test. A leaked
    `running: True` would make the next test's update refuse itself, and the
    failure would point at the route rather than at the leak."""
    atlas._update_slots.clear()
    atlas._update_all_status.update({'running': False, 'complete': False,
                                     'error': False, 'log': [], 'results': []})
    yield
    atlas._update_slots.clear()


def box(monkeypatch, tmp_path, instances, checkouts=(), projects=(),
        running=()):
    """A console holding `instances`, with those checkouts and containers.

    `running` names the compose projects whose API container answers "true".
    """
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, 'compose_projects_present',
                        lambda ctx=None: set(projects))
    for name, version in checkouts:
        d = deployment_dir(name)
        d.mkdir(parents=True, exist_ok=True)
        (d / 'VERSION').write_text(version, encoding='utf-8')

    def probe_run(argv, **kwargs):
        container = argv[-1]
        alive = any(container == '%s-api-1' % p for p in running)
        return Probe('true' if alive else 'false')

    settings = {'atlas_enabled': True, ai.INSTANCES_KEY: list(instances)}
    return {'load_settings': lambda: dict(settings),
            'probe_run': probe_run}


# --------------------------------------------------------------------------- #
# The container a question is asked of
# --------------------------------------------------------------------------- #


def test_the_plain_deployment_keeps_the_container_name_on_every_box():
    """`takmdm-api-1` is what `docker ps` shows on every deployed box; asking
    for another name would make the tile report ATLAS down everywhere."""
    assert atlas.api_container(None, None) == 'takmdm-api-1'
    assert atlas.API_CONTAINER == 'takmdm-api-1'


def test_an_agency_has_its_own_container(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))

    assert atlas.api_container(None, {'slug': 'corona'}) == \
        'takmdm-corona-api-1'


def test_no_two_deployments_share_a_container(monkeypatch, tmp_path):
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    names = [atlas.api_container(None, i) for i in
             (None, {'slug': 'corona'}, {'slug': 'redlands'})]

    assert len(set(names)) == 3


# --------------------------------------------------------------------------- #
# The running version
# --------------------------------------------------------------------------- #


def test_the_running_version_is_asked_of_this_deployment_s_port(monkeypatch,
                                                                tmp_path):
    """⚠️ `APP_PORT` is the plain deployment's, so with two deployments the
    second reported the first's version — and an update that rebuilt nothing
    would have looked like it worked."""
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    asked = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        @staticmethod
        def read():
            return b'{"service": "atlas-mdm", "version": "1.48.0"}'

    def fake_urlopen(url, timeout=None):
        asked['url'] = url
        return Response()

    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', fake_urlopen)

    version = atlas._running_version(
        None, ai.make('corona', ai.MODE_DYNAMIC, 50, 8763))

    assert version == '1.48.0'
    assert '127.0.0.1:8763' in asked['url']


def test_the_plain_deployment_is_still_asked_on_its_own_port(monkeypatch):
    asked = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        @staticmethod
        def read():
            return b'{"service": "atlas-mdm", "version": "1.47.3"}'

    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen',
                        lambda url, timeout=None: (asked.update(url=url),
                                                   Response())[1])

    assert atlas._running_version() == '1.47.3'
    assert '127.0.0.1:%d' % atlas.APP_PORT in asked['url']


# --------------------------------------------------------------------------- #
# One deployment's status
# --------------------------------------------------------------------------- #


def test_a_running_deployment_reports_running(monkeypatch, tmp_path):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = box(monkeypatch, tmp_path, [inst],
              checkouts=[('atlas-corona', '1.48.0')],
              projects=['takmdm-corona'], running=['takmdm-corona'])
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: '1.48.0')

    st = atlas.instance_status(ctx, inst, probe_version=True)

    assert st['built'] is True
    assert st['running'] is True
    assert st['version'] == '1.48.0'
    assert st['running_version'] == '1.48.0'


def test_the_version_probe_is_asked_for_not_assumed(monkeypatch, tmp_path):
    """⚠️ **A performance contract, not a preference.** Asking the container
    its version is an HTTP round-trip with a five-second timeout, and `detect`
    runs on every dashboard poll from several threads. Three deployments made
    the tile take six seconds before this was opt-in — measured, not guessed."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = box(monkeypatch, tmp_path, [inst],
              checkouts=[('atlas-corona', '1.48.0')],
              projects=['takmdm-corona'], running=['takmdm-corona'])
    asked = []
    monkeypatch.setattr(atlas, '_running_version',
                        lambda c=None, i=None: asked.append(1) or '1.48.0')

    assert atlas.instance_status(ctx, inst)['running_version'] is None
    assert asked == []


def test_a_stopped_deployment_is_built_but_not_running(monkeypatch, tmp_path):
    """⚠️ Stopped is not unfinished. `docker ps -a` still lists its containers,
    so it is deployed and what it needs is *start*, not *deploy*."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = box(monkeypatch, tmp_path, [inst],
              checkouts=[('atlas-corona', '1.48.0')],
              projects=['takmdm-corona'], running=[])

    st = atlas.instance_status(ctx, inst)

    assert st['built'] is True
    assert st['running'] is False
    assert st['running_version'] is None


def test_an_unfinished_deployment_is_neither(monkeypatch, tmp_path):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = box(monkeypatch, tmp_path, [inst],
              checkouts=[('atlas-corona', '1.48.0')], projects=[])

    st = atlas.instance_status(ctx, inst)

    assert st['built'] is False
    assert st['running'] is False


def test_an_unfinished_deployment_is_never_probed(monkeypatch, tmp_path):
    """⚠️ A `docker inspect` per unfinished deployment on every dashboard poll,
    for a container that cannot exist. `detect` must answer in under a second
    from several threads."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = box(monkeypatch, tmp_path, [inst],
              checkouts=[('atlas-corona', '1.48.0')], projects=[])
    probes = []
    ctx['probe_run'] = lambda argv, **k: probes.append(argv) or Probe('false')

    atlas.instance_status(ctx, inst)

    assert probes == []


# --------------------------------------------------------------------------- #
# The tile
# --------------------------------------------------------------------------- #


def _detect(monkeypatch, ctx):
    monkeypatch.setattr(atlas, 'access_state', lambda c, s=None: True)
    monkeypatch.setattr(atlas, 'unrestricted_deployments', lambda c, s=None: [])
    monkeypatch.setattr(atlas, '_installed_version', lambda c, i=None: '1.48.0')
    return atlas.detect(ctx)


def test_an_agency_only_box_reports_atlas_running(monkeypatch, tmp_path):
    """⚠️ **The visible bug.** The tile probed `takmdm-api-1`, which does not
    exist on a box whose only deployment is an agency — so a serving console
    reported itself down."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = box(monkeypatch, tmp_path, [inst],
              checkouts=[('atlas-corona', '1.48.0')],
              projects=['takmdm-corona'], running=['takmdm-corona'])

    assert _detect(monkeypatch, ctx)['running'] is True


def test_one_stopped_deployment_stops_the_box_reading_as_up(monkeypatch,
                                                            tmp_path):
    """⚠️ Reporting "running" while an agency is down would hide the outage from
    the only page that shows it."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.48.0')],
              projects=['takmdm', 'takmdm-corona'], running=['takmdm'])

    assert _detect(monkeypatch, ctx)['running'] is False


def test_an_unfinished_deployment_does_not_hold_the_tile_down(monkeypatch,
                                                              tmp_path):
    """⚠️ An unfinished deployment has no containers by definition, so counting
    it as down would pin the tile to "not running" until the operator finished
    or forgot it — a different message, which the page already shows."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.48.0')],
              projects=['takmdm'], running=['takmdm'])

    assert _detect(monkeypatch, ctx)['running'] is True


def test_a_box_with_nothing_built_is_not_running(monkeypatch, tmp_path):
    """`all()` over an empty list is True, which would have reported a box with
    one unfinished deployment as running."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas-corona', '1.48.0')], projects=[])

    assert _detect(monkeypatch, ctx)['running'] is False


# --------------------------------------------------------------------------- #
# Update slots
# --------------------------------------------------------------------------- #


def test_each_deployment_gets_its_own_update_slot():
    """⚠️ A module-global slot meant updating an agency wrote into the plain
    deployment's log, and the second of two updates was refused as "already
    running" against the first."""
    plain = atlas._update_slot(None)
    corona = atlas._update_slot({'slug': 'corona'})

    plain['running'] = True

    assert corona['running'] is False
    assert plain is not corona


def test_the_same_deployment_gets_the_same_slot():
    """Otherwise the status route would poll a slot the job never writes to, and
    the log would stay empty through a whole update."""
    first = atlas._update_slot({'slug': 'corona'})
    first['log'] = ['a line']

    assert atlas._update_slot({'slug': 'corona'})['log'] == ['a line']


def test_the_slot_is_keyed_by_the_job_key_derive_owns():
    atlas._update_slot({'slug': 'corona'})

    assert 'atlas-corona' in atlas._update_slots


# --------------------------------------------------------------------------- #
# Updating every deployment
# --------------------------------------------------------------------------- #


def _fake_updates(monkeypatch, outcomes):
    """Replace `_run_update` with one that reports `outcomes[slug]`."""
    ran = []

    def fake(ctx, inst=None):
        slug = (inst or {}).get('slug')
        ran.append(slug)
        ok = outcomes.get(slug, True)
        slot = atlas._update_slot(inst)
        slot['log'] = ['%s: %s' % (slug, 'ok' if ok else 'boom')]
        slot.update({'running': False, 'complete': bool(ok), 'error': not ok})

    monkeypatch.setattr(atlas, '_run_update', fake)
    return ran


def test_update_all_visits_every_finished_deployment(monkeypatch, tmp_path):
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.48.0')],
              projects=['takmdm', 'takmdm-corona'])
    ran = _fake_updates(monkeypatch, {})

    atlas._run_update_all(ctx)

    assert ran == [None, 'corona']
    assert atlas._update_all_status['error'] is False


def test_update_all_continues_past_a_failure(monkeypatch, tmp_path):
    """⚠️ **The whole reason this is not a loop with a success flag.** Stopping
    at the first failure leaves the remaining agencies on an old release for a
    reason that has nothing to do with them."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
               ai.make('redlands', ai.MODE_DYNAMIC, 50, 8762)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.48.0'),
                         ('atlas-redlands', '1.48.0')],
              projects=['takmdm', 'takmdm-corona', 'takmdm-redlands'])
    ran = _fake_updates(monkeypatch, {'corona': False})

    atlas._run_update_all(ctx)

    assert ran == [None, 'corona', 'redlands']


def test_update_all_says_which_deployment_failed(monkeypatch, tmp_path):
    """⚠️ A single success flag would report a run where one of three failed
    with no way to tell which — or as a success, because the last one worked."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.48.0')],
              projects=['takmdm', 'takmdm-corona'])
    _fake_updates(monkeypatch, {'corona': False})

    atlas._run_update_all(ctx)

    results = {r['slug']: r['ok'] for r in atlas._update_all_status['results']}

    assert results == {None: True, 'corona': False}
    assert any('atlas-corona' in line
               for line in atlas._update_all_status['log'])


def test_a_partial_failure_is_a_finished_run_that_failed(monkeypatch, tmp_path):
    """⚠️ `complete` says the run ended; `error` says something in it failed.
    Conflating them would leave the page polling a run that had finished."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas-corona', '1.48.0')],
              projects=['takmdm-corona'])
    _fake_updates(monkeypatch, {'corona': False})

    atlas._run_update_all(ctx)

    assert atlas._update_all_status['complete'] is True
    assert atlas._update_all_status['error'] is True
    assert atlas._update_all_status['running'] is False


def test_update_all_skips_an_unfinished_deployment(monkeypatch, tmp_path):
    """⚠️ It has no checkout to update and no containers to rebuild. `update`
    would fail on the missing directory and report that as an update failure,
    when what it needs is a deploy."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0')], projects=['takmdm'])
    ran = _fake_updates(monkeypatch, {})

    atlas._run_update_all(ctx)

    assert ran == [None]
    skipped = [r for r in atlas._update_all_status['results']
               if r['slug'] == 'corona']
    assert skipped and skipped[0]['ok'] is None
    assert 'not finished' in skipped[0]['detail']


def test_a_skipped_deployment_is_not_a_failure(monkeypatch, tmp_path):
    """Otherwise a box with one unfinished deployment could never report a
    successful update-all, and the operator would learn to ignore the result."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0')], projects=['takmdm'])
    _fake_updates(monkeypatch, {})

    atlas._run_update_all(ctx)

    assert atlas._update_all_status['error'] is False


# --------------------------------------------------------------------------- #
# Drift
# --------------------------------------------------------------------------- #


def test_an_unfinished_deployment_is_not_drift(monkeypatch, tmp_path):
    """⚠️ Its checkout carries a VERSION the moment the clone succeeds, so a
    failed deploy of a newer release reported the box as drifted — true, and not
    something anybody can act on. The page already labels it unfinished."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.47.3'), ('atlas-corona', '1.48.0')],
              projects=['takmdm'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')

    drift = atlas.version_drift(ctx)

    assert drift['drifted'] is False
    assert drift['versions'] == ['1.47.3']


def test_two_finished_deployments_on_different_releases_are_drift(monkeypatch,
                                                                  tmp_path):
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.47.3'), ('atlas-corona', '1.48.0')],
              projects=['takmdm', 'takmdm-corona'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')

    assert atlas.version_drift(ctx)['drifted'] is True


def test_the_tile_never_asks_a_container_its_version(monkeypatch, tmp_path):
    """⚠️ The same contract, at the call site that matters. `detect` must answer
    in under a second; an HTTP round-trip per deployment would make ATLAS's tile
    report its own containers' latency, and a slow container would read as ATLAS
    being down."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.48.0')],
              projects=['takmdm', 'takmdm-corona'],
              running=['takmdm', 'takmdm-corona'])
    asked = []
    monkeypatch.setattr(atlas, '_running_version',
                        lambda c=None, i=None: asked.append(1) or '1.48.0')

    _detect(monkeypatch, ctx)

    assert asked == []


def test_the_drift_table_does_ask(monkeypatch, tmp_path):
    """It is served by a route an operator opened deliberately, and the running
    version is the only thing that answers "did the update take"."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas-corona', '1.48.0')],
              projects=['takmdm-corona'], running=['takmdm-corona'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: '1.47.3')

    rows = atlas.version_drift(ctx)['instances']

    assert rows[0]['running_version'] == '1.47.3'


def test_a_stopped_deployment_is_never_asked_its_version(monkeypatch, tmp_path):
    """⚠️ Nothing is listening on its port. The probe would spend its five-second
    timeout per stopped deployment and then report None anyway — and on a box
    where another service had taken that port, it would report *that* service's
    version as ATLAS's."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = box(monkeypatch, tmp_path, [inst],
              checkouts=[('atlas-corona', '1.48.0')],
              projects=['takmdm-corona'], running=[])
    asked = []
    monkeypatch.setattr(atlas, '_running_version',
                        lambda c=None, i=None: asked.append(1) or '9.9.9')

    st = atlas.instance_status(ctx, inst, probe_version=True)

    assert st['running_version'] is None
    assert asked == []


# --------------------------------------------------------------------------- #
# The dashboard badge
# --------------------------------------------------------------------------- #


def test_the_badge_answers_for_the_deployment_furthest_behind(monkeypatch,
                                                              tmp_path):
    """⚠️ **The only place an operator passively learns an update exists.** On a
    box with several agencies the question is answered by whichever is oldest;
    reporting the newest would hide the one that needs doing."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.47.3')],
              projects=['takmdm', 'takmdm-corona'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: None)

    info = atlas.get_version_info(ctx)

    assert info['version'] == '1.47.3'
    assert info['update_available'] is True


def test_a_single_deployment_reports_exactly_what_it_did_before(monkeypatch,
                                                                tmp_path):
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760)],
              checkouts=[('atlas', '1.48.0')], projects=['takmdm'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: None)

    info = atlas.get_version_info(ctx)

    assert info['version'] == '1.48.0'
    assert info['update_available'] is False


def test_an_agency_only_box_reports_the_agency_s_version(monkeypatch, tmp_path):
    """⚠️ It read the plain checkout, which does not exist — so the card showed
    no version and no badge on a box that was a release behind."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas-corona', '1.47.3')],
              projects=['takmdm-corona'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: None)

    assert atlas.get_version_info(ctx)['version'] == '1.47.3'


def test_an_unreadable_version_is_treated_as_the_oldest(monkeypatch, tmp_path):
    """⚠️ `VERSION` arrived in 1.0.0, so a deployment without one predates every
    release we can see — and is precisely the one that most needs telling.
    Sorting it as newest would leave the oldest boxes the quietest."""
    (tmp_path / 'atlas' / 'corona').mkdir(parents=True, exist_ok=True)
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0')],
              projects=['takmdm', 'takmdm-corona'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: None)

    info = atlas.get_version_info(ctx)

    assert info['version'] == ''
    assert info['update_available'] is True


def test_the_badge_asks_one_container_not_every_one(monkeypatch, tmp_path):
    """⚠️ The HTTP probe costs a five-second timeout. Three deployments would
    make the dashboard's versions card wait fifteen; versions come from the
    checkouts and only the reported deployment is asked."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
               ai.make('redlands', ai.MODE_DYNAMIC, 50, 8762)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.47.3'),
                         ('atlas-redlands', '1.48.0')],
              projects=['takmdm', 'takmdm-corona', 'takmdm-redlands'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    asked = []
    monkeypatch.setattr(atlas, '_running_version',
                        lambda c=None, i=None: asked.append(
                            (i or {}).get('slug')) or None)

    atlas.get_version_info(ctx)

    assert asked == ['corona']


def test_an_unfinished_deployment_does_not_drag_the_badge_back(monkeypatch,
                                                              tmp_path):
    """⚠️ Its checkout carries whatever tag the clone fetched, so a failed
    deploy of an *older* pin would report the box as behind — and "Update all"
    would skip it, leaving a badge nothing can clear."""
    ctx = box(monkeypatch, tmp_path,
              [ai.make(None, ai.MODE_FIXED, 100, 8760),
               ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)],
              checkouts=[('atlas', '1.48.0'), ('atlas-corona', '1.47.3')],
              projects=['takmdm'])
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=True, channel=None: '1.48.0')
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: None)

    info = atlas.get_version_info(ctx)

    assert info['version'] == '1.48.0'
    assert info['update_available'] is False


def test_an_update_records_the_commit_it_moved_to(monkeypatch, tmp_path):
    """⚠️ **A provenance record that lies is worth less than none**, because it
    will be believed. `commit_sha` was written only at deploy, so after an
    update the settings said 1.50.0 beside the commit of v1.49.0 — found on
    the box during a structural scan. Nothing reads it today; that is exactly
    why it could drift unnoticed. The sibling `tvr` module already refreshes
    its own at this point.
    """
    import inspect

    source = inspect.getsource(atlas._run_update)
    record = source.index('Step 3/3: Recording')

    assert 'commit_sha' in source[record:], (
        'the update records a version without the commit it came from')
    assert '_module_head(' in source[record:]
