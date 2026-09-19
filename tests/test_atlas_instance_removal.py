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
"""Tearing one deployment down, and tearing them all down (W216 chunk 9).

⚠️ **`uninstall` only ever removed the plain deployment.** It resolved
`atlas_dir(ctx)` and `remove_store(ctx, …, inst=None)`, so on a box running one
agency and no plain ATLAS it reported success having removed nothing at all —
W212 again, multiplied by the number of agencies.

⚠️ **And the settings sweep was a prefix match.** `atlas_` is a prefix of
`atlas_corona_`, so clearing the plain deployment's keys would have taken every
agency's database password with it. Postgres only honours `POSTGRES_PASSWORD` on
an empty volume, so those databases would have become permanently unopenable by
deployments that were still running.
"""

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402
from atlas_layout import deployment_dir  # noqa: E402


# --------------------------------------------------------------------------- #
# Which settings a deployment owns
# --------------------------------------------------------------------------- #


#: Every generated key a deploy writes, by the names `deploy` actually uses.
#: ⚠️ Derived from the prefixes rather than typed out, so a new per-deployment
#: setting is covered without anyone remembering to add it here.
def _generated(prefix):
    return [prefix + tail for tail in
            ('pg_password', 'commit_sha', 'version',
             'access_restricted', 'access_checked_at')]


BOX = ['atlas_enabled', 'atlas_domain', 'atlas_instances', 'fqdn',
       'authentik_api_token']


def test_removing_the_plain_deployment_keeps_every_agency_key():
    """⚠️ **The trap.** `atlas_` is a prefix of `atlas_corona_`, so a
    `startswith` sweep would clear a running agency's database password — and
    Postgres keeps the old one on a non-empty volume, so that database can never
    be opened again."""
    keys = BOX + _generated('atlas_') + _generated('atlas_corona_')
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760),
                 ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)]

    owned = ai.owned_settings_keys(instances[0], keys, instances)

    assert owned == sorted(_generated('atlas_'))
    assert not any(k.startswith('atlas_corona_') for k in owned)


def test_removing_an_agency_keeps_the_plain_deployment_s_keys():
    keys = BOX + _generated('atlas_') + _generated('atlas_corona_')
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760),
                 ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)]

    owned = ai.owned_settings_keys(instances[1], keys, instances)

    assert owned == sorted(_generated('atlas_corona_'))


def test_no_deployment_owns_the_box_s_own_settings():
    """⚠️ **`atlas_domain` is the operator's service-domain override**, and it is
    what `agency_host` builds every agency hostname from. Taking it with one
    deployment would move every remaining agency to a different name — new
    certificates, and every enrolled tablet pointing at a host that no longer
    answers."""
    keys = BOX + _generated('atlas_')
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760)]

    owned = ai.owned_settings_keys(instances[0], keys, instances)

    for key in ('atlas_enabled', 'atlas_domain', 'atlas_instances'):
        assert key not in owned, f'{key} belongs to the box, not a deployment'


def test_a_deployment_owns_nothing_of_another_agency_s(monkeypatch):
    """⚠️ Slugs are lowercase letters only, so `atlas_pd_` and `atlas_pdx_`
    cannot overlap — the trailing underscore separates them. `validate_slug` is
    what keeps that true, and this is the consequence that depends on it."""
    keys = BOX + _generated('atlas_pd_') + _generated('atlas_pdx_')
    instances = [ai.make('pd', ai.MODE_FIXED, 50, 8760),
                 ai.make('pdx', ai.MODE_FIXED, 50, 8761)]

    assert ai.owned_settings_keys(instances[0], keys, instances) == \
        sorted(_generated('atlas_pd_'))
    assert ai.owned_settings_keys(instances[1], keys, instances) == \
        sorted(_generated('atlas_pdx_'))


def test_a_slug_cannot_produce_a_prefix_that_swallows_another():
    """The property the test above relies on, asserted against the validator
    rather than assumed: a slug that could contain an underscore would make
    `atlas_pd_x_` and `atlas_pd_` overlap."""
    _slug, err = ai.validate_slug('pd_x')

    assert err, 'an underscore in a slug would make two prefixes overlap'


def test_the_only_deployment_owns_all_of_its_generated_keys():
    keys = BOX + _generated('atlas_')

    owned = ai.owned_settings_keys(None, keys, [])

    assert owned == sorted(_generated('atlas_'))


# --------------------------------------------------------------------------- #
# The images compose actually built
# --------------------------------------------------------------------------- #


def test_the_plain_deployment_keeps_the_image_names_on_every_box():
    """These are what `docker images` shows on every deployed box."""
    assert ai.derive(None)['images'] == ['takmdm-api', 'takmdm-init']


def test_an_agency_has_its_own_images():
    """⚠️ Compose names a built image `<project>-<service>`. `takmdm-api` was
    hardcoded in `uninstall`, so an agency's two images survived every teardown
    and accumulated a release of layers each time."""
    assert ai.derive({'slug': 'corona'})['images'] == \
        ['takmdm-corona-api', 'takmdm-corona-init']


def test_no_two_deployments_share_an_image():
    names = (ai.derive(None)['images']
             + ai.derive({'slug': 'corona'})['images']
             + ai.derive({'slug': 'redlands'})['images'])

    assert len(set(names)) == len(names)


# --------------------------------------------------------------------------- #
# Removing one deployment
# --------------------------------------------------------------------------- #


class Ctx(dict):
    """Enough console to run a teardown, recording what it was asked to do.

    ⚠️ `save_settings` **replaces**; it must not merge. Written as an update
    this fake could not express a deletion, and every assertion that a key was
    cleared would hold no matter what the code did — the trap a mutation caught
    the last time this file's neighbour was written.
    """

    def __init__(self, settings, instances):
        super().__init__()
        self.settings = dict(settings)
        self.settings[ai.INSTANCES_KEY] = list(instances)
        self.caddy_generated = 0
        self.fw_removed = []
        self.authentik = []
        self.update({
            'load_settings': lambda: dict(self.settings),
            'save_settings': self._save,
            '_sudo_wrap': lambda argv: list(argv),
            '_fw_remove': lambda port, proto: self.fw_removed.append(port),
            'generate_caddyfile': self._caddy,
            '_caddy_reload': lambda *a: None,
            '_deregister_authentik_proxy_app': self._deregister,
        })

    def _save(self, s):
        self.settings = dict(s)

    def _caddy(self, _s):
        self.caddy_generated += 1

    def _deregister(self, _settings, app_slug, prov_name):
        self.authentik.append((app_slug, prov_name))


@pytest.fixture
def box(monkeypatch, tmp_path):
    """A box whose deployments exist on disk, with every root action faked."""
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, '_stale_deploy_key', lambda _d: [])
    monkeypatch.setattr(atlas, '_caddy_ca_dir', lambda inst=None: None)
    return tmp_path


@pytest.fixture
def actions(monkeypatch):
    """Everything the teardown shells out to, recorded rather than run."""
    seen = {'compose': [], 'images': [], 'store': [], 'rmtree': []}

    class Result:
        returncode = 0
        stdout = ''
        stderr = ''

    def compose(ctx, action, timeout=180, inst=None):
        seen['compose'].append((action, (inst or {}).get('slug')))
        return Result()

    def run(ctx, argv):
        if 'image' in argv:
            # ⚠️ Only the image names, not the flags — `-f` sits between.
            seen['images'].extend(a for a in argv if a.startswith('takmdm'))
        return True

    def remove_store(ctx, plog, inst=None):
        seen['store'].append((inst or {}).get('slug'))
        # ⚠️ Logs its own progress, exactly as the real one does. A fake that
        # ignored `plog` could not express the duplicate-logging bug at all, so
        # the test for it passed with the guard removed.
        plog('store removed')
        return ['store removed'], []

    monkeypatch.setattr(atlas, '_compose', compose)
    monkeypatch.setattr(atlas, '_run', run)
    monkeypatch.setattr(atlas, 'remove_store', remove_store)
    real_rmtree = atlas.shutil.rmtree

    def rmtree(path, *a, **k):
        seen['rmtree'].append(str(path))
        return real_rmtree(path, *a, **k)

    monkeypatch.setattr(atlas.shutil, 'rmtree', rmtree)
    return seen


def _make_box(tmp_path, instances, extra=None):
    for inst in instances:
        d = deployment_dir(ai.derive(inst)['name'])
        d.mkdir(parents=True, exist_ok=True)
        (d / 'VERSION').write_text('1.48.0', encoding='utf-8')
    settings = {'atlas_enabled': True, 'atlas_domain': 'atlas.example.com'}
    for inst in instances:
        prefix = ai.derive(inst)['settings_prefix']
        for key in _generated(prefix):
            settings[key] = 'secret'
    settings.update(extra or {})
    return Ctx(settings, instances)


def test_it_stops_that_deployment_s_containers(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert actions['compose'] == [('down -v --remove-orphans', 'corona')]


def test_it_removes_that_deployment_s_images(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert actions['images'] == ['takmdm-corona-api', 'takmdm-corona-init']


def test_it_takes_the_store_down_before_deleting_the_directory(box, actions):
    """⚠️ **The W212 ordering, per deployment.** Three mount points live inside
    the install directory and `shutil.rmtree` cannot delete through a mount — so
    a teardown in the other order leaves the device CA, the Postgres data
    directory and `.env` on disk while reporting success."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])
    order = []
    real_store = atlas.remove_store

    def watched(c, plog, i=None):
        order.append('store')
        return real_store(c, plog, i)

    def watched_rmtree(path, *a, **k):
        order.append('rmtree')
        return None

    import unittest.mock as mock
    with mock.patch.object(atlas, 'remove_store', watched), \
            mock.patch.object(atlas.shutil, 'rmtree', watched_rmtree):
        atlas.remove_instance(ctx, inst)

    assert order and order[0] == 'store', order


def test_it_deletes_that_deployment_s_install_directory(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    other = ai.make(None, ai.MODE_FIXED, 100, 8760)
    ctx = _make_box(box, [other, inst])

    atlas.remove_instance(ctx, inst)

    assert not (box / 'atlas' / 'corona').exists()
    assert (box / 'atlas').exists(), \
        "removing an agency deleted the plain deployment's directory"


def test_it_removes_that_deployment_s_caddy_trust_pool(box, actions,
                                                        monkeypatch):
    """⚠️ Hardcoded to `atlas`, tearing down an agency deleted the *plain*
    deployment's trust pool — and Caddy then refuses to start, taking every
    vhost on the box with it, not only ATLAS's."""
    asked = []
    monkeypatch.setattr(atlas, '_caddy_ca_dir',
                        lambda inst=None: asked.append(
                            ai.derive(inst)['name']) or None)
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert asked == ['atlas-corona']


def test_it_deregisters_that_deployment_s_authentik_application(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert ctx.authentik == [('atlas-corona', 'ATLAS MDM Proxy (corona)')]


def test_it_clears_only_that_deployment_s_settings(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    plain = ai.make(None, ai.MODE_FIXED, 100, 8760)
    ctx = _make_box(box, [plain, inst])

    atlas.remove_instance(ctx, inst)

    assert 'atlas_corona_pg_password' not in ctx.settings
    assert ctx.settings['atlas_pg_password'] == 'secret'
    assert ctx.settings['atlas_domain'] == 'atlas.example.com'


def test_it_drops_that_deployment_from_the_list(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    plain = ai.make(None, ai.MODE_FIXED, 100, 8760)
    ctx = _make_box(box, [plain, inst])

    atlas.remove_instance(ctx, inst)

    assert [i.get('slug') for i in atlas.load_instances(ctx)] == [None]


def test_it_leaves_the_shared_device_port_alone(box, actions):
    """⚠️ Caddy selects the device site by SNI, so every deployment shares 8449.
    Removing the rule with the first agency would take the device listener away
    from every remaining one — and tablets would stop checking in for agencies
    nobody touched."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [ai.make(None, ai.MODE_FIXED, 100, 8760), inst])

    atlas.remove_instance(ctx, inst)

    assert ctx.fw_removed == []


def test_it_leaves_the_module_marked_installed(box, actions):
    """⚠️ `atlas_enabled` means "the module is installed on this box". Clearing
    it with one deployment would make the remaining ones invisible: `detect`
    reports absent, `caddy_sites` emits nothing, and the console offers to
    install what is already running."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [ai.make(None, ai.MODE_FIXED, 100, 8760), inst])

    atlas.remove_instance(ctx, inst)

    assert ctx.settings.get('atlas_enabled') is True


def test_it_re_emits_the_caddyfile(box, actions):
    """Otherwise Caddy keeps asking a certificate authority for a host with no
    upstream, and the removed deployment's vhost answers 502 forever."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert ctx.caddy_generated >= 1


# --------------------------------------------------------------------------- #
# A teardown that failed
# --------------------------------------------------------------------------- #


@pytest.fixture
def busy_store(monkeypatch):
    monkeypatch.setattr(atlas, 'remove_store',
                        lambda c, plog, i=None: ([], ['could not unmount']))


def test_a_busy_store_stops_before_the_directory_is_deleted(box, actions,
                                                            busy_store):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    steps, errs = atlas.remove_instance(ctx, inst)

    assert errs and 'store could not be removed' in errs[0]
    assert (box / 'atlas' / 'corona').exists()


def test_a_failed_teardown_keeps_the_database_password(box, actions,
                                                       monkeypatch):
    """⚠️ Clearing `atlas_corona_pg_password` while that database is still on
    disk arms the next deploy to fail forever: it generates a fresh password,
    Postgres keeps the old one because the data directory is not empty, and the
    API sits on "password authentication failed" with no way back."""
    monkeypatch.setattr(
        atlas.shutil, 'rmtree',
        lambda p, *a, **k: (_ for _ in ()).throw(
            OSError(16, 'Device or resource busy')))
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    steps, errs = atlas.remove_instance(ctx, inst)

    assert errs
    assert ctx.settings['atlas_corona_pg_password'] == 'secret'


def test_a_failed_teardown_keeps_the_record(box, actions, monkeypatch):
    """⚠️ Dropping it would leave the store, the CA and the database on the box
    with nothing left that knows about them — and the slug free for a second
    deployment to land on top."""
    monkeypatch.setattr(
        atlas.shutil, 'rmtree',
        lambda p, *a, **k: (_ for _ in ()).throw(
            OSError(16, 'Device or resource busy')))
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert [i.get('slug') for i in atlas.load_instances(ctx)] == ['corona']


def test_a_failed_teardown_leaves_authentik_alone(box, actions, monkeypatch):
    """A deployment still serving needs its sign-in to keep working; removing
    the application would answer 401 to every administrator while the console
    itself is still up."""
    monkeypatch.setattr(
        atlas.shutil, 'rmtree',
        lambda p, *a, **k: (_ for _ in ()).throw(
            OSError(16, 'Device or resource busy')))
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert ctx.authentik == []


# --------------------------------------------------------------------------- #
# Uninstalling the module
# --------------------------------------------------------------------------- #


def test_uninstall_removes_every_deployment(box, actions):
    """⚠️ **The bug.** It resolved `atlas_dir(ctx)` and `remove_store(inst=None)`
    and stopped there, so a box with two agencies kept both — reported as a
    clean uninstall."""
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760),
                 ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
                 ai.make('redlands', ai.MODE_DYNAMIC, 50, 8762)]
    ctx = _make_box(box, instances)

    result = atlas.uninstall(ctx, None, {})

    assert result['success'] is True
    assert sorted(actions['store'], key=str) == [None, 'corona', 'redlands']
    for name in ('atlas', 'atlas-corona', 'atlas-redlands'):
        assert not deployment_dir(name).exists(),             f'{name} survived the uninstall'


def test_uninstall_leaves_no_empty_root_behind(box, actions):
    """⚠️ Nesting created `<base>/atlas` (W233), so nesting has to clean it
    up. An operator who uninstalls expects the box as it was, and the previous
    layout left nothing at all -- every deployment *was* a top-level
    directory, so removing them removed everything."""
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760),
                 ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)]
    ctx = _make_box(box, instances)

    assert atlas.uninstall(ctx, None, {})['success'] is True

    assert not (box / 'atlas').exists()


def test_a_root_holding_something_else_is_left_alone(box, actions):
    """⚠️ It ends in a delete, so it removes the root only when the root is
    *empty*. A stranded deployment the console could not reach, or anything an
    operator put there, stays -- and `rmdir` rather than a recursive remove is
    what makes that true by construction rather than by a check that could be
    wrong."""
    ctx = _make_box(box, [ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)])
    (box / 'atlas' / 'somebody-elses').mkdir(parents=True)

    assert atlas.uninstall(ctx, None, {})['success'] is True

    assert (box / 'atlas' / 'somebody-elses').exists()


def test_uninstall_removes_an_agency_only_box(box, actions):
    """⚠️ The operator's own box: one agency, no plain ATLAS. Every path in the
    old uninstall pointed at `/root/atlas`, which does not exist there, so it
    removed nothing and said it had succeeded."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    result = atlas.uninstall(ctx, None, {})

    assert result['success'] is True
    assert not deployment_dir('atlas-corona').exists()


def test_uninstall_clears_every_deployment_s_settings(box, actions):
    """`startswith` is right *here* — the point is to leave nothing — where in
    `remove_instance` it would have taken a running agency's password."""
    instances = [ai.make(None, ai.MODE_FIXED, 100, 8760),
                 ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)]
    ctx = _make_box(box, instances)

    atlas.uninstall(ctx, None, {})

    assert [k for k in ctx.settings if k.startswith('atlas_')] == \
        ['atlas_enabled']
    assert ctx.settings['atlas_enabled'] is False


def test_uninstall_removes_the_device_port_once_everything_is_gone(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.uninstall(ctx, None, {})

    assert ctx.fw_removed == [atlas.DEVICE_PORT]


def test_uninstall_continues_past_one_deployment_that_will_not_go(box, actions,
                                                                  monkeypatch):
    """⚠️ One agency whose mounts are busy must not leave four others
    installed."""
    def selective(ctx, plog, inst=None):
        if (inst or {}).get('slug') == 'corona':
            return [], ['could not unmount']
        return ['store removed'], []

    monkeypatch.setattr(atlas, 'remove_store', selective)
    instances = [ai.make('corona', ai.MODE_DYNAMIC, 50, 8761),
                 ai.make('redlands', ai.MODE_DYNAMIC, 50, 8762)]
    ctx = _make_box(box, instances)

    result = atlas.uninstall(ctx, None, {})

    assert result['success'] is False
    assert (box / 'atlas' / 'corona').exists()
    assert not (box / 'atlas' / 'redlands').exists(), \
        'one failure stopped the others from being removed'


def test_a_partly_failed_uninstall_keeps_what_is_left_installed(box, actions,
                                                                monkeypatch):
    """⚠️ A deployment whose files survived is still a deployment: it needs its
    device port, its settings and `atlas_enabled`, or the console reports a
    running ATLAS as absent and nothing holds its database password."""
    monkeypatch.setattr(atlas, 'remove_store',
                        lambda c, plog, i=None: ([], ['could not unmount']))
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    result = atlas.uninstall(ctx, None, {})

    assert result['success'] is False
    assert ctx.settings.get('atlas_enabled') is True
    assert ctx.settings['atlas_corona_pg_password'] == 'secret'
    assert ctx.fw_removed == []
    assert [i.get('slug') for i in atlas.load_instances(ctx)] == ['corona']


def test_a_box_with_nothing_recorded_still_uninstalls_cleanly(box, actions):
    """An operator clearing up after a failed first install must not be told the
    uninstall failed because there was nothing to remove."""
    ctx = Ctx({}, [])

    result = atlas.uninstall(ctx, None, {})

    assert result['success'] is True
    assert any('No ATLAS deployment' in step for step in result['steps'])


# --------------------------------------------------------------------------- #
# The removal job
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def clean_slots():
    atlas._removal_slots.clear()
    atlas._update_slots.clear()
    yield
    atlas._removal_slots.clear()
    atlas._update_slots.clear()


def test_a_removal_has_its_own_slot_per_deployment():
    """⚠️ Not the update slot. A teardown log rendered in a card labelled
    "update" is how an operator comes to believe a deployment was updated when
    it was destroyed."""
    a = atlas._removal_slot({'slug': 'corona'})
    b = atlas._update_slot({'slug': 'corona'})
    c = atlas._removal_slot({'slug': 'redlands'})

    a['running'] = True

    assert b['running'] is False
    assert c['running'] is False


def test_the_removal_job_records_what_it_did(box, actions):
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas._run_removal(ctx, inst)

    slot = atlas._removal_slot(inst)

    assert slot['complete'] is True
    assert slot['error'] is False
    assert slot['running'] is False
    assert any('atlas-corona' in line for line in slot['log'])


def test_the_removal_job_reports_a_failure_as_a_failure(box, actions,
                                                        busy_store):
    """⚠️ An error that read as complete would reload the page over a deployment
    still on disk, and the log saying what survived is the only place that says
    so."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas._run_removal(ctx, inst)

    slot = atlas._removal_slot(inst)

    assert slot['error'] is True
    assert slot['complete'] is False
    assert any('ERROR' in line for line in slot['log'])


def test_the_removal_log_says_each_step_once(box, actions):
    """⚠️ `remove_store`'s own progress lines were logged twice — once raw from
    its plog, once labelled from the returned list — and a teardown log that
    repeats itself reads like a teardown that ran twice."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas._run_removal(ctx, inst)

    lines = [line.split('] ', 1)[-1] for line in atlas._removal_slot(inst)['log']]

    # ⚠️ Not an exact-duplicate check. The two copies were *differently worded* —
    # `store removed` from `remove_store`'s own plog and
    # `atlas-corona: store removed` from the returned list — so comparing lines
    # for equality passed while the log said everything twice.
    store_lines = [line for line in lines if 'store removed' in line]

    assert len(store_lines) == 1, store_lines
    assert len(lines) == len(set(lines)), [l for l in lines if lines.count(l) > 1]


# --------------------------------------------------------------------------- #
# Where the Caddy trust pool is looked for
# --------------------------------------------------------------------------- #


def _probe(monkeypatch):
    seen = []
    monkeypatch.setattr(atlas.os.path, 'isdir',
                        lambda path: seen.append(path) or False)
    return seen


def test_the_plain_trust_pool_is_the_directory_already_on_disk(monkeypatch):
    """`/var/lib/caddy/atlas` is what every deployed box has; looking elsewhere
    would leave a stale trust pool behind on all of them."""
    seen = _probe(monkeypatch)

    atlas._caddy_ca_dir(None)

    assert seen
    assert all(os.path.basename(p) == 'atlas' for p in seen), seen


def test_an_agency_s_trust_pool_is_looked_for_under_its_own_name(monkeypatch):
    """⚠️ **The one that survived a mutation.** Hardcoded to `atlas`, tearing
    down an agency deleted the *plain* deployment's trust pool — and Caddy then
    refuses to start, taking every vhost on the box with it, not only ATLAS's.
    The call-site test could not catch it, because it patched this function."""
    seen = _probe(monkeypatch)

    atlas._caddy_ca_dir({'slug': 'corona'})

    assert seen
    assert all(os.path.basename(p) == 'atlas-corona' for p in seen), seen


# --------------------------------------------------------------------------- #
# When a removal must wait
# --------------------------------------------------------------------------- #


def test_a_quiet_box_allows_a_removal():
    assert atlas.removal_refusal({'slug': 'corona'}) is None


def test_a_removal_will_not_run_during_a_deploy():
    """⚠️ **Measured on the box, 2026-09-18.** A removal started while a deploy
    was at step 4, ran `docker compose down -v` over the containers the deploy
    had just created, and the deploy failed three seconds later. An unfinished
    deployment is exactly what a deploy *in progress* looks like, so the page's
    retry row sat beside a running build offering to delete it."""
    refusal = atlas.removal_refusal({'slug': 'corona'}, deploy_running=True)

    assert refusal and 'being built' in refusal


def test_any_deploy_blocks_any_removal():
    """⚠️ The registry runs deploy under the module's own job key whatever is
    being built, so one slot covers the box. Refusing too widely costs a wait;
    refusing too narrowly costs a deployment."""
    assert atlas.removal_refusal(None, deploy_running=True)
    assert atlas.removal_refusal({'slug': 'redlands'}, deploy_running=True)


def test_a_removal_will_not_run_during_that_deployment_s_update():
    atlas._update_slot({'slug': 'corona'})['running'] = True

    refusal = atlas.removal_refusal({'slug': 'corona'})

    assert refusal and 'update' in refusal


def test_another_deployment_s_update_does_not_block_this_removal():
    """They share no containers and no checkout. Blocking here would make a box
    with five agencies unmanageable whenever any one of them was updating."""
    atlas._update_slot({'slug': 'redlands'})['running'] = True

    assert atlas.removal_refusal({'slug': 'corona'}) is None


def test_update_all_blocks_every_removal():
    """It walks every deployment in turn, so any of them may be the one being
    rebuilt at the moment the button is pressed."""
    atlas._update_all_status['running'] = True
    try:
        assert atlas.removal_refusal({'slug': 'corona'})
    finally:
        atlas._update_all_status['running'] = False


def test_a_removal_will_not_run_twice():
    atlas._removal_slot({'slug': 'corona'})['running'] = True

    refusal = atlas.removal_refusal({'slug': 'corona'})

    assert refusal and 'already being removed' in refusal


# --------------------------------------------------------------------------- #
# What an empty list means
# --------------------------------------------------------------------------- #


def test_removing_the_last_deployment_leaves_none(box, actions):
    """⚠️ **The phantom.** `if stored:` treated an empty list and a missing key
    as the same thing, so removing the last deployment — which leaves `[]` and
    `atlas_enabled` still true, because the module is still installed — fell
    through to the migration branch and synthesised a plain deployment that does
    not exist. The page would list it, refuse a new general ATLAS as a duplicate
    of it, and offer to update a directory that is not there."""
    inst = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    ctx = _make_box(box, [inst])

    atlas.remove_instance(ctx, inst)

    assert ctx.settings.get('atlas_enabled') is True
    assert atlas.load_instances(ctx) == []


def test_a_box_that_predates_the_list_still_migrates(monkeypatch, tmp_path):
    """⚠️ And the branch that empty list must not trigger is still reachable by
    the box it was written for: installed before `atlas_instances` existed, so
    the key is *absent* rather than empty."""
    image = tmp_path / 'store.img'
    image.write_bytes(bytes(1024))
    monkeypatch.setattr(atlas, 'STORE_IMAGE', str(image))
    ctx = {'load_settings': lambda: {'atlas_enabled': True}}

    found = atlas.load_instances(ctx)

    assert len(found) == 1
    assert found[0]['slug'] is None
