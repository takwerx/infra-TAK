# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
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
"""A Docker TAK box an OLDER failed update left with no containers can press Update again (ops #1367).

The old update (console 10.4.8 and before) removed both TAK containers and the old bundle folder,
then failed at the image build. /opt/tak then points into the new, half-built bundle folder, the
database volume holds PostgreSQL 18, and no container exists. Update with the same zip used to go to
the 5.7 -> 5.8 migration ("takserver-db is not running PostgreSQL 15 - nothing to migrate from")
and, past that, to the refusal "already installed". Two fixes are proved here:

  1. the route: a container box whose bundle is 5.8 and whose volume is PostgreSQL 18 takes the
     container update, not the migration, even when the database container is down;
  2. run_takserver_upgrade_container: the zip is the folder /opt/tak already points to and the
     `takserver` container is missing -> rebuild and start in place (no unpack, no carry-over,
     no deletes).

The real functions run against a fake Docker and a real temporary folder tree (the harness of the
#1326 tests). Set INFRATAK_APP_PY to run the same tests against another app.py: that is how the
base branch is shown red.
"""

import os
import pathlib
import re
import types

import pytest

from test_tak_container_update_order_ops1326 import (   # noqa: E402
    APP, HARDENED_DB, LEGACY_DB, Box, _const, _load, _make_zip, _ns)

TOP = 'takserver-docker-hardened-5.8-RELEASE-104'


class Stranded(Box):
    """The box an older failed update left: both containers gone, /opt/tak into the new folder."""

    def __init__(self, tmp, top=TOP, layout='ROOT=18 LEGACY=none'):
        super().__init__(tmp, old_top=top, layout=layout)
        self.containers.clear()
        self.schema = 120               # what the database answers for max(schema_version)
        self.volume_ops = []

    def _start(self, name, cmd, image, created=False):
        if 'start_resume' in self.fail and name == 'takserver':
            return 1
        return super()._start(name, cmd, image, created)


def _stranded_ns(box):
    ns = _ns(box)
    ns['_TAK58_MIN_SCHEMA_VERSION'] = 100
    ns['_tak58_container_schema_version'] = lambda c, pgbin, pw: box.schema
    ns['_tak58_container_pgbin'] = lambda c, m: ('/usr/pgsql-%d/bin' % m) if m in (15, 18) else None
    # an unpack here would be a second copy of a folder that already is the box: fail loudly
    def no_unpack(*a, **k):
        raise AssertionError('the zip was unpacked on a rebuild in place')
    ns['_safe_extract_zip'] = no_unpack
    return ns


def _press(tmp_path, top=TOP, fail=(), layout='ROOT=18 LEGACY=none', hardened=True,
           db_text=HARDENED_DB, mutate=None, schema=120):
    box = Stranded(tmp_path, top=top, layout=layout)
    box.fail = set(fail)
    box.schema = schema
    if mutate:
        mutate(box)
    z = box.zip_dir / f'{top}.zip'
    _make_zip(z, top, db_text, hardened)
    ns = _stranded_ns(box)
    ns['run_takserver_upgrade_container'](str(z))
    return box, ns, ns['upgrade_status'], '\n'.join(ns['upgrade_log'])


def _folder_intact(box):
    tak = box.old_ctx / 'tak'
    assert box.link == tak, 'the /opt/tak link moved'
    assert (tak / 'certs/files/takserver.jks').read_text() == 'jks'
    assert (tak / 'CoreConfig.xml').exists() and (tak / 'UserAuthenticationFile.xml').exists()
    assert (tak / 'lib/my-plugin.jar').exists() and (tak / 'conf/plugins/my.plugin.yaml').exists()
    assert (tak / 'snapshots/pre-1/cot.pgdump').read_text() == 'dump'
    assert (tak / 'setenv.sh').read_text().startswith('# >>> infra-TAK managed heap >>>')
    assert not any(re.search(r'(^| )rm -rf .*' + re.escape(str(box.old_ctx)) + r'($| )', c)
                   for c in box.calls), [c for c in box.calls if 'rm ' in c]


def _made_something(box):
    """True when a docker call that creates, starts, removes or builds ran. The read-only look at the
    volume is `docker run --rm ... sh -c 'cat PG_VERSION'` and is not one of them."""
    return any(c.startswith(('docker rm ', 'docker create ', 'docker start ', 'docker tag '))
               or (c.startswith('docker run ') and ' --rm ' not in c)
               or ' docker build ' in c for c in box.calls)


def _no_volume_changes(box):
    assert not any(c.startswith('docker volume') and 'inspect' not in c for c in box.calls), box.calls


_no_volume_changes_other_than_inspect = _no_volume_changes


# ── 1. the stranded box recovers ────────────────────────────────────────────

def test_stranded_box_is_rebuilt_in_place_and_tak_comes_back(tmp_path):
    box, ns, st, log = _press(tmp_path)
    assert st['complete'] and not st['error'], log
    new_tak = box.old_ctx / 'tak'
    assert set(box.containers) == {'takserver', 'takserver-db'}
    assert box.containers['takserver']['bundle'] == str(new_tak)
    assert box.containers['takserver-db']['bundle'] == str(new_tak)
    assert box.images['takserver'].startswith('img-new') and box.images['takserver_db'].startswith('img-new')
    assert not any(':' in k for k in box.images), 'temporary image tags were left behind'
    _folder_intact(box)
    _no_volume_changes(box)
    assert 'already unpacked' in log and 'rebuilt in place' in log
    # the link was not removed and made again, and the folder was not copied anywhere
    assert not any(c.startswith(('ln -sfn', 'rm -f /opt/tak')) for c in box.calls), box.calls
    assert not any(c.startswith('cp ') and 'certs' in c for c in box.calls)


def test_the_database_must_hold_tak_data_before_tak_starts(tmp_path):
    box, ns, st, log = _press(tmp_path)
    db_up = next(i for i, c in enumerate(box.calls) if c.startswith('docker run '))
    tak_up = next(i for i, c in enumerate(box.calls) if c.startswith('docker create '))
    assert db_up < tak_up


def test_stranded_box_works_with_the_database_image_tag_missing_too(tmp_path):
    # the older update failed at the DB build: tags may be old, or gone
    def mutate(box):
        box.images.pop('takserver_db')
    box, ns, st, log = _press(tmp_path, mutate=mutate)
    assert st['complete'], log
    _folder_intact(box)


# ── 2. what is still refused, with nothing changed ──────────────────────────

def test_same_zip_with_the_container_present_is_still_refused(tmp_path):
    def mutate(box):
        box.containers['takserver'] = {'image': 'img-old-app', 'bundle': str(box.old_ctx / 'tak')}
    box, ns, st, log = _press(tmp_path, mutate=mutate)
    assert st['error'] and 'already installed' in log
    assert not any(c.startswith('docker rm ') for c in box.calls)
    _folder_intact(box)


def test_docker_that_cannot_be_asked_is_refused_not_guessed(tmp_path):
    box, ns, st, log = _press(tmp_path, fail=['docker_down'])
    assert st['error'] and 'already installed' in log and 'could not say' in log
    assert not any(c.startswith('docker rm ') for c in box.calls)
    _folder_intact(box)


@pytest.mark.parametrize('gone,words', [
    ('tak/certs/files/takserver.jks', 'certs/files/takserver.jks'),
    ('tak/CoreConfig.xml', 'CoreConfig.xml'),
])
def test_a_folder_with_missing_parts_is_refused_and_nothing_is_changed(tmp_path, gone, words):
    def mutate(box):
        (box.old_ctx / gone).unlink()
    box, ns, st, log = _press(tmp_path, mutate=mutate)
    assert st['error'] and 'not complete' in log and words in log
    assert not _made_something(box), box.calls
    assert box.containers == {}


def test_volume_of_another_postgresql_major_is_refused_before_anything_changes(tmp_path):
    box, ns, st, log = _press(tmp_path, layout='ROOT=17 LEGACY=none')
    assert st['error'] and 'PostgreSQL 18 but your data is PostgreSQL 17' in log
    assert not _made_something(box), box.calls
    assert box.containers == {}
    _folder_intact(box)


def test_unreadable_volume_is_refused_instead_of_guessed(tmp_path):
    box, ns, st, log = _press(tmp_path, layout='')
    assert st['error'] and 'could not be read' in log
    assert box.containers == {}
    _folder_intact(box)


# ── 3. a failed try leaves the box as it was and can be repeated ────────────

@pytest.mark.parametrize('which', ['build_db', 'build_app'])
def test_failed_build_leaves_the_folder_and_a_second_press_works(tmp_path, which):
    box, ns, st, log = _press(tmp_path, fail=[which])
    assert st['error'] and 'bundle folder was not changed' in log
    assert box.containers == {}, 'a container was made by a try that failed at the build'
    _folder_intact(box)
    assert not any(k.startswith(('takserver:', 'takserver_db:')) for k in box.images), box.images
    box.fail.clear()
    st.update({'running': True, 'complete': False, 'error': False})
    ns['run_takserver_upgrade_container'](str(next(box.zip_dir.glob('*.zip'))))
    assert st['complete'] and not st['error'], '\n'.join(ns['upgrade_log'])
    assert set(box.containers) == {'takserver', 'takserver-db'}


def test_failed_start_removes_what_it_made_and_leaves_the_folder_for_another_try(tmp_path):
    box, ns, st, log = _press(tmp_path, fail=['start_resume'])
    assert st['error'] and 'stays stopped' in log and 'untouched' in log
    assert box.containers == {}, 'containers of the failed try were left, so the next Update says "already installed"'
    _folder_intact(box)
    _no_volume_changes(box)
    assert not any(k.startswith(('takserver:', 'takserver_db:')) for k in box.images), box.images
    # and the next press works
    box.fail.clear()
    st.update({'running': True, 'complete': False, 'error': False})
    ns['run_takserver_upgrade_container'](str(next(box.zip_dir.glob('*.zip'))))
    assert st['complete'], '\n'.join(ns['upgrade_log'])


@pytest.mark.parametrize('volume_made,why', [
    ('2999-01-01T00:00:00Z', 'newer than the folder'),   # the 5.8 migration made the volume AFTER the folder
    ('not a time', 'could not be read'),
])
def test_a_volume_that_may_be_a_new_empty_database_is_never_given_to_tak(tmp_path, volume_made, why):
    # Box test, ops #1367: the hardened database image builds TAK's schema on its first start, so a
    # brand-new EMPTY volume looks healthy (schema version 106) and TAK came up with no data. The
    # only difference from the box's own volume is its age: it is older than the folder.
    def mutate(box):
        box.vol_created = volume_made
    box, ns, st, log = _press(tmp_path, mutate=mutate)
    assert st['error'] and why in log and 'EMPTY' in log
    assert not _made_something(box), box.calls
    assert box.containers == {}
    _folder_intact(box)
    _no_volume_changes_other_than_inspect(box)


@pytest.mark.parametrize('schema', [None, 0, 12])
def test_a_database_that_cannot_be_read_or_has_no_schema_does_not_get_tak(tmp_path, schema):
    box, ns, st, log = _press(tmp_path, schema=schema)
    assert st['error'] and 'NOT started' in log and 'EMPTY' in log
    assert not any(c.startswith('docker create ') or c.startswith('docker start ') for c in box.calls)
    assert 'takserver' not in box.containers
    _folder_intact(box)
    _no_volume_changes(box)


def test_a_slow_start_keeps_the_folder_and_says_so(tmp_path):
    box, ns, st, log = _press(tmp_path, fail=['no_messaging'])
    assert 'KEPT' in log or 'Did not see messaging' in log
    _folder_intact(box)


@pytest.mark.parametrize('text,epoch', [
    ('2026-11-27T16:21:09Z', 1795796469),
    ('2026-11-27T16:21:09.123456789Z', 1795796469),
    ('2026-11-27T18:21:09+02:00', 1795796469),
    ('2026-11-27T11:21:09-05:00', 1795796469),
    ('2026-11-27 16:21:09 +0000', 1795796469),
    ('', None), (None, None), ('yesterday', None),
])
def test_docker_created_at_is_read_in_every_shape_docker_prints(text, epoch):
    ns = {'re': re}
    _load(ns, ['_tak_docker_time'])
    assert ns['_tak_docker_time'](text) == epoch


# ── 4. a stranded 5.7-era bundle (PostgreSQL 15, legacy layout) ─────────────

def test_stranded_57_bundle_is_rebuilt_the_same_way(tmp_path):
    box, ns, st, log = _press(tmp_path, top='takserver-docker-5.7-RELEASE-43', hardened=False,
                              db_text=LEGACY_DB, layout='ROOT=none LEGACY=15', schema=40)
    assert st['complete'], log
    assert set(box.containers) == {'takserver', 'takserver-db'}
    _folder_intact(box)


# ── 5. the normal update is not changed by any of this ──────────────────────

def test_a_different_zip_on_a_box_with_containers_still_does_the_normal_update(tmp_path):
    box = Box(tmp_path)                                            # healthy 5.8 R105 box
    z = box.zip_dir / 'takserver-docker-hardened-5.8-RELEASE-106.zip'
    _make_zip(z, 'takserver-docker-hardened-5.8-RELEASE-106', HARDENED_DB)
    ns = _ns(box)
    ns['run_takserver_upgrade_container'](str(z))
    st = ns['upgrade_status']
    assert st['complete'], '\n'.join(ns['upgrade_log'])
    assert not box.old_ctx.exists()                                # normal path: old folder removed last
    assert 'already unpacked' not in '\n'.join(ns['upgrade_log'])


def test_the_migration_call_never_rebuilds_in_place():
    assert 'allow_resume=not migration' in APP


# ── the route: which button path a 5.8 zip takes ────────────────────────────

def _route_env(tmp_path, *, container=True, bundle=TOP, layout=None, installed='5.8-RELEASE104',
               facts=None, zip_name='takserver-docker-hardened-5.8-RELEASE-104.zip'):
    (tmp_path / zip_name).write_bytes(b'x')
    started = []
    n = {
        'os': os, 're': re, 'threading': types.SimpleNamespace(
            Thread=lambda target=None, args=(), kwargs=None, daemon=None:
            types.SimpleNamespace(start=lambda: started.append(target))),
        'jsonify': lambda *a, **k: (a[0] if a else k),
        'UPLOAD_DIR': str(tmp_path), 'upgrade_status': {'running': False}, 'upgrade_log': [],
        'TAK_PG_MAJOR': 18,
        'load_settings': lambda: {},
        '_tak_is_container': lambda: container,
        '_distro_family': lambda: 'debian',
        '_get_tak_deployment_config': lambda s: {},
        '_get_takserver_version_info': lambda: {'version': installed},
        # the running database is DOWN: the pre-flight cannot read a major
        '_tak_58_preflight': lambda: {'ready': False, 'blockers': ['db down'], 'facts': facts or {}},
        '_tak_db_volume_layout': lambda: layout,
        '_tak_update_job': lambda label, fn, log, status: fn.__name__,
    }
    for w in ('run_takserver_upgrade', 'run_takserver_upgrade_rhel', 'run_takserver_upgrade_container',
              'run_takserver_58_migration', 'run_takserver_58_container_migration'):
        n[w] = (lambda name: type(name, (), {'__call__': lambda self: None, '__name__': name})())(w)
    for c in ('_TAK_VER_RE', '_TAK_RELEASE_RE', 'TAK_GATE_BLOCK_FROM'):
        exec(_const(c), n)
    n['TAK_GATE_MESSAGE'] = 'gate'
    _load(n, ['_tak_artifact_version', '_tak_target_version_gate', '_tak_already_on_58',
              '_tak_release_key', '_tak_package_downgrade', '_tak_fmt_release',
              '_tak_cross_minor_downgrade_message', '_tak_container_on_58_data'])
    src = re.search(r"^def takserver_update\(\):.*?(?=^@app\.route)", APP, re.S | re.M).group(0)
    exec(src, n)
    real_exists = os.path.exists
    n['os'] = types.SimpleNamespace(
        listdir=os.listdir, path=types.SimpleNamespace(
            exists=lambda p: True if p == '/opt/tak' else real_exists(p),
            join=os.path.join, getmtime=os.path.getmtime, basename=os.path.basename,
            realpath=lambda p: ('/home/u/tak-docker/%s/tak' % bundle) if p == '/opt/tak' else os.path.realpath(p),
            dirname=os.path.dirname))
    return n, started


def _click(tmp_path, **kw):
    n, started = _route_env(tmp_path, **kw)
    return n['takserver_update'](), [t for t in started]


PG18 = {'exists': True, 'root': 18, 'legacy': None}


def test_58_bundle_with_a_pg18_volume_and_the_database_down_takes_the_container_update(tmp_path):
    resp, started = _click(tmp_path, layout=PG18)
    assert resp == {'success': True}
    assert started == ['run_takserver_upgrade_container']


def test_58_zip_on_a_57_box_still_takes_the_migration(tmp_path):
    resp, started = _click(tmp_path, bundle='takserver-docker-5.7-RELEASE-43', installed='5.7-RELEASE43',
                           layout={'exists': True, 'root': None, 'legacy': 15})
    assert resp.get('migration') is True
    assert started == ['run_takserver_58_container_migration']


@pytest.mark.parametrize('layout', [
    {'exists': False, 'root': None, 'legacy': None},          # no volume (a migration removed it)
    {'exists': True, 'root': None, 'legacy': None},           # an empty volume
    {'exists': True, 'root': None, 'legacy': 15},             # PostgreSQL 15 data under a 5.8 folder
    None,                                                     # volume unreadable
])
def test_58_bundle_without_a_pg18_volume_still_takes_the_migration(tmp_path, layout):
    resp, started = _click(tmp_path, layout=layout)
    assert started == ['run_takserver_58_container_migration']


def test_a_57_bundle_folder_with_a_pg18_volume_is_not_treated_as_58(tmp_path):
    resp, started = _click(tmp_path, bundle='takserver-docker-5.7-RELEASE-43', installed='5.7-RELEASE43',
                           layout=PG18)
    assert started == ['run_takserver_58_container_migration']


def test_a_box_whose_database_answers_keeps_the_old_route(tmp_path):
    resp, started = _click(tmp_path, layout=None, facts={'already_migrated': True, 'pg_running_major': 18})
    assert started == ['run_takserver_upgrade_container']


def test_native_box_is_not_asked_about_a_volume(tmp_path):
    def boom():
        raise AssertionError('a native box asked about the Docker volume')
    n, started = _route_env(tmp_path, container=False,
                            zip_name='takserver_5.8-RELEASE92_all.deb')
    n['_tak_db_volume_layout'] = boom
    n['_tak_58_preflight'] = lambda: {'ready': True, 'blockers': [], 'facts': {}}
    n['takserver_update']()
    assert started == ['run_takserver_58_migration']
