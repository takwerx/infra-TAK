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
"""The ATLAS Update button takes a database backup first (ops #864).

⚠️ **The bug.** ATLAS 2.x opens a database that 1.138.0 cannot read (the api restart-loops with
"Can't locate revision identified by ..."), and the Update button changed nothing before it ran:
no dump, nothing kept. An operator who updated and then hit a problem had no way back.

⚠️ **Driven, not grepped.** `_run_update` is run for real from "installed 1.138.0, newest 2.1.2".
The first step after the backup (`_ls_remote`) is replaced with a recorder that stops the run, so a
test sees exactly what happened before the update touched anything: the dump ran, the file is
there, and it is a whole dump. On the base branch (no backup step) the recorder fires with no dump
and no file, so every test here that checks them fails.
"""

import os
import pathlib
import stat
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_backup as ab  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402

CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)

DUMP = (b'--\n-- PostgreSQL database dump\n--\n' + b'CREATE TABLE devices (id int);\n' * 20 +
        b'--\n-- PostgreSQL database dump complete\n--\n')


class Stop(Exception):
    """Raised by the recorder that stands in for the first step after the backup."""


@pytest.fixture
def box(monkeypatch, tmp_path):
    """A box with a built deployment on 1.138.0, a running database and a recorder for events."""
    base = str(tmp_path).replace(chr(92), '/')
    dep = tmp_path / 'atlas' / 'default'
    (dep / '.git').mkdir(parents=True)
    events = []
    state = {'dump': (0, DUMP, ''), 'cid': 'dbc1'}

    monkeypatch.setattr(atlas, 'install_base', lambda c=None: base)
    monkeypatch.setattr(atlas, '_channel_of', lambda _c: 'main')
    monkeypatch.setattr(atlas, 'deployment_identity', lambda c, i, s: {
        'name': 'atlas', 'dir': str(dep).replace(chr(92), '/'), 'settings_prefix': 'atlas_',
        'compose_project': 'takmdm'})
    monkeypatch.setattr(atlas, '_latest_version', lambda use_cache=False, channel=None: '2.1.2')
    monkeypatch.setattr(atlas, '_installed_version', lambda _c, _i=None: '1.138.0')
    monkeypatch.setattr(atlas, '_db_container', lambda project: state['cid'])
    monkeypatch.setattr(atlas, '_module_head', lambda c, d: None)
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: None)

    def fake_dump(cid):
        events.append(('dump', cid))
        return state['dump']

    def first_step(*_a, **_k):
        events.append(('first-step-after-backup',))
        raise Stop()

    monkeypatch.setattr(atlas, '_run_pg_dump', fake_dump)
    monkeypatch.setattr(atlas, '_ls_remote', first_step)
    monkeypatch.setattr(atlas, '_compose', lambda *a, **k: events.append(('compose', a[1:])))
    store = {'s': {}}
    ctx = {'load_settings': lambda: dict(store['s']),
           'save_settings': lambda s: store.__setitem__('s', dict(s))}
    return {'ctx': ctx, 'events': events, 'state': state, 'base': base,
            'dir': str(dep).replace(chr(92), '/')}


def run_update(box, inst=None):
    slot = atlas._update_slot(inst)
    slot.clear()
    atlas._run_update(box['ctx'], inst)
    return slot


def backups(box, name='atlas'):
    return ab.list_backups(os.path.join(box['base'], ab.BACKUP_DIRNAME, name))


# --------------------------------------------------------------------------- #
# The proof test: red on the base branch, green with the fix
# --------------------------------------------------------------------------- #


def test_update_takes_a_database_backup_before_it_changes_anything(box):
    """⚠️ **The reported case.** Update from 1.138.0 to 2.1.2: the dump runs, a complete file is
    kept, and all of that happens before the first step that touches the deployment."""
    run_update(box)

    kinds = [e[0] for e in box['events']]
    assert kinds[:2] == ['dump', 'first-step-after-backup'], kinds
    found = backups(box)
    assert len(found) == 1, found
    assert found[0]['version'] == '1.138.0'
    data = open(found[0]['path'], 'rb').read()
    assert data == DUMP
    assert b'PostgreSQL database dump complete' in data[-400:]


def test_the_backup_file_is_private(box):
    run_update(box)

    b = backups(box)[0]
    assert stat.S_IMODE(os.stat(b['path']).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(b['path'])).st_mode) == 0o700


def test_the_update_log_says_where_the_backup_is_and_how_to_restore(box):
    slot = run_update(box)

    log = chr(10).join(slot['log'])
    path = backups(box)[0]['path']
    assert path in log, log
    assert 'DROP DATABASE takmdm WITH (FORCE)' in log
    assert 'checkout -f v1.138.0' in log
    assert 'up -d --build api' in log


# --------------------------------------------------------------------------- #
# No backup, no update
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('dump', [
    (1, b'', 'pg_dump: error: connection to server failed'),
    (0, b'', ''),
    (0, DUMP[:120], ''),   # cut short: no completion line
], ids=['dump-fails', 'dump-empty', 'dump-truncated'])
def test_a_failed_backup_stops_the_update_before_anything_changes(box, dump):
    box['state']['dump'] = dump

    slot = run_update(box)

    kinds = [e[0] for e in box['events']]
    assert 'first-step-after-backup' not in kinds, kinds
    assert 'compose' not in kinds, kinds
    assert slot['error'] and not slot['complete'], slot
    assert 'nothing was changed' in chr(10).join(slot['log'])
    assert backups(box) == []


def test_a_half_written_file_is_never_left_looking_like_a_backup(box):
    box['state']['dump'] = (0, DUMP[:120], '')

    run_update(box)

    folder = os.path.join(box['base'], ab.BACKUP_DIRNAME, 'atlas')
    assert [n for n in os.listdir(folder)] == [], os.listdir(folder)


def test_a_stopped_database_is_started_for_the_backup(box, monkeypatch):
    seen = {'n': 0}

    def cid(project):
        seen['n'] += 1
        return '' if seen['n'] == 1 else 'dbc2'

    class R:
        returncode = 0
        stdout = stderr = ''

    monkeypatch.setattr(atlas, '_db_container', cid)
    monkeypatch.setattr(atlas, '_compose',
                        lambda ctx, action, timeout=180, inst=None:
                        box['events'].append(('compose', action)) or R())
    monkeypatch.setattr(atlas, '_run_root', lambda argv, timeout=120: (0, ''))

    run_update(box)

    assert ('compose', 'up -d --no-deps db') in box['events']
    assert ('dump', 'dbc2') in box['events']
    assert len(backups(box)) == 1


# --------------------------------------------------------------------------- #
# Agencies, retention, restore text
# --------------------------------------------------------------------------- #


def test_an_agency_has_its_own_folder_and_its_own_compose_project(box):
    folder, flag = atlas.backup_paths(box['ctx'], CORONA)

    assert folder.endswith('/atlas-backups/atlas-corona'), folder
    assert flag == '-p takmdm-corona'
    plain, plain_flag = atlas.backup_paths(box['ctx'], None)
    assert plain.endswith('/atlas-backups/atlas') and plain_flag == ''


def test_backups_live_beside_the_deployments_not_inside_them(box):
    folder, _ = atlas.backup_paths(box['ctx'], None)

    assert not folder.startswith(atlas.atlas_root(box['ctx']) + '/'), folder


def test_only_the_newest_three_are_kept(tmp_path):
    d = str(tmp_path / 'b')
    stamps = []
    for i in range(5):
        t = 1_700_000_000 + i * 60
        stamps.append(time.strftime('%Y%m%d-%H%M%S', time.gmtime(t)))
        ab.take(d, '1.138.0', lambda: (0, DUMP, ''), lambda m: None, now=t)

    names = sorted(b['name'] for b in ab.list_backups(d))

    assert len(names) == ab.KEEP == 3, names
    assert [n[len('takmdm-v1.138.0-'):-4] for n in names] == stamps[-3:]


def test_restore_steps_drop_recreate_load_check_out_and_rebuild():
    steps = ab.restore_steps('/home/t/atlas/default', '', 'v1.138.0',
                             '/home/t/atlas-backups/atlas/takmdm-v1.138.0-20261116-230000.sql')

    text = chr(10).join(steps)
    assert steps[0].endswith('stop api')
    assert 'DROP DATABASE takmdm WITH (FORCE)' in text and 'CREATE DATABASE takmdm OWNER takmdm' in text
    assert '< ' in steps[2] and 'ON_ERROR_STOP=1' in steps[2]
    assert 'checkout -f v1.138.0' in text
    assert steps[-1].endswith('up -d --build api')
    assert text.index('DROP DATABASE') < text.index('ON_ERROR_STOP') < text.index('checkout') < text.index('--build')


def test_restore_steps_for_an_agency_name_its_compose_project():
    steps = ab.restore_steps('/h/atlas/corona', '-p takmdm-corona', 'v1.138.0', '/h/b.sql')

    assert all('-p takmdm-corona' in s for s in steps if 'docker compose' in s)


def test_restore_steps_quote_a_hostile_path():
    steps = ab.restore_steps('/h/a b', '', 'v1.0.0', "/h/x'; rm -rf /; '.sql")

    assert "'/h/a b'" in steps[0]
    assert "rm -rf /" in steps[2] and "'\"'\"'" in steps[2]


def test_a_version_cannot_put_path_or_shell_characters_in_the_file_name():
    name = ab.backup_name('1.0/../../etc; rm -rf', now=0)

    assert '/' not in name and ' ' not in name and ';' not in name
    assert name.endswith('.sql') and name.startswith('takmdm-v')


# --------------------------------------------------------------------------- #
# The page
# --------------------------------------------------------------------------- #


def test_the_page_lists_backups_from_the_route_it_reads(box, monkeypatch):
    ab.take(os.path.join(box['base'], ab.BACKUP_DIRNAME, 'atlas'), '1.138.0',
            lambda: (0, DUMP, ''), lambda m: None)
    monkeypatch.setattr(atlas, 'load_instances', lambda ctx: [ai.make(None, ai.MODE_FIXED, 100, 8760)])
    monkeypatch.setattr(atlas, 'compose_projects_present', lambda c=None: {'takmdm'})
    monkeypatch.setattr(atlas, 'instance_is_built', lambda c, i, p=None: True)

    out = atlas.backups_payload(box['ctx'])

    assert list(out) == ['atlas'], out
    one = out['atlas']
    assert one['backups'][0]['version'] == '1.138.0'
    assert any('DROP DATABASE' in s for s in one['restore'])

    page = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    assert "fetch('/api/atlas/backups'" in page and 'id="backupCard"' in page
    for key in ('backups', 'restore', 'path', 'version', 'size', 'mtime'):
        assert key in page, key
