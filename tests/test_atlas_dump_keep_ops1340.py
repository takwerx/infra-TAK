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
"""ATLAS dump keeping, redeploy dump and Update All wording (ops #1340).

⚠️ **The bug.** An ATLAS update that dies after its checkout moved is retried with "run it
again". Each retry took a dump named for the release now on disk (already the NEW one) and
`KEEP = 3` pruned by age, so three retries deleted the only dump taken before the migration.
Deploy on a built deployment took no dump at all, and Update All reported a refused downgrade
as "updated".

⚠️ **Driven, not grepped.** `_run_update`, `deploy` and `_run_update_all` run for real with the
git, Docker and network seams replaced by recorders (the pattern of
test_atlas_backup_before_update.py), and the dump files are real files on disk.
"""

import os
import pathlib
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_backup as ab  # noqa: E402

END = b'--\n-- PostgreSQL database dump complete\n--\n'


def dump_of(label):
    """A whole dump whose body says which run wrote it."""
    return (b'--\n-- PostgreSQL database dump\n--\n' + b'-- ' + label.encode() + b'\n' +
            b'CREATE TABLE devices (id int);\n' * 20 + END)


class Stop(Exception):
    """Stands in for the first step after the backup."""


@pytest.fixture
def box(monkeypatch, tmp_path):
    """A built ATLAS deployment on 1.138.0 with a database that can be dumped."""
    base = str(tmp_path).replace(chr(92), '/')
    dep = tmp_path / 'atlas' / 'default'
    (dep / '.git').mkdir(parents=True)
    events = []
    st = {'installed': '1.138.0', 'running': None, 'target': '2.1.2', 'n': 0, 'label': 'first',
          'head': 'aaaa1111', 'dump_rc': 0, 'settings': {}}

    monkeypatch.setattr(atlas, 'install_base', lambda c=None: base)
    monkeypatch.setattr(atlas, '_channel_of', lambda _c: 'main')
    monkeypatch.setattr(atlas, 'deployment_identity', lambda c, i, s: {
        'name': 'atlas', 'dir': str(dep).replace(chr(92), '/'), 'settings_prefix': 'atlas_',
        'compose_project': 'takmdm', 'app_port': 8760})
    monkeypatch.setattr(atlas, '_latest_version',
                        lambda use_cache=False, channel=None: st['target'])
    monkeypatch.setattr(atlas, '_installed_version', lambda _c, _i=None: st['installed'])
    monkeypatch.setattr(atlas, '_running_version', lambda c=None, i=None: st['running'])
    monkeypatch.setattr(atlas, '_db_container', lambda project: 'dbc1')
    monkeypatch.setattr(atlas, '_module_head', lambda c, d: st['head'])
    monkeypatch.setattr(atlas, '_compose', lambda *a, **k: events.append(('compose', a[1:])))

    def fake_dump(cid):
        events.append(('dump', st['label']))
        if st['dump_rc']:
            return st['dump_rc'], b'', 'pg_dump: error: out of space'
        return 0, dump_of(st['label']), ''

    def first_step(*_a, **_k):
        events.append(('first-step-after-backup',))
        raise Stop()

    monkeypatch.setattr(atlas, '_run_pg_dump', fake_dump)
    monkeypatch.setattr(atlas, '_ls_remote', first_step)

    # Each dump gets its own second, so two dumps are two files.
    real_name = ab.backup_name

    def stepped_name(version, now=None):
        st['n'] += 1
        return real_name(version, now=1_800_000_000 + st['n'] * 60)

    monkeypatch.setattr(ab, 'backup_name', stepped_name)

    ctx = {'load_settings': lambda: dict(st['settings']),
           'save_settings': lambda s: st['settings'].update(s)}
    return {'ctx': ctx, 'events': events, 'st': st, 'base': base,
            'dir': str(dep).replace(chr(92), '/')}


def folder(box):
    return os.path.join(box['base'], ab.BACKUP_DIRNAME, 'atlas')


def backups(box):
    return ab.list_backups(folder(box))


def run_update(box):
    slot = atlas._update_slot(None)
    slot.clear()
    atlas._run_update(box['ctx'], None)
    return slot


def interrupt_the_update(box):
    """Where an update killed mid-rebuild leaves the box: the checkout already reads the NEW
    release, the commit recorded after a finished update is the old one."""
    st = box['st']
    st['installed'] = st['target']
    st['settings']['atlas_commit_sha'] = 'aaaa1111'
    st['head'] = 'bbbb2222'


# --------------------------------------------------------------------------- #
# The proof test: red on the base branch, green with the fix
# --------------------------------------------------------------------------- #


def test_three_retries_of_an_interrupted_update_keep_the_dump_taken_before_the_migration(box):
    """⚠️ **The reported case.** The first attempt takes the dump of 1.138.0. Its checkout moved
    to 2.1.2 and it died, so every retry names its dump for 2.1.2. After three retries the first
    dump must still be there, byte for byte."""
    run_update(box)
    first = backups(box)
    assert [b['version'] for b in first] == ['1.138.0'], first
    original = open(first[0]['path'], 'rb').read()

    interrupt_the_update(box)
    for i in range(3):
        box['st']['label'] = 'retry-%d' % (i + 1)
        slot = run_update(box)
        assert 'Finishing the update that was interrupted' in chr(10).join(slot['log'])

    found = backups(box)
    versions = [b['version'] for b in found]
    assert '1.138.0' in versions, versions
    kept = [b for b in found if b['version'] == '1.138.0'][0]
    assert open(kept['path'], 'rb').read() == original
    assert versions.count('2.1.2') == 3, versions
    assert len(found) == ab.KEEP + 1, versions


def test_a_retry_tells_the_operator_the_old_dump_is_still_there(box):
    run_update(box)
    interrupt_the_update(box)
    box['st']['label'] = 'retry-1'

    log = chr(10).join(run_update(box)['log'])

    old = [b for b in backups(box) if b['version'] == '1.138.0'][0]
    assert 'The backup from the earlier release v1.138.0 is kept too: ' + old['path'] in log, log


# --------------------------------------------------------------------------- #
# Naming: the release the data was written by
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('running, named', [
    ('1.138.0', '1.138.0'),   # the new api never started: the data is still 1.138.0's
    (None, '2.1.2'),          # nothing answers: the safe direction is the newer release
    ('2.1.2', '2.1.2'),       # the new api ran and migrated
], ids=['old-api-still-running', 'nothing-answers', 'new-api-ran'])
def test_a_retry_names_its_dump_for_the_release_that_wrote_the_data(box, running, named):
    interrupt_the_update(box)
    box['st']['running'] = running

    slot = run_update(box)

    found = backups(box)
    assert [b['version'] for b in found] == [named], found
    log = chr(10).join(slot['log'])
    assert ('checkout -f v' + named) in log, log


# --------------------------------------------------------------------------- #
# Pruning stays bounded and still ages out
# --------------------------------------------------------------------------- #


def test_plain_updates_still_keep_only_the_newest_three(tmp_path):
    d = str(tmp_path / 'b')
    for i in range(6):
        ab.take(d, '2.1.2', lambda: (0, dump_of('x%d' % i), ''), lambda m: None,
                now=1_800_000_000 + i * 60)

    assert len(ab.list_backups(d)) == ab.KEEP


def test_the_extra_dump_is_one_file_and_ages_out_at_the_next_release(tmp_path):
    d = str(tmp_path / 'b')
    t = [1_800_000_000]

    def take(version):
        t[0] += 60
        ab.take(d, version, lambda: (0, dump_of(version), ''), lambda m: None, now=t[0])

    take('1.138.0')
    for _ in range(6):
        take('2.1.2')
    held = sorted(b['version'] for b in ab.list_backups(d))
    assert held == ['1.138.0', '2.1.2', '2.1.2', '2.1.2'], held

    take('2.2.0')   # the next real update: the 1.138.0 dump is no longer the newest different one
    held = sorted(b['version'] for b in ab.list_backups(d))
    assert held == ['2.1.2', '2.1.2', '2.2.0'], held


def test_another_deployments_dumps_are_never_counted(tmp_path):
    a, b = str(tmp_path / 'atlas'), str(tmp_path / 'atlas-corona')
    ab.take(a, '1.138.0', lambda: (0, dump_of('a'), ''), lambda m: None, now=1_800_000_060)
    for i in range(5):
        ab.take(b, '2.1.2', lambda: (0, dump_of('b'), ''), lambda m: None,
                now=1_800_000_120 + i * 60)

    assert [x['version'] for x in ab.list_backups(a)] == ['1.138.0']
    assert len(ab.list_backups(b)) == ab.KEEP


# --------------------------------------------------------------------------- #
# Deploy on a built deployment
# --------------------------------------------------------------------------- #


@pytest.fixture
def redeploy(box, monkeypatch):
    """`deploy` run for real up to the git checkout, which is replaced by a recorder."""
    events = box['events']
    monkeypatch.setattr(atlas, '_plog', lambda m: events.append(('log', m)))
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [])
    monkeypatch.setattr(atlas, 'instance_is_stranded', lambda c, i: False)
    monkeypatch.setattr(atlas, 'instance_is_built', lambda c, i, p=None: True)
    monkeypatch.setattr(atlas, '_resolve_install_target',
                        lambda c, plog: ('v2.1.2', 'e580fa6618fc9dbfe2b782f7ca9ff980fd813f2b'))
    monkeypatch.setattr(atlas, '_is_pin_fallback', lambda t, e: False)

    def git(*args, **kwargs):
        events.append(('git', args))
        raise Stop()

    ctx = dict(box['ctx'])
    ctx['_docker_probe'] = lambda: (0, 'Docker version 27')
    ctx['_module_git'] = git

    def go():
        job = {}
        atlas.deploy(ctx, job, {'slug': None})
        return job, chr(10).join(str(e[1]) for e in events if e[0] == 'log')

    return go


def test_deploy_on_a_finished_deployment_dumps_before_the_checkout_moves(box, redeploy):
    box['st']['settings']['atlas_commit_sha'] = 'aaaa1111'   # a deploy finished before
    box['st']['head'] = 'aaaa1111'

    job, log = redeploy()

    kinds = [e[0] for e in box['events'] if e[0] in ('dump', 'git')]
    assert kinds == ['dump', 'git'], kinds
    found = backups(box)
    assert [b['version'] for b in found] == ['1.138.0'], found
    assert open(found[0]['path'], 'rb').read() == dump_of('first')
    assert 'Database backed up' in log, log


def test_deploy_stops_when_the_dump_fails_and_changes_nothing(box, redeploy):
    box['st']['settings']['atlas_commit_sha'] = 'aaaa1111'
    box['st']['dump_rc'] = 1

    job, log = redeploy()

    kinds = [e[0] for e in box['events']]
    assert 'git' not in kinds, kinds
    assert job['error'] is True and not job.get('complete'), job
    assert 'nothing was changed' in log, log
    assert backups(box) == []


def test_deploy_of_a_deployment_that_never_finished_takes_no_dump(box, redeploy):
    """A first deploy that failed halfway has no recorded commit and nothing worth keeping.
    Refusing its repair because a dump cannot be made would trap it."""
    box['st']['dump_rc'] = 1   # a dump would fail, and must not be tried

    job, log = redeploy()

    kinds = [e[0] for e in box['events']]
    assert 'dump' not in kinds and 'git' in kinds, kinds


def test_deploy_after_an_interrupted_deploy_keeps_the_old_dump(box, redeploy):
    """The same protection holds on the Deploy path: dump, checkout moved, died, run again."""
    box['st']['settings']['atlas_commit_sha'] = 'aaaa1111'
    box['st']['head'] = 'aaaa1111'
    redeploy()
    assert [b['version'] for b in backups(box)] == ['1.138.0']

    box['st']['installed'] = '2.1.2'   # the checkout moved to the new release, then it died
    for i in range(3):
        box['st']['label'] = 'again-%d' % i
        redeploy()

    versions = [b['version'] for b in backups(box)]
    assert '1.138.0' in versions and versions.count('2.1.2') == 3, versions


# --------------------------------------------------------------------------- #
# Update All
# --------------------------------------------------------------------------- #


def test_update_all_says_not_updated_for_a_refused_downgrade(box, monkeypatch):
    """Installed 2.3.0, the channel offers 2.2.2: Update refuses. Update All used to report that
    deployment as `updated to 2.3.0`."""
    box['st']['installed'] = '2.3.0'
    box['st']['target'] = '2.2.2'
    inst = {'slug': None}
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [inst])
    monkeypatch.setattr(atlas, 'compose_projects_present', lambda c=None: {'takmdm'})
    monkeypatch.setattr(atlas, 'instance_is_built', lambda c, i, p=None: True)
    monkeypatch.setattr(atlas, '_reconcile_access', lambda *a, **k: None)
    monkeypatch.setattr(atlas, '_run_update_recorded',
                        lambda ctx, i=None: atlas._run_update(ctx, i))

    atlas._run_update_all(box['ctx'])

    status = atlas._update_all_status
    assert status['results'][0]['ok'] is None, status['results']
    assert 'not updated' in status['results'][0]['detail'], status['results']
    assert 'updated to' not in status['results'][0]['detail']
    log = chr(10).join(status['log'])
    assert 'Every finished deployment is on the newest release' not in log, log
    assert status['complete'] and not status['error']
    assert not [e for e in box['events'] if e[0] in ('dump', 'compose')], box['events']


def test_update_all_still_says_updated_when_it_updated(box, monkeypatch):
    inst = {'slug': None}
    monkeypatch.setattr(atlas, 'load_instances', lambda c: [inst])
    monkeypatch.setattr(atlas, 'compose_projects_present', lambda c=None: {'takmdm'})
    monkeypatch.setattr(atlas, 'instance_is_built', lambda c, i, p=None: True)

    def fake_update(ctx, i=None):
        slot = atlas._update_slot(i)
        slot.update({'running': False, 'complete': True, 'error': False, 'refused': False,
                     'log': ['ok']})
        box['st']['installed'] = '2.1.2'

    monkeypatch.setattr(atlas, '_run_update_recorded', fake_update)

    atlas._run_update_all(box['ctx'])

    status = atlas._update_all_status
    assert status['results'][0]['ok'] is True and 'updated to 2.1.2' in status['results'][0]['detail']
    assert 'Every finished deployment is on the newest release' in chr(10).join(status['log'])
