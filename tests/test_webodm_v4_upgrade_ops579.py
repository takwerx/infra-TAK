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
"""WebODM 3.3.1 → 4.0.0 (ops #579): Django 2.2 (end of life) → 5.2, PostgreSQL 9.5 → 18.

The 4.x database image upgrades a 9.5 data dir in place on its first start, one way. Update
must check there is room, dump the 9.5 database before the new containers start, and put the
previous version and its data back by itself when the upgrade or the first start fails.
"""

import ast
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

OLD = '''services:
  wo_db:
    image: webodm/webodm_db@sha256:03f18ec0089325ec2b8975ba1781277bcdc212b6d86c9de33f6409d313e90430
    container_name: wo_db
  wo_broker:
    image: redis:8.10.2-alpine
    container_name: wo_broker
  wo_webapp:
    image: webodm/webodm_webapp:3.3.1
    container_name: webapp
    entrypoint: /bin/bash -c "pip uninstall -y -q olefile >/dev/null 2>&1; service cron start"
  wo_worker:
    image: webodm/webodm_webapp:3.3.1
    container_name: wo_worker
    entrypoint: /bin/bash -c "pip uninstall -y -q olefile >/dev/null 2>&1; /webodm/worker.sh start"
  wo_nodeodm:
    image: webodm/nodeodx:2.4.0
    container_name: wo_nodeodm
'''

WANT = {'WEBODM_VERSION', 'WEBODM_IMAGES', '_webodm_pin_images', 'WEBODM_OLEFILE_STRIP',
        '_webodm_strip_olefile', 'WEBODM_DB_VOLUME', 'WEBODM_DB_DUMP_PREFIX', 'WEBODM_UPGRADE_WAIT_S',
        '_webodm_db_sh', '_webodm_db_needs_upgrade', '_webodm_db_room_check', '_webodm_backup_db_95',
        '_webodm_wait_upgraded', '_webodm_restore_95', '_run_webodm_update'}


class Box:
    """A fake WebODM box: the compose file, the db volume state and every command run."""

    def __init__(self, pg='9.5', used_kb=40_000, free_kb=10_000_000, dump_ok=True,
                 upgrade_fails=False, pull_ok=True):
        self.compose = OLD
        self.pg, self.used_kb, self.free_kb = pg, used_kb, free_kb
        self.dump_ok, self.upgrade_fails, self.pull_ok = dump_ok, upgrade_fails, pull_ok
        self.calls, self.writes, self.running_images = [], [], None

    def _r(self, rc=0, out='', err=''):
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    def run(self, argv, **kw):
        self.calls.append(('run', tuple(argv)))
        if argv[:5] == ['docker', 'exec', '-u', 'postgres', 'wo_db']:
            cmd = argv[-1]
            if 'PG_VERSION' in cmd:
                return self._r(out=self.pg + '\n')
            if cmd.startswith('du -sk'):
                return self._r(out=f'{self.used_kb}\t/var/lib/postgresql/data\nFilesystem 1024-blocks Used '
                                   f'Available Capacity Mounted\n/dev/root 100 50 {self.free_kb} 50% /\n')
            if 'pg_dumpall' in cmd:
                return self._r(out='1\n') if self.dump_ok else self._r(rc=1, err='pg_dumpall: boom')
        if argv[:3] == ['docker', 'logs', 'wo_db']:
            return self._r(out='UPGRADE FAILED. ...' if self.upgrade_fails else 'Upgrade complete.')
        if argv[:3] == ['docker', 'exec', 'webapp']:
            return self._r(rc=0 if 'webodm_webapp:3.3.1' in (self.running_images or '') or not self.upgrade_fails else 7)
        return self._r()

    def compose_cmd(self, d, action, timeout=300):
        self.calls.append(('compose', action))
        if action == 'pull':
            return self._r(0 if self.pull_ok else 1, err='' if self.pull_ok else 'pull access denied')
        if action == 'up -d':
            self.running_images = self.compose
        return self._r()

    def write(self, path, content, **kw):
        self.writes.append(content)
        self.compose = content


def _run(box):
    ns = {'re': re, 'os': __import__('os'),
          'time': types.SimpleNamespace(time=lambda: 0, sleep=lambda s: None,
                                        strftime=lambda f: '20261109-060000')}
    for node in TREE.body:
        names = ({t.id for t in node.targets if isinstance(t, ast.Name)} if isinstance(node, ast.Assign)
                 else {node.name} if isinstance(node, ast.FunctionDef) else set())
        if names & WANT:
            exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
    # _webodm_wait_upgraded's clock: let each wait loop run a few rounds, then time out
    ticks = iter(range(0, 10 ** 6, 400))
    ns['time'].time = lambda: next(ticks)
    status = {'running': True, 'complete': False, 'error': False, 'log': []}
    ns.update({
        '_webodm_update_status': status,
        '_webodm_dir': lambda: '/home/takwerx/webodm',
        '_read_priv': lambda p: box.compose,
        '_write_priv': box.write,
        '_webodm_compose': box.compose_cmd,
        '_sudo_wrap': lambda a: a,
        'subprocess': types.SimpleNamespace(run=box.run),
    })
    ns['_run_webodm_update']()
    return status, ns


def _images(compose):
    return dict(re.findall(r'^  (\w+):\n(?:    [^\n]*\n)*?    image: ([^\n]*)$', compose, re.M))


def test_pins_move_to_webodm_4_and_postgres_18_by_digest():
    _, ns = _run(Box(pg='18'))
    imgs = ns['WEBODM_IMAGES']
    assert ns['WEBODM_VERSION'] == '4.0.0'
    assert imgs['wo_webapp'] == imgs['wo_worker'] == 'webodm/webodm_webapp:4.0.0'
    assert re.fullmatch(r'webodm/webodm_db:18@sha256:[0-9a-f]{64}', imgs['wo_db'])


def test_update_from_3x_checks_room_dumps_then_starts_4x():
    box = Box()
    status, ns = _run(box)
    assert status['complete'] and not status['error'], status['log']
    order = [c for c in box.calls if c[0] == 'compose' or 'pg_dumpall' in ' '.join(c[1]) or 'du -sk' in ' '.join(c[1])]
    kinds = [('room' if 'du -sk' in ' '.join(c[1]) else 'dump' if c[0] == 'run' else c[1]) for c in order]
    # room check before anything changes, pull while 3.x still serves, dump after webapp/worker stop
    assert kinds.index('room') < kinds.index('pull') < kinds.index('dump') < kinds.index('up -d')
    stop = box.calls.index(('run', ('docker', 'stop', 'webapp', 'wo_worker')))
    dump = next(i for i, c in enumerate(box.calls) if 'pg_dumpall' in ' '.join(c[1]))
    assert stop < dump
    assert _images(box.running_images) == ns['WEBODM_IMAGES']
    assert any('backup-infratak-20261109-060000-pg95.sql.gz' in m for m in status['log'])


def test_update_already_on_18_makes_no_backup_and_no_stop():
    box = Box(pg='18')
    status, _ = _run(box)
    assert status['complete']
    flat = ' '.join(' '.join(map(str, c[1])) for c in box.calls)
    assert 'pg_dumpall' not in flat and 'docker stop' not in flat and 'du -sk' not in flat


def test_not_enough_disk_changes_nothing():
    box = Box(used_kb=1_000_000, free_kb=3_000_000)
    status, _ = _run(box)
    assert status['error'] and 'not enough free disk' in status['error']
    assert box.writes == [] and box.compose == OLD
    assert ('compose', 'pull') not in box.calls and ('compose', 'up -d') not in box.calls


def test_failed_pull_puts_the_old_compose_back():
    box = Box(pull_ok=False)
    status, _ = _run(box)
    assert status['error'] and box.compose == OLD
    assert ('compose', 'up -d') not in box.calls


def test_failed_dump_starts_3x_again_without_upgrading():
    box = Box(dump_ok=False)
    status, _ = _run(box)
    assert status['error'] and 'backup failed' in status['error']
    assert box.compose == OLD and _images(box.running_images)['wo_webapp'].endswith(':3.3.1')


def test_failed_upgrade_restores_95_copy_and_old_compose():
    box = Box(upgrade_fails=True)
    status, _ = _run(box)
    assert status['error'] and 'previous version and its data are back' in status['error']
    restore = [c for c in box.calls if c[0] == 'compose' and c[1].startswith('run --rm --no-deps')]
    assert len(restore) == 1
    script = restore[0][1]
    # only from the untouched copy, never deleting the copies or the upgrade log
    assert 'backup-9.5/PG_VERSION' in script and 'cp -a backup-9.5/. .' in script
    assert '! -name "backup-*"' in script and '! -name upgrade.log' in script
    assert box.compose == OLD and _images(box.running_images)['wo_webapp'].endswith(':3.3.1')
    # stop the stack before touching the data dir
    assert box.calls.index(('compose', 'stop')) < box.calls.index(restore[0])
