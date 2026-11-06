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
"""infra-TAK #421 — the module ownership self-heal never re-owns container data.

A non-root CloudTAK Update ran _module_checkout_ownership_selfheal() on ~/CloudTAK. The
operator's postgis bind-mount (.docker-postgres/postgres-data, uid 70, mode 700) was
foreign-owned and unreadable to the console, so the walk saw it as one entry and chowned it
to takwerx. Postgres refused every new connection (`could not open file
"global/pg_filenode.map": Permission denied`) until it was chowned back by hand. The same
run also called the heal "did not complete" over an operator's chattr +i override file, and
the 176 entries it did re-own were nowhere in the log.

Runs the real function on a real temp tree; only ownership, `os.access`, chown, docker and
lsattr are faked, so the test also holds when CI runs as root.
"""

import os
import pathlib
import re
import subprocess
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

FOREIGN_UID = 70           # postgres in the postgis alpine image


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    return m.group(0) if m else ''


class Box:
    """A module checkout on disk with fake owners, permissions, chown, docker and lsattr."""

    def __init__(self, root, foreign=(), unreadable=(), immutable=(), binds=(),
                 chown_fails=()):
        self.root = str(root)
        self.uid = os.getuid()
        self.foreign = {self.p(r) for r in foreign}
        self.unreadable = {self.p(r) for r in unreadable}
        self.immutable = {self.p(r) for r in immutable}
        self.binds = [self.p(r) for r in binds]
        self.chown_fails = {self.p(r) for r in chown_fails}
        self.chowned = []
        self.logs = []

        real_os = os
        fake_os = types.ModuleType('os')
        fake_os.__dict__.update(real_os.__dict__)
        box = self

        def lstat(p):
            st = real_os.lstat(p)
            if str(p) in box.foreign:
                return types.SimpleNamespace(st_uid=FOREIGN_UID, st_mode=st.st_mode)
            return st

        def access(p, mode):
            return str(p) not in box.unreadable

        fake_os.lstat = lstat
        fake_os.access = access
        fake_os.getuid = lambda: box.uid

        def run(argv, **kw):
            if argv[0] == 'chown':
                args = argv[1:]
                paths = [a for a in args if a.startswith('/')]
                err = []
                for p in paths:
                    box.chowned.append(p)
                    if p in box.immutable or p in box.chown_fails:
                        why = ('Operation not permitted' if p in box.immutable
                               else 'Read-only file system')
                        err.append(f"/usr/bin/chown: changing ownership of '{p}': {why}")
                    else:
                        if '-R' in args:
                            box.foreign = {f for f in box.foreign
                                           if not (f == p or f.startswith(p + os.sep))}
                        box.foreign.discard(p)
                return subprocess.CompletedProcess(argv, 1 if err else 0, '', '\n'.join(err))
            if argv[:2] == ['docker', 'ps']:
                return subprocess.CompletedProcess(argv, 0, 'c1\nc2\n', '')
            if argv[:2] == ['docker', 'inspect']:
                out = ''.join(f'{b}\n' for b in box.binds) + '/var/lib/elsewhere\n'
                return subprocess.CompletedProcess(argv, 0, out, '')
            if argv[0] == 'lsattr':
                flags = '----i---------e-------' if argv[-1] in box.immutable else '--------------e-------'
                return subprocess.CompletedProcess(argv, 0, f'{flags} {argv[-1]}\n', '')
            raise AssertionError(f'unexpected command: {argv}')

        ns = {
            'os': fake_os, 're': re,
            'subprocess': types.SimpleNamespace(run=run, CompletedProcess=subprocess.CompletedProcess),
            '_sudo_wrap': lambda cmd: list(cmd),
        }
        src = '\n'.join(_fn(n) for n in ('_container_bind_dirs', '_path_is_immutable',
                                          '_module_checkout_ownership_selfheal'))
        assert '_module_checkout_ownership_selfheal' in src
        exec(compile(src, 'app.py', 'exec'), ns)
        self.heal = ns['_module_checkout_ownership_selfheal']

    def p(self, rel):
        return os.path.join(self.root, rel)

    def run(self):
        return self.heal(self.root, plog=self.logs.append)

    def touched(self, rel):
        top = self.p(rel)
        return [c for c in self.chowned if c == top or c.startswith(top + os.sep)]


def _tree(root):
    for d in ('.git/objects', 'api/lib', '.docker-postgres/postgres-data/global',
              'pgdata/global', 'redis-data', 'app/plugins/x'):
        (root / d).mkdir(parents=True)
    for f in ('api/lib/a.js', 'app/plugins/x/index.js', 'docker-compose.override.yml',
              '.docker-postgres/postgres-data/global/pg_filenode.map',
              'pgdata/global/pg_filenode.map', 'redis-data/dump.rdb'):
        (root / f).write_text('x')
    return root


def test_reporter_box_postgres_data_is_never_reowned(tmp_path):
    """The exact #421 box: PGDATA uid 70 mode 700 under .docker-postgres, override +i."""
    box = Box(_tree(tmp_path),
              foreign=['api/lib/a.js', 'docker-compose.override.yml',
                       '.docker-postgres/postgres-data'],
              unreadable=['.docker-postgres/postgres-data'],
              immutable=['docker-compose.override.yml'],
              binds=['.docker-postgres/postgres-data'])
    healed, err = box.run()
    assert box.touched('.docker-postgres') == []
    assert box.p('api/lib/a.js') in box.chowned
    assert err == '', err                      # the +i override is expected, not a failure
    assert healed is True
    assert any('left immutable file' in l and 'docker-compose.override.yml' in l
               for l in box.logs), box.logs


@pytest.mark.parametrize('guard', ['name', 'unreadable', 'bind-mount'])
def test_each_guard_alone_keeps_container_data(tmp_path, guard):
    """Any one guard is enough, so a renamed or readable data dir is still safe."""
    _tree(tmp_path)
    data = {'name': '.docker-postgres/postgres-data',
            'unreadable': 'pgdata', 'bind-mount': 'redis-data'}[guard]
    box = Box(tmp_path, foreign=['api/lib/a.js', data],
              unreadable=[data] if guard == 'unreadable' else [],
              binds=[data] if guard == 'bind-mount' else [])
    healed, err = box.run()
    assert box.touched(data) == [], box.chowned
    assert box.p('api/lib/a.js') in box.chowned
    assert (healed, err) == (True, '')
    if guard != 'name':
        assert any('left alone' in l and data in l for l in box.logs), box.logs


def test_readable_foreign_worktree_is_still_healed(tmp_path):
    """The guards must not undo the original fix: root-era plugin files and .git get healed."""
    box = Box(_tree(tmp_path),
              foreign=['app/plugins/x', 'app/plugins/x/index.js', '.git/objects'])
    healed, err = box.run()
    assert (healed, err) == (True, '')
    assert box.p('app/plugins/x') in box.chowned
    assert box.p('app/plugins/x/index.js') in box.chowned
    assert box.p('.git') in box.chowned


def test_partial_heal_lists_what_it_changed(tmp_path):
    """A real failure still says "did not complete", and the log names every path it re-owned."""
    box = Box(_tree(tmp_path),
              foreign=['api/lib/a.js', 'app/plugins/x/index.js'],
              chown_fails=['app/plugins/x/index.js'])
    healed, err = box.run()
    assert healed is False
    assert 're-owned 1 of 2' in err and 'Read-only file system' in err, err
    assert any(l.strip() == 're-owned: api/lib/a.js' for l in box.logs), box.logs
    assert not any('re-owned: app/plugins/x/index.js' in l for l in box.logs), box.logs


def test_bind_mounts_outside_the_checkout_are_ignored(tmp_path):
    """docker reports every bind on the box; only ones under this module dir matter."""
    box = Box(_tree(tmp_path), foreign=['api/lib/a.js'])
    box.run()
    assert box.p('api/lib/a.js') in box.chowned
