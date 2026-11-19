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
"""ops #941: a Docker TAK box whose certificate folder an OLD restore re-owned to uid 1000.

Releases up to 10.4.1 chowned the whole folder to a made-up 1000:0 on a restore. The hardened
container runs as 1001:0 and makeCert.sh runs `chmod og-rwx takserver.key` there, which fails on
a file owned by another uid, so Rotate Intermediate CA stopped at Step 3. The console now gives
exactly those entries back to the container's user, at start and at the top of the rotation.
"""

import ast
import os
import pathlib
import types

import pytest

pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

CGID = 0


def _src(kind, name):
    for n in TREE.body:
        if kind == 'def' and isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
        if kind == 'assign' and isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed (ops #941)')


class _Box:
    """An in-memory certificate folder: path -> (uid, gid). Real directory, fake owners.

    `chown -R -h --from=U:G NEW:GRP DIR` on the host (or inside the root container) changes
    exactly the entries that match U:G, like GNU chown. `host_works=False` makes the host
    command do nothing (the quiet failure _container_own_tree warns about)."""

    def __init__(self, tmp_path, owners, host_works=True):
        self.d = tmp_path / 'files'
        self.d.mkdir()
        self.owners = {str(self.d): owners.pop('.', (1000, CGID))}
        for name, own in owners.items():
            (self.d / name).write_text('x')
            self.owners[str(self.d / name)] = own
        self.host_works = host_works
        self.calls = []

    def lstat(self, p):
        uid, gid = self.owners[str(p)]
        return types.SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=0o100664)

    def run(self, argv, **kw):
        argv = list(argv)
        self.calls.append(argv)
        if 'docker' in argv:
            inner = argv[-1]
            assert inner.startswith('chown -R -h --from='), inner
            self._chown(inner.split()[3], inner.split()[4])
        elif 'chown' in argv and self.host_works:
            i = argv.index('chown')
            self._chown(argv[i + 3], argv[i + 4])
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    def _chown(self, frm, new):
        fu, fg = (int(x) for x in frm.split('=')[1].split(':'))
        nu, ng = (int(x) for x in new.split(':'))
        for p, (u, g) in list(self.owners.items()):
            if (u, g) == (fu, fg):
                self.owners[p] = (nu, ng)


def _ns(box, container=True, ids=('1001', '0')):
    ns = {'os': types.SimpleNamespace(path=os.path, walk=os.walk, lstat=box.lstat,
                                      scandir=os.scandir),
          'subprocess': types.SimpleNamespace(run=box.run),
          '_tak_is_container': lambda: container,
          '_sudo_wrap': lambda a: list(a),
          'TAK_CONTAINER': 'takserver',
          '_CERT_FILES_DIR': str(box.d),
          'audit': lambda *a, **k: ns.setdefault('_audit', []).append(a)}
    if ids is None:
        def _ids():
            return (None, None)
    else:
        def _ids():
            return ids
    ns['_tak_container_ids'] = _ids
    ns['os'].path = types.SimpleNamespace(isdir=os.path.isdir, join=os.path.join,
                                          realpath=os.path.realpath)
    exec(compile(_src('assign', '_RESTORE_MADE_UP_UID'), 'app.py', 'exec'), ns)
    exec(compile(_src('def', '_tak_cert_owner_repair'), 'app.py', 'exec'), ns)
    return ns


def _owners(box):
    return {os.path.basename(p): o for p, o in box.owners.items()}


def test_old_restore_owners_go_back_to_the_container_user(tmp_path):
    """The folder and every entry at 1000:0 become 1001:0; nothing else changes."""
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0), 'takserver.key': (1000, 0),
                          'admin.p12': (1001, 0)})
    ns = _ns(box)
    logs = []
    assert ns['_tak_cert_owner_repair'](logs.append) == 3
    got = _owners(box)
    assert got['files'] == (1001, 0) and got['ca.pem'] == (1001, 0) and got['takserver.key'] == (1001, 0)
    assert got['admin.p12'] == (1001, 0)
    assert len(logs) == 1 and 'old restore' in logs[0] and '1001:0' in logs[0]
    assert ns['_audit']


def test_only_the_old_restore_signature_is_changed(tmp_path):
    """Another owner, or uid 1000 with a different group, is somebody's choice: left alone."""
    box = _Box(tmp_path, {'.': (1001, 0), 'a': (1000, 1000), 'b': (0, 0), 'c': (1000, 0),
                          'd': (1001, 0), 'e': (33, 0)})
    ns = _ns(box)
    assert ns['_tak_cert_owner_repair']() == 1
    got = _owners(box)
    assert got['a'] == (1000, 1000) and got['b'] == (0, 0) and got['e'] == (33, 0)
    assert got['c'] == (1001, 0) and got['d'] == (1001, 0)


def test_the_command_only_touches_the_signature_and_never_follows_links(tmp_path):
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0)})
    ns = _ns(box)
    ns['_tak_cert_owner_repair']()
    argv = box.calls[0]
    assert argv[:4] == ['chown', '-R', '-h', '--from=1000:0']
    assert argv[4] == '1001:0' and argv[5] == str(box.d)


def test_nothing_to_repair_runs_no_command(tmp_path):
    box = _Box(tmp_path, {'.': (1001, 0), 'ca.pem': (1001, 0)})
    ns = _ns(box)
    logs = []
    assert ns['_tak_cert_owner_repair'](logs.append) == 0
    assert box.calls == [] and logs == []


def test_second_run_changes_nothing(tmp_path):
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0)})
    ns = _ns(box)
    assert ns['_tak_cert_owner_repair']() == 2
    n_calls = len(box.calls)
    assert ns['_tak_cert_owner_repair']() == 0
    assert len(box.calls) == n_calls


def test_native_tak_server_is_left_alone(tmp_path):
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0)})
    ns = _ns(box, container=False)
    assert ns['_tak_cert_owner_repair']() == 0
    assert box.calls == []


def test_stock_image_that_runs_as_1000_is_left_alone(tmp_path):
    """On the stock image 1000:0 IS the container's user: nothing is wrong."""
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0)})
    ns = _ns(box, ids=('1000', '0'))
    assert ns['_tak_cert_owner_repair']() == 0
    assert box.calls == []


def test_container_ids_unknown_means_no_guess(tmp_path):
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0)})
    ns = _ns(box, ids=None)
    assert ns['_tak_cert_owner_repair']() == 0
    assert box.calls == []
    assert _owners(box)['ca.pem'] == (1000, 0)


def test_quiet_host_failure_falls_back_to_root_inside_the_image(tmp_path):
    """A host chown on the bundle tree can say success and change nothing: ask the image."""
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0)}, host_works=False)
    ns = _ns(box)
    assert ns['_tak_cert_owner_repair']() == 2
    assert any('docker' in c for c in box.calls)
    assert _owners(box)['ca.pem'] == (1001, 0)


def test_a_repair_that_does_not_take_is_reported(tmp_path):
    box = _Box(tmp_path, {'.': (1000, 0), 'ca.pem': (1000, 0)}, host_works=False)
    ns = _ns(box)
    box.run = lambda argv, **kw: (box.calls.append(list(argv)) or types.SimpleNamespace(
        returncode=1, stdout='', stderr='no'))
    ns['subprocess'].run = box.run
    logs = []
    assert ns['_tak_cert_owner_repair'](logs.append) == 0
    assert logs and logs[-1].startswith('⚠') and 'Rotate CA may fail' in logs[-1]


# ── where it is called ───────────────────────────────────────────────────────────────────────

def test_rotate_intermediate_ca_repairs_the_owners_before_step_1():
    rot = _src('def', 'takserver_rotate_intca')
    assert '_tak_cert_owner_repair(' in rot
    assert rot.index('_tak_cert_owner_repair(') < rot.index('Step 1/7')


def test_console_start_repairs_the_owners_before_the_ca_key_lockdown():
    i = APP.index('_tak_cert_owner_repair(lambda m: print(f"Startup migration: {m}"')
    j = APP.index('_tak_ca_private_lockdown_all(lambda m: print(f"Startup migration')
    assert i < j


def test_the_signature_is_the_uid_the_old_restore_invented():
    """If ops #839's old fallback uid ever changes, this signature has to change with it."""
    ns = {}
    exec(compile(_src('assign', '_RESTORE_MADE_UP_UID'), 'app.py', 'exec'), ns)
    assert ns['_RESTORE_MADE_UP_UID'] == 1000
