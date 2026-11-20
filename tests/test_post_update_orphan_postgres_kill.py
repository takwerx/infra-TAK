# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""v10.4.3 W4: the post-update "orphaned postgres" kill never touches another container.

Before: the shm-recreate pass recorded every UID-70 `postgres` PID, recreated
authentik-postgresql-1, and `kill -9`ed (before ∩ after). tak-portal-postgres is UID 70
too, so its PIDs were in both sets: a root console killed TAK Portal's database; a non-root
console's bare `kill` failed and still logged "killed orphaned postgres process" ×21 (akres
E3c). Now one helper, _kill_orphan_postgres(), kills only a UID-70 postgres whose cgroup
names a container that is not running (and, for the shm pass, is the old Authentik PG
container), through _sudo_wrap, logging "killed" only on rc 0. The broker re-proves the
same thing in _check_kill before it runs `kill` as root.
"""
import ast
import importlib.util
import os
import pathlib
import re
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER = REPO / 'broker' / 'takwerx_broker.py'

A_OLD = 'a' * 64      # authentik-postgresql-1 before the recreate (gone)
A_NEW = 'e' * 64      # authentik-postgresql-1 after the recreate (running)
PORTAL = 'b' * 64     # tak-portal-postgres (running) — UID 70 as well
POSTGIS = 'c' * 64    # cloudtak-postgis-1 (running)
OTHER_GONE = 'd' * 64  # some other container that is gone

RUNNING = {A_NEW, PORTAL, POSTGIS}


def _cg(cid):
    return f'0::/system.slice/docker-{cid}.scope\n'


# pid -> (uid, comm, cgroup)
PROCS = {
    '101': ('70', 'postgres', _cg(A_OLD)),          # the real orphan of the shm recreate
    '102': ('70', 'postgres', _cg(PORTAL)),         # live TAK Portal PG — never
    '103': ('70', 'postgres', _cg(POSTGIS)),        # live CloudTAK postgis — never
    '104': ('70', 'postgres', '0::/system.slice/postgresql.service\n'),  # host, no container
    '105': ('999', 'postgres', _cg(OTHER_GONE)),    # not UID 70
    '106': ('70', 'postgres', _cg(OTHER_GONE)),     # orphan of a different gone container
    '107': ('70', 'postgres', _cg(A_NEW)),          # the new live Authentik PG — never
    '108': ('70', 'bash', _cg(A_OLD)),              # not postgres
}


def _fake_proc_files(procs):
    files = {}
    for pid, (uid, comm, cg) in procs.items():
        files[f'/proc/{pid}/status'] = f'Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n'
        files[f'/proc/{pid}/comm'] = comm + '\n'
        files[f'/proc/{pid}/cgroup'] = cg
    return files


class _FakeFile:
    def __init__(self, text):
        self._t = text

    def read(self):
        return self._t

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _app_funcs():
    tree = ast.parse(APP)
    want = {'_pg_proc_container_id', '_container_postgres_pids', '_kill_orphan_postgres'}
    parts = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in want:
            parts.append(ast.get_source_segment(APP, node))
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) == '_PG_CGROUP_CONTAINER_RE'):
            parts.append(ast.get_source_segment(APP, node))
    assert len(parts) == 4, 'W4 helpers missing from app.py'
    return '\n\n'.join(parts)


class Box:
    def __init__(self, procs=PROCS, running=RUNNING, ps_rc=0, kill_rc=0):
        self.files = _fake_proc_files(procs)
        self.pids = list(procs)
        self.running = running
        self.ps_rc = ps_rc
        self.kill_rc = kill_rc
        self.calls = []
        self.logs = []

    def open(self, path, *a, **k):
        self.calls.append(('open', path))
        if path not in self.files:
            raise FileNotFoundError(path)
        return _FakeFile(self.files[path])

    def listdir(self, path):
        assert path == '/proc'
        return self.pids + ['self', 'meminfo']

    def run(self, cmd, **kw):
        self.calls.append(('run', list(cmd)))
        assert cmd[0] == 'BROKER', 'privileged command not routed through _sudo_wrap'
        argv = cmd[1:]
        if argv[:2] == ['docker', 'ps']:
            return types.SimpleNamespace(returncode=self.ps_rc, stdout='\n'.join(self.running) + '\n', stderr='')
        if argv[0] == 'kill':
            return types.SimpleNamespace(returncode=self.kill_rc, stdout='',
                                         stderr='' if self.kill_rc == 0 else 'Denied: not an orphan')
        raise AssertionError(f'unexpected command {argv}')

    def ns(self):
        g = {
            're': re,
            'open': self.open,
            'os': types.SimpleNamespace(listdir=self.listdir),
            'subprocess': types.SimpleNamespace(run=self.run),
            '_sudo_wrap': lambda c: ['BROKER'] + list(c),
        }
        exec(compile(_app_funcs(), 'app.py[W4]', 'exec'), g)
        return g

    def killed(self):
        return [c[1][3] for c in self.calls if c[0] == 'run' and c[1][1] == 'kill']


def test_shm_pass_kills_only_the_old_authentik_containers_postgres():
    box = Box()
    killed = box.ns()['_kill_orphan_postgres'](box.logs.append, owner_ids={A_OLD})
    assert killed == ['101'] and box.killed() == ['101']
    assert any('killed orphaned postgres PID 101' in m for m in box.logs)


def test_live_tak_portal_postgres_is_never_killed():
    """The acceptance case: a PID set containing a live tak-portal-postgres PID."""
    for owners in (None, {A_OLD}, {A_OLD, PORTAL}):
        box = Box()
        box.ns()['_kill_orphan_postgres'](box.logs.append, owner_ids=owners)
        assert '102' not in box.killed()
        assert not any('PID 102' in m for m in box.logs)


def test_unowned_pass_kills_only_gone_container_uid70_postgres():
    box = Box()
    killed = box.ns()['_kill_orphan_postgres'](box.logs.append, label='final pass')
    assert killed == ['101', '106']
    for pid in ('102', '103', '104', '105', '107', '108'):
        assert pid not in box.killed()
    assert all(m.startswith('final pass — ') for m in box.logs)


def test_failed_kill_is_never_logged_as_killed():
    box = Box(kill_rc=1)
    killed = box.ns()['_kill_orphan_postgres'](box.logs.append)
    assert killed == []
    assert not any('killed orphaned' in m for m in box.logs)
    assert sum('could not kill orphaned postgres PID' in m for m in box.logs) == 2


@pytest.mark.parametrize('ps_rc,running', [(1, RUNNING), (0, set())])
def test_no_kill_when_running_set_is_unknown(ps_rc, running):
    box = Box(ps_rc=ps_rc, running=running)
    assert box.ns()['_kill_orphan_postgres'](box.logs.append) == []
    assert box.killed() == []


def test_proc_scanned_before_docker_ps():
    """A container that starts between the two reads must already be in the running set."""
    box = Box()
    box.ns()['_kill_orphan_postgres'](box.logs.append)
    first_ps = next(i for i, c in enumerate(box.calls) if c[0] == 'run')
    last_open = max(i for i, c in enumerate(box.calls[:first_ps + 1]) if c[0] == 'open')
    assert last_open < first_ps
    assert not any(c[0] == 'open' for c in box.calls[first_ps:])


def test_app_has_no_uid70_intersection_or_bare_kill_left():
    assert "$1==70" not in APP, 'UID-70 ps|awk orphan scan is back — use _kill_orphan_postgres()'
    for m in re.finditer(r"\[\s*'kill'\s*,\s*'-9'", APP):
        line = APP[APP.rfind('\n', 0, m.start()) + 1:APP.find('\n', m.start())]
        assert '_sudo_wrap(' in line, f'bare kill -9 outside _sudo_wrap: {line.strip()}'
    assert APP.count('_kill_orphan_postgres(') >= 4   # def + three post-update passes


# ── broker side: _check_kill re-proves the target before running kill as root ──

@pytest.fixture
def broker(monkeypatch):
    spec = importlib.util.spec_from_file_location('tb_kill_test', BROKER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    box = Box()
    monkeypatch.setattr(m, 'open', box.open, raising=False)
    monkeypatch.setattr(m, '_running_container_ids', lambda: set(RUNNING))
    return m


def test_broker_allows_kill_of_orphan(broker):
    assert broker.check_exec(['kill', '-9', '101']) == ['kill', '-9', '101']
    assert broker.check_exec(['kill', '-9', '106']) == ['kill', '-9', '106']


@pytest.mark.parametrize('pid', ['102', '103', '104', '105', '107', '108', '999999'])
def test_broker_denies_kill_of_anything_else(broker, pid):
    with pytest.raises(broker.Denied):
        broker.check_exec(['kill', '-9', pid])


@pytest.mark.parametrize('argv', [
    ['kill', '101'], ['kill', '-15', '101'], ['kill', '-KILL', '101'], ['kill', '-9', '-1'],
    ['kill', '-9', '1'], ['kill', '-9', '0'], ['kill', '-9', '101', '102'], ['kill', '-9', '١٠١'],
    ['/tmp/x/kill', '-9', '101'], ['/bin/kill', '-9', '101'], ['kill', '-9', '101 '],
])
def test_broker_denies_other_kill_shapes(broker, argv):
    with pytest.raises(broker.Denied):
        broker.check_exec(argv)


@pytest.mark.parametrize('rc,out', [(0, ''), (0, '\n'), (1, 'a' * 64 + '\n')])
def test_broker_never_kills_when_the_running_set_is_unknown(monkeypatch, rc, out):
    # Security review L3: an empty `docker ps` (docker hiccup, other runtime) or a failed one
    # must deny — never read as "every container is gone".
    spec = importlib.util.spec_from_file_location('tb_kill_test2', BROKER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m.shutil, 'which', lambda n, path=None: '/usr/bin/docker')
    monkeypatch.setattr(m.subprocess, 'run',
                        lambda *a, **k: types.SimpleNamespace(returncode=rc, stdout=out, stderr=''))
    with pytest.raises(m.Denied):
        m._running_container_ids()
