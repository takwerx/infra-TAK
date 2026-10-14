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
"""Docker TAK: a stale PostgreSQL socket lock no longer keeps takserver-db down after a reboot.

Field 2026-10-14: after a reboot the Docker TAK database container came up running but
PostgreSQL refused to start —
    FATAL: lock file "/run/postgresql/.s.PGSQL.5432.lock" already exists
    HINT: Is another postmaster (PID 9) using socket file "/run/postgresql/.s.PGSQL.5432"?
TAK's db entrypoint does not pass the stop signal on, so PostgreSQL is always SIGKILLed and its
lock stays in the container's writable layer. Two halves: new containers get /run/postgresql as
a tmpfs (empty at every start), and existing containers are healed by the console.
"""

import pathlib
import re
import subprocess
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, name
    return m.group(0)


def _const(name):
    m = re.search(r'^%s = (?:\(.*?^\)|[^\n]*)' % re.escape(name), APP, re.S | re.M)
    assert m, name
    return m.group(0)


def _heal(audits=None):
    from datetime import datetime
    ns = {'subprocess': subprocess, 'time': time, 'datetime': datetime,
          '_sudo_wrap': lambda c: ['sudo', '-n'] + c,
          'TAK_DB_CONTAINER': 'takserver-db', 'TAK_CONTAINER': 'takserver',
          'audit': lambda *a, **k: (audits.append(a) if audits is not None else None)}
    for c in ('_TAK_DB_STALE_LOCK_PROBE', '_TAK_DB_STALE_LOCK_MIN_UP_S'):
        exec(compile(_const(c), 'app.py', 'exec'), ns)
    exec(compile(_fn('_tak_db_stale_lock_heal'), 'app.py', 'exec'), ns)
    return ns['_tak_db_stale_lock_heal']


class _R:
    def __init__(self, out='', rc=0):
        self.stdout, self.returncode = out, rc


STARTED = '2026-10-14T21:31:49.525277251Z'
T0 = 1792013509.0  # = STARTED, in epoch seconds


class Box:
    """Fake docker: answers inspect/exec/restart from a script, records every call."""

    def __init__(self, state, probe='REMOVED', health_after=('starting', 'healthy')):
        self.state, self.probe, self.calls = state, probe, []
        self.health_after = list(health_after)

    def __call__(self, argv, **kw):
        a = argv[2:]                       # drop sudo -n
        self.calls.append(a)
        if a[:2] == ['docker', 'inspect']:
            fmt = a[3]
            if '.State.Running' in fmt:
                return _R(self.state)
            return _R(self.health_after.pop(0) if self.health_after else 'starting')
        if a[:2] == ['docker', 'exec']:
            return _R(self.probe + '\n')
        return _R('')

    def restarts(self):
        return [c[2] for c in self.calls if c[:2] == ['docker', 'restart']]


def _run(box, now=T0 + 600, **kw):
    logs = []
    out = _heal(**kw)(run=box, sleep=lambda s: None, log=logs.append, now=lambda: now)
    return out, logs


def test_started_at_parses_to_the_right_epoch():
    from datetime import datetime, timezone
    assert datetime(2026, 10, 14, 21, 31, 49, tzinfo=timezone.utc).timestamp() == T0


# ── new containers: the lock cannot survive ────────────────────────────────────────────────────

def test_tmpfs_flag_is_exactly_run_postgresql():
    assert "TAK_DB_RUN_TMPFS = '--tmpfs /run/postgresql:rw,mode=1777'" in APP


def test_both_database_container_creations_use_the_tmpfs():
    runs = re.findall(r"--name \{TAK_DB_CONTAINER\}[^\n]*-d takserver_db", APP)
    assert len(runs) == 2, runs          # deploy and update
    assert all('{TAK_DB_RUN_TMPFS}' in r for r in runs)


# ── existing containers: the heal ──────────────────────────────────────────────────────────────

def test_healthy_database_is_left_alone():
    box = Box(f'true healthy {STARTED}')
    assert _run(box)[0] is None
    assert len(box.calls) == 1           # one inspect, no exec, no restart


def test_container_without_a_healthcheck_is_left_alone():
    box = Box(f'true none {STARTED}')
    assert _run(box)[0] is None and len(box.calls) == 1


def test_stopped_or_missing_container_is_left_alone():
    for state, rc in ((f'false unhealthy {STARTED}', 0), ('', 1)):
        calls = []
        out, _ = _run(lambda a, **k: (calls.append(a), _R(state, rc))[1])
        assert out is None and len(calls) == 1


def test_a_container_someone_just_started_is_left_alone():
    box = Box(f'true starting {STARTED}')
    assert _run(box, now=T0 + 30)[0] is None
    assert len(box.calls) == 1


def test_postgres_alive_means_no_restart():
    box = Box(f'true unhealthy {STARTED}', probe='alive=1')
    assert _run(box)[0] is None
    assert box.restarts() == []


def test_no_lock_means_no_restart():
    box = Box(f'true starting {STARTED}', probe='alive=0')
    assert _run(box)[0] is None
    assert box.restarts() == []


def test_stale_lock_heals_database_then_restarts_tak():
    audits = []
    box = Box(f'true starting {STARTED}', probe='REMOVED')
    out, logs = _run(box, audits=audits)
    assert out == 'healed'
    assert box.restarts() == ['takserver-db', 'takserver']
    # takserver is restarted only after the database reported healthy
    i_db = box.calls.index(['docker', 'restart', 'takserver-db'])
    i_tak = box.calls.index(['docker', 'restart', 'takserver'])
    healthy_polls = [i for i, c in enumerate(box.calls) if c[:2] == ['docker', 'inspect'] and i > i_db]
    assert i_db < healthy_polls[0] < healthy_polls[-1] < i_tak
    assert any('stale socket lock' in m for m in logs)
    assert audits and audits[0][0] == 'takdb:stale-lock-heal'


def test_database_still_down_leaves_tak_alone():
    box = Box(f'true unhealthy {STARTED}', probe='REMOVED', health_after=())
    out, logs = _run(box)
    assert out == 'healed-db-not-healthy'
    assert box.restarts() == ['takserver-db']
    assert any('still not healthy' in m for m in logs)


def test_every_docker_call_goes_through_sudo_wrap():
    # argv lists only — the probe is a fixed constant passed as one sh -c argument
    src = _fn('_tak_db_stale_lock_heal')
    assert 'shell=True' not in src
    assert src.count("run(_sudo_wrap(['docker'") == 5


# ── the probe itself, run in a real shell against a fake /proc and /run/postgresql ─────────────

def _probe(tmp_path, procs, lock):
    proc = tmp_path / 'proc'
    run_pg = tmp_path / 'runpg'
    proc.mkdir()
    run_pg.mkdir()
    for pid, comm in procs.items():
        (proc / str(pid)).mkdir()
        (proc / str(pid) / 'comm').write_text(comm + '\n')
    (proc / 'self').mkdir()                      # non-numeric entries must be skipped
    if lock:
        (run_pg / '.s.PGSQL.5432.lock').write_text('9\n/var/lib/postgresql/data\n')
        (run_pg / '.s.PGSQL.5432').write_text('')
    ns = {}
    exec(compile(_const('_TAK_DB_STALE_LOCK_PROBE'), 'app.py', 'exec'), ns)
    script = ns['_TAK_DB_STALE_LOCK_PROBE'].replace('/proc/', f'{proc}/').replace('/run/postgresql', str(run_pg))
    out = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=10).stdout.strip()
    return out, sorted(p.name for p in run_pg.iterdir())


def test_probe_removes_a_lock_nobody_holds(tmp_path):
    out, left = _probe(tmp_path, {1: 'bash', 9: 'sleep', 77: 'java'}, lock=True)
    assert out == 'REMOVED' and left == []


def test_probe_never_touches_a_lock_while_postgres_runs(tmp_path):
    out, left = _probe(tmp_path, {1: 'bash', 9: 'postgres', 10: 'postgres'}, lock=True)
    assert out == 'alive=1'
    assert left == ['.s.PGSQL.5432', '.s.PGSQL.5432.lock']


def test_probe_with_no_lock_does_nothing(tmp_path):
    out, left = _probe(tmp_path, {1: 'bash'}, lock=False)
    assert out == 'alive=0' and left == []


# ── wiring ─────────────────────────────────────────────────────────────────────────────────────

def test_watcher_starts_at_console_start_and_checks_for_container_tak_each_pass():
    start = APP[APP.index('def _startup_migrations('):]
    start = start[:start.index('\ndef ', 10)]
    assert "threading.Thread(target=_watch_tak_db_stale_lock, daemon=True" in start
    w = _fn('_watch_tak_db_stale_lock')
    assert '_tak_is_container() and _tak_db_stale_lock_heal()' in w
    assert 'while True' in w and 'time.sleep(interval)' in w
