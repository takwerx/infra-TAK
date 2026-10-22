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
"""Every Authentik compose call takes the same lock, and the lock works on
fs.protected_regular=2 boxes (ops #173).

Found on test12 during the ops #167 box test, 2026-10-22:
  * the console's Reconfigure ran `docker compose up -d` without the compose lock while
    the Update's pull/down/up (also unlocked) was running; the two raced and left the
    server container named `200f…_authentik-server-1`, which Guard Dog cannot find;
  * root could not open the takwerx-owned /tmp/takwerx-authentik-compose.lock for
    writing (protected_regular refuses an O_CREAT open of someone else's file in sticky
    /tmp, root included), so tak-authentik-watch.sh restarted Authentik UNLOCKED
    (restarts.log 06:10 and 10:34 UTC).

The watcher half runs the REAL script in a sandbox with docker/curl stubbed. flock(1)
is replaced by a stub that calls flock(2) on the inherited descriptor, exactly what
util-linux does, so the test runs on macOS too. A read-only lock file stands in for
protected_regular: either way `>>` fails and `<` works.
"""

import ast
import contextlib
import fcntl
import os
import pathlib
import subprocess
import sys
import time
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-authentik-watch.sh').read_text()
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
FUNCS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}

not_root = pytest.mark.skipif(os.geteuid() == 0, reason='root ignores file modes')

LIB = '''
gd_find_stack_dir() { echo "%(ak)s"; }
gd_ldap_groups_ok() { return 0; }
'''

# flock -w SECS FD / flock -u FD on an inherited descriptor, like util-linux flock(1).
FLOCK_STUB = '''#!%(py)s -I
import fcntl, sys, time
a = sys.argv[1:]
open(%(calls)r, 'a').write('flock ' + ' '.join(a) + '\\n')
if a[0] == '-u':
    fcntl.flock(int(a[1]), fcntl.LOCK_UN); sys.exit(0)
wait, fd = float(a[1]), int(a[2])
end = time.time() + wait
while True:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); sys.exit(0)
    except OSError:
        if time.time() >= end:
            sys.exit(1)
        time.sleep(0.05)
'''


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    ak = tmp_path / 'authentik'
    ak.mkdir()
    gd = tmp_path / 'gd'
    gd.mkdir()
    state = tmp_path / 'state'
    logs = tmp_path / 'logs'
    proc = tmp_path / 'proc'
    proc.mkdir()
    (proc / 'uptime').write_text('99999.00 1.00\n')
    (proc / 'loadavg').write_text('0.50 0.40 0.30 1/999 1234\n')
    (gd / '_gd-tak-lib.sh').write_text(LIB % {'ak': ak})
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\necho "alert $1" >> %s\ncat > /dev/null\n' % calls)
    alert.chmod(0o755)
    (stubs / 'curl').write_text('#!/bin/sh\nprintf "000 0.00"\nexit 7\n')   # refused
    (stubs / 'docker').write_text(
        '#!/bin/sh\necho "docker $*" >> %(calls)s\n'
        'case "$*" in\n'
        '  *"ps --status running --services"*) printf "postgresql\\nredis\\nserver\\nworker\\n" ;;\n'
        '  inspect*) exit 1 ;;\n'
        'esac\nexit 0\n' % {'calls': calls})
    (stubs / 'flock').write_text(FLOCK_STUB % {'py': sys.executable, 'calls': str(calls)})
    (stubs / 'sleep').write_text('#!/bin/sh\nexit 0\n')
    (stubs / 'timeout').write_text('#!/bin/sh\nshift\nexec "$@"\n')
    (stubs / 'nproc').write_text('#!/bin/sh\necho 8\n')
    for f in stubs.iterdir():
        f.chmod(0o755)

    lock = tmp_path / 'takwerx-authentik-compose.lock'

    def run(ticks=3, wait=180):
        script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                       .replace('/var/lib/takguard', str(state))
                       .replace('/var/log/takguard', str(logs))
                       .replace('/proc/', str(proc) + '/')
                       .replace('/tmp/', str(tmp_path) + '/')
                       .replace('_AK_LOCK_WAIT=180', '_AK_LOCK_WAIT=%d' % wait))
        sp = tmp_path / 'watch.sh'
        sp.write_text(script)
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        for _ in range(ticks):                    # three refused checks -> restart
            r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
            assert r.returncode == 0, r.stderr
        log = (logs / 'restarts.log').read_text() if (logs / 'restarts.log').exists() else ''
        return log, calls.read_text() if calls.exists() else ''

    run.lock = lock
    return run


def _compose(calls):
    return [l for l in calls.splitlines() if l.startswith('docker compose') and ' ps ' not in l]


@not_root
def test_unwritable_lock_file_still_locks_the_restart(box):
    # The protected_regular=2 case: the file is there, owned by the console, and root's
    # `>>` open is refused. The restart must still run, and run locked.
    box.lock.write_text('')
    box.lock.chmod(0o444)
    log, calls = box()
    assert 'UNLOCKED' not in log
    assert _compose(calls) == ['docker compose restart -t 30 server worker']
    assert 'flock -w 180 9' in calls and 'flock -u 9' in calls
    i = calls.index('flock -w 180 9')
    assert i < calls.index('docker compose restart') < calls.index('flock -u 9')
    assert oct(box.lock.stat().st_mode & 0o777) == '0o444'      # not chmodded


@not_root
def test_unwritable_lock_held_by_the_console_skips_the_restart(box):
    box.lock.write_text('')
    box.lock.chmod(0o444)
    with open(box.lock) as fh:                    # the console holds it (read-only fd, too)
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        log, calls = box(wait=1)
    assert 'NOT acquired after 1s — skipping server-worker-restart' in log
    assert _compose(calls) == []
    assert 'UNLOCKED' not in log


def test_missing_lock_file_is_created_world_openable(box):
    assert not box.lock.exists()
    log, calls = box()
    assert box.lock.exists() and oct(box.lock.stat().st_mode & 0o777) == '0o666'
    assert 'UNLOCKED' not in log and 'flock -w 180 9' in calls


def test_symlink_at_the_lock_path_is_not_written_or_chmodded(box, tmp_path):
    target = tmp_path / 'victim'
    target.write_text('keep\n')
    target.chmod(0o600)
    box.lock.symlink_to(target)
    box()
    assert target.read_text() == 'keep\n'
    assert oct(target.stat().st_mode & 0o777) == '0o600'


def test_full_restart_path_uses_the_same_read_only_open():
    body = WATCH[WATCH.index('_ak_compose_restart_locked() {'):]
    body = body[:body.index('\n}\n')]
    assert '_ak_lock_open' in body
    single = WATCH[WATCH.index('_ak_compose_locked() {'):]
    single = single[:single.index('\n}\n')]
    assert '_ak_lock_open' in single


def test_no_write_open_or_chmod_of_the_lock_left():
    code = '\n'.join(l for l in WATCH.splitlines() if not l.lstrip().startswith('#'))
    assert 'exec 9>>' not in code and 'exec 9>"' not in code     # `exec 9>&-` (close) is fine
    assert 'chmod 666 "$_AK_LOCK"' not in code
    opener = code[code.index('_ak_lock_open() {'):]
    opener = opener[:opener.index('\n}\n')]
    assert 'exec 9<"$_AK_LOCK"' in opener


# ── the console's lock helper ────────────────────────────────────────────────

_LOCK_FUNCS = ('_ak_compose_lock_path', '_authentik_compose_lock', '_ak_compose_run_locked')
_LOCK_CONSTS = ('_AK_COMPOSE_LOCK_PATH', '_AK_COMPOSE_LOCK_WAIT_S', '_AK_COMPOSE_LOCK_WAIT_LONG_S')


@pytest.fixture
def console(tmp_path):
    parts = []
    for node in TREE.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) in _LOCK_CONSTS:
            parts.append(ast.get_source_segment(APP, node))
    for name in _LOCK_FUNCS:
        node = FUNCS[name]
        src = ast.get_source_segment(APP, node)
        if node.decorator_list:
            src = '@contextlib.contextmanager\n' + src
        parts.append(src)
    assert len(parts) == len(_LOCK_FUNCS) + len(_LOCK_CONSTS)
    lock = tmp_path / 'takwerx-authentik-compose.lock'
    ran = []
    logged = []

    def run(argv, **kw):
        # Prove the command runs while the lock is held: a second open cannot take it.
        with open(lock) as other:
            try:
                fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                held = False
                fcntl.flock(other.fileno(), fcntl.LOCK_UN)
            except OSError:
                held = True
        ran.append((argv, kw.get('cwd'), held))
        if console.raise_in_run:
            raise subprocess.TimeoutExpired(argv, kw.get('timeout'))
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    ns = {'os': os, 'contextlib': contextlib, 'time': time, '_sudo_wrap': lambda c: list(c),
          'subprocess': types.SimpleNamespace(run=run, PIPE=-1, STDOUT=-2,
                                              TimeoutExpired=subprocess.TimeoutExpired)}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    ns['_AK_COMPOSE_LOCK_PATH'] = str(lock)
    console = types.SimpleNamespace(ns=ns, lock=lock, ran=ran, logged=logged, raise_in_run=False,
                                    plog=logged.append)
    return console


def test_run_locked_runs_the_command_holding_the_lock(console):
    r = console.ns['_ak_compose_run_locked'](['up', '-d'], 'reconfigure-up', console.plog, '/ak')
    assert r.returncode == 0
    assert console.ran == [(['docker', 'compose', 'up', '-d'], '/ak', True)]
    assert not any('UNLOCKED' in m or '⚠' in m for m in console.logged)


def test_run_locked_skips_and_says_so_when_the_lock_stays_busy(console):
    console.lock.write_text('')
    with open(console.lock) as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        r = console.ns['_ak_compose_run_locked'](['restart'], 'x', console.plog, '/ak', wait=0)
    assert r is None and console.ran == []
    assert any(m.startswith('  ⚠ Skipped `docker compose restart`') for m in console.logged)


@not_root
def test_console_locks_a_lock_file_it_cannot_write(console):
    # Guard Dog (root) created it first: 0644 root-owned, or refused by protected_regular.
    console.lock.write_text('')
    console.lock.chmod(0o444)
    r = console.ns['_ak_compose_run_locked'](['up', '-d'], 'x', console.plog, '/ak')
    assert r.returncode == 0 and console.ran[0][2] is True
    assert not any('UNLOCKED' in m for m in console.logged)


def test_an_error_inside_the_lock_comes_out_as_itself(console):
    # The old helper caught it, logged "proceeding UNLOCKED" for work that had run locked,
    # yielded again and raised "generator didn't stop after throw()" instead.
    console.raise_in_run = True
    with pytest.raises(subprocess.TimeoutExpired):
        console.ns['_ak_compose_run_locked'](['up', '-d'], 'x', console.plog, '/ak')
    assert not any('UNLOCKED' in m for m in console.logged)
    with open(console.lock) as fh:                # released
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_long_wait_outlasts_the_updates_own_hold():
    m = APP.index("_last = _run_priv_chain([['docker', 'compose', 'pull'],")
    update_timeout = int(APP[m:m + 400].split('timeout=')[1].split(',')[0])
    ns = {}
    exec(next(ast.get_source_segment(APP, n) for n in TREE.body if isinstance(n, ast.Assign)
              and getattr(n.targets[0], 'id', None) == '_AK_COMPOSE_LOCK_WAIT_LONG_S'), ns)
    assert ns['_AK_COMPOSE_LOCK_WAIT_LONG_S'] > update_timeout


# ── wiring: no Authentik compose call on these paths runs unlocked ───────────

_MUTATING = {'up', 'down', 'restart', 'stop', 'start', 'rm'}


def _lock_withs(fn):
    return [w for w in ast.walk(fn) if isinstance(w, ast.With) and any(
        isinstance(i.context_expr, ast.Call) and getattr(i.context_expr.func, 'id', '') == '_authentik_compose_lock'
        for i in w.items)]


def _unlocked_compose(fn, within=None):
    spans = [(w.lineno, w.end_lineno) for w in _lock_withs(fn)]
    out = []
    for node in ast.walk(within or fn):
        if (isinstance(node, ast.List) and len(node.elts) >= 3
                and all(isinstance(e, ast.Constant) for e in node.elts[:3])
                and [e.value for e in node.elts[:2]] == ['docker', 'compose']
                and node.elts[2].value in _MUTATING
                and not any(a <= node.lineno <= b for a, b in spans)):
            out.append(node.lineno)
    return out


def _callees(node):
    return {c.func.id for c in ast.walk(node)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in FUNCS}


def _reconfigure_branch():
    fn = FUNCS['run_authentik_deploy']
    for node in ast.walk(fn):
        if (isinstance(node, ast.If) and getattr(node.test, 'id', None) == 'reconfigure'
                and 'Reconfigure: Updating LDAP' in ast.get_source_segment(APP, node)):
            return fn, node.body
    raise AssertionError('local Reconfigure branch not found')


def test_authentik_control_has_no_unlocked_compose_call():
    assert _unlocked_compose(FUNCS['authentik_control']) == []


def test_update_pull_down_up_and_rollback_share_one_lock_hold():
    fn = FUNCS['authentik_control']
    holds = [w for w in _lock_withs(fn) if "'authentik-update'" in ast.get_source_segment(APP, w.items[0].context_expr)]
    assert len(holds) == 1
    body = ast.get_source_segment(APP, holds[0])
    for piece in ("['docker', 'compose', 'pull']", "['docker', 'compose', 'down', '--timeout', '30']",
                  "'roll back: start the previous version'"):
        assert piece in body
    # The marker is set before the lock is waited for, so Guard Dog skips meanwhile.
    src = ast.get_source_segment(APP, fn)
    assert src.index("_guarddog_authentik_update_begin(") < src.index("_authentik_compose_lock('authentik-update')")


def test_reconfigure_and_everything_it_calls_has_no_unlocked_compose_call():
    fn, body = _reconfigure_branch()
    direct = [l for b in body for l in _unlocked_compose(fn, within=b)]
    assert direct == [], 'unlocked compose in the Reconfigure branch at app.py lines %s' % direct
    seen, todo, bad = set(), [(c, c) for b in body for c in _callees(b)], []
    while todo:
        name, path = todo.pop()
        if name in seen or path.count('->') > 4:
            continue
        seen.add(name)
        if _unlocked_compose(FUNCS[name]):
            bad.append('%s %s' % (path, _unlocked_compose(FUNCS[name])))
        todo.extend((c, '%s->%s' % (path, c)) for c in _callees(FUNCS[name]))
    assert '_apply_authentik_pg_tuning' in seen and '_ensure_ldap_flow_authentication_none' in seen
    assert bad == []
