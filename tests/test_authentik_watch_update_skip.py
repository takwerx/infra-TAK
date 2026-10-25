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
"""Guard Dog leaves Authentik alone while it updates and migrates (ops #167).

v10.2.26 T&E, test6, 2026-10-22: the console's Authentik Update (2026.5.7 -> 2026.8.4)
returned once the new image was running; the server then ran 58 migrations
(06:50:08-06:51:59 UTC) serving 503, and tak-authentik-watch.sh counted three 503s and
restarted server+worker at 06:52:02, before the server had released its migration lock.

The fix has two halves, both tested here:
  * the console writes /var/lib/takguard/authentik_update_in_progress before it pulls and
    removes it once Authentik answers again; the watcher skips while it is fresh and
    ignores (and removes) one older than 30 min, so a crashed update cannot silence it;
  * the watcher holds, without counting, while the server's log shows migrations running,
    for at most an hour.

The REAL watchdog runs with its absolute paths pointed into a sandbox and curl/docker
stubbed (same harness as test_authentik_watch_cpu_starved.py).
"""

import ast
import os
import pathlib
import re
import subprocess
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-authentik-watch.sh').read_text()
APP = (REPO / 'app.py').read_text(encoding='utf-8')

LIB = '''
gd_find_stack_dir() { echo "%(ak)s"; }
gd_ldap_groups_ok() { return 0; }
'''

# authentik-server-1 on test6, 2026-10-22, as `docker logs` printed it (trimmed), up to the
# moment Guard Dog restarted it: the last migration is done but the lock is not released.
TEST6_MIGRATING = '''\
{"event":"authentik is starting","version":"2026.8.4","timestamp":"2026-10-22T06:49:51.024154"}
{"event":"waiting for gunicorn to be ready before starting embedded outpost"}
2026-10-22 06:49:53 [info     ] waiting to acquire database lock
2026-10-22 06:49:53 [info     ] Migration needs to be applied  migration=version_history_update.py
2026-10-22 06:49:53 [info     ] Migration finished applying    migration=version_history_update.py
2026-10-22 06:49:53 [info     ] applying django migrations
=== Starting migration
Operations to perform:
  Apply all migrations: auth, authentik_agents, authentik_blueprints, authentik_core
Running migrations:
  Applying authentik_core.0060_sourcegrouppropertymapping_and_more...
 OK
{"level":"warn","path":"/health/live/","event":"failed to proxy to backend"}
  Applying authentik_tasks.0008_remove_task_update_aggregated_status_and_more...
 OK
  Applying authentik_tenants.0009_alter_tenant_base_url...
 OK
{"level":"warn","path":"/health/live/","event":"failed to proxy to backend"}
'''
# The same server's next boot, through to gunicorn.
TEST6_DONE = '''\
2026-10-22 06:52:12 [info     ] waiting to acquire database lock
2026-10-22 06:52:13 [info     ] applying django migrations
Running migrations:
  No migrations to apply.
{"event": "releasing database lock", "logger": "lifecycle.migrate"}
{"event": "Starting gunicorn 26.0.0", "logger": "gunicorn.error"}
{"event": "Booting worker with pid: 120", "logger": "gunicorn.error"}
'''
WAITING_FOR_LOCK = '2026-10-22 06:52:12 [info     ] waiting to acquire database lock\n'


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

    # curl prints "<code> <secs>" and exits with the rc in $tmp/curl ("503 0.01 0").
    (stubs / 'curl').write_text(
        '#!/bin/sh\nset -- $(cat %s)\nprintf "%%s %%s" "$1" "$2"\nexit "$3"\n' % (tmp_path / 'curl'))
    # docker inspect prints $tmp/inspect ("true <StartedAt>", or exits 1 when it is empty);
    # docker logs prints $tmp/serverlog.
    (stubs / 'docker').write_text(
        '#!/bin/sh\necho "docker $*" >> %(calls)s\n'
        'case "$*" in\n'
        '  *"ps --status running --services"*) cat %(running)s ;;\n'
        '  inspect*) [ -s %(inspect)s ] || exit 1; cat %(inspect)s ;;\n'
        '  logs*) cat %(serverlog)s ;;\n'
        'esac\nexit 0\n'
        % {'calls': calls, 'running': tmp_path / 'running', 'inspect': tmp_path / 'inspect',
           'serverlog': tmp_path / 'serverlog'})
    (stubs / 'sleep').write_text('#!/bin/sh\nexit 0\n')
    (stubs / 'timeout').write_text('#!/bin/sh\nshift\nexec "$@"\n')
    (stubs / 'nproc').write_text('#!/bin/sh\necho 8\n')
    for f in stubs.iterdir():
        f.chmod(0o755)
    (tmp_path / 'running').write_text('postgresql\nredis\nserver\nworker\nldap\n')
    (tmp_path / 'inspect').write_text('true 2026-10-22T06:49:50.123456789Z\n')
    (tmp_path / 'serverlog').write_text(TEST6_DONE)

    script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/var/log/takguard', str(logs))
                   .replace('/proc/', str(proc) + '/')
                   .replace('/tmp/', str(tmp_path) + '/'))
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def tick(curl='503 0.01 0'):
        (tmp_path / 'curl').write_text(curl)
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return calls.read_text() if calls.exists() else ''

    def log():
        p = logs / 'restarts.log'
        return p.read_text() if p.exists() else ''

    def marker(age=None, body=None):
        state.mkdir(exist_ok=True)
        (state / 'authentik_update_in_progress').write_text(
            body if body is not None else '%d authentik-update 2026.5.7 -> 2026.8.4\n' % (time.time() - age))

    def serverlog(text, running=True):
        (tmp_path / 'serverlog').write_text(text)
        (tmp_path / 'inspect').write_text('true 2026-10-22T06:49:50.123456789Z\n' if running else '')

    def age(name, secs):
        (state / name).write_text('%d\n' % (time.time() - secs))

    tick.log, tick.marker, tick.serverlog, tick.age, tick.state = log, marker, serverlog, age, state
    return tick


def _restarts(calls):
    return [l for l in calls.splitlines()
            if l.startswith('docker compose') and ('restart' in l or 'down' in l or ' up ' in l)]


def _fails(box):
    p = box.state / 'authentik.failcount'
    return int(p.read_text()) if p.exists() else 0


# ── the console's update marker ──────────────────────────────────────────────

def test_fresh_update_marker_skips_without_restart_or_alert(box):
    box.marker(age=30)
    for _ in range(6):
        calls = box()
        assert _restarts(calls) == [] and 'alert' not in calls
        assert 'docker inspect' not in calls and 'docker logs' not in calls   # nothing probed
    assert box.log().count('update-skip | console Authentik update in progress') == 6
    assert _fails(box) == 0


def test_marker_resets_failures_counted_before_it(box):
    box(); box()                                          # two 503s already counted
    assert _fails(box) == 2
    box.marker(age=5)
    box()
    assert _fails(box) == 0
    (box.state / 'authentik_update_in_progress').unlink()
    calls = box()                                         # one fresh failure: no restart yet
    assert _restarts(calls) == [] and _fails(box) == 1


def test_stale_marker_is_ignored_removed_and_the_outage_restarted(box):
    box.marker(age=1801)
    calls = box()
    assert 'ignoring a stale update marker' in box.log()
    assert not (box.state / 'authentik_update_in_progress').exists()
    assert _fails(box) == 1
    box()
    calls = box()
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']
    assert 'alert Guard Dog: Authentik restarted' in calls


@pytest.mark.parametrize('body', ['', 'garbage\n', 'authentik-update\n', '-5 x\n'])
def test_unreadable_marker_counts_as_stale(box, body):
    box.marker(body=body)
    box()
    assert 'ignoring a stale update marker' in box.log()
    assert not (box.state / 'authentik_update_in_progress').exists()


def test_marker_in_the_future_counts_as_stale(box):
    box.marker(age=-600)                                  # clock skew or a forged file
    box()
    assert 'ignoring a stale update marker' in box.log()


def test_real_outage_after_the_update_still_restarts_and_alerts(box):
    box.marker(age=60)
    for _ in range(3):
        box()
    (box.state / 'authentik_update_in_progress').unlink()   # console: Authentik answered
    box(curl='200 0.02 0')
    for _ in range(2):
        assert _restarts(box(curl='000 0.00 7')) == []
    calls = box(curl='000 0.00 7')                        # third refused connection
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']
    assert 'alert Guard Dog: Authentik restarted' in calls


# ── migrations in the server's log ───────────────────────────────────────────

def test_test6_migrations_hold_without_restart_or_alert(box):
    box.serverlog(TEST6_MIGRATING)
    for _ in range(5):                                    # test6 restarted on the third
        calls = box()
        assert _restarts(calls) == [] and 'alert' not in calls
    assert 'while its migrations run (last: Applying authentik_tenants.0009_alter_tenant_base_url)' in box.log()
    assert 'NOT restarting' in box.log() and _fails(box) == 0


def test_waiting_for_the_migration_lock_holds_too(box):
    box.serverlog(WAITING_FOR_LOCK)                       # the worker is migrating, server waits
    for _ in range(4):
        assert _restarts(box()) == []
    assert '(last: waiting to acquire database lock)' in box.log()


def test_finished_migrations_do_not_hold(box):
    box.serverlog(TEST6_DONE)
    for _ in range(2):
        box()
    calls = box()
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']
    assert 'migrations run' not in box.log()


def test_released_lock_without_gunicorn_yet_does_not_hold(box):
    box.serverlog(TEST6_MIGRATING + '{"event": "releasing database lock"}\n')
    for _ in range(3):
        calls = box()
    assert _restarts(calls)


def test_no_migration_lines_do_not_hold(box):
    box.serverlog('{"event": "Booting worker with pid: 120"}\n')   # up for weeks: --tail has none
    for _ in range(3):
        calls = box()
    assert _restarts(calls)


def _request_line(ua):
    """One request log line from the 2026.8 server, User-Agent encoded the way it logs it."""
    import json
    headers = json.dumps({'user_agent': ua})
    return json.dumps({'level': 'warn', 'spans': [{'host': '127.0.0.1:9090', 'http_headers': headers,
                                                   'method': 'GET', 'path': '/'}],
                       'event': 'failed to proxy to backend'}, separators=(',', ':')) + '\n'


@pytest.mark.parametrize('ua', [
    '2026-10-22 06:49:53 [info     ] waiting to acquire database lock',
    '[info     ] applying django migrations',
    '  Applying authentik_core.0060_x...',
    '", "event": "waiting to acquire database lock',
    'x\n  Applying authentik_core.0060_x...',
])
def test_client_text_in_the_request_log_cannot_fake_migrations(box, ua):
    box.serverlog(TEST6_DONE + _request_line(ua) * 3)
    for _ in range(3):
        calls = box()
    assert _restarts(calls) and 'migrations run' not in box.log()


def test_stopped_server_is_not_migrating(box):
    box.serverlog(TEST6_MIGRATING, running=False)         # its old log must not count
    for _ in range(3):
        calls = box(curl='000 0.00 7')
    assert _restarts(calls)
    assert 'docker logs' not in calls


def test_migration_hold_is_capped_at_an_hour(box):
    box.serverlog(TEST6_MIGRATING)
    box()
    assert (box.state / 'authentik_migrate_since').exists()
    box.age('authentik_migrate_since', 3601)
    box(); box()
    calls = box()
    assert 'still running after' in box.log()
    assert _restarts(calls) and 'alert Guard Dog: Authentik restarted' in calls


def test_cap_survives_server_restarts_mid_migration(box):
    # A migration that crash-loops restarts the container (new StartedAt, fresh "waiting to
    # acquire database lock"), but the hold is timed from the first held tick, not the boot.
    box.serverlog(TEST6_MIGRATING)
    box()
    box.age('authentik_migrate_since', 3601)
    box.serverlog(WAITING_FOR_LOCK)
    for _ in range(3):
        calls = box()
    assert _restarts(calls)


def test_healthy_server_clears_the_migration_hold(box):
    box.serverlog(TEST6_MIGRATING)
    box()
    assert (box.state / 'authentik_migrate_since').exists()
    box(curl='200 0.02 0')
    assert not (box.state / 'authentik_migrate_since').exists()


def test_healthy_ticks_never_read_the_server_log(box):
    box.serverlog(TEST6_MIGRATING)
    calls = box(curl='200 0.02 0')
    assert 'docker inspect' not in calls and '--tail 20000' not in calls


def test_log_read_is_bounded(box):
    box.serverlog(TEST6_MIGRATING)
    calls = box()
    line = next(l for l in calls.splitlines() if l.startswith('docker logs'))
    assert '--since 2026-10-22T06:49:50.123456789Z' in line and '--tail 20000' in line


# ── the console half ─────────────────────────────────────────────────────────

_FUNCS = {'_guarddog_authentik_update_begin', '_guarddog_authentik_update_end',
          '_local_authentik_http_ok', '_guarddog_authentik_update_end_when_healthy'}
_CONSTS = {'_GD_AUTHENTIK_UPDATE_MARKER', '_GD_AUTHENTIK_UPDATE_MAX_S', '_AK_LOCAL_HEALTH_URL',
           '_AK_UPDATE_INPROC'}


def _load():
    parts = []
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            parts.append(ast.get_source_segment(APP, node))
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], 'id', None) in _CONSTS):
            parts.append(ast.get_source_segment(APP, node))
    assert len(parts) == len(_FUNCS) + len(_CONSTS), 'a name under test was renamed or removed'
    return '\n\n'.join(parts)


class _Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s


@pytest.fixture
def console(tmp_path, monkeypatch):
    import types
    state = tmp_path / 'takguard'
    state.mkdir()
    clock = _Clock()
    health = {'ok': False, 'after': None}
    ran = []

    def write_priv(path, content, mode='w', perm=None):
        assert path.startswith('/var/lib/takguard/') and perm == 0o644
        (state / os.path.basename(path)).write_text(content)

    def run(argv, **kw):
        ran.append(argv)
        if argv[:2] == ['rm', '-f']:
            p = state / os.path.basename(argv[2])
            if p.exists():
                p.unlink()
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(url, timeout=None):
        assert url == 'http://127.0.0.1:9090/-/health/live/'
        if health['after'] is not None and clock.now >= health['after']:
            health['ok'] = True
        if not health['ok']:
            raise OSError('503')
        return _Resp()

    real_isdir = os.path.isdir
    fake_os = types.SimpleNamespace(path=types.SimpleNamespace(
        isdir=lambda p: real_isdir(state) if p == '/var/lib/takguard' else real_isdir(p),
        dirname=os.path.dirname))
    ns = {'os': fake_os, 'time': clock, '_write_priv': write_priv, '_sudo_wrap': lambda c: list(c),
          'subprocess': types.SimpleNamespace(run=run),
          'urllib': types.SimpleNamespace(request=types.SimpleNamespace(urlopen=urlopen))}
    exec(compile(_load(), 'app.py', 'exec'), ns)
    ns['_state'], ns['_clock'], ns['_health'], ns['_ran'] = state, clock, health, ran
    return ns


def test_console_writes_the_epoch_the_watcher_reads(console):
    assert console['_guarddog_authentik_update_begin']('authentik-update 2026.5.7 -> 2026.8.4')
    body = (console['_state'] / 'authentik_update_in_progress').read_text()
    assert body == '1800000000 authentik-update 2026.5.7 -> 2026.8.4\n'
    assert re.fullmatch(r'\d+ .*\n', body)                # the watcher's awk reads field 1


def test_console_without_guard_dog_writes_nothing(console):
    import shutil
    shutil.rmtree(console['_state'])
    assert console['_guarddog_authentik_update_begin']('x') is False


def test_marker_cleared_once_authentik_answers(console):
    console['_guarddog_authentik_update_begin']('x')
    console['_health']['after'] = console['_clock'].now + 130   # migrations take ~2 min
    t0 = console['_clock'].now
    console['_guarddog_authentik_update_end_when_healthy']()
    assert not (console['_state'] / 'authentik_update_in_progress').exists()
    assert 130 <= console['_clock'].now - t0 < 140


def test_marker_wait_gives_up_at_the_watchers_own_timeout(console):
    console['_guarddog_authentik_update_begin']('x')
    t0 = console['_clock'].now
    console['_guarddog_authentik_update_end_when_healthy']()      # never healthy
    assert console['_clock'].now - t0 == console['_GD_AUTHENTIK_UPDATE_MAX_S']
    assert not (console['_state'] / 'authentik_update_in_progress').exists()


def test_console_and_watcher_agree_on_path_and_timeout():
    m = re.search(r"^_GD_AUTHENTIK_UPDATE_MARKER = '(/var/lib/takguard/[^']+)'", APP, re.M)
    assert m and os.path.basename(m.group(1)) == 'authentik_update_in_progress'
    assert 'UPDATE_MARKER="$STATE_DIR/authentik_update_in_progress"' in WATCH
    assert 'STATE_DIR="/var/lib/takguard"' in WATCH
    app_max = int(re.search(r'^_GD_AUTHENTIK_UPDATE_MAX_S = (\d+)', APP, re.M).group(1))
    assert re.search(r'^UPDATE_MAX_SECS=%d\b' % app_max, WATCH, re.M)


def test_local_update_sets_the_marker_around_the_recreate():
    m = re.search(r"    elif action == 'update':\n        # v10\.1\.39 \(COPIX", APP)
    body = APP[m.start():APP.index("@app.route('/api/authentik/deploy'", m.end())]
    i_set = body.index("_gd_marker['set'] = _guarddog_authentik_update_begin(")
    assert i_set < body.index("['docker', 'compose', 'pull']")
    # Success hands it to the thread that waits for health, after the running image is right.
    i_hand = body.index('target=_guarddog_authentik_update_end_when_healthy')
    assert body.index('if _run_tag != latest:') < i_hand
    assert "_gd_marker['handed_off'] = True" in body[i_hand:i_hand + 300]
    # Every other exit clears it.
    fin = body[body.index('        finally:\n', i_hand):]
    assert re.match(r"        finally:\n(?:\s*#.*\n)*\s*if _gd_marker\['set'\] and not _gd_marker\['handed_off'\]:\n"
                    r"\s*_guarddog_authentik_update_end\(\)", fin)
