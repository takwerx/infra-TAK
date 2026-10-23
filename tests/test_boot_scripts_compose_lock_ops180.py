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
"""The Guard Dog boot scripts take the Authentik compose lock too (ops #180).

ops #173/#178 put every console and watcher Authentik `docker compose` call under
/tmp/takwerx-authentik-compose.lock. tak-boot-sequencer.sh (`compose stop`) and
tak-post-start.sh (`up -d postgresql`, `up -d`, LDAP `--force-recreate`) still ran
unlocked, in the same boot minutes the console runs its own locked `up -d` (idle-load
converge, stack-down heal).

The REAL scripts run here with the REAL _gd-tak-lib.sh, paths pointed into a sandbox
and docker stubbed. flock(1) is a stub calling flock(2) on the inherited descriptor,
as util-linux does, so this runs on macOS too. A read-only lock file stands in for
fs.protected_regular=2: either way a write open fails and `<` works.
"""

import fcntl
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
SEQ = (GD / 'tak-boot-sequencer.sh').read_text()
POST = (GD / 'tak-post-start.sh').read_text()
LIB = (GD / '_gd-tak-lib.sh').read_text()

not_root = pytest.mark.skipif(os.geteuid() == 0, reason='root ignores file modes')

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

# Records every call. `compose exec ... pg_isready` and `ps` answer healthy.
DOCKER_STUB = '''#!/bin/sh
echo "docker $*" >> %(calls)s
case "$*" in
  "ps --filter"*) echo "Up 2 minutes (healthy)" ;;
  inspect*) exit 1 ;;
esac
exit 0
'''


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    home = tmp_path / 'home'
    (home / 'authentik').mkdir(parents=True)
    (home / 'authentik' / 'docker-compose.yml').write_text('services: {}\n')
    gd = tmp_path / 'gd'
    gd.mkdir()
    lock = tmp_path / 'takwerx-authentik-compose.lock'

    def sandbox(src):
        return (src.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/opt/tak/', str(tmp_path / 'absent-tak') + '/')
                   .replace('/proc/uptime', str(tmp_path / 'uptime'))
                   .replace('/run/takguard-boot-sequenced', str(tmp_path / 'boot-sequenced'))
                   .replace('/tmp/', str(tmp_path) + '/')
                   # gd_find_stack_dir's /home/*/ glob: macOS automounts /home and hangs.
                   .replace('/home/*/', str(tmp_path / 'nohome') + '/*/')
                   .replace('/root/', str(tmp_path / 'noroot') + '/'))

    (gd / '_gd-tak-lib.sh').write_text(sandbox(LIB))
    (stubs / 'docker').write_text(DOCKER_STUB % {'calls': calls})
    (stubs / 'flock').write_text(FLOCK_STUB % {'py': sys.executable, 'calls': str(calls)})
    (stubs / 'ss').write_text('#!/bin/sh\necho "LISTEN 0 4096 *:8089 *:*"\n')
    (stubs / 'id').write_text('#!/bin/sh\nexit 1\n')                 # no local postgres
    (stubs / 'systemctl').write_text('#!/bin/sh\nexit 1\n')          # no MediaMTX
    (stubs / 'timeout').write_text('#!/bin/sh\nexit 1\n')            # every TCP probe: down
    for name in ('sleep', 'logger'):
        (stubs / name).write_text('#!/bin/sh\nexit 0\n')
    for f in stubs.iterdir():
        f.chmod(0o755)
    (tmp_path / 'uptime').write_text('26.42 99.00\n')

    def run(which, wait=None):
        src = sandbox(SEQ if which == 'seq' else POST)
        if wait is not None:
            src = src.replace('AK_LOCK_WAIT=60', 'AK_LOCK_WAIT=%d' % wait) \
                     .replace('AK_LOCK_WAIT=180', 'AK_LOCK_WAIT=%d' % wait)
        sp = tmp_path / ('%s.sh' % which)
        sp.write_text(src)
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'HOME': str(home),
               'JAVA_HOME': str(tmp_path / 'nojava')}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return r.stdout, (calls.read_text() if calls.exists() else '')

    run.lock = lock
    return run


def _compose(calls):
    return [l for l in calls.splitlines()
            if l.startswith('docker compose') and ' exec ' not in l]


def _locked(calls, cmd, wait):
    """`cmd` ran after `flock -w <wait> 9` and before the matching `flock -u 9`."""
    lines = calls.splitlines()
    i = lines.index(cmd)
    take = max(j for j, l in enumerate(lines[:i]) if l.startswith('flock '))
    assert lines[take] == 'flock -w %d 9' % wait, lines
    assert 'flock -u 9' in lines[i + 1:], lines
    return True


def _held(lock):
    """The console holding the lock (it may hold a read-only fd, too)."""
    lock.touch()
    fh = open(lock)
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fh


# ── tak-boot-sequencer.sh ────────────────────────────────────────────────────

@not_root
def test_sequencer_stops_authentik_under_the_lock_on_an_unwritable_lock_file(box):
    box.lock.write_text('')
    box.lock.chmod(0o444)                         # the console's file under protected_regular
    out, calls = box('seq')
    assert 'UNLOCKED' not in out
    assert _compose(calls) == ['docker compose stop -t 10']
    assert _locked(calls, 'docker compose stop -t 10', 60)
    assert oct(box.lock.stat().st_mode & 0o777) == '0o444'      # not chmodded


def test_sequencer_leaves_authentik_running_when_the_console_holds_the_lock(box):
    with _held(box.lock):
        out, calls = box('seq', wait=1)
    assert 'Authentik compose lock busy for 1s' in out
    assert _compose(calls) == []
    assert not any('authentik' in l for l in calls.splitlines() if l.startswith('docker stop'))
    assert 'docker stop tak-portal' in calls      # the rest of the sequence still runs


def test_sequencer_creates_a_missing_lock_file_world_openable(box):
    out, calls = box('seq')
    assert oct(box.lock.stat().st_mode & 0o777) == '0o666'
    assert _locked(calls, 'docker compose stop -t 10', 60)


# ── tak-post-start.sh ────────────────────────────────────────────────────────

@not_root
def test_post_start_brings_authentik_up_in_one_lock_hold(box):
    box.lock.write_text('')
    box.lock.chmod(0o444)
    out, calls = box('post')
    assert 'UNLOCKED' not in out
    lines = calls.splitlines()
    up_pg, up = lines.index('docker compose up -d postgresql'), lines.index('docker compose up -d')
    take = lines.index('flock -w 180 9')
    release = lines.index('flock -u 9')
    assert take < up_pg < up < release            # down to the full up -d, no release between
    assert 'Boot sequence complete' in out


def test_post_start_ldap_recreate_runs_under_the_lock(box):
    out, calls = box('post')                      # every 389 probe fails -> GH #64 recreate
    assert 'force-recreating' in out
    assert _locked(calls, 'docker compose up -d --force-recreate ldap', 180)


def test_post_start_skips_compose_while_the_console_holds_the_lock(box):
    with _held(box.lock):
        out, calls = box('post', wait=1)
    assert 'not starting it here' in out and 'LDAP recreate skipped' in out
    assert _compose(calls) == []
    assert 'Boot sequence complete' in out        # and the boot carries on


def test_lock_path_matches_the_console_and_the_watcher():
    app = (REPO / 'app.py').read_text(encoding='utf-8')
    watch = (GD / 'tak-authentik-watch.sh').read_text()
    path = '/tmp/takwerx-authentik-compose.lock'
    assert "_AK_COMPOSE_LOCK_PATH = '%s'" % path in app
    assert '_AK_LOCK="%s"' % path in watch
    assert 'GD_AK_LOCK="%s"' % path in LIB
