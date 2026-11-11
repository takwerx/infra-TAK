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
"""Guard Dog puts back a container whose compose recreate was cut off (ops #416).

v10.3.3, Ubuntu 22.04, 15 minutes after an OS-patch reboot: `d843390e3870_authentik-server-1`
and `9f90bd08cfd9_tak-portal` were running and nothing was called `authentik-server-1`. Compose
swaps a changed container under a temporary `<12 hex>_<name>` name (the old one renamed, or
in current Compose the new one created under it); a compose client that dies part-way leaves
it so. The ports still answered and the watchers
go by port / compose label, so nothing noticed, and the compose lock (ops #173/#180) cannot
help once the client is already dead.

The REAL _gd-tak-lib.sh and the REAL tak-authentik-watch.sh / tak-takportal-watch.sh run in a
sandbox against a small fake `docker` that keeps containers in a JSON file and implements
ps / rename / rm / start the way the daemon does. flock(1) is a stub calling flock(2), as in
test_boot_scripts_compose_lock_ops180.py, so this runs on macOS too.
"""

import fcntl
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
LIB = (GD / '_gd-tak-lib.sh').read_text()
AK_WATCH = (GD / 'tak-authentik-watch.sh').read_text()
TP_WATCH = (GD / 'tak-takportal-watch.sh').read_text()

OLD_SERVER = 'd843390e3870'      # the ids from the field report
OLD_PORTAL = '9f90bd08cfd9'
NEW_ID = '5a1b2c3d4e5f'

FAKE_DOCKER = '''#!%(py)s -I
import json, re, sys
state, calls = %(state)r, %(calls)r
a = sys.argv[1:]
open(calls, 'a').write('docker ' + ' '.join(a) + '\\n')
cs = json.load(open(state))
def save():
    json.dump(cs, open(state, 'w'))
if a[:1] == ['ps']:
    flt = [x.split('=', 1) for i, x in enumerate(a) if i and a[i - 1] == '--filter']
    fmt = a[a.index('--format') + 1]
    for c in cs:
        ok = True
        for k, v in flt:
            if k == 'label':
                lk, lv = v.split('=', 1)
                ok = ok and c['labels'].get(lk) == lv
            elif k == 'name':
                ok = ok and re.search(v, c['name']) is not None
        if ok:
            print(fmt.replace('{{.ID}}', c['id']).replace('{{.Names}}', c['name']).replace('{{.State}}', c['state']))
    sys.exit(0)
def find(ref):
    return next((c for c in cs if c['name'] == ref or c['id'] == ref), None)
if a[:1] == ['rename']:
    c = find(a[1])
    if c is None or find(a[2]) is not None:
        sys.exit(1)
    c['name'] = a[2]; save()
elif a[:2] == ['rm', '-f']:
    cs[:] = [c for c in cs if c['id'] != a[2] and c['name'] != a[2]]; save()
elif a[:1] == ['start']:
    c = find(a[1])
    if c is None:
        sys.exit(1)
    c['state'] = 'running'; save()
elif a[:1] == ['inspect']:
    sys.exit(1)
sys.exit(0)
'''

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


def _c(cid, name, state, project, **extra):
    labels = {'com.docker.compose.project': project, 'com.docker.compose.oneoff': 'False'}
    labels.update(extra)
    return {'id': cid, 'name': name, 'state': state, 'labels': labels}


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    state = tmp_path / 'containers.json'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    home = tmp_path / 'home'
    for d in ('authentik', 'TAK-Portal'):
        (home / d).mkdir(parents=True)
        (home / d / 'docker-compose.yml').write_text('services: {}\n')
    gd = tmp_path / 'gd'
    gd.mkdir()
    logs = tmp_path / 'logs'
    proc = tmp_path / 'proc'
    proc.mkdir()
    (proc / 'uptime').write_text('99999.00 1.00\n')
    (proc / 'loadavg').write_text('0.50 0.40 0.30 1/999 1234\n')
    lock = tmp_path / 'takwerx-authentik-compose.lock'

    def sandbox(src):
        return (src.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(tmp_path / 'state'))
                   .replace('/var/log/takguard', str(logs))
                   .replace('/proc/', str(proc) + '/')
                   .replace('/tmp/', str(tmp_path) + '/')
                   .replace('/home/*/', str(tmp_path / 'nohome') + '/*/')   # macOS automounts /home
                   .replace('/root/', str(tmp_path / 'noroot') + '/'))

    (gd / '_gd-tak-lib.sh').write_text(sandbox(LIB))
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\ncat > /dev/null\n')
    alert.chmod(0o755)
    (stubs / 'docker').write_text(FAKE_DOCKER % {'py': sys.executable, 'state': str(state), 'calls': str(calls)})
    (stubs / 'flock').write_text(FLOCK_STUB % {'py': sys.executable, 'calls': str(calls)})
    (stubs / 'curl').write_text('#!/bin/sh\nprintf "200 0.01"\nexit 0\n')
    (stubs / 'timeout').write_text('#!/bin/sh\nshift\nexec "$@"\n')
    (stubs / 'pgrep').write_text('#!/bin/sh\nexit 1\n')                 # no compose run in flight
    (stubs / 'nproc').write_text('#!/bin/sh\necho 8\n')
    for name in ('sleep', 'logger'):
        (stubs / name).write_text('#!/bin/sh\nexit 0\n')
    for f in stubs.iterdir():
        f.chmod(0o755)

    class Box:
        pass
    b = Box()
    b.lock, b.stubs, b.calls = lock, stubs, calls

    def put(*containers):
        state.write_text(json.dumps(list(containers)))
        calls.write_text('')

    def names():
        return {c['name']: c['state'] for c in json.loads(state.read_text())}

    def env():
        # GD_STACK_OWNER: the fake stack dirs belong to the test user, not root/takwerx (ops #633).
        return {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'HOME': str(home),
                'GD_STACK_OWNER': str(os.getuid())}

    def lib(fn_call):
        """Run one lib call with the real library sourced."""
        r = subprocess.run(['bash', '-c', 'source %s/_gd-tak-lib.sh; %s' % (gd, fn_call)],
                           capture_output=True, text=True, env=env(), timeout=60)
        assert r.returncode == 0, r.stderr
        return r.stdout

    def watch(which):
        src = sandbox(AK_WATCH if which == 'authentik' else TP_WATCH)
        sp = tmp_path / ('%s-watch.sh' % which)
        sp.write_text(src)
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env(), timeout=60)
        assert r.returncode == 0, r.stderr
        p = logs / 'restarts.log'
        return p.read_text() if p.exists() else ''

    def mutating():
        return [l for l in calls.read_text().splitlines()
                if l.split(' ')[1:2] in (['rename'], ['rm'], ['start'])]

    b.put, b.names, b.lib, b.watch, b.mutating = put, names, lib, watch, mutating
    return b


# ── the library: what gets put back, what is left alone ──────────────────────

def test_a_cut_off_recreate_is_renamed_back_and_keeps_running(box):
    box.put(_c(OLD_SERVER, OLD_SERVER + '_authentik-server-1', 'running', 'authentik'))
    out = box.lib('gd_heal_compose_strays authentik')
    assert box.names() == {'authentik-server-1': 'running'}
    assert 'renamed leftover %s_authentik-server-1 back to authentik-server-1' % OLD_SERVER in out
    assert box.mutating() == ['docker rename %s authentik-server-1' % OLD_SERVER]


def test_a_stopped_leftover_is_renamed_back_and_started(box):
    box.put(_c(OLD_PORTAL, OLD_PORTAL + '_tak-portal', 'exited', 'tak-portal'))
    box.lib('gd_heal_compose_strays tak-portal')
    assert box.names() == {'tak-portal': 'running'}


def test_a_leftover_beside_a_running_replacement_is_removed(box):
    box.put(_c(OLD_SERVER, OLD_SERVER + '_authentik-server-1', 'exited', 'authentik'),
            _c(NEW_ID, 'authentik-server-1', 'running', 'authentik'))
    out = box.lib('gd_heal_compose_strays authentik')
    assert box.names() == {'authentik-server-1': 'running'}
    assert 'replaced by the running authentik-server-1' in out
    assert box.mutating() == ['docker rm -f %s' % OLD_SERVER]       # the new one is never touched


def test_a_replacement_that_never_started_is_cleared_and_the_old_one_comes_back(box):
    box.put(_c(OLD_SERVER, OLD_SERVER + '_authentik-server-1', 'exited', 'authentik'),
            _c(NEW_ID, 'authentik-server-1', 'created', 'authentik'))
    box.lib('gd_heal_compose_strays authentik')
    assert box.names() == {'authentik-server-1': 'running'}
    assert box.mutating() == ['docker rm -f %s' % NEW_ID, 'docker rename %s authentik-server-1' % OLD_SERVER,
                              'docker start authentik-server-1']


def test_an_exited_replacement_is_left_for_a_person(box):
    box.put(_c(OLD_SERVER, OLD_SERVER + '_authentik-server-1', 'running', 'authentik'),
            _c(NEW_ID, 'authentik-server-1', 'exited', 'authentik'))
    out = box.lib('gd_heal_compose_strays authentik')
    assert box.mutating() == []
    assert 'alone' in out and 'exited' in out


def test_the_new_composes_unfinished_replacement_is_renamed_too(box):
    # Compose v5 creates the NEW container under `<old id prefix>_<name>` and renames it only
    # after the old one is gone: the prefix is the old container's id, not its own.
    box.put(_c(NEW_ID, OLD_SERVER + '_authentik-server-1', 'running', 'authentik'))
    box.lib('gd_heal_compose_strays authentik')
    assert box.names() == {'authentik-server-1': 'running'}


def test_only_composes_temporary_names_in_the_project_match(box):
    box.put(_c('cccccccccccc', 'cccccccccccc_', 'running', 'authentik'),                    # nothing after the prefix
            _c('ffffffffffff', 'notahexprefix_authentik-server-1', 'running', 'authentik'),
            _c('ababababab01', 'abcdef01234_authentik-server-1', 'running', 'authentik'),   # 11 digits
            _c('dddddddddddd', 'authentik-worker-1', 'running', 'authentik'),
            _c('eeeeeeeeeeee', 'eeeeeeeeeeee_other-stack-1', 'running', 'some-other-project'))
    assert box.lib('gd_compose_strays authentik') == ''
    assert box.lib('gd_heal_compose_strays authentik') == ''
    assert box.mutating() == []


def test_project_name_follows_compose(box, tmp_path):
    d = tmp_path / 'My Stack_X'
    d.mkdir()
    assert box.lib('gd_compose_project_name "%s"' % d) == 'mystack_x'
    (d / '.env').write_text('COMPOSE_PROJECT_NAME="custom"\n')
    assert box.lib('gd_compose_project_name "%s"' % d) == 'custom'


# ── the Authentik watcher ────────────────────────────────────────────────────

def test_authentik_watch_puts_it_back_under_the_compose_lock(box):
    box.put(_c(OLD_SERVER, OLD_SERVER + '_authentik-server-1', 'running', 'authentik'))
    log = box.watch('authentik')
    assert box.names() == {'authentik-server-1': 'running'}
    assert 'compose-strays | renamed leftover' in log
    lines = box.calls.read_text().splitlines()
    take, rename = lines.index('flock -w 5 9'), lines.index('docker rename %s authentik-server-1' % OLD_SERVER)
    assert take < rename < lines.index('flock -u 9')


def test_authentik_watch_leaves_it_while_the_console_holds_the_lock(box):
    box.put(_c(OLD_SERVER, OLD_SERVER + '_authentik-server-1', 'running', 'authentik'))
    box.lock.touch()
    with open(box.lock) as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        log = box.watch('authentik')
    assert box.mutating() == []
    assert 'compose lock not taken' in log and 'next tick retries' in log


def test_authentik_watch_does_not_touch_the_lock_when_nothing_is_wrong(box):
    box.put(_c(NEW_ID, 'authentik-server-1', 'running', 'authentik'))
    box.watch('authentik')
    assert box.mutating() == []
    assert not [l for l in box.calls.read_text().splitlines() if l.startswith('flock')]


# ── the TAK Portal watcher ───────────────────────────────────────────────────

def test_takportal_watch_puts_its_containers_back(box):
    box.put(_c(OLD_PORTAL, OLD_PORTAL + '_tak-portal', 'running', 'tak-portal'),
            _c('207f0fa4b779', '207f0fa4b779_tak-portal-worker', 'running', 'tak-portal'),
            _c('111111111111', 'tak-portal-postgres', 'running', 'tak-portal'))
    log = box.watch('takportal')
    assert box.names() == {'tak-portal': 'running', 'tak-portal-worker': 'running', 'tak-portal-postgres': 'running'}
    assert log.count('takportal-watch | compose-strays | renamed leftover') == 2


def test_takportal_watch_waits_while_a_compose_run_is_in_flight(box):
    (box.stubs / 'pgrep').write_text('#!/bin/sh\nexit 0\n')            # a compose client is running
    box.put(_c(OLD_PORTAL, OLD_PORTAL + '_tak-portal', 'running', 'tak-portal'))
    log = box.watch('takportal')
    assert box.mutating() == []
    assert 'a compose run is in flight' in log
