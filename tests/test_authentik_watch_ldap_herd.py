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
"""Guard Dog restarts Authentik when the LDAP flow herd stops draining (ops #38).

Field (test8, 2026-10-12): the LDAP outpost's hourly bind-cache expiry sent every TAK
Server bind through the full ldap-authentication-flow. Authentik was already slow, so the
herd never drained: 750 flows per 10 min, flow median 28 s, health check 7 s. The HTTP
probe (30 s limit) and the port-389 probe both stayed green, so nothing restarted it.

Healthy boxes run one 1-2 minute burst an hour, which must never trip this. The REAL
watchdog runs here with its paths pointed into a sandbox; docker/curl are stubbed and
`docker logs authentik-server-1` serves a synthetic Authentik request log.
"""

import json
import pathlib
import subprocess
import time
from datetime import datetime, timedelta, timezone

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-authentik-watch.sh').read_text()

LIB = '''
gd_find_stack_dir() { echo "%(ak)s"; }
gd_ldap_groups_ok() { return 0; }
'''

TCP_UP = '_tcp_up() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }'


def _flow_line(ts):
    return json.dumps({
        'auth_via': 'unauthenticated', 'event': '/api/v3/flows/executor/ldap-authentication-flow/',
        'logger': 'authentik.asgi', 'method': 'POST', 'status': 302, 'runtime': 28000,
        'timestamp': ts.strftime('%Y-%m-%dT%H:%M:%S.%f'), 'user_agent': 'goauthentik.io/outpost/2026.5.7',
    }, separators=(', ', ': '))


def _health_line(ts):
    return json.dumps({'event': '/-/health/live/', 'logger': 'authentik.asgi', 'status': 200,
                       'timestamp': ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}, separators=(', ', ': '))


def server_log(per_minute, now=None):
    """per_minute: flow counts for the last N minutes, oldest first; the last is the current minute."""
    now = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    lines = []
    for i, n in enumerate(per_minute):
        minute = now - timedelta(minutes=len(per_minute) - 1 - i)
        lines.append(_health_line(minute))
        lines += [_flow_line(minute + timedelta(seconds=s % 60)) for s in range(n)]
    return '\n'.join(lines) + '\n'


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
    (proc / 'loadavg').write_text('1.00 1.00 1.00 9/999 1234\n')

    (gd / '_gd-tak-lib.sh').write_text(LIB % {'ak': ak})
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\necho "alert $1" >> %s\ncat >> %s\n' % (calls, tmp_path / 'alert-bodies'))
    alert.chmod(0o755)

    (stubs / 'curl').write_text('#!/bin/sh\nprintf "200 0.05"\nexit 0\n')
    (stubs / 'docker').write_text(
        '#!/bin/sh\necho "docker $*" >> %s\n'
        'case "$*" in\n'
        '  *"ps --status running --services"*) cat %s ;;\n'
        '  "logs authentik-server-1 --since 10m") cat %s ;;\n'
        'esac\nexit 0\n' % (calls, tmp_path / 'running', tmp_path / 'server.log'))
    (stubs / 'sleep').write_text('#!/bin/sh\nexit 0\n')
    (stubs / 'timeout').write_text('#!/bin/sh\nshift\nexec "$@"\n')
    (stubs / 'nproc').write_text('#!/bin/sh\necho 8\n')
    # Only the herd check's `date -u +%H:%M` is pinned (when a test sets a clock).
    (stubs / 'date').write_text(
        '#!/bin/sh\n[ "$*" = "-u +%%H:%%M" ] && [ -f %s ] && exec cat %s\nexec /bin/date "$@"\n'
        % (tmp_path / 'clock', tmp_path / 'clock'))
    for f in stubs.iterdir():
        f.chmod(0o755)
    (tmp_path / 'running').write_text('postgresql\nredis\nserver\nworker\nldap\n')

    assert TCP_UP in WATCH, '_tcp_up changed; update the stub below'
    script = (WATCH.replace(TCP_UP, '_tcp_up() { [ ! -f %s ]; }' % (tmp_path / 'port389-closed'))
                   .replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/var/log/takguard', str(logs))
                   .replace('/proc/', str(proc) + '/')
                   .replace('/tmp/', str(tmp_path) + '/'))
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def tick(per_minute, now=None):
        (tmp_path / 'server.log').write_text(server_log(per_minute, now))
        if now:
            (tmp_path / 'clock').write_text(now.strftime('%H:%M') + '\n')
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return calls.read_text() if calls.exists() else ''

    def log():
        p = logs / 'restarts.log'
        return p.read_text() if p.exists() else ''

    def age(name, secs):
        (state / name).write_text('%d\n' % (time.time() - secs))

    tick.log, tick.age, tick.tmp = log, age, tmp_path
    return tick


def _restarts(calls):
    return [l for l in calls.splitlines()
            if l.startswith('docker compose') and ('restart' in l or 'down' in l or ' up ' in l)]


# test8 2026-10-12 20:58-21:07 UTC, flows per minute, from the T&E forensics.
STUCK = [124, 190, 147, 98, 100, 100, 86, 97, 107, 68]


def test_stuck_herd_restarts_server_and_worker(box):
    calls = box(STUCK)
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']
    assert 'alert Guard Dog: Authentik LDAP logins backed up, restarted' in calls
    assert 'LDAP flow herd not draining (10 of the last 10 min' in box.log()
    assert 'server-worker restart (restart 1 in 6h' in box.log()


def test_hourly_burst_on_a_healthy_box_is_left_alone(box):
    # test12 / test8 after recovery: one or two busy minutes, then single watchdog binds.
    for burst in ([0, 0, 0, 0, 0, 0, 0, 0, 60, 0], [0, 0, 0, 0, 0, 0, 0, 73, 133, 1],
                  [1, 0, 0, 0, 0, 1, 0, 0, 0, 1], [0] * 10):
        calls = box(burst)
        assert _restarts(calls) == [] and 'alert' not in calls, burst
    assert 'herd' not in box.log()


def test_seven_busy_minutes_is_not_enough(box):
    calls = box([0, 0, 0, 30, 30, 30, 30, 30, 30, 30])
    assert _restarts(calls) == []


def test_herd_shares_the_http_restart_backoff(box):
    box(STUCK)                                           # restart 1: server+worker
    box.age('authentik_last_restart', 1000)              # past 15 min, inside the 30 min backoff
    calls = box(STUCK)
    assert _restarts(calls) == [] and 'alert' not in calls
    assert 'docker logs' not in calls                    # cooling down: logs are not even read
    box.age('authentik_last_restart', 1801)
    calls = box(STUCK)
    assert 'docker compose down --timeout 30' in calls   # second in 6h escalates to full, like HTTP
    assert 'restart 2 in 6h; next allowed after 60 min' in box.log()


# ops #64: test12 2026-10-16 10:30-10:39 AM PT (17:30-17:39 UTC), flows per minute. An outpost
# expiry met a 2,200-request POWER-OUTAGES poll; it was falling on its own when the old
# rule restarted server+worker at 10:39:33, which caused a 90 s LDAP group outage and a
# second herd. The last minute is the partial 10:39 one.
DRAINING = [2, 149, 237, 225, 192, 96, 40, 58, 15, 6]


def test_draining_herd_at_the_outpost_expiry_is_left_alone(box):
    calls = box(DRAINING)
    assert _restarts(calls) == [] and 'alert' not in calls
    assert 'hold | LDAP flow herd draining (8 of the last 10 min' in box.log()
    assert 'the last 3 min ran 113 vs a peak of 237/min' in box.log()
    assert 'restart |' not in box.log()


def test_draining_herd_is_left_alone_on_every_tick(box):
    # Each minute's tick from the expiry through the tail, the current minute half done.
    minutes = DRAINING[:-1] + [14, 8, 3, 1]
    for end in range(1, len(minutes) + 1):
        seen = minutes[max(0, end - 10):end]
        calls = box(seen[:-1] + [seen[-1] // 2])
        assert _restarts(calls) == [] and 'alert' not in calls, seen
    assert 'restart |' not in box.log()


def test_sustained_herd_still_restarts(box):
    calls = box([60] * 10)
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']
    assert 'the last 3 min ran 180 vs a peak of 60/min' in box.log()


def test_rising_herd_still_restarts(box):
    calls = box([10, 20, 30, 40, 60, 80, 100, 120, 150, 90])
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']


def test_tail_that_settles_into_its_own_herd_restarts_once_the_peak_slides_out(box):
    # The draining hold ends by itself: the peak is gone from the window and the herd
    # never stopped, so it is judged against its own level.
    calls = box([40, 40, 40, 40, 40, 40, 40, 40, 40, 40])
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']


def test_trend_is_read_by_minute_age_across_midnight(box):
    now = datetime(2026, 10, 17, 0, 4, 30, tzinfo=timezone.utc)   # window 23:55..00:04
    calls = box(DRAINING, now=now)
    assert _restarts(calls) == []
    assert 'the last 3 min ran 113 vs a peak of 237/min' in box.log()
    calls = box(STUCK, now=now)
    assert _restarts(calls) == ['docker compose restart -t 30 server worker']
    assert 'the last 3 min ran 290 vs a peak of 190/min' in box.log()


def test_no_herd_check_while_port_389_is_down(box):
    (box.tmp / 'port389-closed').write_text('')
    calls = box(STUCK)
    assert _restarts(calls) == []
    assert 'herd' not in box.log()
