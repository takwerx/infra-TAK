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
"""Guard Dog starts a TAK Server whose service FAILED to start (ops #413, GH #373).

Field (v10.3.3, Ubuntu 22.04): the box rebooted after an OS patch, the boot start ran
under heavy disk wait and hit takserver.service's 300 s start timeout. The unit was
left failed(timeout) and every Guard Dog TAK watcher skips a TAK that isn't active, so
nothing ever started it again.

The REAL tak-process-watch.sh and _gd-tak-lib.sh run here with their absolute paths
pointed into a sandbox and systemctl/docker/pkill/pgrep/sleep stubbed; every call is
recorded.
"""

import pathlib
import subprocess
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
WATCH = (GD / 'tak-process-watch.sh').read_text()
LIB = (GD / '_gd-tak-lib.sh').read_text()


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    state = tmp_path / 'state'
    logs = tmp_path / 'log'
    gd = tmp_path / 'gd'
    stubs = tmp_path / 'bin'
    for d in (state, logs, gd, stubs, tmp_path / 'tak' / 'work'):
        d.mkdir(parents=True)

    def sandbox(text):
        return (text.replace('/var/lib/takguard', str(state))
                    .replace('/var/log/takguard', str(logs))
                    .replace('/opt/tak-guarddog/', str(gd) + '/')
                    .replace('/opt/tak/', str(tmp_path / 'tak') + '/')
                    .replace('/proc/uptime', str(tmp_path / 'uptime')))

    (gd / '_gd-tak-lib.sh').write_text(sandbox(LIB))
    sp = tmp_path / 'tak-process-watch.sh'
    sp.write_text(sandbox(WATCH))
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\necho "alert $1" >> %s\ncat >/dev/null\n' % calls)
    alert.chmod(0o755)

    # systemctl: the unit state comes from $UNIT (active | inactive | failed).
    (stubs / 'systemctl').write_text(
        '#!/bin/sh\necho "systemctl $*" >> %s\n'
        'case "$1" in\n'
        '  is-active) [ "$UNIT" = active ]; exit $? ;;\n'
        '  is-failed) [ "$UNIT" = failed ]; exit $? ;;\n'
        '  show) case "$*" in *Result*) echo timeout ;; *) echo 0 ;; esac ;;\n'
        'esac\nexit 0\n' % calls)
    for name, rc in (('docker', 0), ('pkill', 0), ('logger', 0), ('sleep', 0), ('pgrep', 1)):
        (stubs / name).write_text('#!/bin/sh\necho "%s $*" >> %s\nexit %d\n' % (name, calls, rc))
    for f in stubs.iterdir():
        f.chmod(0o755)

    def run(unit, uptime_s=1500):
        (tmp_path / 'uptime').write_text('%d.42 9999.00\n' % uptime_s)
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'UNIT': unit}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return calls.read_text() if calls.exists() else ''

    run.state = state
    run.gd = gd
    run.restarts = logs / 'restarts.log'
    run.ignite = tmp_path / 'tak' / 'work'
    return run


def _restarted(calls):
    lines = calls.splitlines()
    return 'systemctl start takserver' in lines


def test_failed_unit_after_boot_is_started_again(box):
    calls = box('failed')
    lines = calls.splitlines()
    # Guard Dog's clean restart: stop, kill orphan JVMs, clear Ignite, start.
    i_stop, i_kill, i_start = (lines.index('systemctl stop takserver'),
                               lines.index('pkill -9 -u tak'),
                               lines.index('systemctl start takserver'))
    assert i_stop < i_kill < i_start
    assert not box.ignite.exists()
    assert 'alert TAK Server Start Failed on' in calls
    log = box.restarts.read_text()
    assert 'TAK Server service failed to start (result=timeout)' in log
    assert (box.state / 'tak_restart_count_24h').read_text().strip() == '1'
    assert not (box.state / 'restart.lock').exists()


def test_operator_stop_is_left_alone(box):
    calls = box('inactive')                    # `systemctl stop` -> inactive, never failed
    assert not _restarted(calls) and 'pkill' not in calls


def test_not_during_the_first_15_minutes_of_boot(box):
    assert not _restarted(box('failed', uptime_s=600))


def test_waits_out_the_cooldown_after_a_guarddog_restart(box):
    (box.state / 'last_restart_time').write_text('%d\n' % (int(time.time()) - 300))
    assert not _restarted(box('failed'))
    (box.state / 'last_restart_time').write_text('%d\n' % (int(time.time()) - 1000))
    assert _restarted(box('failed'))


def test_daily_cap_stops_a_start_loop(box):
    (box.state / 'tak_restart_window').write_text('%d\n' % int(time.time()))
    (box.state / 'tak_restart_count_24h').write_text('3\n')
    calls = box('failed')
    assert not _restarted(calls)
    assert 'daily restart cap (3) reached' in box.restarts.read_text()


def test_split_db_maintenance_stands_down(box):
    (box.state / 'dbserver-maintenance').write_text('%d\n' % (int(time.time()) + 3600))
    assert not _restarted(box('failed'))


def test_container_tak_is_not_touched(box):
    (box.gd / 'guarddog.conf').write_text('{"tak_mode": "container"}')
    calls = box('failed')
    assert not _restarted(calls) and 'docker restart' not in calls


def test_missing_jvm_restart_still_uses_the_shared_daily_cap(box):
    (box.state / 'process_fail_count').write_text('2\n')
    calls = box('active')                      # pgrep stub: every JVM missing
    assert _restarted(calls)
    assert 'missing processes' in box.restarts.read_text()
    assert (box.state / 'tak_restart_count_24h').read_text().strip() == '1'
