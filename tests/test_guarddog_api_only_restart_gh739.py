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
"""Guard Dog restarts only takserver-api when `api` is the only missing process (GH #739, ops #1273).

Field (a user's box): the API JVM sometimes dies alone (OOM under load). Guard Dog restarted all of
TAK Server for it, which drops every device on 8089 for minutes. Now, on a native install where
`api` is the ONLY missing process, only `takserver-api` is restarted, with the same 3 failures in
a row, daily cap, lock and alert mail. Everything else keeps the full clean restart.

The REAL tak-process-watch.sh and _gd-tak-lib.sh run here with their absolute paths pointed into a
sandbox and systemctl/docker/pkill/pgrep/sleep stubbed; every call is recorded.
"""

import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
WATCH = (GD / 'tak-process-watch.sh').read_text()
LIB = (GD / '_gd-tak-lib.sh').read_text()

PGREP_STUB = r'''#!/bin/sh
echo "pgrep $*" >> %(calls)s
for m in $(echo "$MISSING" | tr ',' ' '); do
  case "$m" in
    api) p='spring.profiles.active=api' ;;
    messaging) p='spring.profiles.active=messaging' ;;
    config) p='spring.profiles.active=config' ;;
    plugins) p='takserver-pm.jar' ;;
    retention) p='takserver-retention.jar' ;;
  esac
  [ "$2" = "$p" ] && exit 1
done
exit 0
'''


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
    alert.write_text('#!/bin/sh\necho "alert $1" >> %s\ncat > %s\n' % (calls, tmp_path / 'alert-body.txt'))
    alert.chmod(0o755)

    # systemctl: TAK is active; `cat takserver-api.service` answers $CATRC (the unit exists or not);
    # `restart takserver-api` answers $APIRC.
    (stubs / 'systemctl').write_text(
        '#!/bin/sh\necho "systemctl $*" >> %s\n'
        'case "$1" in\n'
        '  is-active) exit 0 ;;\n'
        '  is-failed) exit 1 ;;\n'
        '  cat) exit ${CATRC:-0} ;;\n'
        '  restart) case "$2" in takserver-api) exit ${APIRC:-0} ;; esac ;;\n'
        'esac\nexit 0\n' % calls)
    (stubs / 'pgrep').write_text(PGREP_STUB % {'calls': calls})
    # docker (container TAK only): the container is running; `top` lists every JVM except $MISSING.
    (stubs / 'docker').write_text(
        '#!/bin/sh\necho "docker $*" >> %s\n'
        'case "$1" in\n'
        '  inspect) case "$*" in *Running*) echo true ;; esac ;;\n'
        '  top) echo "PID COMMAND"\n'
        '       for p in messaging:spring.profiles.active=messaging api:spring.profiles.active=api'
        ' config:spring.profiles.active=config plugins:takserver-pm.jar retention:takserver-retention.jar; do\n'
        '         m=${p%%%%:*}; case ",$MISSING," in *,$m,*) ;; *) echo "1 java -D${p#*:}" ;; esac\n'
        '       done ;;\n'
        'esac\nexit 0\n' % calls)
    for name in ('pkill', 'logger', 'sleep'):
        (stubs / name).write_text('#!/bin/sh\necho "%s $*" >> %s\nexit 0\n' % (name, calls))
    for f in stubs.iterdir():
        f.chmod(0o755)

    def run(missing, fails=2, container=False, **extra):
        (tmp_path / 'uptime').write_text('1500.42 9999.00\n')
        if calls.exists():
            calls.unlink()
        (state / 'process_fail_count').write_text('%d\n' % fails)
        if container:
            (gd / 'guarddog.conf').write_text('{"tak_mode": "container"}')
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'MISSING': missing}
        env.update(extra)
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return calls.read_text() if calls.exists() else ''

    run.state = state
    run.restarts = logs / 'restarts.log'
    run.body = tmp_path / 'alert-body.txt'
    return run


def _lines(calls):
    return calls.splitlines()


def _full_restart(calls):
    return 'systemctl stop takserver' in _lines(calls) and 'systemctl start takserver' in _lines(calls)


def test_api_only_missing_restarts_just_takserver_api(box):
    calls = box('api')
    assert 'systemctl restart takserver-api' in _lines(calls)
    # No full restart: no stop/start of takserver, no pkill of the tak user's JVMs.
    assert not _full_restart(calls) and 'pkill' not in calls
    assert 'docker restart' not in calls
    body = box.body.read_text()
    assert 'Missing Processes: api' in body
    assert 'Restarting only the TAK Server API process (takserver-api)' in body
    assert 'restarting only takserver-api' in box.restarts.read_text()
    # Same bookkeeping as the full restart: daily cap counted, lock released, fail count reset.
    assert (box.state / 'tak_restart_count_24h').read_text().strip() == '1'
    assert (box.state / 'last_restart_time').exists()
    assert not (box.state / 'restart.lock').exists()
    assert not (box.state / 'process_fail_count').exists()


@pytest.mark.parametrize('missing', ['api,messaging', 'api,config', 'messaging', 'config', 'plugins', 'retention',
                                     'messaging,api,config,plugins,retention'])
def test_any_other_missing_process_still_gets_the_full_restart(box, missing):
    calls = box(missing)
    assert _full_restart(calls)
    assert 'systemctl restart takserver-api' not in _lines(calls)
    assert 'Action taken: Restarting TAK Server' in box.body.read_text()
    assert 'only takserver-api' not in box.restarts.read_text()


def test_container_tak_keeps_the_full_restart(box):
    # A Docker TAK Server has no separate API unit: `api` missing restarts the container.
    calls = box('api', container=True)
    assert 'docker restart takserver' in _lines(calls)
    assert 'systemctl restart takserver-api' not in _lines(calls)


def test_box_without_the_api_unit_keeps_the_full_restart(box):
    calls = box('api', CATRC='1')
    assert _full_restart(calls)
    assert 'systemctl restart takserver-api' not in _lines(calls)


def test_failed_api_restart_falls_back_to_the_full_restart(box):
    calls = box('api', APIRC='1')
    lines = _lines(calls)
    assert 'systemctl restart takserver-api' in lines
    assert _full_restart(calls)
    assert lines.index('systemctl restart takserver-api') < lines.index('systemctl stop takserver')
    assert 'falling back to the full restart' in box.restarts.read_text()
    assert (box.state / 'tak_restart_count_24h').read_text().strip() == '1'


def test_still_waits_for_three_failures_in_a_row(box):
    calls = box('api', fails=0)
    assert 'systemctl restart takserver-api' not in _lines(calls) and not _full_restart(calls)
    assert (box.state / 'process_fail_count').read_text().strip() == '1'


def test_daily_cap_applies_to_the_api_only_restart(box):
    import time
    (box.state / 'tak_restart_window').write_text('%d\n' % int(time.time()))
    (box.state / 'tak_restart_count_24h').write_text('3\n')
    calls = box('api')
    assert 'systemctl restart takserver-api' not in _lines(calls) and not _full_restart(calls)
    assert 'daily restart cap (3) reached' in box.restarts.read_text()


def test_restart_lock_applies_to_the_api_only_restart(box):
    (box.state / 'restart.lock').write_text('')
    calls = box('api')
    assert 'systemctl restart takserver-api' not in _lines(calls) and not _full_restart(calls)
