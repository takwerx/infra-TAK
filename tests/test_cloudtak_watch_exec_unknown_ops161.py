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
"""A failed `docker exec` is not a missing HLS profile (ops #161).

Field (ops1, 2026-10-21): the patch job's apt run restarted Docker. For ~45s
`docker exec cloudtak-media-1 ...` failed, tak-cloudtak-watch.sh read that as
the HLS profile being gone, and two checks in a row sent the drift alert. The
profile was intact the whole time.

The REAL watchdog runs here with its absolute paths pointed into a sandbox and
docker stubbed; every alert is recorded.
"""

import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-cloudtak-watch.sh').read_text()

PROFILE = ('logLevel: info\nhlsVariant: mpegts\nhlsSegmentCount: 3\n'
           'hlsSegmentDuration: 500ms\nhlsPartDuration: 200ms\n')
STOCK = 'logLevel: info\nhlsVariant: lowLatency\nhlsSegmentCount: 7\nhlsSegmentDuration: 1s\n'


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    ct = tmp_path / 'CloudTAK'
    ct.mkdir()
    gd = tmp_path / 'gd'
    gd.mkdir()
    state = tmp_path / 'state'
    logs = tmp_path / 'logs'
    proc = tmp_path / 'proc'
    proc.mkdir()
    (proc / 'uptime').write_text('99999.00 1.00\n')

    (gd / '_gd-tak-lib.sh').write_text('gd_find_stack_dir() { echo "%s"; }\n' % ct)
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\necho "alert $1" >> %s\ncat > /dev/null\n' % calls)
    alert.chmod(0o755)

    # `docker exec` prints $tmp/media.yml and exits with the rc in $tmp/exec_rc.
    (stubs / 'docker').write_text(
        '#!/bin/sh\necho "docker $*" >> %(calls)s\n'
        'case "$1" in\n'
        '  inspect) exit 0 ;;\n'
        '  exec) rc=$(cat %(rc)s); [ "$rc" = 0 ] && cat %(yml)s; exit "$rc" ;;\n'
        '  ps) echo "Up 3 hours" ;;\n'
        'esac\nexit 0\n' % {'calls': calls, 'rc': tmp_path / 'exec_rc', 'yml': tmp_path / 'media.yml'})
    (stubs / 'docker').chmod(0o755)

    script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/var/log/takguard', str(logs))
                   .replace('/proc/', str(proc) + '/')
                   .replace('/tmp/', str(tmp_path) + '/'))
    assert str(state) in script and str(proc) in script
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def tick(yml=PROFILE, rc=0):
        (tmp_path / 'media.yml').write_text(yml)
        (tmp_path / 'exec_rc').write_text(str(rc))
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return calls.read_text() if calls.exists() else ''

    def log():
        p = logs / 'restarts.log'
        return p.read_text() if p.exists() else ''

    tick.log, tick.state = log, state
    return tick


def _alerts(calls):
    return [l for l in calls.splitlines() if l.startswith('alert ')]


def test_failed_exec_during_docker_restart_never_alerts(box):
    for _ in range(3):
        calls = box(rc=1)                                 # docker daemon restarting under apt
        assert _alerts(calls) == []
    assert 'UNKNOWN' in box.log() and 'MISSING' not in box.log()
    assert not (box.state / 'cloudtak_media_drift_pending').exists()


def test_exec_ok_but_empty_read_is_unknown(box):
    for _ in range(2):
        calls = box(yml='', rc=0)
    assert _alerts(calls) == [] and 'MISSING' not in box.log()


def test_profile_present_after_restart_is_quiet(box):
    box(rc=1)
    box(rc=126)
    calls = box()                                         # Docker back, profile intact
    assert _alerts(calls) == [] and 'MISSING' not in box.log()


def test_real_drift_still_alerts_on_second_check(box):
    assert _alerts(box(yml=STOCK)) == []                  # first strike deferred
    alerts = _alerts(box(yml=STOCK))
    assert len(alerts) == 1 and alerts[0].startswith('alert Guard Dog: CloudTAK video config drift on ')
    assert 'MISSING' in box.log()


def test_unknown_does_not_break_a_real_drift_episode(box):
    box(yml=STOCK)                                        # first strike
    assert _alerts(box(rc=1)) == []                       # exec hiccup: no count either way
    assert (box.state / 'cloudtak_media_drift_pending').exists()
    calls = box(yml=STOCK)                                # still stock: alert now
    assert len(_alerts(calls)) == 1


def test_one_missing_key_is_still_drift(box):
    partial = PROFILE.replace('hlsPartDuration: 200ms\n', '')
    box(yml=partial)
    assert len(_alerts(box(yml=partial))) == 1
