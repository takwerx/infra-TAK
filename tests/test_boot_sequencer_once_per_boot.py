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
"""A TAK Server restart during boot no longer takes the stack down (v10.2.5, GH #83).

Field (v10.2.4, Ubuntu 22.04): the console's startup migration healed the LDAP
service account and restarted TAK Server at 106 s uptime. tak-boot-sequencer.sh
treated it as another boot (uptime < 600 s) and stopped every container — but what
it stops is restored only by tak-post-start.service, a oneshot that runs once per
boot and had already brought Authentik back. Authentik and TAK Portal stayed down
~12 minutes, and the 8089 client gate was re-engaged with nothing left to release it.

The REAL sequencer runs here with its absolute paths pointed into a sandbox and
docker/systemctl stubbed; every call it makes is recorded.
"""

import os
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SEQ = (REPO / 'scripts' / 'guarddog' / 'tak-boot-sequencer.sh').read_text()
APP = (REPO / 'app.py').read_text(encoding='utf-8')


@pytest.fixture
def box(tmp_path):
    calls = tmp_path / 'calls.log'
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    for name in ('docker', 'systemctl', 'logger'):
        f = stubs / name
        f.write_text('#!/bin/sh\necho "%s $*" >> %s\n%s\n'
                     % (name, calls, 'exit 1' if name == 'systemctl' else 'exit 0'))
        f.chmod(0o755)
    (stubs / 'id').write_text('#!/bin/sh\nexit 1\n')          # no local postgres user
    (stubs / 'id').chmod(0o755)
    gate = tmp_path / 'gate.sh'
    gate.write_text('#!/bin/sh\necho "gate $*" >> %s\n' % calls)
    gate.chmod(0o755)
    (tmp_path / 'runfs').mkdir()
    script = (SEQ.replace('/proc/uptime', str(tmp_path / 'uptime'))
                 .replace('/run/takguard-boot-sequenced', str(tmp_path / 'runfs' / 'takguard-boot-sequenced'))
                 .replace('/opt/tak-guarddog/tak-client-gate.sh', str(gate))
                 .replace('/opt/tak-guarddog/', str(tmp_path / 'absent') + '/')
                 .replace('/opt/tak/', str(tmp_path / 'absent-tak') + '/'))
    assert '/proc/uptime' not in script and '/run/takguard' not in script
    sp = tmp_path / 'tak-boot-sequencer.sh'
    sp.write_text(script)

    def start(uptime_s):
        (tmp_path / 'uptime').write_text('%d.42 9999.00\n' % uptime_s)
        if calls.exists():
            calls.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs, 'JAVA_HOME': str(tmp_path / 'nojava')}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return r.stdout, (calls.read_text() if calls.exists() else '')
    start.marker = tmp_path / 'runfs' / 'takguard-boot-sequenced'
    return start


def _stopped(calls):
    return [l for l in calls.splitlines() if l.startswith('docker stop')]


def test_first_start_of_a_boot_is_sequenced(box):
    out, calls = box(26)
    assert 'Boot detected (uptime 26s)' in out
    assert 'gate insert' in calls                       # 8089 held shut until TAK can count clients
    assert any('authentik-server-1' in l for l in _stopped(calls))
    assert any(l.strip() == 'docker stop tak-portal' for l in _stopped(calls))
    assert box.marker.exists()


def test_a_restart_during_the_same_boot_leaves_everything_running(box):
    box(26)
    out, calls = box(106)                                # the field case: restart at 106 s
    assert 'Restart during boot (uptime 106s)' in out
    assert 'Boot detected' not in out
    assert _stopped(calls) == []                         # nothing stopped -> nothing left down
    assert 'gate insert' not in calls                    # and no gate left engaged


def test_after_the_boot_window_it_is_a_runtime_restart(box):
    box(26)
    out, calls = box(900)
    assert 'Runtime restart (uptime 900s)' in out and _stopped(calls) == [] and 'gate' not in calls


def test_a_new_boot_clears_the_marker_and_sequences_again(box):
    box(26)
    box.marker.unlink()                                  # /run is a tmpfs: a reboot empties it
    out, calls = box(31)
    assert 'Boot detected (uptime 31s)' in out and _stopped(calls)


def test_startup_migration_restarts_tak_only_for_a_changed_coreconfig_credential():
    body = re.search(r'^def _startup_resync_ldap_service_account\(.*?(?=^def )', APP, re.S | re.M).group(0)
    code = re.sub(r'#.*', '', body)
    assert 'to flush cached state' not in code
    restart_at = code.index("_tak_systemctl('restart')")
    guard = code.rfind('if ', 0, restart_at)
    branch = code[code.rfind('\n', 0, code.rfind('elif', 0, restart_at)):restart_at]
    assert 'coreconfig_changed' in branch and "final_verdict == 'ok'" in branch, branch
    # the Authentik-side-only heal is its own branch and does not restart TAK itself.
    # ops #126: it hands off to the shared helper, which restarts only when the outpost
    # restarted under a TAK that had been up 5+ min (never at box boot — the GH #83 case;
    # covered in test_tak_ldap_recycle.py::test_box_boot_order_never_restarts_tak).
    noop = code[code.index("if healing_performed and final_verdict == 'ok' and not coreconfig_changed:"):]
    noop = noop[:noop.index('elif')]
    assert '_tak_systemctl' not in noop and 'systemctl' not in noop
    assert "_tak_recycle_after_ldap_outage(" in noop and 'check_outpost=True' in noop
    assert 'final=True' not in noop          # defers to the end of a running console update
    assert guard >= 0
