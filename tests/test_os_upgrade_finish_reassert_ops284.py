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
"""ops #284 — boxes v10.3.0 already stopped at `reassert` (on 24.04, venv rebuilt, console
not restarted, no reboot) finish by themselves once the console is updated: the startup
hook re-runs reassert's PG rule with the fixed check, does the cleanup the job skipped,
and hands over to the post-reboot verify. The finish script is EXECUTED here with
pg_lsclusters / systemctl / os-release stubbed.
"""

import json
import subprocess
import types

from test_os_upgrade import _fn, _ns, APP

FIELD = [('15', 'main', '5434', 'down'), ('18', 'main', '5432', 'online')]


def _line(c):
    return f'{c[0]} {c[1]} {c[2]} {c[3]} postgres /var/lib/postgresql/{c[0]}/{c[1]} log/postgresql-%a.log'


def _finish_ns():
    ns = _ns()
    for name in ('_os_upgrade_finish_script', '_os_upgrade_finish_eligible', '_os_upgrade_pg_layout'):
        exec(compile(_fn(name), f'app.py:{name}', 'exec'), ns)
    ns['_OS_UPGRADE_FINISH_MARK'] = ns['_OS_UPGRADE_DIR'] + '/finish-reassert-tried'
    return ns


def _run_finish(tmp_path, clusters, version_id='24.04'):
    ns = _finish_ns()
    script = ns['_os_upgrade_finish_script']('18')
    etc = tmp_path / 'etc'
    (etc / 'apt' / 'apt.conf.d').mkdir(parents=True)
    (etc / 'update-manager' / 'release-upgrades.d').mkdir(parents=True)
    (etc / 'apt' / 'apt.conf.d' / '99infratak-os-upgrade').write_text('x\n')
    (etc / 'update-manager' / 'release-upgrades.d' / 'infratak.cfg').write_text('x\n')
    (etc / 'os-release').write_text(f'ID=ubuntu\nVERSION_ID="{version_id}"\nPRETTY_NAME="Ubuntu {version_id}"\n')
    state = tmp_path / 'state'
    (state / 'pre').mkdir(parents=True)
    (state / 'pre' / 'dpkg-versions.txt').write_text('old 1\n')
    script = (script.replace('/var/lib/infratak-os-upgrade', str(state))
                    .replace('/etc/', f'{etc}/'))
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (tmp_path / 'listing').write_text(''.join(_line(c) + '\n' for c in clusters))
    calls = tmp_path / 'calls'
    stubs = {
        'pg_lsclusters': f'cat {tmp_path}/listing',
        'dpkg': 'exit 0',
        'dpkg-query': 'echo "new 2"',
        'systemctl': (f'echo "systemctl $*" >> {calls}\n'
                      'case "$1" in list-unit-files) echo "$2 enabled enabled" ;; esac\nexit 0'),
    }
    for name, body in stubs.items():
        p = bindir / name
        p.write_text(f'#!/bin/bash\n{body}\n')
        p.chmod(0o755)
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                       env={'PATH': f'{bindir}:/usr/bin:/bin'})
    return types.SimpleNamespace(
        rc=r.returncode, out=r.stdout + r.stderr,
        status=(state / 'status').read_text().strip(),
        calls=calls.read_text() if calls.exists() else '',
        cleaned=not (etc / 'apt' / 'apt.conf.d' / '99infratak-os-upgrade').exists()
                and not (etc / 'update-manager' / 'release-upgrades.d' / 'infratak.cfg').exists())


def test_field_box_finishes_and_hands_over_to_verify(tmp_path):
    r = _run_finish(tmp_path, FIELD)
    assert r.rc == 0, r.out
    assert r.status == 'verifying'
    assert r.cleaned
    assert 'systemctl enable docker' in r.calls
    assert 'systemctl daemon-reload' in r.calls
    assert 'systemctl restart takwerx-broker' in r.calls
    assert 'stopped PostgreSQL 15/main on 5434' in r.out
    # the console that runs this IS the restarted one; it never restarts itself or reboots
    assert 'takwerx-console' not in r.calls and 'reboot' not in r.calls


def test_unsafe_layout_changes_nothing(tmp_path):
    r = _run_finish(tmp_path, [('15', 'main', '5434', 'online'), ('18', 'main', '5432', 'online')])
    assert r.rc == 1
    assert r.status == 'failed:reassert'
    assert not r.cleaned and r.calls.count('enable docker') == 0
    assert 'Nothing was changed by this retry' in r.out


def test_refuses_off_2404(tmp_path):
    r = _run_finish(tmp_path, FIELD, version_id='22.04')
    assert r.rc == 1 and r.status == 'failed:reassert' and not r.cleaned


def test_script_parses():
    ns = _finish_ns()
    r = subprocess.run(['bash', '-n'], input=ns['_os_upgrade_finish_script']('18'),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def _eligible(status='failed:reassert', os_type='ubuntu-24.04', marked=False,
              baseline=None, clusters=FIELD):
    ns = _finish_ns()
    base = {'pg_expect': '18'} if baseline is None else baseline
    ns.update({
        '_os_upgrade_read_status': lambda: status,
        '_read_os_release': lambda: (os_type, ''),
        '_read_priv': lambda p: json.dumps(base),
        '_os_upgrade_pg_clusters': lambda: list(clusters),
        'os': types.SimpleNamespace(path=types.SimpleNamespace(exists=lambda p: marked)),
    })
    return ns['_os_upgrade_finish_eligible']()


def test_eligible_only_for_the_stuck_field_state():
    assert _eligible()[0] is True
    assert _eligible(status='done')[0] is False
    assert _eligible(status='failed:venv-rebuild')[0] is False
    assert _eligible(os_type='ubuntu-22.04')[0] is False
    assert _eligible(marked=True) == (False, 'already tried once')
    assert _eligible(baseline={})[0] is False
    ok, why = _eligible(clusters=[('15', 'main', '5434', 'online'), ('18', 'main', '5432', 'online')])
    assert ok is False and 'still unsafe' in why


def test_thread_marks_once_and_uses_the_broker_shape():
    body = _fn('_startup_os_upgrade_finish_reassert')
    # re-checked after the wait, marked BEFORE launching so a crash can't loop it
    assert body.count('_os_upgrade_finish_eligible()') == 2
    assert body.index('_write_priv(_OS_UPGRADE_FINISH_MARK') < body.index('_os_upgrade_unit_cmd()')
    assert "_sudo_wrap(['systemctl', 'reset-failed', _OS_UPGRADE_UNIT])" in body
    assert '_POST_UPDATE_ACTIVE' in body and 'update-now.lock' in body
    assert body.index("== 'verifying'") < body.index('_startup_os_upgrade_verify()')


def test_startup_runs_it_after_the_post_reboot_verify():
    i = APP.index('if _startup_os_upgrade_verify():')
    assert APP.index('if _startup_os_upgrade_finish_reassert():', i) > i
