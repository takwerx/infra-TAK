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
"""TAK 5.8 update on a box where takserver is apt-held (#117).

Field: the OS patch job's takserver hold made `apt-get install -y` refuse the 5.8
package (exit 100, nothing unpacked). The migration called that the expected pg15
postinst stop, went looking for upgrade-db.sh, and left TAK stopped on an untouched
5.7 under "THIS SERVER IS MID-UPGRADE". run_takserver_58_migration is cut out of
app.py and run with the package manager and systemctl faked.
"""

import os
import pathlib
import re
import shlex
import subprocess as _real_subprocess
import time
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _cut(name):
    return re.search(rf'^def {name}\(.*?(?=^\S)', APP, re.S | re.M).group(0)


def _run(versions, install_rc, held=True):
    """versions: (before, after) installed takserver version around the install."""
    calls, state = [], {'installed': False}

    def fake_run(argv, *a, **k):
        calls.append((argv, k.get('input')))
        out = ''
        if argv[:2] == ['dpkg-query', '-W']:
            if argv[2] == '-f=${Status}':
                out = ('hold' if held else 'install') + ' ok installed'
            else:
                out = versions[1] if state['installed'] else versions[0]
        return _real_subprocess.CompletedProcess(argv, 0, out, '')

    def fake_install(cmd, cwd, log, timeout_sec=0):
        calls.append((cmd, None))
        state['installed'] = True
        return install_rc

    log, status = [], {}
    n = {
        'os': os, 'shlex': shlex, 'time': time,
        'subprocess': types.SimpleNamespace(run=fake_run),
        'tak58_log': [], 'tak58_status': {},
        '_sudo_wrap': lambda argv: argv,
        '_distro_family': lambda: 'debian',
        '_tak_58_preflight': lambda: {'ready': True, 'facts': {'pg_running_major': 15}},
        '_cotdb_fmt_bytes': str,
        '_tak_58_backup': lambda plog=None: {'ok': True, 'snapshot_path': '/opt/tak/snapshots/x'},
        '_tak_upgrade_apt_install_streamed': fake_install,
        '_pgdg_gis_pin_ensure': lambda log_fn=None: True,
        '_get_tak_deployment_config': lambda s: {},
        'load_settings': dict,
        'TAK_PG_MAJOR': 18,
        '_TAK58_UPGRADE_DB_SH': '/nonexistent/upgrade-db.sh',
    }
    exec(compile(_cut('run_takserver_58_migration'), 'app.py:run_takserver_58_migration',
                 'exec'), n)
    n['run_takserver_58_migration']('/tmp/takserver_5.8-RELEASE92_all.deb', log=log,
                                    status=status)
    return calls, log, status


def test_install_is_allowed_past_a_hold():
    calls, _, _ = _run(('5.7-RELEASE32', '5.8-RELEASE92'), 0)
    install = [c for c, _ in calls if isinstance(c, str) and 'apt-get install' in c]
    assert install and '--allow-change-held-packages' in install[0]


def test_refused_install_restarts_tak_and_is_not_called_mid_upgrade():
    calls, log, status = _run(('5.7-RELEASE32', '5.7-RELEASE32'), 100)
    text = '\n'.join(log)
    assert status.get('error') and not status.get('complete')
    assert 'nothing was installed' in text
    assert 'MID-UPGRADE' not in text and '5.8 package is installed' not in text
    assert 'stopped short' not in text and 'upgrade-db.sh' not in text
    argvs = [c for c, _ in calls]
    assert argvs.index(['systemctl', 'start', 'takserver']) > argvs.index(
        ['systemctl', 'stop', 'takserver'])


def test_a_hold_that_was_there_is_put_back():
    calls, _, _ = _run(('5.7-RELEASE32', '5.8-RELEASE92'), 1)
    assert (['dpkg', '--set-selections'], 'takserver hold\n') in calls
    calls, _, _ = _run(('5.7-RELEASE32', '5.8-RELEASE92'), 1, held=False)
    assert not any(c == ['dpkg', '--set-selections'] for c, _ in calls)


def test_unpacked_pg15_stop_still_continues_to_the_migration():
    # The real 5.8 stop happens in the postinst, after the new version is on disk.
    # That path is unchanged: it goes on to the database step (which fails here only
    # because the fake has no upgrade-db.sh) and leaves TAK down, as before.
    calls, log, status = _run(('5.7-RELEASE32', '5.8-RELEASE92'), 1)
    text = '\n'.join(log)
    assert 'stopped short (exit 1)' in text
    assert 'MID-UPGRADE' in text
    assert ['systemctl', 'start', 'takserver'] not in [c for c, _ in calls]
