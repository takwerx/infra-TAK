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

import importlib.util
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
        '_TAK58_MANAGED_STORAGE': 'provider-managed',
    }
    for helper in ('_tak58_fmt_measured', '_tak58_preflight_summary_line'):
        exec(compile(_cut(helper), 'app.py:' + helper, 'exec'), n)
    exec(compile(_cut('run_takserver_58_migration'), 'app.py:run_takserver_58_migration',
                 'exec'), n)
    n['run_takserver_58_migration']('/tmp/takserver_5.8-RELEASE92_all.deb', log=log,
                                    status=status)
    return calls, log, status


def _broker():
    spec = importlib.util.spec_from_file_location(
        'takwerx_broker_gh761', REPO / 'broker' / 'takwerx_broker.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _install_argv(held):
    """The argv the 5.8 update really sends to apt-get, taken from the function itself."""
    calls, _, _ = _run(('5.7-RELEASE43', '5.8-RELEASE105'), 0, held=held)
    cmd = [c for c, _ in calls if isinstance(c, str) and 'apt-get install' in c][0]
    words = shlex.split(cmd)
    while words and re.fullmatch(r'[A-Z_]+=\S*', words[0]):
        words.pop(0)                      # DEBIAN_FRONTEND=noninteractive
    assert words[-1] == '2>&1'
    return words[:-1]


def test_gh761_the_install_command_passes_the_broker_rulebook():
    # GH #761: the console sent --allow-change-held-packages, a non-root console routes
    # apt through the broker, and the broker's allow-list refused it ("option not
    # allowed") after TAK Server was already stopped. The flag is sent whether or not a
    # package is held, so this holds for the held and the not-held box alike.
    B = _broker()
    for held in (True, False):
        argv = _install_argv(held)
        assert argv[:2] == ['apt-get', 'install']
        assert '--allow-change-held-packages' in argv
        B.check_exec(argv)                # raises Denied on the base branch


def test_gh761_only_the_exact_flag_spelling_is_allowed():
    # The control is allowed; shortened spellings and the neighbouring unsafe flag are not.
    B = _broker()
    deb = '/tmp/takserver_5.8-RELEASE105_all.deb'
    base = ['apt-get', 'install', '-y', '--allow-downgrades']
    B.check_exec(base + ['--allow-change-held-packages', deb])
    B.check_exec(base + [deb])
    for bad in ('--allow-change-held-package', '--allow-change-held', '--allow-change',
                '--allow-c', '--allow-change-held-packages=1', '--allow-unauthenticated'):
        try:
            B.check_exec(base + [bad, deb])
        except B.Denied:
            continue
        raise AssertionError('broker allowed %s' % bad)


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
