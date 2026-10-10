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
"""The remote-DB watch restarts PostgreSQL only when Server One confirms it is down (GH #99).

Field (10.2.6-alpha, split install): the operator restricted the shared SSH key to rsync
for their own backups. Guard Dog restarted a HEALTHY production PostgreSQL five times and
logged "is down, restart FAILED" 1,540 times over two months, with nothing saying why.
The box was running the May script: the console update skipped every remote-DB script
unless settings said two_server, so it never received the July rework.

The REAL script runs here with its absolute paths pointed into a sandbox and ssh/timeout
stubbed; every restart it sends to Server One is recorded.
"""

import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-remotedb-watch.sh').read_text()
APP = (REPO / 'app.py').read_text(encoding='utf-8')

SSH_STUB = r'''#!/bin/bash
case "$*" in
  *SSHOK*)
    m=$(cat "%(dir)s/ssh_mode")
    case "$m" in
      ok:*)   echo "SSHOK PR=${m#ok:} SU=0"; exit 0 ;;
      forced) echo "rsync: connection unexpectedly closed (0 bytes received so far) [sender]"; exit 12 ;;
      *)      echo "ssh: connect to host db1 port 22: Connection timed out" >&2; exit 255 ;;
    esac ;;
  *restart*)
    echo RESTART >> "%(dir)s/restarts"
    echo "Job for postgresql.service failed." ; exit 1 ;;
esac
'''


@pytest.fixture
def box(tmp_path):
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    gd = tmp_path / 'gd'
    gd.mkdir()
    (stubs / 'ssh').write_text(SSH_STUB % {'dir': tmp_path})
    # `timeout 6 bash -c "</dev/tcp/..."` is the TCP probe -> answer from a file
    (stubs / 'timeout').write_text('#!/bin/sh\n[ "$(cat %s/tcp)" = up ]\n' % tmp_path)
    (stubs / 'sleep').write_text('#!/bin/sh\nexit 0\n')
    (gd / 'send-alert-email.sh').write_text('#!/bin/sh\necho "$1" >> %s/alerts\n' % tmp_path)
    for f in list(stubs.iterdir()) + [gd / 'send-alert-email.sh']:
        f.chmod(0o755)
    key = tmp_path / 'key'
    key.write_text('k')
    script = (WATCH.replace('/var/lib/takguard', str(tmp_path / 'state'))
                   .replace('/var/log/takguard', str(tmp_path / 'log'))
                   .replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('DB_HOST_PLACEHOLDER', 'db1')
                   .replace('DB_PORT_PLACEHOLDER', '5432')
                   .replace('SSH_KEY_PLACEHOLDER', str(key))
                   .replace('SSH_USER_PLACEHOLDER', 'root')
                   .replace('EXTERNAL_DB_PLACEHOLDER', '')
                   .replace('ALERT_EMAIL_PLACEHOLDER', ''))
    assert '/var/lib/takguard' not in script and '/opt/tak-guarddog' not in script
    sp = tmp_path / 'tak-remotedb-watch.sh'
    sp.write_text(script)

    def run(tcp, ssh_mode, times=1):
        (tmp_path / 'tcp').write_text(tcp)
        (tmp_path / 'ssh_mode').write_text(ssh_mode)
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        for _ in range(times):
            r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
            assert r.returncode == 0, r.stderr
        log = tmp_path / 'log' / 'restarts.log'
        rs = tmp_path / 'restarts'
        return (log.read_text() if log.exists() else ''), (len(rs.read_text().split()) if rs.exists() else 0)
    return run


def test_key_restricted_to_a_forced_command_says_so_and_never_restarts(box):
    log, restarts = box('up', 'forced', times=5)                # the field box
    assert restarts == 0
    assert 'forced command' in log and 'rsync: connection unexpectedly closed' in log
    assert 'connect/auth failed' not in log


def test_db_up_on_server_one_is_a_network_problem_not_a_restart(box):
    log, restarts = box('down', 'ok:0', times=6)
    assert restarts == 0
    assert 'NOT restarted' in log and 'network path' in log


def test_server_one_unreachable_is_unknown_and_never_restarted(box):
    log, restarts = box('down', 'unreachable', times=6)        # this node lost its network
    assert restarts == 0
    assert 'could not ask Server One' in log and 'Connection timed out' in log


def test_starting_up_is_not_restarted(box):
    _, restarts = box('down', 'ok:1', times=6)
    assert restarts == 0


def test_confirmed_down_restarts_at_most_three_times_a_day_and_logs_why(box):
    log, restarts = box('down', 'ok:2', times=30)              # an hour of a real outage
    assert restarts == 3                                       # was: every run past the 3rd
    assert 'restart FAILED — Job for postgresql.service failed.' in log
    assert 'daily restart cap (3) reached' in log


# --- delivery: the console update must reach a split box whatever its settings say ---

def _baked(installed):
    src = re.search(r'^_GD_BAKED_REMOTE_KEYS = .*?(?=^def _auto_update_guarddog)', APP, re.S | re.M).group(0)

    def read(path):
        if installed is None:
            raise FileNotFoundError(path)
        return installed
    ns = {'re': re, '_read_priv': read}
    exec(compile(src, 'app.py:baked', 'exec'), ns)
    return ns['_gd_baked_remote_values']('/opt/tak-guarddog/tak-remotedb-watch.sh')


def test_update_refreshes_an_installed_script_with_its_own_endpoint():
    old = ('DB_HOST="10.20.0.5"\nDB_PORT="5432"\nSSH_KEY="/root/.ssh/id_ed25519"\n'
           'SSH_USER="root"\nEXTERNAL_DB="EXTERNAL_DB_PLACEHOLDER"\n')
    vals = _baked(old)
    assert vals == {'DB_HOST': '10.20.0.5', 'DB_PORT': '5432',
                    'SSH_KEY': '/root/.ssh/id_ed25519', 'SSH_USER': 'root'}
    new = WATCH
    for k, v in vals.items():
        new = new.replace(f'{k}_PLACEHOLDER', v)
    assert 'DB_HOST="10.20.0.5"' in new and 'SSH_KEY="/root/.ssh/id_ed25519"' in new
    assert 'MAX_DAILY_DB_RESTARTS=3' in new


def test_update_leaves_alone_what_it_cannot_fill():
    assert _baked(None) is None                                 # not installed on this box
    assert _baked('DB_HOST="DB_HOST_PLACEHOLDER"\n') is None    # never pointed at a host


def test_auto_update_no_longer_skips_remotedb_on_settings_alone():
    body = re.search(r'^def _auto_update_guarddog\(.*?(?=^_auto_update_guarddog\(\))', APP, re.S | re.M).group(0)
    code = re.sub(r'#.*', '', body)
    assert "if not is_two_server and 'remotedb' in name:\n                continue" not in code
    assert '_gd_baked_remote_values(' in code
