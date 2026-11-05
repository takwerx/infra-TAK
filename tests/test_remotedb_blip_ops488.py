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
"""Guard Dog's split-install database checks do not email on one blip (ops #488).

Field (test8, a split install): two emails about the database box at 2:43 AM and 3:04 AM PT,
and the same two on Oct 24, 28, 31 and Nov 1, while the database port answered and TAK was
using the database normally.
  - 2:43 AM: tak-remotedb-watch.sh. ONE SSH probe to Server One timed out on port 22 ->
    "management channel degraded" email at once.
  - 3:04 AM: tak-remotedb-auth-watch.sh. ONE failed password check, the password matching on
    Server One -> "DB Credential Alert ... check pg_hba.conf" email at once.
Both now need 3 failures in a row (one per 2-minute timer run) before they email, and the
email names the check that failed and what the database port did at that moment. A real
outage (port down) and proven password drift still act within the same few minutes.

The REAL scripts run here with their absolute paths pointed into a sandbox and ssh, timeout,
sudo (and, where the system grep has no -P, grep) stubbed.
"""

import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
WATCH = (GD / 'tak-remotedb-watch.sh').read_text()
AUTH = (GD / 'tak-remotedb-auth-watch.sh').read_text()

# --- stubs ---------------------------------------------------------------------------

WATCH_SSH = r'''#!/bin/bash
case "$*" in
  *SSHOK*)
    if [ "$(cat "@DIR@/ssh_mode")" = ok ]; then echo "SSHOK PR=0 SU=0"; echo "PGOUT accepting connections"; exit 0; fi
    echo "ssh: connect to host db1 port 22: Connection timed out" >&2; exit 255 ;;
  *restart*) echo RESTART >> "@DIR@/restarts"; exit 0 ;;
esac
'''

AUTH_SSH = r'''#!/bin/bash
CFG='<connection url="jdbc:postgresql://db1:5432/cot" username="martiuser" password="%s"/>'
case "$*" in
  *__mgmt_ok__*) echo __mgmt_ok__ ;;
  *PGPASSWORD=*)
    [ "$(cat "@DIR@/psql_mode")" = ssh_drop ] && exit 255
    pw=$(printf '%s' "$*" | sed -n "s/.*PGPASSWORD='\([^']*\)'.*/\1/p")
    [ "$pw" = "$(cat "@DIR@/db_accepts")" ] && echo 1 ;;
  *"sudo cat"*) printf "$CFG\n" "$(cat "@DIR@/server_one_pw")" ;;
esac
exit 0
'''

SUDO = r'''#!/bin/bash
if [ "$1" = cat ]; then shift; exec cat "$@"; fi
echo "$*" >> "@DIR@/sudo.log"; exit 0
'''

# Minimal grep -oP 'X\KY' for a system grep without -P (macOS); everything else is the real grep.
GREP_SHIM = r'''#!/usr/bin/python3 -I
import os, re, sys
a = sys.argv[1:]
if a and a[0] == '-oP':
    pat = a[1]
    pre, _, post = pat.partition('\\K')
    for m in re.finditer('(?:%s)(%s)' % (pre, post), sys.stdin.read()):
        print(m.group(1))
    sys.exit(0)
os.execv('/usr/bin/grep', ['grep'] + a)
'''


def _system_grep_has_P():
    return subprocess.run(['grep', '-oP', 'a\\Kb'], input='ab', capture_output=True, text=True).stdout.strip() == 'b'


def _sandbox(tmp_path, script_text, ssh_stub, extra=()):
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    gd = tmp_path / 'gd'
    gd.mkdir()
    (tmp_path / 'state').mkdir()
    (tmp_path / 'log').mkdir()
    (stubs / 'ssh').write_text(ssh_stub.replace('@DIR@', str(tmp_path)))
    # `timeout 6 bash -c "</dev/tcp/..."` is the TCP probe -> answer from a file
    (stubs / 'timeout').write_text('#!/bin/sh\n[ "$(cat %s/tcp)" = up ]\n' % tmp_path)
    (stubs / 'sleep').write_text('#!/bin/sh\nexit 0\n')
    (stubs / 'sudo').write_text(SUDO.replace('@DIR@', str(tmp_path)))
    if not _system_grep_has_P():
        (stubs / 'grep').write_text(GREP_SHIM)
    (gd / 'send-alert-email.sh').write_text(
        '#!/bin/sh\necho "$1" >> %s/alerts\ncat >> %s/bodies\n' % (tmp_path, tmp_path))
    for f in list(stubs.iterdir()) + [gd / 'send-alert-email.sh']:
        f.chmod(0o755)
    key = tmp_path / 'key'
    key.write_text('k')
    script = (script_text.replace('/var/lib/takguard', str(tmp_path / 'state'))
                         .replace('/var/log/takguard', str(tmp_path / 'log'))
                         .replace('/opt/tak-guarddog/', str(gd) + '/')
                         .replace('CORE_CONFIG="/opt/tak/CoreConfig.xml"', 'CORE_CONFIG="%s/CoreConfig.xml"' % tmp_path)
                         .replace('DB_HOST_PLACEHOLDER', 'db1')
                         .replace('DB_PORT_PLACEHOLDER', '5432')
                         .replace('SSH_KEY_PLACEHOLDER', str(key))
                         .replace('SSH_USER_PLACEHOLDER', 'root')
                         .replace('EXTERNAL_DB_PLACEHOLDER', '')
                         .replace('ALERT_EMAIL_PLACEHOLDER', ''))
    assert '/var/lib/takguard' not in script and '/opt/tak-guarddog' not in script
    sp = tmp_path / 'script.sh'
    sp.write_text(script)
    return stubs, sp


def _alerts(tmp_path):
    f = tmp_path / 'alerts'
    return f.read_text().splitlines() if f.exists() else []


def _log(tmp_path):
    f = tmp_path / 'log' / 'restarts.log'
    return f.read_text() if f.exists() else ''


def _run(stubs, sp, tmp_path):
    env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
    r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr


# --- tak-remotedb-watch.sh: the 2:43 AM "management channel degraded" email ----------------

@pytest.fixture
def watch(tmp_path):
    stubs, sp = _sandbox(tmp_path, WATCH, WATCH_SSH)

    def run(tcp, ssh_mode, times=1):
        (tmp_path / 'tcp').write_text(tcp)
        (tmp_path / 'ssh_mode').write_text(ssh_mode)
        for _ in range(times):
            _run(stubs, sp, tmp_path)
        return tmp_path
    return run


def test_one_ssh_timeout_with_the_database_port_open_sends_no_email(watch):
    t = watch('up', 'timeout', times=1)                         # the 2:43 AM blip
    assert _alerts(t) == []
    assert 'SSH management probe failed (1 of 3 in a row' in _log(t)


def test_two_ssh_timeouts_in_a_row_still_send_no_email(watch):
    assert _alerts(watch('up', 'timeout', times=2)) == []


def test_three_ssh_timeouts_in_a_row_email_and_name_the_check_and_the_port(watch, tmp_path):
    t = watch('up', 'timeout', times=3)
    assert _alerts(t) == ['Guard Dog: remote DB management channel degraded on ' + (
        subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())]
    body = (t / 'bodies').read_text()
    assert 'Check that failed: SSH management probe to root@db1 (3 probes in a row' in body
    assert 'Database port at the same moment: OPEN' in body and 'db1:5432' in body
    assert 'Connection timed out' in body
    watch('up', 'timeout', times=5)                             # same state: no repeat within the hour
    assert len(_alerts(tmp_path)) == 1


def test_a_passing_probe_resets_the_count(watch):
    watch('up', 'timeout', times=2)
    watch('up', 'ok', times=1)                                  # healthy again
    t = watch('up', 'timeout', times=2)                         # two more: still under three
    assert _alerts(t) == []
    assert (t / 'state' / 'remotedb_mgmt_fail_count').read_text().strip() == '2'   # restarted from 0, not 4


def test_a_real_outage_still_emails_within_three_runs_and_restarts_nothing_unconfirmed(watch):
    t = watch('down', 'timeout', times=3)                       # port closed AND Server One silent
    assert _alerts(t) == ['TAK Server Remote Database Alert on ' + (
        subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())]
    assert not (t / 'restarts').exists()                        # cannot confirm from Server One


# --- tak-remotedb-auth-watch.sh: the 3:04 AM "DB Credential Alert" email -------------------

@pytest.fixture
def auth(tmp_path):
    stubs, sp = _sandbox(tmp_path, AUTH, AUTH_SSH)
    (tmp_path / 'CoreConfig.xml').write_text(
        '<connection url="jdbc:postgresql://db1:5432/cot" username="martiuser" password="pw-local"/>\n')

    def run(db_accepts, server_one_pw='pw-local', psql_mode='ok', times=1, tcp='up'):
        (tmp_path / 'db_accepts').write_text(db_accepts)
        (tmp_path / 'server_one_pw').write_text(server_one_pw)
        (tmp_path / 'psql_mode').write_text(psql_mode)
        (tmp_path / 'tcp').write_text(tcp)
        for _ in range(times):
            _run(stubs, sp, tmp_path)
        return tmp_path
    return run


def test_one_failed_password_check_that_matches_server_one_sends_no_email(auth):
    t = auth('something-else', times=1)                         # the 3:04 AM blip
    assert _alerts(t) == []
    assert 'DB password check failed (1 of 3 in a row, no alert yet)' in _log(t)


def test_three_failed_checks_in_a_row_email_and_name_the_check_and_the_port(auth):
    t = auth('something-else', times=3)
    assert len(_alerts(t)) == 1 and 'DB Credential Alert' in _alerts(t)[0]
    body = (t / 'bodies').read_text()
    assert 'Check that failed: database login as martiuser to db1:5432 (3 checks in a row' in body
    assert 'Database port at the same moment: OPEN' in body
    assert 'Check pg_hba.conf' in body


def test_a_passing_check_between_failures_resets_the_count(auth):
    auth('something-else', times=2)
    auth('pw-local', times=1)                                   # login works again
    t = auth('something-else', times=2)
    assert _alerts(t) == []


def test_proven_drift_is_still_fixed_and_reported_on_the_first_failure(auth):
    t = auth('pw-new', server_one_pw='pw-new', times=1)         # Server One has a new password that works
    assert len(_alerts(t)) == 1 and 'Auto-Resynced' in _alerts(t)[0]
    assert 'systemctl restart takserver' in (t / 'sudo.log').read_text()


def test_a_dropped_ssh_session_is_not_a_credential_failure(auth):
    t = auth('whatever', psql_mode='ssh_drop', times=5)         # ssh rc 255 on the password check
    assert _alerts(t) == []
    assert 'Credentials were not tested' in _log(t)
    assert not (t / 'state' / 'remotedb_auth_fail_count').exists()
