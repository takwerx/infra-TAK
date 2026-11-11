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
"""Guard Dog checks every number before it does arithmetic with it (ops #628).

The session watch reads TAK's client list (free-text clientUid / takClient fields) and
the DB scripts read psql output. Every number must be digits only before bash does
arithmetic with it; a value that is not is skipped. A marker file shows the odd value
was not evaluated.

The REAL scripts run with their absolute paths pointed into a sandbox and the system
tools stubbed.
"""

import json
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
GD = REPO / 'scripts' / 'guarddog'
WATCH = (GD / 'tak-session-watch.sh').read_text()

NORMAL = {'subscriptionUid': 'tls:2', 'username': 'admin', 'clientUid': '', 'ipAddress': '172.21.0.2',
          'groups': [{'name': 'OPS', 'direction': 'IN'}, {'name': 'OPS', 'direction': 'OUT'}]}


def _client(uid, **kw):
    r = {'subscriptionUid': 'tls:9', 'username': 'u1', 'clientUid': uid, 'takClient': 'ATAK-CIV',
         'takVersion': '5.4.0.1', 'ipAddress': '47.153.3.83',
         'groups': [{'name': 'OPS', 'direction': 'IN'}]}
    r.update(kw)
    return r


@pytest.fixture
def box(tmp_path):
    stubs, gd, state, logs, proc = (tmp_path / n for n in ('bin', 'gd', 'state', 'logs', 'proc'))
    for d in (stubs, gd, proc):
        d.mkdir()
    (proc / 'uptime').write_text('99999.00 1.00\n')
    (gd / '_marti_admin.pem').write_text('PEM')
    (gd / '_marti_admin.key').write_text('KEY')
    mails = tmp_path / 'mails'
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\n{ echo "SUBJECT $1"; cat; echo; } >> %s\n' % mails)
    alert.chmod(0o755)
    (stubs / 'curl').write_text('#!/bin/sh\ncat %s/body\nprintf "\\n__HTTP:200"\n' % tmp_path)
    (stubs / 'ss').write_text(
        '#!/bin/sh\ncase "$*" in\n'
        '  *-ltn*) echo "State Recv-Q Send-Q Local Peer"; echo "LISTEN 0 4096 *:8089 *:*" ;;\n'
        '  *) echo "Recv-Q Send-Q Local Peer"; echo "0 0 10.0.0.5:8089 47.153.3.83:49844" ;;\nesac\n')
    (stubs / 'systemctl').write_text('#!/bin/sh\necho 1000000\n')
    (stubs / 'logger').write_text('#!/bin/sh\nexit 0\n')
    for f in stubs.iterdir():
        f.chmod(0o755)
    script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/var/log/takguard', str(logs))
                   .replace('/proc/', str(proc) + '/')
                   .replace('/tmp/', str(tmp_path) + '/'))
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def tick(rows):
        (tmp_path / 'body').write_text(json.dumps({'data': rows}))
        if mails.exists():
            mails.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        # cwd = the sandbox, so a relative path in a payload lands where we look
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env,
                           timeout=60, cwd=str(tmp_path))
        assert r.returncode == 0, r.stderr
        return mails.read_text() if mails.exists() else ''

    tick.log = lambda: (logs / 'session.log').read_text() if (logs / 'session.log').exists() else ''
    tick.tmp = tmp_path
    tick.stubs = stubs
    return tick


def _check_line(log):
    lines = [ln for ln in log.splitlines() if '| CHECK |' in ln]
    assert lines, log
    return lines[-1]


def test_uid_with_spaces_stays_one_field(box):
    marker = box.tmp / 'marker'                 # relative: the uid is cut at 64 characters
    uid = 'x 1 c v 1.2.3.4 999 a[$(touch${IFS}marker)]'
    box([NORMAL, _client(uid), _client(uid)])
    assert not marker.exists(), 'the session watch evaluated clientUid text'
    line = _check_line(box.log())
    # the uid is one plain word; the counts after it are the real ones, not shifted
    assert ' top_uid=x-1-c-v-1.2.3.4-999-a' in line and '/2 top_ip=' in line
    assert '$(' not in line and '[' not in line.split('top_uid=')[1]


def test_takclient_with_tabs_stays_one_field(box):
    # takClient had spaces replaced but not tabs, so a tab shifted the fields too.
    box([NORMAL, _client('ANDROID-1', takClient='c\tv\t1\t999\ta[$(>marker2)]')])
    assert not (box.tmp / 'marker2').exists()
    line = _check_line(box.log())
    assert 'top_uid=ANDROID-1/1 ' in line and 'top_ip=47.153.3.83/1 sockets/1 uids' in line


def test_shell_side_fails_closed_on_a_non_number_from_the_helper(box):
    # Belt and braces: even if the helper printed a bad field, bash checks before $(( )).
    (box.stubs / 'python3').write_text(
        '#!/bin/sh\necho "3 0 0 0 uid 1 c v 1.2.3.4 999 a[\\$(>marker3)] keys"\n')
    (box.stubs / 'python3').chmod(0o755)
    box([NORMAL])
    assert not (box.tmp / 'marker3').exists()
    log = box.log()
    assert 'SKIP | subscriptions helper gave a non-number for TOPIPUIDS' in log
    assert '| CHECK |' not in log and '$(' not in log


def test_blank_tak_version_no_longer_blinds_the_check(box):
    box([NORMAL, _client('ANDROID-2', takVersion='   ')])
    log = box.log()
    assert 'could not parse' not in log
    assert 'top_uid=ANDROID-2/1 ' in _check_line(log)


def test_real_storm_still_alerts_with_the_device_named(box):
    rows = [NORMAL] + [_client('ANDROID-storm')] * 60
    assert box(rows) == '' and box(rows) == ''
    mail = box(rows)
    assert mail.startswith('SUBJECT TAK connection storm on ')
    assert 'Device (clientUid): ANDROID-storm' in mail
    assert 'Client / version  : ATAK-CIV 5.4.0.1' in mail


# ── DB scripts: psql output is not ours either ──────────────────────────────────────────
# A fake `sudo -u postgres psql`: SELECT 1 answers 1 (so the probes pass), every other
# query answers the payload. No DB container, no remote DB.
FAKE_SUDO = r'''#!/bin/bash
sql="${@: -1}"
case "$sql" in
  "SELECT 1;") echo 1 ;;
  *pg_stat_activity*pid\ FROM*) echo 4242 ;;
  *) echo "$PAYLOAD" ;;
esac
'''


@pytest.mark.parametrize('name', ['tak-cotdb-watch.sh', 'tak-auto-vacuum.sh',
                                  'tak-db-repack.sh', 'tak-retention-guard.sh'])
def test_db_scripts_check_psql_numbers(tmp_path, name):
    stubs, gd, logs, state = (tmp_path / n for n in ('bin', 'gd', 'logs', 'state'))
    for d in (stubs, gd, logs, state):
        d.mkdir()
    marker = tmp_path / 'marker'
    (stubs / 'sudo').write_text(FAKE_SUDO)
    (stubs / 'psql').write_text(FAKE_SUDO)      # gd_psql_present looks for psql on PATH
    # auto-vacuum skips a host with no postgres account
    (stubs / 'id').write_text('#!/bin/sh\n[ "$*" = "-u postgres" ] && { echo 999; exit 0; }\n'
                              'exec /usr/bin/id "$@"\n')
    for tool, body in (('ssh', 'exit 1'), ('docker', 'exit 1'), ('ip', 'exit 0'),
                       ('systemctl', 'exit 0'), ('logger', 'exit 0'), ('df', 'exit 1'),
                       ('pg_repack', 'exit 0')):
        (stubs / tool).write_text('#!/bin/sh\n%s\n' % body)
    for f in stubs.iterdir():
        f.chmod(0o755)
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\ncat >/dev/null\n')
    alert.chmod(0o755)
    (gd / '_gd-tak-lib.sh').write_text((GD / '_gd-tak-lib.sh').read_text()
                                       .replace('/opt/tak/CoreConfig.xml', str(tmp_path / 'none.xml')))
    script = ((GD / name).read_text()
              .replace('/opt/tak-guarddog/', str(gd) + '/')
              .replace('/var/log/takguard', str(logs))
              .replace('/var/lib/takguard', str(state))
              .replace('/opt/tak/conf/retention/', str(tmp_path) + '/'))
    sp = tmp_path / name
    sp.write_text(script)
    env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs,
           'GD_CONF_FILE': str(gd / 'guarddog.conf'),
           'PAYLOAD': 'a[$(touch${IFS}%s)]' % marker}
    subprocess.run(['bash', str(sp), '--force'], capture_output=True, text=True, env=env,
                   timeout=60, cwd=str(tmp_path))
    assert not marker.exists(), '%s evaluated psql output as a number' % name


def test_update_reinstalls_every_fixed_script():
    # Existing boxes get the fix through Update Now: the post-update Guard Dog redeploy
    # rewrites every script in this list whose content changed and logs their names.
    app = (REPO / 'app.py').read_text()
    start = app.index('def run_guarddog_deploy(')
    body = app[start:app.index('\ndef ', start + 10)]
    for name in ('tak-session-watch.sh', 'tak-cotdb-watch.sh', 'tak-auto-vacuum.sh',
                 'tak-db-repack.sh', 'tak-retention-guard.sh'):
        assert "'%s'" % name in body, name
    assert 'Scripts installed:' in body
