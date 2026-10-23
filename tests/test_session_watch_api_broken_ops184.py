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
"""Guard Dog says so when TAK's client list keeps failing (ops #184).

test12, 2026-10-22: the tak-dev emulator reconnected while an Authentik Reconfigure had the
LDAP outpost down, right after a TAK restart. TAK kept a ghost of that connection (added and
removed within 200 ms, still listed, refuses deletion) and every read of
/Marti/api/subscriptions/all answered HTTP 500 from then on. tak-session-watch.sh logged
"SKIP | subscriptions API returned no usable data" every 5 min and never said anything, while
the Client Dashboard and the console's client heal were just as blind.

A 5xx now counts as a failing check (3 in a row before the email, one per hour, like the
rest); a timeout / no answer is still a SKIP. The REAL script runs with its absolute paths
pointed into a sandbox and curl / ss / systemctl stubbed.
"""

import json
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-session-watch.sh').read_text()

HEALTHY = {'data': [
    {'subscriptionUid': 'tls:2', 'username': 'admin', 'clientUid': '', 'ipAddress': '172.21.0.2',
     'groups': [{'name': 'OPS', 'direction': 'IN'}, {'name': 'OPS', 'direction': 'OUT'}]},
    {'subscriptionUid': 'tls:9', 'username': 'takdev-emu', 'clientUid': 'ANDROID-9d5f', 'takClient': 'ATAK-CIV',
     'ipAddress': '47.153.3.83', 'groups': [{'name': 'TAKDEV-EMU', 'direction': 'IN'}]},
]}


@pytest.fixture
def box(tmp_path):
    stubs, gd, state, logs, proc = (tmp_path / n for n in ('bin', 'gd', 'state', 'logs', 'proc'))
    for d in (stubs, gd, proc):
        d.mkdir()
    (proc / 'uptime').write_text('99999.00 1.00\n')            # booted long ago
    (gd / '_marti_admin.pem').write_text('PEM')
    (gd / '_marti_admin.key').write_text('KEY')
    mails = tmp_path / 'mails'
    alert = gd / 'send-alert-email.sh'
    alert.write_text('#!/bin/sh\n{ echo "SUBJECT $1"; cat; echo; } >> %s\n' % mails)
    alert.chmod(0o755)
    # curl: body from $tmp/body, then the -w trailer with the code in $tmp/code (000 = no answer)
    (stubs / 'curl').write_text(
        '#!/bin/sh\necho call >> %(t)s/curl.calls\ncode=$(cat %(t)s/code)\n'
        '[ "$code" = 000 ] && { printf "\\n__HTTP:000"; exit 28; }\n'
        'cat %(t)s/body\nprintf "\\n__HTTP:%%s" "$code"\n' % {'t': tmp_path})
    # ss: 8089 listening, one external client (the emulator) and one container
    (stubs / 'ss').write_text(
        '#!/bin/sh\ncase "$*" in\n'
        '  *-ltn*) echo "State Recv-Q Send-Q Local Peer"; echo "LISTEN 0 4096 *:8089 *:*" ;;\n'
        '  *) echo "Recv-Q Send-Q Local Peer"; echo "0 0 10.0.0.5:8089 47.153.3.83:49844";'
        ' echo "0 0 10.0.0.5:8089 172.21.0.2:35378" ;;\nesac\n')
    # TAK started long ago (well past the startup grace)
    (stubs / 'systemctl').write_text('#!/bin/sh\necho 1000000\n')
    (stubs / 'logger').write_text('#!/bin/sh\necho "logger $*" >> %s\n' % (tmp_path / 'logger'))
    for f in stubs.iterdir():
        f.chmod(0o755)
    script = (WATCH.replace('/opt/tak-guarddog/', str(gd) + '/')
                   .replace('/var/lib/takguard', str(state))
                   .replace('/var/log/takguard', str(logs))
                   .replace('/proc/', str(proc) + '/')
                   .replace('/tmp/', str(tmp_path) + '/'))
    sp = tmp_path / 'watch.sh'
    sp.write_text(script)

    def tick(code='500', body='<html>TAK Server resource unavailable or not allowed.</html>'):
        (tmp_path / 'code').write_text(code)
        (tmp_path / 'body').write_text(body if isinstance(body, str) else json.dumps(body))
        if mails.exists():
            mails.unlink()                                  # only what this run sent
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        return mails.read_text() if mails.exists() else ''

    tick.log = lambda: (logs / 'session.log').read_text() if (logs / 'session.log').exists() else ''
    tick.fails = lambda: int((state / 'session.failcount').read_text()) if (state / 'session.failcount').exists() else 0
    tick.tmp = tmp_path
    return tick


def test_ops184_client_list_failing_with_500_is_alerted_after_three_checks(box):
    assert box() == '' and box() == ''                      # 1st and 2nd: counted, not mailed
    assert box.fails() == 2
    mail = box()
    assert mail.startswith('SUBJECT TAK client list unreadable on ')
    assert "TAK Server's client list FAILS" in mail and 'HTTP 500' in mail
    assert 'restart TAK Server from the console' in mail
    assert 'INVISIBLE' not in mail                          # no list: no socket-vs-subscription verdict
    log = box.log()
    assert log.count('CHECK | subscriptions API BROKEN (HTTP 500 on every read) external_sockets=1') == 3
    assert 'SKIP' not in log and '| ALERT | api_broken=1 ' in log
    assert (box.tmp / 'curl.calls').read_text().count('call') == 6   # paginated, then plain, each time
    assert 'api_broken=1' in (box.tmp / 'logger').read_text()


def test_ops184_one_hour_cooldown_also_applies(box):
    for _ in range(3):
        box()
    for _ in range(6):
        assert box() == ''
    assert box.log().count('| ALERT |') == 1


def test_ops184_no_answer_is_still_a_skip_not_a_failure(box):
    for _ in range(4):
        assert box(code='000', body='') == ''
    assert box.fails() == 0
    assert box.log().count('SKIP | subscriptions API returned no usable data (HTTP 000)') == 4


def test_ops184_list_readable_again_resets_the_count(box):
    box(); box()
    assert box.fails() == 2
    assert box(code='200', body=HEALTHY) == ''
    assert box.fails() == 0
    assert box() == ''                                      # a new run of 500s starts from 1
    assert box.fails() == 1


def test_healthy_list_is_quiet(box):
    for _ in range(4):
        assert box(code='200', body=HEALTHY) == ''
    log = box.log()
    assert log.count('CHECK | external_sockets=1 subscriptions=2 groupless=0') == 4
    assert 'BROKEN' not in log and box.fails() == 0


def test_groupless_device_still_alerts_as_before(box):
    anon = {'data': HEALTHY['data'][:1] + [dict(HEALTHY['data'][1], groups=[{'name': '__ANON__', 'direction': 'IN'}])]}
    for _ in range(2):
        assert box(code='200', body=anon) == ''
    mail = box(code='200', body=anon)
    assert mail.startswith('SUBJECT TAK client visibility alert on ')
    assert 'Subscriptions with no channel (__ANON__): 1' in mail
    assert "client list FAILS" not in mail
