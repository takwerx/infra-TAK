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
"""Guard Dog's client visibility email backs off on an unchanged state (ops #486).

test8, Tue Nov 3 2026: one client with no channel produced about 15 identical emails in a day and
a half. tak-session-watch.sh had a flat one-hour cooldown that never backed off, unlike the remote
database alert ("backs off to daily after 24h of the same state"). Now: hourly for the first 24 h
of the same state, daily after, a changed state (or a healthy box) starts over, and the email says
how long the state has lasted. The REAL script runs with its absolute paths pointed into a sandbox
and curl / ss / systemctl stubbed; the state's age is moved by rewriting its state files.
"""

import json
import pathlib
import subprocess
import time

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
    tick.state = state
    return tick



ANON = {'data': HEALTHY['data'][:1] + [dict(HEALTHY['data'][1], groups=[{'name': '__ANON__', 'direction': 'IN'}])]}


def _round(box, body=ANON, code='200'):
    """Three checks in a row (the alert needs 3 bad ones in a row); returns the mail, if any went out."""
    return ''.join(box(code=code, body=body) for _ in range(3))


def _age(box, state_hours, last_alert_hours):
    """Pretend the current state began state_hours ago and the last email went out last_alert_hours ago."""
    now = int(time.time())
    (box.state / 'session.state_since').write_text(str(now - int(state_hours * 3600)))
    (box.state / 'session.last_alert').write_text(str(now - int(last_alert_hours * 3600)))


def test_ops486_unchanged_state_over_a_day_does_not_email_hourly(box):
    assert _round(box).startswith('SUBJECT TAK client visibility alert on ')
    _age(box, state_hours=25, last_alert_hours=2)
    assert _round(box) == ''                                # was: another email, every hour, forever
    assert box.log().count('| ALERT |') == 1


def test_ops486_unchanged_state_over_a_day_emails_once_a_day_and_says_how_long(box):
    _round(box)
    _age(box, state_hours=25, last_alert_hours=25)
    mail = _round(box)
    assert mail.startswith('SUBJECT TAK client visibility alert on ')
    assert 'Same state for: 1 d 1 h' in mail
    assert 'now repeats once a day' in mail


def test_ops486_first_day_still_hourly_and_says_how_long(box):
    _round(box)
    _age(box, state_hours=5, last_alert_hours=0.5)
    assert _round(box) == ''                                # under an hour since the last one
    _age(box, state_hours=5, last_alert_hours=2)
    mail = _round(box)
    assert 'Same state for: 5 h 0 min' in mail
    assert 'repeats hourly for the first day' in mail


def test_ops486_new_kind_of_problem_alerts_promptly_even_after_backoff(box):
    _round(box)
    _age(box, state_hours=30, last_alert_hours=1)
    assert _round(box) == ''                                # backed off
    mail = _round(box, body='<html>unavailable</html>', code='500')
    assert mail.startswith('SUBJECT TAK client list unreadable on ')
    assert 'Same state for: 0 min' in mail                  # the clock started over


def test_ops486_client_count_changing_does_not_restart_the_clock(box):
    _round(box)
    _age(box, state_hours=25, last_alert_hours=2)
    two_anon = {'data': ANON['data'] + [dict(ANON['data'][1], subscriptionUid='tls:10', clientUid='ANDROID-77aa')]}
    assert _round(box, body=two_anon) == ''


def test_ops486_healthy_again_starts_over(box):
    _round(box)
    _age(box, state_hours=30, last_alert_hours=1)
    assert box(code='200', body=HEALTHY) == ''
    assert not (box.state / 'session.state').exists() and not (box.state / 'session.state_since').exists()
    mail = _round(box)                                      # the same problem coming back is a fresh state
    assert mail.startswith('SUBJECT TAK client visibility alert on ')
    assert 'Same state for: 0 min' in mail
