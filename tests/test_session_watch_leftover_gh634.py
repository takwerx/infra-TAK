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
"""Guard Dog names a leftover subscription and stops promising it clears by itself (GH #634).

Field report 2026-11-22: one ATAK device reconnected every few minutes. TAK Server kept one of
its subscriptions after the connection closed: no groups, user name set, silent for 89 minutes,
its source port not in `ss`. The device had a live subscription with 4 groups at the same time.
Guard Dog's email said such a row "self-heals within about 10 minutes". It does not: the
console only drops connections TAK gave NO user name, so this row stayed until a TAK restart.

The REAL tak-session-watch.sh runs with its absolute paths pointed into a sandbox and curl / ss /
systemctl stubbed. `ss` answers from a file, so each test sets which sockets are open.
"""

import json
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
WATCH = (REPO / 'scripts' / 'guarddog' / 'tak-session-watch.sh').read_text()

IP = '203.0.113.7'                     # documentation address, not a real device

ADMIN = {'subscriptionUid': 'tls:2', 'username': 'admin', 'clientUid': '', 'ipAddress': '172.21.0.2',
         'port': '35378', 'groups': [{'name': 'OPS', 'direction': 'IN'}, {'name': 'OPS', 'direction': 'OUT'}]}
LIVE = {'subscriptionUid': 'tls:443', 'username': 'u1', 'dn': 'CN=u1', 'clientUid': 'ANDROID-a',
        'takClient': 'ATAK-CIV', 'takVersion': '5.6.0.12', 'ipAddress': ' ' + IP, 'port': '57833',
        'lastReportDiffMilliseconds': 6937,
        'groups': [{'name': 'OPS', 'direction': 'IN'}, {'name': 'OPS', 'direction': 'OUT'}]}
# The leaked row, field values from the report: leading space in ipAddress, empty group vector.
LEAKED = {'subscriptionUid': 'tls:412', 'username': 'u1', 'dn': 'CN=u1', 'clientUid': 'ANDROID-a',
          'takClient': 'ATAK-CIV', 'takVersion': '5.6.0.12', 'ipAddress': ' ' + IP, 'port': '57834',
          'lastReportDiffMilliseconds': 5347819, 'groups': []}


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
    # ss: 8089 listening; the established peers come from the file `peers` (one "ip:port" a line)
    (stubs / 'ss').write_text(
        '#!/bin/sh\ncase "$*" in\n'
        '  *-ltn*) echo "State Recv-Q Send-Q Local Peer"; echo "LISTEN 0 4096 *:8089 *:*" ;;\n'
        '  *) echo "Recv-Q Send-Q Local Peer"; while read p; do echo "0 0 10.0.0.5:8089 $p"; done < %s/peers ;;\n'
        'esac\n' % tmp_path)
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

    def run(rows, peers, ticks=3):
        """Run the watch `ticks` times; return the last email (3 in a row are needed to send one)."""
        (tmp_path / 'body').write_text(json.dumps({'data': rows}))
        (tmp_path / 'peers').write_text(''.join(p + '\n' for p in peers))
        if mails.exists():
            mails.unlink()
        env = {'PATH': '%s:/usr/bin:/bin:/usr/sbin:/sbin' % stubs}
        for _ in range(ticks):
            r = subprocess.run(['bash', str(sp)], capture_output=True, text=True, env=env,
                               timeout=60, cwd=str(tmp_path))
            assert r.returncode == 0, r.stderr
        return mails.read_text() if mails.exists() else ''

    run.log = lambda: (logs / 'session.log').read_text() if (logs / 'session.log').exists() else ''
    return run


def _check_line(log):
    lines = [ln for ln in log.splitlines() if '| CHECK |' in ln]
    assert lines, log
    return lines[-1]


def test_gh634_leftover_row_is_named_and_not_promised_to_self_heal(box):
    # The report's data: the live socket 57833 is open, the leaked row's 57834 is not.
    mail = box([ADMIN, LIVE, LEAKED], [IP + ':57833'])
    assert mail.startswith('SUBJECT TAK client visibility alert on ')
    assert 'Subscriptions with no channel (__ANON__): 1' in mail
    assert '1 of them are LEFTOVERS' in mail and 'TAK entries: tls:412' in mail
    assert 'does NOT drop them, and they do not clear by themselves' in mail
    # the two causes that did not apply are not offered for a row nobody is connected on
    assert 'reconnects these by itself' not in mail and 'NO CHANNEL ASSIGNED' not in mail
    # identity (callsign, user name, DN, device uid) stays out of the mail
    for private in ('u1', 'ANDROID-a', 'CN=', IP):
        assert private not in mail
    line = _check_line(box.log())
    assert 'groupless=1 ' in line and 'groupless_named=1 leftover=1' in line


def test_gh634_row_with_an_open_socket_is_not_a_leftover(box):
    mail = box([ADMIN, LIVE, LEAKED], [IP + ':57833', IP + ':57834'])
    assert 'LEFTOVER' not in mail
    assert 'reconnects these by itself' in mail
    # a connection TAK knows by name is only reconnected after an outage the console saw
    assert 'only after an LDAP outage the console saw' in mail.replace('\n     ', ' ')
    assert 'leftover=0' in _check_line(box.log())


def test_gh634_no_socket_claim_when_the_match_cannot_be_trusted(box):
    # Docker TAK behind a proxy: ss shows other addresses, so nothing matches, not even the live
    # row. Then "no socket" proves nothing and no row may be called a leftover.
    mail = box([ADMIN, LIVE, LEAKED], ['172.18.0.1:40000'])
    assert 'LEFTOVER' not in mail
    assert 'leftover=0' in _check_line(box.log())


def test_gh634_recently_active_row_is_not_a_leftover(box):
    # A connection made after the ss read is in the API but not in ss. It is not silent yet.
    fresh = dict(LEAKED, lastReportDiffMilliseconds=12000)
    mail = box([ADMIN, LIVE, fresh], [IP + ':57833'])
    assert 'LEFTOVER' not in mail
    assert 'leftover=0' in _check_line(box.log())


def test_gh634_row_with_no_silence_number_is_not_a_leftover(box):
    odd = {k: v for k, v in LEAKED.items() if k != 'lastReportDiffMilliseconds'}
    assert 'LEFTOVER' not in box([ADMIN, LIVE, odd], [IP + ':57833'])


def test_gh634_unnamed_row_stays_with_the_console_drop(box):
    # No user name and no DN: the console drops these itself (ops #565), so it is not a leftover.
    unnamed = {k: v for k, v in LEAKED.items() if k not in ('username', 'dn')}
    mail = box([ADMIN, LIVE, unnamed], [IP + ':57833'])
    assert 'LEFTOVER' not in mail
    assert 'drops one TAK never looked up, with no user at' in mail
    line = _check_line(box.log())
    assert 'groupless=1 ' in line and 'groupless_named=0 leftover=0' in line


def test_gh634_leftover_and_another_groupless_row_get_both_texts(box):
    other = dict(LEAKED, subscriptionUid='tls:500', clientUid='ANDROID-b', ipAddress='198.51.100.9',
                 port='40000', lastReportDiffMilliseconds=1000)
    mail = box([ADMIN, LIVE, LEAKED, other], [IP + ':57833', '198.51.100.9:40000'])
    assert 'Subscriptions with no channel (__ANON__): 2' in mail
    assert '1 of them are LEFTOVERS' in mail and 'TAK entries: tls:412' in mail
    assert 'For the other __ANON__ subscriptions' in mail and 'NO CHANNEL ASSIGNED' in mail


def test_gh634_ipv6_mapped_peer_still_matches(box):
    # ss prints a dual-stack peer as [::ffff:a.b.c.d]:port
    mail = box([ADMIN, LIVE, LEAKED], ['[::ffff:%s]:57833' % IP])
    assert '1 of them are LEFTOVERS' in mail


def test_gh634_state_change_to_leftover_restarts_the_back_off(box):
    # A new kind of problem (leftover) must mail promptly with the new advice, not wait an hour.
    first = box([ADMIN, LIVE, dict(LEAKED, lastReportDiffMilliseconds=1000)], [IP + ':57833'])
    assert 'LEFTOVER' not in first
    second = box([ADMIN, LIVE, LEAKED], [IP + ':57833'], ticks=3)
    assert '1 of them are LEFTOVERS' in second


def test_gh634_container_row_is_never_a_leftover(box):
    # test12, Nov 21: two channel-holding rows from our own containers (172.x) match no socket in
    # the host's ss. They must never be called leftovers, whatever their silence.
    for local in ('172.18.0.5', '127.0.0.1', '172.31.9.9'):
        row = dict(LEAKED, ipAddress=local, port='41000')
        mail = box([ADMIN, LIVE, row], [IP + ':57833'])
        assert 'LEFTOVER' not in mail, local
        assert 'leftover=0' in _check_line(box.log())
