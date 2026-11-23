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
"""The "no channel" Guard Dog email names the device behind each row (ops #1052, GH #634 REQ-5).

For every channel-less device row the email prints the TAK entry, the device ID, the client name
and version and the minutes silent. It never prints callsign, user name, certificate name or the
address. The REAL tak-session-watch.sh runs in the same sandbox as the GH #634 test.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_session_watch_leftover_gh634 import ADMIN, IP, LEAKED, LIVE, box  # noqa: E402,F401


def test_ops1052_email_names_the_device_behind_a_leftover(box):
    mail = box([ADMIN, LIVE, LEAKED], [IP + ':57833'])
    assert 'Devices with no channel (longest silent first, up to 5):' in mail
    # 5347819 ms is 89 minutes
    assert 'TAK entry tls:412: device ANDROID-a, ATAK-CIV 5.6.0.12, silent 89 min, leftover' in mail


def test_ops1052_email_names_a_device_that_is_still_connected(box):
    mail = box([ADMIN, LIVE, LEAKED], [IP + ':57833', IP + ':57834'])
    assert 'TAK entry tls:412: device ANDROID-a, ATAK-CIV 5.6.0.12, silent 89 min' in mail
    assert 'leftover' not in mail.split('TAK entry tls:412')[1].splitlines()[0]


def test_ops1052_email_never_names_a_person_or_an_address(box):
    row = dict(LEAKED, callsign='ALPHA-6', username='jsmith', dn='CN=jsmith,OU=Fire')
    mail = box([ADMIN, LIVE, row], [IP + ':57833'])
    assert 'ANDROID-a' in mail
    for private in ('ALPHA-6', 'jsmith', 'CN=', 'OU=Fire', IP, '57834'):
        assert private not in mail


def test_ops1052_longest_silent_first_and_at_most_five(box):
    rows = [ADMIN, LIVE]
    for i in range(7):
        rows.append(dict(LEAKED, subscriptionUid='tls:%d' % (500 + i), clientUid='ANDROID-d%d' % i,
                         port=str(40000 + i), lastReportDiffMilliseconds=(i + 1) * 120000))
    mail = box(rows, [IP + ':57833'])
    shown = [ln for ln in mail.splitlines() if ln.strip().startswith('TAK entry tls:')]
    assert len(shown) == 5
    assert 'tls:506' in shown[0] and 'silent 14 min' in shown[0]
    assert 'tls:502' in shown[-1]


def test_ops1052_text_a_client_sends_cannot_break_the_email_or_the_shell(box):
    # takClient / takVersion / clientUid come from the device. Spaces, quotes and shell
    # characters must come out as plain words and never run or split the line.
    row = dict(LEAKED, clientUid='ANDROID-a;$(touch${IFS}pwned)`id`', takClient="ATAK CIV'x", takVersion='5.6 "x" +1')
    mail = box([ADMIN, LIVE, row], [IP + ':57833'])
    line = [ln for ln in mail.splitlines() if 'TAK entry tls:412' in ln]
    assert len(line) == 1, mail
    assert '$(' not in line[0] and '`' not in line[0] and ';' not in line[0] and "'" not in line[0]
    assert 'silent 89 min' in line[0]


def test_ops1052_row_with_no_silence_number_says_unknown(box):
    odd = {k: v for k, v in LEAKED.items() if k != 'lastReportDiffMilliseconds'}
    mail = box([ADMIN, LIVE, odd], [IP + ':57833'])
    assert 'device ANDROID-a, ATAK-CIV 5.6.0.12, silent ? min' in mail


def test_ops1052_no_device_list_when_nothing_is_channel_less(box):
    mail = box([ADMIN, LIVE], [IP + ':57833'])
    assert 'Devices with no channel' not in mail


def test_ops1052_service_row_with_no_identity_is_not_listed(box):
    # A server-side service (no device id, no client) is expected on no channel and not listed.
    svc = {'subscriptionUid': 'tls:9', 'username': 'svc', 'clientUid': '', 'ipAddress': '172.21.0.9',
           'port': '1', 'groups': []}
    mail = box([ADMIN, LIVE, LEAKED, svc], [IP + ':57833'])
    assert 'tls:9' not in mail
    assert 'tls:412' in mail
