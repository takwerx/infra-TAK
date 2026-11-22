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
"""Rotate Intermediate CA after an earlier rotation that stopped half-way (ops #986).

Before: Step 6 replaced the CA name it read from ca.pem inside CoreConfig.xml. A rotation that
failed at Step 3 had already made the new CA the working one (ca.pem) but never touched
CoreConfig.xml, which kept naming the first CA. The next rotation found nothing to replace, logged
"CoreConfig.xml updated" and "ROTATION COMPLETE", and TAK Server went on signing with, and trusting,
the old CA: the admin cert and new clients were refused. A second rotation changed nothing either.
(Seen on a Docker TAK Server, ARM, Ubuntu 22.04, v10.4.2 and the v10.4.3 candidate, ops #984.)

Same harness as ops #942 (the real takserver_rotate_intca in a Flask test client, stand-in
makeCert.sh), with a CoreConfig.xml on disk that Step 6 really reads and writes.
"""

import re
import sys

import pytest

sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent))
from test_rotate_intca_existing_name_ops942 import Box, _func, _log, coreconfig_naming  # noqa: E402

FIRST_CA = 'INTERMEDIATE-CA-01'


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


@pytest.fixture
def stuck(box):
    """ca.pem is INT-CA-B2 (the half-failed rotation made it) while CoreConfig.xml still names the
    first CA: the state ops #984 left the Docker box in."""
    (box.tak / 'CoreConfig.xml').write_text(coreconfig_naming(FIRST_CA))
    return box


# Read with plain regexes, not the app's helpers, so these tests also run (and fail for the right
# reason) on code that does not have the helpers.
def _signing(box):
    return re.search(r'keystoreFile="certs/files/([^"]+)-signing\.jks"', box.corecfg()).group(1)


def _truststore(box):
    return re.search(r'truststoreFile="certs/files/truststore-([^"]+)\.jks"', box.corecfg()).group(1)


# ── the bug, as the admin met it ─────────────────────────────────────────────────────────────

def test_rotation_moves_corecfg_to_the_new_ca_when_ca_pem_is_ahead_of_it(stuck):
    assert stuck.working_ca() == 'INT-CA-B2' and _signing(stuck) == FIRST_CA
    r, done = stuck.rotate('INT-CA-B3')
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    assert done and done['complete'] and not done['error'], _log(stuck)
    assert _signing(stuck) == 'INT-CA-B3', 'CoreConfig.xml still signs enrollment with the old CA\n' + stuck.corecfg()
    assert _truststore(stuck) == 'INT-CA-B3', 'CoreConfig.xml still enforces the old truststore\n' + stuck.corecfg()
    assert FIRST_CA not in stuck.corecfg()


def test_a_second_rotation_on_the_stuck_box_is_not_a_silent_no_op(stuck):
    """The report: rotating again said COMPLETE and changed nothing. Now each one lands."""
    for name in ('INT-CA-B3', 'INT-CA-B4'):
        r, done = stuck.rotate(name)
        assert done and not done['error'], _log(stuck)
        assert _signing(stuck) == name and _truststore(stuck) == name


def test_the_federation_truststore_and_the_other_tls_fields_are_left_alone(stuck):
    stuck.rotate('INT-CA-B3')
    cc = stuck.corecfg()
    assert 'certs/files/fed-truststore.jks' in cc
    assert cc.count('certs/files/takserver.jks') == 2
    assert 'keystorePass="atakatak"' in cc and 'validityDays="730"' in cc


def test_a_clean_box_still_rotates_as_before(box):
    """CoreConfig.xml names the working CA (the normal case): same result as ever."""
    assert _signing(box) == 'INT-CA-B2'
    r, done = box.rotate('INT-CA-B3')
    assert done and done['complete'] and not done['error'], _log(box)
    assert _signing(box) == 'INT-CA-B3' and _truststore(box) == 'INT-CA-B3'
    assert 'ROTATION COMPLETE' in _log(box)


def test_the_example_file_only_has_the_old_ca_name_replaced(stuck):
    (stuck.tak / 'CoreConfig.example.xml').write_text(coreconfig_naming('INT-CA-B2'))
    stuck.rotate('INT-CA-B3')
    assert 'INT-CA-B3-signing.jks' in (stuck.tak / 'CoreConfig.example.xml').read_text()


# ── the second line of defence: never say COMPLETE over a CoreConfig that names another CA ────

def test_a_corecfg_that_cannot_be_moved_fails_the_rotation_and_does_not_restart_tak(stuck):
    stuck.ns['_write_priv'] = lambda p, t: None      # the write is lost (read-only file, broker refusal)
    r, done = stuck.rotate('INT-CA-B3')
    assert r.status_code == 200
    assert done is not None and done['error'] is True, _log(stuck)
    log = _log(stuck)
    assert 'ROTATION COMPLETE' not in log and 'ROTATION FAILED' in log
    assert f'{FIRST_CA}-signing.jks' in log and 'INT-CA-B3' in log, 'the failure must name both CAs'
    assert 'TAK Server restarted' not in log
    assert stuck.steps_after_ca.count('state-saved') == 0, 'a failed rotation must not open the rotation window'


def test_an_unreadable_corecfg_fails_the_rotation(stuck):
    def boom(p):
        if p.endswith('CoreConfig.xml'):
            raise PermissionError('denied')
        return open(p).read()
    stuck.ns['_read_priv'] = boom
    r, done = stuck.rotate('INT-CA-B3')
    assert done is not None and done['error'] is True and 'ROTATION COMPLETE' not in _log(stuck)


# ── the helpers ────────────────────────────────────────────────────────────────────────────────

def _h():
    ns = {'os': __import__('os'), 're': __import__('re'), 'html': __import__('html')}
    for n in ('_rotate_coreconfig_truststore', '_coreconfig_signing_ca', '_coreconfig_truststore_ca',
              '_coreconfig_point_at_ca', '_coreconfig_ca_mismatch'):
        exec(compile(_func(n), 'app.py', 'exec'), ns)
    return ns


def test_helpers_read_the_names_the_file_holds():
    h = _h()
    cc = coreconfig_naming('MY-CA')
    assert h['_coreconfig_signing_ca'](cc) == 'MY-CA'
    assert h['_coreconfig_truststore_ca'](cc) == 'MY-CA'
    assert h['_coreconfig_ca_mismatch'](cc, 'MY-CA') == []
    assert len(h['_coreconfig_ca_mismatch'](cc, 'NEXT')) == 2


@pytest.mark.parametrize('text', ['', '<Configuration/>', None,
                                  '<security><tls truststoreFile="certs/files/truststore.jks"/></security>'])
def test_helpers_say_nothing_when_corecfg_has_no_ca_pointer(text):
    h = _h()
    assert h['_coreconfig_signing_ca'](text) == '' and h['_coreconfig_truststore_ca'](text) == ''
    assert h['_coreconfig_ca_mismatch'](text, 'NEW') == []
    assert h['_coreconfig_point_at_ca'](text, 'OLD', 'NEW') == (text or '')


def test_point_at_ca_uses_the_file_name_even_when_old_name_is_elsewhere():
    h = _h()
    out = h['_coreconfig_point_at_ca'](coreconfig_naming('FROM-FILE'), 'FROM-CA-PEM', 'NEW')
    assert 'certs/files/NEW-signing.jks' in out and 'certs/files/truststore-NEW.jks' in out
    assert 'FROM-FILE' not in out
