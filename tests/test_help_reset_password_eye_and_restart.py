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
"""Help → Reset console password (operator, v10.4.0 T&E on nuc, 2026-11-15).

1. With 12+ characters required and every field masked, the operator could not see what
   they typed. Each field gets a show/hide eye, and the new password shows its length.
2. The page said "Console will restart in a few seconds" and then never changed, so it looked
   like the restart never happened (it did: nuc 16:32:09 stop → 16:32:16 start). The page now
   waits for the console to come back and says so.
"""

import pathlib
import re

HELP = (pathlib.Path(__file__).resolve().parent.parent / 'templates' / 'help.html').read_text()


def test_each_reset_field_has_a_show_hide_eye():
    for fid in ('reset-current', 'reset-new', 'reset-confirm'):
        assert re.search(r'id="%s"[^>]*>\s*<span onclick="toggleResetPw\(\'%s\',this\)"' % (fid, fid), HELP), fid
    assert "i.type=show?'text':'password'" in HELP
    assert "visibility_off" in HELP


def test_new_password_length_is_shown():
    assert 'id="reset-new-count"' in HELP and 'oninput="resetPwCount()"' in HELP


def test_success_waits_for_the_restart_and_says_so():
    body = HELP[HELP.index('function doResetPassword'):]
    assert 'resetWaitForRestart(msg)' in body
    assert 'the console restarted' in body
    # the fields are cleared and masked again after success
    assert "i.value='';i.type='password'" in body


def test_confirm_field_says_when_it_matches():
    # operator, v10.4.0 T&E: the counter turned green, the confirm field gave no sign
    assert 'id="reset-confirm-match"' in HELP
    assert re.search(r'id="reset-confirm"[^>]*oninput="resetPwCount\(\)"', HELP)
    assert "'✓ Matches'" in HELP and "'Does not match yet'" in HELP
