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
"""The TAK Server snapshot Restore dialog says the package is not changed (ops #1224).

A rollback restores configuration, certificates and the database. It never reinstalls the
TAK Server package (ops #1218). The confirm dialog must say so before the button is pressed,
so a customer who wants an older package knows to use Update with that package.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = (REPO / 'templates' / 'takserver.html').read_text(encoding='utf-8')


def _dialog_text():
    fn = re.search(r'function restoreSnapshot\(label\)\{(.*?)\n\}', TEMPLATE, re.S)
    assert fn, 'restoreSnapshot() not found in takserver.html'
    m = re.search(r"confirm\('(.*?)'\)\)return;", fn.group(1), re.S)
    assert m, 'restoreSnapshot() has no confirm dialog'
    return m.group(1)


def test_restore_dialog_says_the_package_stays():
    text = _dialog_text()
    assert 'The TAK Server package stays as it is now.' in text
    assert 'use Update with that package' in text


def test_restore_dialog_keeps_its_original_lines():
    text = _dialog_text()
    for line in ('• Stop TAK Server', '• Restart TAK Server',
                 'CoreConfig.xml, UserAuthenticationFile.xml, certs, and database',
                 'Current data will be overwritten.'):
        assert line in text
