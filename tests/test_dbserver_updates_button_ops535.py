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
"""The database server card's update button never opens the 24.04 upgrade (ops #535).

Field (Fri Nov 6, 2026): on a split install the card's "Reboot / updates..." button opened
"Upgrade the database server to Ubuntu 24.04 LTS", a one-way job, instead of installing
updates and rebooting. The button now opens a routine updates view of the same modal; the
upgrade stays on the card's own "Check & upgrade..." button. The page side is driven by
scripts/check_dbserver_updates_button.js, which runs the real modal functions.
"""

import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONSOLE = (ROOT / 'templates' / 'console.html').read_text(encoding='utf-8')


def test_card_update_button_is_not_wired_to_the_upgrade_dialog():
    start = CONSOLE.index("{% if host.id == 'tak_db' %}<button")
    buttons = CONSOLE[start:CONSOLE.index('{% endif %}', start)]
    assert 'dbsCardInstallUpdates()' in buttons   # AJ, Sat Nov 7: "Updates needed" installs them when clicked
    assert 'osupOpenPreflight' not in buttons


def test_card_has_a_reboot_button_that_is_always_there():
    """Sat Nov 7, 2026 (AJ): "i need a way to reboot anytime i want", "the card should clearly say if an update is needed"."""
    start = CONSOLE.index("{% if host.id == 'tak_db' %}<button")
    buttons = CONSOLE[start:CONSOLE.index('{% endif %}', start)]
    assert 'dbsOpenReboot()' in buttons
    assert 'reboot_required' not in buttons
    assert 'id="dbs-card-updates-line"' in CONSOLE
    assert '&#10003; No restart needed' in CONSOLE


def test_upgrade_keeps_its_own_named_buttons():
    assert 'id="dbs-check-btn" onclick="osupOpenPreflight(\'dbserver\')"' in CONSOLE
    assert 'id="osup-upgrade-link-btn" onclick="osupOpenPreflight(\'dbserver\')"' in CONSOLE


def test_updates_view_is_driven():
    """Driven, not matched: the modal functions run against a hand-rolled DOM."""
    node = shutil.which('node')
    if node is None:
        pytest.skip('no node on PATH, so the database server updates view is unexercised')
    r = subprocess.run([node, str(ROOT / 'scripts' / 'check_dbserver_updates_button.js')],
                       cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert 'all checks passed' in out, out


def test_result_banner_after_updates_leads_to_the_reboot():
    """Sat Nov 7, 2026: after Install updates the banner said "press Check & upgrade, then Reboot" and its only
    button opened the 24.04 upgrade dialog. The banner now says Reboot and opens the updates view (driven above)."""
    assert 'press Check & upgrade, then Reboot database server' not in CONSOLE
    assert "dbsOpenUpdates();});}" in CONSOLE
