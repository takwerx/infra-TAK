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
"""os_name / os_type follow an in-place release upgrade (GH #101 follow-up).

The reporter's box moved 22.04 -> 24.04 in place and the console footer said 22.04
for eleven weeks: start.sh writes os_name once, and the boot heal only filled an
EMPTY value. _read_os_release() and _heal_settings_core_keys() are cut out of app.py
and run against a fake /etc/os-release.
"""

import builtins
import io
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

U2404 = 'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n'
U2204 = 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nID=ubuntu\nVERSION_ID="22.04"\n'
RHEL94 = 'PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"\nID="rhel"\nVERSION_ID="9.4"\n'
ROCKY95 = 'PRETTY_NAME="Rocky Linux 9.5 (Blue Onyx)"\nID="rocky"\nVERSION_ID="9.5"\n'
ALMA8 = 'PRETTY_NAME="AlmaLinux 8.10"\nID="almalinux"\nVERSION_ID="8.10"\n'
DEB12 = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'
FEDORA = 'PRETTY_NAME="Fedora Linux 40"\nID=fedora\nVERSION_ID=40\n'


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^\S)' % re.escape(name), APP, re.S | re.M)
    assert m, f'{name} not found in app.py'
    return m.group(0)


class Box:
    def __init__(self, os_release, settings):
        self.os_release = os_release
        self.settings = dict(settings)
        self.saved = []
        real_open = builtins.open

        def fake_open(path, *a, **kw):
            if path == '/etc/os-release':
                if self.os_release is None:
                    raise FileNotFoundError(path)
                return io.StringIO(self.os_release)
            return real_open(path, *a, **kw)

        self.ns = {
            'open': fake_open,
            'load_settings': lambda: dict(self.settings),
            'save_settings': self._save,
            '_recover_fqdn': lambda: None,
            'BASE_DIR': '/root/infra-TAK',
        }
        for name in ('_read_os_release', '_heal_settings_core_keys'):
            exec(compile(_fn(name), f'app.py:{name}', 'exec'), self.ns)

    def _save(self, s):
        self.saved.append(dict(s))
        self.settings = dict(s)


WHOLE = {'os_type': 'ubuntu-22.04', 'os_name': 'Ubuntu 22.04.5 LTS', 'pkg_mgr': 'apt',
         'arch': 'amd64', 'console_port': 5001, 'install_dir': '/root/infra-TAK',
         'ssl_mode': 'fqdn', 'server_ip': '203.0.113.7', 'fqdn': 'tak.example'}


@pytest.mark.parametrize('text,want', [
    (U2204, 'ubuntu-22.04'), (U2404, 'ubuntu-24.04'), (DEB12, 'debian-12'),
    (RHEL94, 'rocky-9'), (ROCKY95, 'rocky-9'), (ALMA8, 'rocky-8.10'), (FEDORA, 'fedora-40'),
])
def test_os_type_matches_start_sh(text, want):
    """start.sh detect_os() maps the whole EL family to rocky-<major>; a plain
    '<ID>-<VERSION_ID>' would turn a RHEL box's 'rocky-9' into 'rhel-9.4' on refresh."""
    box = Box(text, {})
    assert box.ns['_read_os_release']()[0] == want


def test_in_place_upgrade_is_picked_up_on_boot():
    box = Box(U2404, WHOLE)
    box.ns['_heal_settings_core_keys']()
    assert box.settings['os_name'] == 'Ubuntu 24.04.5 LTS'
    assert box.settings['os_type'] == 'ubuntu-24.04'
    # nothing else touched
    assert {k: v for k, v in box.settings.items() if k not in ('os_name', 'os_type')} == \
        {k: v for k, v in WHOLE.items() if k not in ('os_name', 'os_type')}


def test_current_box_is_not_rewritten():
    box = Box(U2204, WHOLE)
    box.ns['_heal_settings_core_keys']()
    assert box.saved == []


def test_rhel_box_keeps_rocky_9():
    s = dict(WHOLE, os_type='rocky-9', os_name='Red Hat Enterprise Linux 9.4 (Plow)', pkg_mgr='dnf')
    box = Box(RHEL94, s)
    box.ns['_heal_settings_core_keys']()
    assert box.saved == []


def test_unreadable_os_release_changes_nothing():
    box = Box(None, WHOLE)
    box.ns['_heal_settings_core_keys']()
    assert box.saved == []
