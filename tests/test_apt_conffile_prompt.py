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
"""apt installs never stop at dpkg's conffile prompt (found by TEST-MATRIX-v10.3.0 row 5).

The console wrote /etc/caddy/Caddyfile, then `apt-get install -y caddy` died at
"end of file on stdin at conffile prompt" and left caddy half-configured (iU).
DEBIAN_FRONTEND=noninteractive does not answer that prompt; DPKG_FORCE does.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
BROKER = (REPO / 'broker' / 'takwerx_broker.py').read_text(encoding='utf-8')


def test_pkg_install_keeps_existing_conffiles_on_root_boxes():
    body = re.search(r'^def _pkg_install\(.*?(?=^def )', APP, re.S | re.M).group(0)
    assert "DPKG_FORCE='confdef,confold'" in body


def test_broker_keeps_existing_conffiles_for_apt_and_only_apt():
    i = BROKER.index("if os.path.basename(argv[0]) in ('apt', 'apt-get'):\n        env = dict(os.environ)")
    block = BROKER[i:BROKER.index('proc = subprocess.run(argv', i)]
    assert "env.setdefault('DPKG_FORCE', 'confdef,confold')" in block


def test_broker_still_denies_dpkg_options_on_the_command_line():
    assert "raise Denied(f'{argv[0]}: -o/--setopt option not allowed')" in BROKER
