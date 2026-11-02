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
"""TAK Portal deploy floor (ops #343).

TAKPORTAL_REF_FALLBACK is what a deploy installs when the releases API cannot be reached. It must
not sit below the hardened-grant release (2.0.19), and moving it to a release whose marketplace
helper has not been reviewed must not pin that helper by accident (the pin lives in the broker).
"""

import importlib.util
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent


def _floor():
    src = (REPO / 'app.py').read_text(encoding='utf-8')
    m = re.search(r'^TAKPORTAL_REF_FALLBACK\s*=\s*"(\d+(?:\.\d+){1,3})"', src, re.M)
    assert m, 'TAKPORTAL_REF_FALLBACK not found in app.py'
    return tuple(int(x) for x in m.group(1).split('.'))


def test_floor_is_at_least_the_dependency_refresh_release():
    # 2.0.26 is the release that shipped TAK-Portal#77 (the dependency refresh we asked for).
    assert _floor() >= (2, 0, 26)


def test_floor_is_not_below_the_hardened_grant_release():
    spec = importlib.util.spec_from_file_location('takwerx_broker_t343', REPO / 'broker' / 'takwerx_broker.py')
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    assert _floor() >= tuple(b.TAKPORTAL_HARDENED_MIN_VERSION)


def test_portal_2_0_26_helper_stays_unpinned():
    # marketplace-helper in TAK Portal 2.0.26 (same bytes in 2.0.28): apply-caddyfile still runs
    # `caddy validate` as root on caller-supplied text, so it can print root-only files. Never pinned
    # (ops #295, #340). 2.0.29 fixed that by validating as the caddy user; that one IS pinned.
    spec = importlib.util.spec_from_file_location('takwerx_broker_t343b', REPO / 'broker' / 'takwerx_broker.py')
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    assert 'ba749885c92e9ea097012438a98cc0b45f3fabf4d46252d1bac54ef1720123cd' not in b.TAKPORTAL_HELPER_SHA256
    assert '4d093f4b834bda8ad712c5df4155929dd9b40f4d14ecded0cdd01b84d14c4559' in b.TAKPORTAL_HELPER_SHA256


def test_floor_ships_a_pinned_helper():
    # ops #395: 2.0.29 and 2.0.30 carry the same marketplace-helper, the one the broker pins. A floor
    # below 2.0.29 would put an offline-API deploy on the unpinned 2.0.23-2.0.28 helper.
    assert _floor() >= (2, 0, 29)
