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
"""The offline CloudTAK fallback stays current (ops #392).

CLOUDTAK_VETTED_RELEASE is what a fresh Deploy installs when GitHub cannot be reached. It sat on
13.54.3 for months: that tag builds a MinIO image that is gone (quay.io answers 401, so the build
fails) and it predates the 13.117.0 fix for server-side requests to internal addresses. Nothing
noticed, because the pin is only read offline.

These tests fail when the pin falls behind a release we already know matters:
  - the newest CloudTAK entry in KNOWN_SECURITY_RELEASES (a fallback must never be a version
    infra-TAK itself flags as having a security fix pending);
  - 13.117.1, the first release that gives the tiles service its API_URL (13.117.0 left every
    basemap tile at 500 in Docker).
Raise MIN_FALLBACK when a newer release becomes a must-have; the pin has to follow it.
"""

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

MIN_FALLBACK = (13, 117, 1)


def _top_level(name):
    for node in ast.parse(APP).body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found in app.py')


def _ver(text):
    return tuple(int(x) for x in text.lstrip('vV').split('.'))


def test_pin_is_a_plain_release_number():
    pin = _top_level('CLOUDTAK_VETTED_RELEASE')
    assert len(_ver(pin)) == 3, pin


def test_pin_is_not_behind_the_must_have_floor():
    pin = _ver(_top_level('CLOUDTAK_VETTED_RELEASE'))
    assert pin >= MIN_FALLBACK, (
        'offline CloudTAK fallback is older than v%s.%s.%s; bump CLOUDTAK_VETTED_RELEASE' % MIN_FALLBACK)


def test_pin_is_not_behind_any_known_security_release():
    pin = _ver(_top_level('CLOUDTAK_VETTED_RELEASE'))
    fixed = [_ver(e['fixed_in']) for e in _top_level('KNOWN_SECURITY_RELEASES')
             if e['component'] == 'cloudtak']
    assert fixed, 'KNOWN_SECURITY_RELEASES lost its CloudTAK entries'
    assert pin >= max(fixed), (
        'CLOUDTAK_VETTED_RELEASE %s is below a CloudTAK security release we flag (%s)' % (
            pin, max(fixed)))
