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
"""Upstream pins moved off published advisories (v10.2.8 W7-W9).

Found by the first run of the upstream watcher (2026-10-08):

    CRITICAL MediaMTX 1.20.0  GHSA-w334-5mp5-h897  CSRF on the Control API -> runOnInit; fixed 1.21.1
    HIGH     coturn 4.14.0    GHSA-m23x / GHSA-fvj6 + five MEDIUM; all fixed by 4.17.0
    MEDIUM   NetBird 0.74.4   GHSA-v5w2-pqxj-6r94 relay gob decode before HMAC; fixed 0.75.0

1.21.1 only refuses a browser POST whose origin is NOT allowed, so a config that allows '*'
keeps the hole open even on the fixed binary — the deploy templates must not write it.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _v(s):
    return tuple(int(x) for x in re.findall(r'\d+', s)[:3])


def test_mediamtx_fresh_install_pin_has_the_csrf_fix():
    pin = re.search(r'^MEDIAMTX_VETTED_RELEASE = "([^"]+)"', APP, re.M).group(1)
    assert _v(pin) >= (1, 21, 1)


def test_no_deploy_template_allows_every_api_origin():
    templates = re.findall(r'mediamtx_yml = f"""(.*?)"""', APP, re.S)
    assert len(templates) == 2
    for t in templates:
        assert "apiAllowOrigins: ['*']" not in t
        assert re.search(r'^apiAllowOrigins: \[\]$', t, re.M)
        # the API itself stays loopback-only
        assert re.search(r'^apiAddress: 127\.0\.0\.1:', t, re.M)


def test_coturn_pin_is_past_the_advisories():
    pin = re.search(r"^COTURN_IMAGE = 'coturn/coturn:([^']+)'", APP, re.M).group(1)
    assert _v(pin) >= (4, 17, 0)


def test_coturn_flags_avoid_the_ones_418_removed():
    body = APP[APP.index('override_content = f"""services:\n  coturn:'):]
    body = body[:body.index('"""', 10)]
    for gone in ('--drop-invalid-packets', '--no-dtls', '--no-cli'):
        assert gone not in body


def test_netbird_dev_candidate_is_past_the_relay_fix_and_main_is_unchanged_until_promoted():
    dev = re.search(r'^NETBIRD_SERVER_DEV_IMAGE = "netbirdio/netbird-server:([^"]+)"', APP, re.M).group(1)
    assert _v(dev) >= (0, 75, 0)
    assert re.search(r'^NETBIRD_DASHBOARD_DEV_IMAGE = "netbirdio/dashboard:v[0-9.]+"', APP, re.M)
    # every pin is an exact tag, never a moving one
    for name in ('NETBIRD_SERVER_IMAGE', 'NETBIRD_DASHBOARD_IMAGE',
                 'NETBIRD_SERVER_DEV_IMAGE', 'NETBIRD_DASHBOARD_DEV_IMAGE'):
        val = re.search(rf'^{name} = "([^"]+)"', APP, re.M).group(1)
        assert ':latest' not in val and re.search(r':v?\d+\.\d+\.\d+$', val), name
