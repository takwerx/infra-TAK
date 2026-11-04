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
"""ops #470 / infra-TAK #398 — a big hosted-tileset upload through Caddy ended in a 502.

CloudTAK sends nothing back until a pmtiles upload is complete, and Caddy's `read_timeout` is
a deadline on the first read from the upstream, which starts with the request. With 120 s on
the map site, any upload that took longer (a multi-GB file on a home uplink) came back as
"Upload Failed: 502". Reproduced on test12: 3 GB at a throttled 18 MB/s -> 502 after 108 s;
unthrottled (85 s) -> 200.

write_timeout is the same trap (the body copy is one write): 504 after 120 s.

app.py cannot be imported in a test, so this reads the shipped text.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')

# CloudTAK's own nginx accepts at most 5 GB per upload (client_max_body_size 5G).
_ONE_HOUR = 3600


def _seconds(value):
    m = re.fullmatch(r'(\d+)([smh])', value)
    assert m, f'unexpected Caddy duration {value!r}'
    return int(m.group(1)) * {'s': 1, 'm': 60, 'h': 3600}[m.group(2)]


def _map_block():
    start = APP.index('lines.append(f"{ct_map} {{")')
    end = APP.index('@ct_pwa_entry path', start)
    return APP[start:end]


def test_map_site_waits_long_enough_for_a_big_upload():
    const = re.search(r"^_CLOUDTAK_MAP_TIMEOUT = '(\w+)'", APP, re.M)
    assert const, 'the map site timeout constant is gone'
    assert _seconds(const.group(1)) >= _ONE_HOUR


def test_map_site_uses_that_timeout_not_120s():
    block = _map_block()
    assert 'read_timeout {_CLOUDTAK_MAP_TIMEOUT}' in block
    assert 'write_timeout {_CLOUDTAK_MAP_TIMEOUT}' in block
    assert '120s' not in block.split('transport http')[1]
