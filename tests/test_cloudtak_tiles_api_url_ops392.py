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
"""CloudTAK tile server API_URL (ops #392).

From CloudTAK 13.117.0 every basemap's tiles are served by the tiles container, which loads
the basemap's config from the CloudTAK API at API_URL (default http://localhost:5001). Upstream's
docker-compose.yml does not pass API_URL to `tiles`, so in Docker every tile request failed with
500 (ECONNREFUSED). infra-TAK's override gives `tiles` the same internal API address `events`
and `media` already use.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _override():
    return re.search(r'^def _cloudtak_build_override_yml\(.*?(?=^def )', APP, re.S | re.M).group(0)


def _service_block(body, name):
    m = re.search(rf'^  {name}:\n(.*?)(?=^  \w+:|^\{{_sim_networks_top\}}|\Z)', body, re.S | re.M)
    assert m, f'no {name}: service in the override template'
    return m.group(1)


def test_tiles_gets_the_internal_api_url():
    tiles = _service_block(_override(), 'tiles')
    assert 'environment:' in tiles
    assert 'API_URL: "http://api:5000"' in tiles


def test_tiles_block_does_not_touch_other_tile_settings():
    tiles = _service_block(_override(), 'tiles')
    # infra-TAK owns only API_URL here; PMTILES_URL, the S3 keys and ports stay upstream's
    keys = set(re.findall(r'^\s{6}([A-Z_]+):', tiles, re.M))
    assert keys == {'API_URL'}
    assert 'ports:' not in tiles and 'image:' not in tiles


def test_events_and_media_keep_the_same_address():
    body = _override()
    assert 'API_URL: "http://api:5000"' in _service_block(body, 'events')
    assert 'API_URL: "http://api:5000"' in _service_block(body, 'media')
