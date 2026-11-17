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
"""NetBird card must show the real server version and offer the update (ops #853).

The netbirdio/netbird-server images carry only the Ubuntu base image's
org.opencontainers.image.version label ('24.04'). The card showed '24.04 · dash 2.96.0', and
24 > 0 meant the server was never "behind" the pin, so no update was ever offered.
The version now comes from the tag the container runs; the label is only a fallback when it
looks like a NetBird version.

app.py cannot be imported in a test, so the functions are cut out of it and run: the code
under test is the shipped text. A fake `docker inspect` stands in for the box.
"""

import ast
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_CORE = {'_netbird_version_tuple', '_netbird_docker_image_version', '_get_netbird_version_info',
         '_get_netbird_target_images'}
# the fix adds these; on the old code only _CORE exists, so the card tests run and fail on values
_FUNCS = _CORE | {'_netbird_image_ref_version', '_netbird_server_image_version'}

SERVER_PIN = 'netbirdio/netbird-server:0.82.0'
DASH_PIN = 'netbirdio/dashboard:v2.96.0'


def _load(tmp_path, containers, pin_server=SERVER_PIN, pin_dash=DASH_PIN):
    """containers: name -> (Config.Image, version label)."""
    parts = [ast.get_source_segment(APP, n) for n in ast.parse(APP).body
             if isinstance(n, ast.FunctionDef) and n.name in _FUNCS]
    assert len(parts) >= len(_CORE), 'a function under test was renamed or removed'
    (tmp_path / 'docker-compose.yml').write_text('services: {}\n')

    def fake_run(argv, *a, **k):
        name = argv[argv.index('inspect') + 1]
        fmt = argv[argv.index('--format') + 1]
        if name not in containers:
            return subprocess.CompletedProcess(argv, 1, '', 'No such object')
        img, label = containers[name]
        if '.Config.Image' in fmt:
            return subprocess.CompletedProcess(argv, 0, f'{img}|{label}\n', '')
        return subprocess.CompletedProcess(argv, 0, label + '\n', '')

    class _Sub:
        run = staticmethod(fake_run)
        TimeoutExpired = subprocess.TimeoutExpired

    ns = {
        'subprocess': _Sub, 'os': __import__('os'),
        'NETBIRD_INSTALL_DIR': str(tmp_path),
        '_sudo_wrap': lambda argv: list(argv),
        'load_settings': lambda: {},
        'NETBIRD_SERVER_IMAGE': pin_server, 'NETBIRD_DASHBOARD_IMAGE': pin_dash,
        'NETBIRD_SERVER_DEV_IMAGE': pin_server, 'NETBIRD_DASHBOARD_DEV_IMAGE': pin_dash,
        '_get_netbird_github_latest': lambda repo, use_cache=True: None,
    }
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


def _info(tmp_path, containers, **kw):
    return _load(tmp_path, containers, **kw)['_get_netbird_version_info']()


def test_card_shows_the_tag_not_the_ubuntu_label(tmp_path):
    info = _info(tmp_path, {
        'netbird-server': ('netbirdio/netbird-server:0.82.0', '24.04'),
        'netbird-dashboard': ('netbirdio/dashboard:v2.96.0', '2.96.0'),
    })
    assert info['version'] == '0.82.0 · dash 2.96.0'
    assert info['update_available'] is False


def test_pin_one_step_ahead_offers_the_update(tmp_path):
    info = _info(tmp_path, {
        'netbird-server': ('netbirdio/netbird-server:0.82.0', '24.04'),
        'netbird-dashboard': ('netbirdio/dashboard:v2.96.0', '2.96.0'),
    }, pin_server='netbirdio/netbird-server:0.82.1')
    assert info['version'] == '0.82.0 · dash 2.96.0'
    assert info['update_available'] is True
    assert info['latest'] == '0.82.1'


def test_dashboard_only_behind_still_offers_the_update(tmp_path):
    info = _info(tmp_path, {
        'netbird-server': ('netbirdio/netbird-server:0.82.0', '24.04'),
        'netbird-dashboard': ('netbirdio/dashboard:v2.95.0', '2.95.0'),
    })
    assert info['update_available'] is True
    assert info['latest'] == 'dash 2.96.0'


@pytest.mark.parametrize('image,label,want', [
    ('netbirdio/netbird-server:0.82.1', '24.04', '0.82.1'),
    ('netbirdio/netbird-server:v0.82.1', '', '0.82.1'),
    ('docker.io/netbirdio/netbird-server:0.80.0@sha256:abc', '24.04', '0.80.0'),
    ('localhost:5000/netbirdio/netbird-server:0.82.0', '24.04', '0.82.0'),
    # tag is not a version: use the label only when it is a NetBird version
    ('netbirdio/netbird-server:latest', '0.82.1', '0.82.1'),
    ('netbirdio/netbird-server@sha256:abc', 'v0.81.4', '0.81.4'),
    # ... never the Ubuntu label: show nothing rather than a wrong number
    ('netbirdio/netbird-server:latest', '24.04', ''),
    ('netbirdio/netbird-server', '', ''),
])
def test_server_version_sources(tmp_path, image, label, want):
    ns = _load(tmp_path, {'netbird-server': (image, label)})
    assert ns['_netbird_server_image_version']('netbird-server') == want


def test_missing_container_gives_empty_version(tmp_path):
    ns = _load(tmp_path, {})
    assert ns['_netbird_server_image_version']('netbird-server') == ''
