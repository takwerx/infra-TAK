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
"""Simulator video links name the media server, not the bare domain (ops #1424).

The Simulator wrote its drone and camera links as `rtsp://<fqdn>:8554/<stream>`. CloudTAK's
media server pulls an RTSP link itself, and infra-TAK pins only `stream.<fqdn>` to this box
for that pull (ops #560). Through the bare fqdn the pull leaves the box and either comes back
from an address MediaMTX answers 401, or never comes back (home network, no NAT hairpin), so
the player showed an error while a stream made by hand in MediaMTX (a `stream.<fqdn>` address)
played. The link must use the same name the MediaMTX editor hands out.
"""

import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.simulator as sim  # noqa: E402

APP = (ROOT / 'app.py').read_text(encoding='utf-8')


def _app_ns():
    """The REAL _get_service_domain and its defaults table, taken from app.py."""
    tree = ast.parse(APP)
    ns = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == '_get_service_domain':
            exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
        if isinstance(node, ast.Assign) and any(
                getattr(t, 'id', '') == 'SERVICE_DOMAIN_DEFAULTS' for t in node.targets):
            exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
    return ns


def _ctx(installed=('mediamtx',)):
    ns = _app_ns()
    mods = {k: {'installed': True} for k in installed}
    return {
        'detect_modules': lambda fresh=False: mods,
        '_get_service_domain': ns['_get_service_domain'],
    }


def test_link_uses_the_stream_name_of_mediamtx():
    base = sim._video_base(_ctx(), {'fqdn': 'tak.example.com', 'server_ip': '203.0.113.7'})
    assert base == 'rtsp://stream.tak.example.com:8554'


def test_link_uses_the_stream_name_of_tvr():
    base = sim._video_base(_ctx(('tak_video_restreamer',)),
                           {'fqdn': 'tak.example.com', 'server_ip': '203.0.113.7'})
    assert base == 'rtsp://stream.tak.example.com:8554'


def test_operator_chosen_stream_name_is_kept():
    # the Caddy domains card lets an operator rename the stream site
    s = {'fqdn': 'tak.example.com', 'mediamtx_domain': 'video-in.other.org'}
    assert sim._video_base(_ctx(), s) == 'rtsp://video-in.other.org:8554'
    s = {'fqdn': 'tak.example.com', 'mediamtx_domain': 'cams'}
    assert sim._video_base(_ctx(), s) == 'rtsp://cams.tak.example.com:8554'


def test_box_with_no_domain_keeps_its_address():
    assert sim._video_base(_ctx(), {'fqdn': '', 'server_ip': '203.0.113.7'}) == 'rtsp://203.0.113.7:8554'


def test_no_media_server_means_no_link():
    assert sim._video_base(_ctx(()), {'fqdn': 'tak.example.com', 'server_ip': '203.0.113.7'}) == ''


def test_mediamtx_wins_when_both_are_reported():
    base = sim._video_base(_ctx(('mediamtx', 'tak_video_restreamer')),
                           {'fqdn': 'tak.example.com', 'mediamtx_domain': 'mtx.example.com'})
    assert base == 'rtsp://mtx.example.com:8554'


def test_the_link_reaches_the_cot_unchanged():
    """The engine joins base + stream; the CoT carries that exact address in __video."""
    sys.path.insert(0, str(ROOT / 'simulator'))
    from engine.cot import d_video
    base = sim._video_base(_ctx(), {'fqdn': 'tak.example.com'})
    el = d_video('UAS 1', f'{base}/uas1', 'uas1-video')
    assert el.get('url') == 'rtsp://stream.tak.example.com:8554/uas1'
    entry = el.find('ConnectionEntry')
    assert entry.get('address') == 'stream.tak.example.com'
    assert entry.get('port') == '8554'
