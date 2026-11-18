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
"""Stream site player: video must start for a viewer on a slow link (ops #900).

The box's MediaMTX keeps `hlsSegmentCount: 3` (app.py). MediaMTX drops the oldest segment
in the playlist about one segment after it listed it. hls.js with `liveSyncDurationCount`
at or above the playlist length starts at that oldest segment, so a viewer whose request
took longer than that got a 404 on it (the editor proxy turned it into a 502), no video,
and "Stream Offline". Measured with hls.js 1.6.16 in Chrome against MediaMTX v1.20.0,
1-second keyframes, 3 x 500ms, 0.4 s added to each answer: 10 of 16 starts played with
liveSyncDurationCount 4, 16 of 16 with 2.

These tests tie the player to the playlist the product really configures. A real browser
test against MediaMTX cannot run in CI; it is in the PR description.
"""

import importlib.util
import pathlib
import re

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
OVERLAY = REPO / 'mediamtx_ldap_overlay.py'


def _segment_counts():
    """Every hlsSegmentCount the product writes into a MediaMTX config (editor box, remote
    editor box, CloudTAK media converger)."""
    found = [int(n) for n in re.findall(r'hlsSegmentCount: (\d+)', (REPO / 'app.py').read_text())]
    assert len(found) >= 3, found
    return found


def _player_configs(text):
    """Each `new Hls({...})` config in a page or script, as {key: value-text}."""
    configs = []
    for m in re.finditer(r'new Hls\(\{+(.*?)\}+\)', text):
        configs.append(dict(kv.split(':', 1) for kv in m.group(1).split(',') if ':' in kv))
    return configs


@pytest.fixture
def watch_page(tmp_path, monkeypatch):
    cfg = tmp_path / 'mediamtx.yml'
    cfg.write_text('authInternalUsers:\n- user: any\n  ips: [127.0.0.1]\n')
    monkeypatch.setenv('MEDIAMTX_CONFIG', str(cfg))
    spec = importlib.util.spec_from_file_location('overlay_ops900', OVERLAY)
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    vis = tmp_path / 'stream_visibility.json'
    vis.write_text('{}')
    monkeypatch.setattr(ov, 'VISIBILITY_FILE', str(vis))
    app = flask.Flask('overlay-ops900')
    app.secret_key = 'test'
    ov.apply_ldap_overlay(app)
    r = app.test_client().get('/watch/live/cam1')
    assert r.status_code == 200
    return r.get_data(as_text=True)


def test_watch_page_starts_inside_the_playlist(watch_page):
    configs = _player_configs(watch_page)
    assert len(configs) == 1
    sync = int(configs[0]['liveSyncDurationCount'])
    # One segment of room: the first segment the player asks for is not the one MediaMTX
    # is about to drop.
    assert sync <= min(_segment_counts()) - 1, (
        'liveSyncDurationCount %d with a %d-segment playlist starts at the oldest segment'
        % (sync, min(_segment_counts())))


def test_watch_popup_starts_inside_the_playlist():
    # The Watch button's popup is written by the viewer page's script, in the overlay source.
    configs = _player_configs(OVERLAY.read_text())
    assert len(configs) == 2, 'expected the /watch/ page and the Watch popup'
    for cfg in configs:
        assert int(cfg['liveSyncDurationCount']) <= min(_segment_counts()) - 1


def test_both_players_keep_loading_after_a_network_error(watch_page):
    # CloudTAK's player calls startLoad() on a non-fatal network error and recovered every
    # start in the same test where a player without it did not. Both pages do the same.
    src = OVERLAY.read_text()
    guard = 'if(!data.fatal&&data.type===Hls.ErrorTypes.NETWORK_ERROR)'
    assert guard in watch_page
    assert src.count(guard) == 2
    assert src.count('hls.startLoad()') == 2


def test_latency_ceiling_stays_above_the_start_position(watch_page):
    # hls.js ignores a max-latency count that is not above the sync count.
    for cfg in _player_configs(OVERLAY.read_text()):
        assert int(cfg['liveMaxLatencyDurationCount']) > int(cfg['liveSyncDurationCount'])
