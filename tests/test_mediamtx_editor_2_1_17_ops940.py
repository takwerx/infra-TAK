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
"""MediaMTX web editor 2.1.16 -> 2.1.17 (ops #940).

The stream-site share link (/shared/...) is served by the editor core. A slow viewer asked for the
oldest segment of the playlist after MediaMTX had dropped it (404, no video). mediamtx-installer
PR 54 (ops #900) fixed that in the editor itself (hls_live_sync_count), in v2.1.17. The console
installs the pinned editor, so until the pin moved the fix never reached a console box.

1. The pin is v2.1.17 and its COMMIT (not the annotated tag object).
2. The editor at that pin has the fix (fetched from GitHub; skipped when offline) and the
   console's endpoint patch still stamps it exactly once.
"""
import ast
import pathlib
import urllib.error
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

V2_1_17_COMMIT = 'af22db792889a0c93c24e52d6f69099afd676490'
V2_1_17_TAG_OBJECT = 'abf12812242a89a7550bbfce57371b54d5736252'
ENDPOINTS = ('shared_stream_page_core', 'shared_hls_proxy_core', 'api_share_links_list_core',
             'api_share_links_generate_core', 'api_share_links_revoke_core')


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def _patch_fn():
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == '_mediamtx_editor_endpoint_patch':
            ns = {}
            exec(compile(ast.Module([node], []), 'app.py', 'exec'), ns)
            return ns['_mediamtx_editor_endpoint_patch']
    raise AssertionError('_mediamtx_editor_endpoint_patch not found')


def _editor_at_pin():
    url = ('https://raw.githubusercontent.com/takwerx/mediamtx-installer/%s/config-editor/mediamtx_config_editor.py'
           % _const('MEDIAMTX_EDITOR_SHA'))
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read().decode('utf-8')
    except (urllib.error.URLError, OSError) as e:
        pytest.skip('cannot reach raw.githubusercontent.com: %s' % e)


def test_editor_pin_is_v2_1_17_and_its_commit_ops940():
    assert _const('MEDIAMTX_EDITOR_REF') == 'v2.1.17'
    assert _const('MEDIAMTX_EDITOR_SHA') == V2_1_17_COMMIT
    assert _const('MEDIAMTX_EDITOR_SHA') != V2_1_17_TAG_OBJECT


def test_pinned_editor_has_the_share_link_start_fix_ops940():
    src = _editor_at_pin()
    assert 'CURRENT_VERSION = "v2.1.17"' in src
    # the player settings the share page, /watch and the Watch popup all use
    assert 'def hls_live_sync_count():' in src
    assert "'liveSyncDurationCount:%d,liveMaxLatencyDurationCount:7,'" in src
    # the old hard-coded count is gone from the live player settings
    assert "'liveSyncDurationCount:5,liveMaxLatencyDurationCount:7,'" not in src


def test_endpoint_patch_stamps_the_real_pinned_editor_once_ops940():
    import re
    src = _editor_at_pin()
    patch = _patch_fn()
    once = patch(src)
    for ep in ENDPOINTS:
        assert once.count("endpoint='" + ep + "'") == 1, ep
    assert patch(once) == once
    assert len(re.findall(r"endpoint='[a-z_]+_core'", once)) == len(ENDPOINTS)
