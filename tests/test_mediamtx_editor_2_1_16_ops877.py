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
"""MediaMTX web editor 2.1.14 -> 2.1.16 (ops #877).

1. The pin. v2.1.16 is an ANNOTATED tag: `git rev-parse v2.1.16` is the tag object (d8fde95...),
   and raw.githubusercontent answers 404 for it. The pin must be the COMMIT (`v2.1.16^{commit}`),
   the same value `git rev-parse HEAD` prints after the pinned clone.
2. Patching twice. "Patch web editor" runs the endpoint patch on the editor file already on the
   box when the fresh download fails. The old copy of the patch had no idempotency guard (the one
   in the ExecStartPre script has had it since 2026-08-03): on the second run it stamped the
   /api/playback-mode route, which sits next to the share-links routes, with a duplicate endpoint,
   Flask refused the app and the editor crash-looped. Seen on a real box when the pin was wrong.
"""
import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

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


# The layout of the real v2.1.x editor: the playback-mode POST route sits right above the share-links
# routes, inside the 20-line window the old patch looked at.
EDITOR = '''
app = Flask(__name__)

@app.route('/shared/<token>')
def shared_stream_page(token):
    return ''

@app.route('/shared-hls/<token>/<path:p>')
def shared_hls_proxy(token, p):
    return ''

@app.route('/api/playback-mode', methods=['POST'])
@admin_required
def api_set_playback_mode():
    return ''

@app.route('/api/share-links')
@admin_required
def api_share_links_list():
    return ''

@app.route('/api/share-links/generate', methods=['POST'])
@admin_required
def api_share_links_generate():
    return ''

@app.route('/api/share-links/revoke', methods=['POST'])
@admin_required
def api_share_links_revoke():
    return ''
'''


def test_editor_pin_is_v2_1_16_and_its_commit_not_the_tag_object_ops877():
    assert _const('MEDIAMTX_EDITOR_REF') == 'v2.1.16'
    sha = _const('MEDIAMTX_EDITOR_SHA')
    assert sha == '8d76bbec0c93804e0c7a5317cdeec18c28945f68'
    # the annotated tag object of v2.1.16: the clone check (`rev-parse HEAD` == SHA) can never pass with it
    assert sha != 'd8fde95eb125745385df8df9d1e099ef9c78d89e'


def test_endpoint_patch_stamps_each_share_endpoint_once_ops877():
    out = _patch_fn()(EDITOR)
    for ep in ENDPOINTS:
        assert out.count("endpoint='" + ep + "'") == 1, ep
    # the neighbouring route is left alone
    assert "'/api/playback-mode', methods=['POST']" in out
    pb = [ln for ln in out.splitlines() if "'/api/playback-mode'" in ln][0]
    assert 'endpoint=' not in pb


def test_endpoint_patch_run_twice_changes_nothing_ops877():
    patch = _patch_fn()
    once = patch(EDITOR)
    twice = patch(once)
    assert twice == once
    assert len(re.findall(r"endpoint='[a-z_]+_core'", twice)) == len(ENDPOINTS)
    pb = [ln for ln in twice.splitlines() if "'/api/playback-mode'" in ln][0]
    assert 'endpoint=' not in pb, 'the second run stamped the neighbouring route: Flask refuses the editor at start'
