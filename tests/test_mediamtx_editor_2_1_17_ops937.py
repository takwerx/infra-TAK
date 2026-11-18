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
"""MediaMTX web editor 2.1.16 -> 2.1.17 (ops #937, public issue ops #900).

The share link (/shared/TOKEN) failed for slow viewers (about 1 start in 8 was lost): the
editor's player started at the oldest segment of the 3-segment playlist, MediaMTX had already
dropped it, and the page showed Stream Offline. The fix is in the editor core
(mediamtx-installer PR 54, in v2.1.17: liveSyncDurationCount never reaches the playlist length).
infra-TAK PR 560 fixed only the overlay's /watch page and Watch popup. A box gets the editor core
from the pin, so the pin has to move or the share link stays broken.

This file proves the pin took the fix: it fails on dev with v2.1.16, passes with v2.1.17.
"""
import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

# The first editor release with the share-link player fix (mediamtx-installer PR 54).
FIX_RELEASE = (2, 1, 17)
V2_1_17_COMMIT = 'af22db792889a0c93c24e52d6f69099afd676490'   # git rev-parse v2.1.17^{commit}
V2_1_16_COMMIT = '8d76bbec0c93804e0c7a5317cdeec18c28945f68'


def _const(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{name} not found at module level in app.py')


def _version(ref):
    m = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', ref)
    assert m, f'editor ref {ref!r} is not a release tag'
    return tuple(int(x) for x in m.groups())


def test_editor_pin_includes_the_share_link_player_fix_ops937():
    # Version floor, not an exact match: a later editor release keeps this test green.
    ref = _const('MEDIAMTX_EDITOR_REF')
    assert _version(ref) >= FIX_RELEASE, (
        f'{ref} still has the share-link player that starts at the oldest segment (ops #900, #937)')


def test_editor_pin_is_v2_1_17_and_its_commit_ops937():
    # What this PR ships. The next editor bump updates this test with the new pin.
    assert _const('MEDIAMTX_EDITOR_REF') == 'v2.1.17'
    sha = _const('MEDIAMTX_EDITOR_SHA')
    assert sha == V2_1_17_COMMIT
    assert sha != V2_1_16_COMMIT


def test_editor_ref_and_sha_move_together_ops937():
    # Bumping only the tag leaves the clone check (rev-parse HEAD == SHA) failing on every box.
    ref, sha = _const('MEDIAMTX_EDITOR_REF'), _const('MEDIAMTX_EDITOR_SHA')
    assert re.fullmatch(r'[0-9a-f]{40}', sha)
    line = next(ln for ln in APP.splitlines() if ln.startswith('MEDIAMTX_EDITOR_SHA'))
    assert f'COMMIT of tag {ref}' in line, 'the SHA comment names a different tag than MEDIAMTX_EDITOR_REF'
