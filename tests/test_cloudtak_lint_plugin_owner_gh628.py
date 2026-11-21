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
"""A CloudTAK Update that fails on a plugin's lint errors says which plugin, and what to do (GH #628).

Field (v10.4.3, Ubuntu 24.04, Sat Nov 21 2026): the CloudTAK 13.124.0 -> 13.126.0 Update failed
at `npm run lint && npm run build` with 9 OXLint errors in four files of the Replay Marketplace
plugin (stateful/lib/replay-recorder.ts, stateless/lib/replay-player.ts, replay-export.ts,
retention/replay.ts). Since TAK Portal 2.0.38 the Marketplace strips the @ts-nocheck marks and
the ignore entries that let those files skip the lint, so the shield from GH #563 no longer
covers them. The console listed the files and said "Fix the cause above first", but nothing
said the files are a plugin's, not CloudTAK's, or that removing the plugin unblocks the Update.

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import os
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {'_cloudtak_build_failure_hint', '_cloudtak_plugin_owning_route',
          '_cloudtak_lint_files_from_plugins', '_cloudtak_web_dir', '_cloudtak_plugins_dir'}

STEP_API = ('target api: failed to solve: process "/bin/sh -c npm run lint     && npm run build" '
            'did not complete successfully: exit code: 1')

# the reporter's log (diagnostics, Sat Nov 21), BuildKit prefix and all
REPLAY_FAIL = [
    '#58 > oxlint --type-aware index.ts common/ stateful/ stateless/ test/',
    "#58 8.437   x typescript(no-base-to-string): 'days' may use Object's default stringification "
    "format ('[object Object]') when stringified.",
    '#58 8.437     ,-[stateless/lib/retention/replay.ts:22:94]',
    '#58 8.437   x typescript(await-thenable): Unexpected `await` of a non-Promise value.',
    '#58 8.437     ,-[stateless/lib/replay-player.ts:40:9]',
    '#58 8.437     ,-[stateless/lib/replay-export.ts:12:3]',
    '#58 8.437     ,-[stateful/lib/replay-recorder.ts:88:5]',
    '#58 8.437 Found 0 warnings and 9 errors.',
    STEP_API,
]


def _hint(plugins=()):
    tree = ast.parse(APP)
    found = {n.name: ast.get_source_segment(APP, n) for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name in _FUNCS}
    assert '_cloudtak_build_failure_hint' in found, 'the build-failure hint was renamed or removed'
    parts = list(found.values())
    # the helper is new with GH #628; without it the hint must still run (and the proof
    # tests below fail on what the operator reads, not on a missing name)
    if '_cloudtak_lint_files_from_plugins' not in found:
        parts.append('def _cloudtak_lint_files_from_plugins(lint_files, cloudtak_dir):\n'
                     '    raise AssertionError("_cloudtak_lint_files_from_plugins is missing")\n')
    ns ={'re': re, 'os': os, 'subprocess': subprocess, 'CLOUDTAK_PLUGINS': list(plugins)}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


def _git(ct, *args):
    subprocess.run(['git', '-C', str(ct), '-c', 'user.name=t', '-c', 'user.email=t@t', *args],
                   check=True, capture_output=True)


def _tree(tmp_path, plugin_dirs=('replay', 'search-containment')):
    """A CloudTAK checkout: upstream files tracked, the plugin's files on disk but untracked."""
    ct = tmp_path / 'CloudTAK'
    for rel in ('api/stateless/lib/fetch.ts', 'api/stateful/lib/config.ts', 'app/src/main.ts',
                'app/plugins/.gitkeep'):
        (ct / rel).parent.mkdir(parents=True, exist_ok=True)
        (ct / rel).write_text('export {};\n')
    _git(ct, 'init', '-q')
    _git(ct, 'add', '-A')
    _git(ct, 'commit', '-qm', 'upstream')
    for rel in ('api/stateless/lib/retention/replay.ts', 'api/stateless/lib/replay-player.ts',
                'api/stateless/lib/replay-export.ts', 'api/stateful/lib/replay-recorder.ts'):
        (ct / rel).parent.mkdir(parents=True, exist_ok=True)
        (ct / rel).write_text('export const days = 10;\n')
    for d in plugin_dirs:
        (ct / 'app' / 'plugins' / d).mkdir(parents=True, exist_ok=True)
        (ct / 'app' / 'plugins' / d / 'index.ts').write_text('export {};\n')
    return ct


def _text(ct, plugins=()):
    return '\n'.join(_hint(plugins)['_cloudtak_build_failure_hint'](REPLAY_FAIL, str(ct)))


def test_replay_lint_failure_names_the_plugin_and_the_way_out(tmp_path):
    out = _text(_tree(tmp_path))
    assert 'Likely cause: the CloudTAK lint check (OXLint) failed.' in out
    assert 'These 4 files are not part of CloudTAK: a plugin added them (plugin: replay).' in out, out
    assert 'open the CloudTAK Marketplace and update that plugin, or uninstall it' in out, out
    assert 'search-containment' not in out


def test_upstream_files_are_not_blamed_on_a_plugin(tmp_path):
    ct = _tree(tmp_path)
    lines = ['#58     ,-[stateless/lib/fetch.ts:3:1]', '#58 Found 0 warnings and 1 error.', STEP_API]
    out = '\n'.join(_hint()['_cloudtak_build_failure_hint'](lines, str(ct)))
    assert 'Likely cause: the CloudTAK lint check (OXLint) failed.' in out
    assert 'not part of CloudTAK' not in out and 'Marketplace' not in out, out


def test_a_plugin_file_with_no_matching_folder_is_still_called_a_plugin_file(tmp_path):
    out = _text(_tree(tmp_path, plugin_dirs=()))
    assert 'These 4 files are not part of CloudTAK: a plugin added them.' in out, out
    assert '(plugin:' not in out
    assert 'CloudTAK Marketplace' in out


def test_an_infra_tak_plugin_points_to_the_cloudtak_page(tmp_path):
    ct = _tree(tmp_path)
    out = _text(ct, plugins=[{'install_dir': 'replay', 'name': 'Replay'}])
    assert 'Update or remove that plugin on the CloudTAK page' in out, out
    assert 'Marketplace' not in out


def test_route_file_maps_to_a_folder_with_a_longer_name(tmp_path):
    ns = _hint()
    ct = _tree(tmp_path, plugin_dirs=('livewx-radar',))
    (ct / 'api' / 'stateless' / 'routes').mkdir(parents=True)
    (ct / 'api' / 'stateless' / 'routes' / 'plugin-livewx.ts').write_text('export {};\n')
    files, names = ns['_cloudtak_lint_files_from_plugins'](['stateless/routes/plugin-livewx.ts'], str(ct))
    assert files == ['stateless/routes/plugin-livewx.ts'] and names == ['livewx-radar']


def test_no_tree_or_no_git_gives_the_old_hint_and_never_raises(tmp_path):
    ns = _hint()
    out = '\n'.join(ns['_cloudtak_build_failure_hint'](REPLAY_FAIL, None))
    assert 'Files with findings:' in out and 'not part of CloudTAK' not in out
    plain = tmp_path / 'not-a-checkout'
    (plain / 'api' / 'stateless' / 'lib' / 'retention').mkdir(parents=True)
    (plain / 'api' / 'stateless' / 'lib' / 'retention' / 'replay.ts').write_text('x\n')
    assert ns['_cloudtak_lint_files_from_plugins'](['stateless/lib/retention/replay.ts'],
                                                   str(plain)) == ([], [])
    assert ns['_cloudtak_lint_files_from_plugins'](['../../etc/passwd'], str(plain)) == ([], [])
