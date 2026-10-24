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
"""A failed CloudTAK build names its own cause (GH #249).

Field (v10.2.27, Ubuntu 22.04): the 13.112.3 -> 13.113.0 Update failed three times at
step 3/3, once in `npm install` and once in `npm run lint && npm run check && npm run build`,
and the log said only "Build failed with exit code 1". The hint looked for `npm ERR!`, which
npm 10+ no longer prints (`npm error`), and knew nothing of memory kills, ESLint or vite.

app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_FUNCS = {'_cloudtak_build_failure_hint', '_cloudtak_plugin_owning_route'}

STEP_APP = ('target api: failed to solve: process "/bin/sh -c cd ../app     && npm run lint     '
            '&& npm run check     && npm run build" did not complete successfully: exit code: 1')
STEP_NPM = ('target api: failed to solve: process "/bin/sh -c npm install" '
            'did not complete successfully: exit code: 1')


def _hint():
    tree = ast.parse(APP)
    parts = [ast.get_source_segment(APP, n) for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name in _FUNCS]
    assert len(parts) == len(_FUNCS), 'a function under test was renamed or removed'
    ns = {'re': re, 'os': __import__('os'), 'CLOUDTAK_PLUGINS': []}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns['_cloudtak_build_failure_hint']


def _text(lines):
    return '\n'.join(_hint()(lines))


def test_npm_10_plus_error_lines_are_recognised():
    out = _text(['#26 41.20 npm error code E404',
                 '#26 41.20 npm error 404 Not Found - GET https://registry.npmjs.org/nope',
                 '#26 41.21 npm error A complete log of this run can be found in: /root/.npm/x.log',
                 STEP_NPM])
    assert 'Likely cause: an npm step failed inside the build.' in out
    assert 'npm error code E404' in out
    assert 'Failed step: npm install' in out


def test_old_npm_err_prefix_still_recognised():
    assert 'npm ERR! code ERESOLVE' in _text(['#26 3.1 npm ERR! code ERESOLVE'])


def test_npm_bookkeeping_lines_are_not_the_cause():
    out = _text(['#31 9.0 npm error path /home/etl/app',
                 '#31 9.0 npm error command failed',
                 '#31 9.0 npm error code EINTEGRITY'])
    assert 'npm error code EINTEGRITY' in out
    assert 'error path' not in out


def test_npm_network_failure_says_network():
    out = _text(['#26 120.4 npm error code ECONNRESET',
                 '#26 120.4 npm error network aborted', STEP_NPM])
    assert 'Likely cause: npm could not download packages (network).' in out
    assert 'registry.npmjs.org' in out


def test_step_killed_by_signal_is_out_of_memory():
    out = _text(['#31 88.1 npm error path /home/etl/app',
                 '#31 88.1 npm error command failed',
                 '#31 88.1 npm error signal SIGKILL',
                 '#31 88.1 npm error command sh -c vue-tsc --noEmit', STEP_APP])
    assert 'Likely cause: the build ran out of memory' in out
    assert 'signal SIGKILL' in out
    assert 'Failed step: cd ../app' in out


def test_node_heap_exhaustion_is_out_of_memory():
    out = _text(['#31 201.7 FATAL ERROR: Reached heap limit Allocation failed - '
                 'JavaScript heap out of memory', STEP_APP])
    assert 'Likely cause: the build ran out of memory' in out


def test_eslint_failure_is_named():
    out = _text(['#31 30.2 /home/etl/app/src/x.ts',
                 "#31 30.2   12:5  error  'y' is defined but never used  no-unused-vars",
                 '#31 30.2 ✖ 1 problem (1 error, 0 warnings)', STEP_APP])
    assert 'Likely cause: the CloudTAK lint check (ESLint) failed.' in out
    assert '✖ 1 problem (1 error, 0 warnings)' in out


def test_eslint_errors_in_plugin_folders_name_the_plugins():
    # shape of the reporter's own log (GH #252, same box): third-party plugins in app/plugins/
    out = _text(['#32 33.23 /home/etl/app/plugins/livewx-radar/server/plugin-livewx.ts',
                 '#32 33.23   1:1  warning  Unused eslint-disable directive',
                 '#32 33.23 /home/etl/app/plugins/sidebar-configurator/lib/apply.ts',
                 "#32 33.23   4:12  error  'require' is not defined  no-undef",
                 "#32 33.23   9:31  error  '__dirname' is not defined  no-undef",
                 '#32 33.23 /home/etl/app/src/App.vue',
                 "#32 33.23   2:1  error  'x' is defined but never used  no-unused-vars",
                 '#32 33.23 ✖ 380 problems (271 errors, 109 warnings)',
                 '#32 ERROR: process "/bin/sh -c cd ../app && npm run lint && npm run check && '
                 'npm run build" did not complete successfully: exit code: 1'])
    assert 'Likely cause: the CloudTAK lint check (ESLint) failed.' in out
    assert 'plugin folder(s): sidebar-configurator (app/plugins/)' in out
    assert 'livewx-radar' not in out.split('plugin folder(s):')[1]   # warnings only
    assert 'Failed step: cd ../app && npm run lint' in out


def test_warnings_only_lint_summary_is_not_a_failure():
    # printed by every passing CloudTAK build (test6, 13.113.0)
    out = _text(['#58 45.89 ✖ 119 problems (0 errors, 119 warnings)',
                 '#31 140.0 error during build:'])
    assert 'ESLint' not in out
    assert 'vite' in out


def test_vite_failure_is_named():
    out = _text(['#31 140.0 error during build:',
                 '#31 140.0 [vite]: Rollup failed to resolve import "x"', STEP_APP])
    assert 'Likely cause: the CloudTAK web app build (vite) failed.' in out


def test_plugin_type_error_still_wins():
    out = _text(['#32 10.0 stateless/routes/plugin-takcad.ts(12,3): error TS18047: x is possibly null',
                 '#32 10.1 npm error code 2', STEP_APP])
    assert 'CloudTAK PLUGIN server route failed the TypeScript check' in out
    assert 'an npm step failed' not in out


def test_unrecognised_failure_still_names_the_step():
    out = _hint()(['#31 9.0 something odd', STEP_APP])
    assert out and out[-1].startswith('  Failed step: cd ../app')


def test_nothing_decisive_returns_nothing():
    assert _hint()(['#1 DONE 0.1s', 'Build failed']) == []


def test_never_raises():
    assert _hint()([None]) == []
