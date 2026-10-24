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
"""Applying the suggested heap wiped the operator's /etc/default/takserver (GH #282).

The reporter kept their own environment variables in /etc/default/takserver; set-heap
rewrote the whole file with only infra-TAK's five *_MAX_HEAP lines. It now merges by
variable name: only those five vars are replaced, everything else is kept.

app.py cannot be imported in a test, so its helpers are cut out of it and run as they
ship: the code under test is the shipped text.
"""

import ast
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


NS = {}
exec(compile('\n\n'.join(_segment(n) for n in (
    'TAKSERVER_HEAP_VARS', '_TAKSERVER_HEAP_BLOCK_A', '_TAKSERVER_HEAP_BLOCK_B',
    '_merge_takserver_heap_defaults')), 'app.py', 'exec'), NS)
merge = NS['_merge_takserver_heap_defaults']

HEAPS = {'CONFIG_MAX_HEAP': 409, 'API_MAX_HEAP': 2276, 'MESSAGING_MAX_HEAP': 2276,
         'PLUGIN_MANAGER_MAX_HEAP': 477, 'RETENTION_MAX_HEAP': 477}

OPERATOR = (
    '# my own settings\n'
    'export TAKSERVER_EXTRA_OPTS="-Dfoo=bar"\n'
    'HTTPS_PROXY=http://proxy.local:3128\n'
    '\n'
    'export API_MAX_HEAP=1024\n'
    'MESSAGING_MAX_HEAP=512\n'
)

# Exactly what releases before the fix wrote, plus a var the operator added afterwards.
LEGACY = (
    '# infra-TAK total heap: 4g\n'
    '# Proportional split across TAK Server processes (same ratios as setenv.sh defaults)\n'
    'export CONFIG_MAX_HEAP=204\n'
    'export API_MAX_HEAP=1138\n'
    'export MESSAGING_MAX_HEAP=1138\n'
    'export PLUGIN_MANAGER_MAX_HEAP=238\n'
    'export RETENTION_MAX_HEAP=238\n'
    'export MY_VAR=keep-me\n'
)


def _assignments(text):
    return [ln for ln in text.splitlines() if re.match(r'\s*(export\s+)?\w+=', ln)]


def test_operator_variables_survive():
    out = merge(OPERATOR, 8, HEAPS)
    for line in ('# my own settings', 'export TAKSERVER_EXTRA_OPTS="-Dfoo=bar"',
                 'HTTPS_PROXY=http://proxy.local:3128'):
        assert line in out.splitlines()
    assert out.index('HTTPS_PROXY') < out.index(NS['_TAKSERVER_HEAP_BLOCK_A'])


def test_each_heap_var_set_exactly_once_with_new_value():
    out = merge(OPERATOR, 8, HEAPS)
    for name, mb in HEAPS.items():
        hits = [ln for ln in _assignments(out) if re.match(rf'\s*(export\s+)?{name}=', ln)]
        assert hits == [f'export {name}={mb}'], (name, hits)


def test_legacy_unmarked_file_is_converted_without_duplicates():
    out = merge(LEGACY, 8, HEAPS)
    assert 'export MY_VAR=keep-me' in out.splitlines()
    assert out.count('# infra-TAK total heap:') == 1
    assert '# infra-TAK total heap: 8g' in out
    assert out.count('# Proportional split') == 1
    assert len(_assignments(out)) == len(HEAPS) + 1


def test_reapply_is_idempotent_and_replaces_the_block():
    once = merge(OPERATOR, 8, HEAPS)
    assert merge(once, 8, HEAPS) == once
    smaller = {k: v // 2 for k, v in HEAPS.items()}
    twice = merge(once, 4, smaller)
    assert twice.count(NS['_TAKSERVER_HEAP_BLOCK_A']) == 1
    assert '# infra-TAK total heap: 4g' in twice and '8g' not in twice
    assert 'HTTPS_PROXY=http://proxy.local:3128' in twice


def test_missing_or_empty_file_gets_just_the_block():
    for existing in ('', None, '\n\n'):
        out = merge(existing, 8, HEAPS)
        assert out.startswith(NS['_TAKSERVER_HEAP_BLOCK_A'])
        assert out.endswith(NS['_TAKSERVER_HEAP_BLOCK_B'] + '\n')


def test_similar_names_are_not_touched():
    text = 'export MY_API_MAX_HEAP=1\nexport API_MAX_HEAP_NOTE=2\n#export API_MAX_HEAP=3\n'
    out = merge(text, 8, HEAPS)
    for line in text.splitlines():
        assert line in out.splitlines()


def test_heap_info_still_reads_the_total():
    # _get_current_takserver_heap_gb() looks for this comment; the block must keep it.
    assert re.search(r'# infra-TAK total heap: (\d+)g', merge(OPERATOR, 12, HEAPS)).group(1) == '12'


@pytest.mark.skipif(not shutil.which('bash'), reason='bash not available')
def test_sourced_by_a_shell_the_operator_vars_and_our_heaps_win(tmp_path):
    f = tmp_path / 'takserver'
    f.write_text(merge(OPERATOR, 8, HEAPS))
    out = subprocess.run(['bash', '-c', f'. {f}; echo "$HTTPS_PROXY|$API_MAX_HEAP|$MESSAGING_MAX_HEAP"'],
                         capture_output=True, text=True, check=True).stdout.strip()
    assert out == 'http://proxy.local:3128|2276|2276'


def test_route_merges_and_refuses_to_overwrite_an_unreadable_file():
    src = _segment('takserver_set_heap')
    assert '_merge_takserver_heap_defaults(existing' in src
    assert '_read_own_or_priv(defaults_file)' in src
    # The read failure must return before any write happens.
    read_fail = src.index('left it unchanged')
    assert read_fail < src.index('_write_priv(defaults_file')
    # The old whole-file literal is gone.
    assert 'defaults_content = (' not in src
