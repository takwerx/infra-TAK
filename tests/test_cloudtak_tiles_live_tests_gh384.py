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
"""GH #384: CloudTAK Update must not need outside map servers to build the tiles image.

A customer box failed 13.116.1 -> 13.117.1 four times at
`npm run lint && npm run test && npm run build` in tasks/pmtiles: two upstream tests named
"... (live network)" fetch real tiles from maps.six.nsw.gov.au and sampleserver6.arcgisonline.com,
and when the box can't reach them the tile route answers 400 ("actual: 400, expected: 200").
infra-TAK now skips only those tests in the image build, after every checkout.
"""

import ast
import os
import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

# tasks/pmtiles/Dockerfile.compose at CloudTAK v13.117.1, verbatim
UPSTREAM_DF = """FROM node:26-alpine3.24

EXPOSE 5002

ENV APP_ROOT=/workspace

WORKDIR $APP_ROOT/tasks/pmtiles

COPY tasks/pmtiles/package*.json ./
COPY api/derived-types.d.ts $APP_ROOT/api/derived-types.d.ts

RUN npm install

COPY tasks/pmtiles/ ./

RUN npm run lint \\
    && npm run test \\
    && npm run build

CMD ["npm", "run", "prod"]
"""
PATCHED_TEST_LINE = '    && NODE_OPTIONS=--test-skip-pattern=live.network npm run test \\\n'

NAMES = ('_CLOUDTAK_TILES_DOCKERFILE', '_CLOUDTAK_TILES_LIVE_SKIP', '_CLOUDTAK_TILES_TEST_RE',
         '_CLOUDTAK_REMOTE_TILES_LIVE_PERL', '_patch_cloudtak_tiles_live_tests',
         '_patch_cloudtak_tiles_arm64')


def _load(arch='amd64'):
    src = ''.join(ast.get_source_segment(APP, n) + '\n\n' for n in TREE.body
                  if (isinstance(n, ast.FunctionDef) and n.name in NAMES)
                  or (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in NAMES for t in n.targets)))
    ns = {'os': os, 're': re, '_host_arch': lambda: arch}
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


def _box(tmp_path, df=UPSTREAM_DF):
    ct = tmp_path / 'CloudTAK'
    (ct / 'tasks' / 'pmtiles').mkdir(parents=True)
    (ct / 'tasks' / 'pmtiles' / 'Dockerfile.compose').write_text(df)
    return ct


def _df(ct):
    return (ct / 'tasks' / 'pmtiles' / 'Dockerfile.compose').read_text()


def test_skips_live_network_tests_in_the_tiles_build(tmp_path):
    ct = _box(tmp_path)
    assert _load()['_patch_cloudtak_tiles_live_tests'](str(ct)) is True
    assert _df(ct) == UPSTREAM_DF.replace('    && npm run test \\\n', PATCHED_TEST_LINE)


def test_lint_and_build_still_run(tmp_path):
    ct = _box(tmp_path)
    _load()['_patch_cloudtak_tiles_live_tests'](str(ct))
    assert 'RUN npm run lint \\\n' in _df(ct)
    assert '    && npm run build\n' in _df(ct)
    assert _df(ct).count('test-skip-pattern') == 1


def test_idempotent(tmp_path):
    ct = _box(tmp_path)
    fn = _load()['_patch_cloudtak_tiles_live_tests']
    fn(str(ct))
    once = _df(ct)
    assert fn(str(ct)) is False
    assert _df(ct) == once


def test_plain_run_test_line(tmp_path):
    ct = _box(tmp_path, df='FROM node:26-alpine\nRUN npm run test\n')
    _load()['_patch_cloudtak_tiles_live_tests'](str(ct))
    assert _df(ct) == 'FROM node:26-alpine\nRUN NODE_OPTIONS=--test-skip-pattern=live.network npm run test\n'


def test_no_test_step_or_no_file_is_a_noop(tmp_path):
    fn = _load()['_patch_cloudtak_tiles_live_tests']
    ct = _box(tmp_path, df='FROM node:26-alpine\nRUN npm run build\n')
    assert fn(str(ct)) is False
    assert fn(str(tmp_path / 'missing')) is False


def test_works_with_the_arm64_base_swap(tmp_path):
    ct = _box(tmp_path)
    ns = _load('arm64')
    ns['_patch_cloudtak_tiles_arm64'](str(ct))
    ns['_patch_cloudtak_tiles_live_tests'](str(ct))
    assert _df(ct).startswith('FROM node:26-bookworm-slim\n')
    assert PATCHED_TEST_LINE in _df(ct)


@pytest.mark.skipif(not shutil.which('perl'), reason='perl not installed')
def test_remote_perl_matches_the_local_patch(tmp_path):
    ct = _box(tmp_path)
    cmd = _load()['_CLOUDTAK_REMOTE_TILES_LIVE_PERL']
    env = dict(os.environ, HOME=str(tmp_path))
    for _ in range(2):  # second run must change nothing
        r = subprocess.run(['sh', '-c', cmd], env=env, capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        assert _df(ct) == UPSTREAM_DF.replace('    && npm run test \\\n', PATCHED_TEST_LINE)


def _node_has_skip_pattern():
    node = shutil.which('node')
    if not node:
        return False
    r = subprocess.run([node, '--version'], capture_output=True, text=True)
    m = re.match(r'v(\d+)\.(\d+)', r.stdout.strip())
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (22, 1)


@pytest.mark.skipif(not _node_has_skip_pattern(), reason='needs node >= 22.1 (--test-skip-pattern)')
def test_patched_command_really_skips_live_tests(tmp_path):
    """Run the patched RUN line's test step with Node's runner against a live test that fails
    without network: stock fails, patched passes and the offline test still runs."""
    (tmp_path / 't.test.mjs').write_text(
        "import test from 'node:test';\n"
        "test('offline ok', () => {});\n"
        "test('proxies a zxy tile (live network)', () => { throw new Error('no route to NSW'); });\n")
    ct = _box(tmp_path)
    _load()['_patch_cloudtak_tiles_live_tests'](str(ct))
    line = next(ln for ln in _df(ct).splitlines() if 'npm run test' in ln)
    prefix = line.split('npm run test')[0].replace('&&', '').strip()
    stock = subprocess.run(['sh', '-c', 'node --test t.test.mjs'], cwd=tmp_path,
                           capture_output=True, text=True, timeout=60)
    patched = subprocess.run(['sh', '-c', f'{prefix} node --test t.test.mjs'], cwd=tmp_path,
                             capture_output=True, text=True, timeout=60)
    assert stock.returncode != 0
    assert patched.returncode == 0, patched.stdout + patched.stderr
    assert re.search(r'pass 1\b', patched.stdout)


def _body(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def test_update_applies_it_before_the_build():
    body = _body('run_cloudtak_update')
    i = body.index('_patch_cloudtak_tiles_live_tests(cloudtak_dir)')
    assert i < body.index("f'{dcc} build --no-cache'")
    assert body.index('_CLOUDTAK_REMOTE_TILES_LIVE_PERL') < body.index('build_cmd = f"cd ~/CloudTAK && {dcc} build --no-cache"')


def test_deploy_applies_it_before_the_build():
    body = _body('run_cloudtak_deploy')
    assert body.index('_patch_cloudtak_tiles_live_tests(cloudtak_dir)') < \
        body.index("_sudo_wrap(['docker', 'compose', 'build', '--no-cache'])")
    assert body.index('_CLOUDTAK_REMOTE_TILES_LIVE_PERL') < body.index('"docker compose build --no-cache && "')
