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
"""ops #1262: a CloudTAK Update must not say "updated" while the api crash-loops.

Field (test6, Nov 24, 2026): CloudTAK 13.x with the Replay Marketplace plugin, Update to 14.1.1.
The image built, the log said "CloudTAK updated to v14.1.1", and then the api restarted about every
90 seconds (`Cannot find package 'csv-stringify' imported from .../replay-export.js`: 14.x no
longer lists it). Map and video answered 502 until Replay was uninstalled, about 40 minutes.

Two guards: before the build, refuse when a plugin file in api/ imports a package the NEW api
lacks; after the restart, watch the api for 2 minutes and undo the update on a restart loop.
app.py cannot be imported in a test, so the functions are cut out of it.
"""

import ast
import json
import os
import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
CID = 'c' * 12


def _node(name):
    return next(n for n in TREE.body
                if (isinstance(n, ast.FunctionDef) and n.name == name)
                or (isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets)))


def _src(name):
    return ast.get_source_segment(APP, _node(name))


def _load(**extra):
    consts = ('_CT_IMPORT_RE', '_CT_NPM_NAME_RE', '_CT_NODE_BUILTINS', '_CT_API_SKIP_DIRS',
              '_CT_MODULE_MISSING_RE')
    funcs = ('_cloudtak_api_plugin_missing_packages', '_cloudtak_api_plugin_preflight',
             '_cloudtak_api_stability_watch', '_cloudtak_web_dir', '_cloudtak_plugins_dir',
             '_cloudtak_lint_files_from_plugins')
    src = '\n\n'.join(_src(n) for n in consts + funcs)
    ns = {'os': os, 're': re, 'json': json, 'subprocess': subprocess,
          'time': type('T', (), {'sleep': staticmethod(lambda s: None)})}
    ns.update(extra)
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


# ── the tree: CloudTAK 14.1.1-shaped api, Replay's files left untracked ──────────────────────
API_PKG = {'name': '@tak-ps/cloudtak-api', 'version': '14.1.1',
           'dependencies': {'@tak-ps/node-cot': '^14.0.0', 'pg': '^8.0.0', 'zod': '^3.0.0'}}
REPLAY_EXPORT = ("import { stringify } from 'csv-stringify/sync';\n"
                 "import fs from 'node:fs';\nimport path from 'path';\n"
                 "import type { Foo } from 'not-a-runtime-import';\n"
                 "import { std } from '../helpers.js';\nimport { z } from 'zod';\n")


def _git(ct, *args):
    subprocess.run(['git', '-C', str(ct), '-c', 'user.name=t', '-c', 'user.email=t@t', *args],
                   check=True, capture_output=True)


def _tree(tmp_path, lock_packages=None, api_pkg=None):
    ct = tmp_path / 'CloudTAK'
    (ct / 'api' / 'stateless' / 'lib').mkdir(parents=True)
    (ct / 'api' / 'package.json').write_text(json.dumps(api_pkg or API_PKG, indent=2))
    if lock_packages is not None:
        (ct / 'api' / 'package-lock.json').write_text(json.dumps({'packages': lock_packages}))
    (ct / 'api' / 'stateless' / 'lib' / 'helpers.ts').write_text("import pg from 'pg';\n")
    (ct / 'app' / 'plugins' / 'replay').mkdir(parents=True)
    (ct / 'app' / 'plugins' / 'replay' / 'index.ts').write_text('export default {};\n')
    (ct / '.gitignore').write_text('node_modules/\n')
    _git(ct, 'init', '-q')
    _git(ct, 'add', '-A')
    _git(ct, 'commit', '-qm', 'cloudtak 14.1.1')
    return ct


def _replay_files(ct, body=REPLAY_EXPORT):
    f = ct / 'api' / 'stateless' / 'lib' / 'replay-export.ts'
    f.write_text(body)
    return f


def _web_dir(_ct):
    return None


def _ns():
    ns = _load()
    ns['_cloudtak_web_dir'] = lambda ct: os.path.join(ct, 'app')   # 13.102+ layout
    ns['_cloudtak_plugins_dir'] = lambda ct: os.path.join(ct, 'app', 'plugins')
    return ns


# ── guard 1: refuse before the build ─────────────────────────────────────────────────────────
def test_replay_files_importing_a_package_the_new_api_lacks_are_found(tmp_path):
    ct = _tree(tmp_path)
    _replay_files(ct)
    missing = _ns()['_cloudtak_api_plugin_missing_packages'](str(ct))
    assert missing == {'csv-stringify': ['stateless/lib/replay-export.ts']}, missing


def test_preflight_refuses_and_names_the_plugin_the_package_and_the_way_out(tmp_path):
    ct = _tree(tmp_path)
    _replay_files(ct)
    log = []
    ok = _ns()['_cloudtak_api_plugin_preflight'](str(ct), log.append, 'v14.1.1')
    text = '\n'.join(log)
    assert ok is False
    assert 'replay needs the npm package csv-stringify' in text, text
    assert 'CloudTAK v14.1.1 no longer includes' in text, text
    assert 'uninstall replay' in text and 'then press Update again' in text, text


def test_preflight_passes_when_the_new_api_still_has_the_package(tmp_path):
    api = dict(API_PKG, dependencies=dict(API_PKG['dependencies'], **{'csv-stringify': '^6.0.0'}))
    ct = _tree(tmp_path, api_pkg=api)
    _replay_files(ct)
    log = []
    assert _ns()['_cloudtak_api_plugin_preflight'](str(ct), log.append, 'v13.128.0') is True
    assert log == []


def test_a_package_that_only_the_lock_file_lists_still_resolves(tmp_path):
    ct = _tree(tmp_path, lock_packages={'': {}, 'node_modules/csv-stringify': {'version': '6.5.0'},
                                        'node_modules/a/node_modules/other': {}})
    _replay_files(ct)
    assert _ns()['_cloudtak_api_plugin_missing_packages'](str(ct)) == {}


def test_builtins_relative_type_only_and_own_packages_are_not_missing(tmp_path):
    ct = _tree(tmp_path)
    _replay_files(ct, "import fs from 'node:fs';\nimport { join } from 'path';\n"
                      "import { readFile } from 'fs/promises';\nimport type { X } from 'nope';\n"
                      "import { a } from './a.js';\nimport { z } from 'zod';\n"
                      "import cot from '@tak-ps/node-cot';\nconst m = await import('pg');\n")
    assert _ns()['_cloudtak_api_plugin_missing_packages'](str(ct)) == {}


def test_a_scoped_package_is_named_with_its_scope(tmp_path):
    ct = _tree(tmp_path)
    _replay_files(ct, "import x from '@scope/thing/deep/file.js';\n")
    assert list(_ns()['_cloudtak_api_plugin_missing_packages'](str(ct))) == ['@scope/thing']


def test_files_that_cloudtak_tracks_are_never_read(tmp_path):
    ct = _tree(tmp_path)
    # an upstream file that imports something odd stays out of the check: only plugin files count
    (ct / 'api' / 'stateless' / 'lib' / 'helpers.ts').write_text("import x from 'csv-stringify';\n")
    assert _ns()['_cloudtak_api_plugin_missing_packages'](str(ct)) == {}


def test_node_modules_dist_and_tests_inside_the_untracked_tree_are_skipped(tmp_path):
    ct = _tree(tmp_path)
    for d in ('node_modules/x', 'dist', 'test'):
        p = ct / 'api' / d
        p.mkdir(parents=True)
        (p / 'a.ts').write_text("import x from 'csv-stringify';\n")
    (ct / 'api' / 'stateless' / 'lib' / 'replay.test.ts').write_text("import x from 'csv-stringify';\n")
    assert _ns()['_cloudtak_api_plugin_missing_packages'](str(ct)) == {}


def test_a_broken_tree_never_raises_and_never_blocks_the_update(tmp_path):
    ns = _ns()
    log = []
    assert ns['_cloudtak_api_plugin_missing_packages'](str(tmp_path / 'nothing')) == {}
    assert ns['_cloudtak_api_plugin_preflight'](str(tmp_path / 'nothing'), log.append) is True


# ── guard 2: the api must stay up after the restart ──────────────────────────────────────────
class Docker:
    """Stand-in for _cloudtak_compose_at and _cloudtak_docker. `states` is one inspect answer per
    look; the last one repeats. Records the argv of every docker call."""
    def __init__(self, states, logs='', cid=CID):
        self.states, self.logs, self.cid, self.calls, self.i = list(states), logs, cid, [], 0

    def compose_at(self, cloudtak_dir, args, remote_cfg=None, timeout=600):
        self.calls.append(['compose'] + list(args))
        return 0, self.cid + '\n'

    def docker(self, argv, remote_cfg=None, timeout=60):
        self.calls.append(list(argv))
        if argv[:2] == ['docker', 'inspect']:
            out = self.states[min(self.i, len(self.states) - 1)]
            self.i += 1
            return 0, out + '\n', ''
        if argv[:2] == ['docker', 'logs']:
            return 0, '', self.logs
        return 1, '', 'unexpected'


def _watch(states, logs='', cid=CID, seconds=120, interval=10):
    d = Docker(states, logs, cid)
    ns = _load(_cloudtak_compose_at=d.compose_at, _cloudtak_docker=d.docker)
    sleeps = []
    res = ns['_cloudtak_api_stability_watch']('/x/CloudTAK', lambda m: None, seconds=seconds,
                                              interval=interval, sleep=sleeps.append)
    return res, d, sleeps


RUN = 'running|false|0|2026-11-25T18:00:00Z'
CSV_LOG = ("Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'csv-stringify' imported from "
           "/home/etl/api/dist/stateless/lib/replay-export.js\n")


def test_an_api_that_stays_up_for_two_minutes_passes():
    (ok, why), d, sleeps = _watch([RUN])
    assert (ok, why) == (True, '')
    assert sum(sleeps) >= 120, sleeps          # it really waited the 2 minutes
    assert not any(c[:2] == ['docker', 'logs'] for c in d.calls)


def test_the_test6_crash_loop_fails_the_watch_and_names_the_missing_package():
    # Nov 24: up for a while, then Docker restarts it about every 90 seconds
    states = [RUN] * 4 + ['running|false|1|2026-11-25T18:01:30Z']
    (ok, why), d, _ = _watch(states, logs=CSV_LOG)
    assert ok is False
    assert 'Docker restarted the CloudTAK API (1 restarts)' in why, why
    assert "cannot find the package 'csv-stringify'" in why, why


def test_an_api_caught_while_restarting_fails_at_once():
    (ok, why), _d, sleeps = _watch(['restarting|true|3|2026-11-25T18:00:00Z'], logs=CSV_LOG)
    assert ok is False and 'is restarting' in why, why
    assert sleeps == []                         # no waiting out the 2 minutes once it is plainly down


def test_a_stopped_api_fails():
    (ok, why), _d, _ = _watch([RUN, 'exited|false|0|2026-11-25T18:00:00Z'])
    assert ok is False and 'exited' in why, why


def test_an_api_that_started_again_by_itself_fails():
    (ok, why), _d, _ = _watch([RUN, 'running|false|0|2026-11-25T18:01:00Z'])
    assert ok is False and 'started again' in why, why


def test_one_start_up_retry_before_the_first_look_is_not_a_loop():
    # the first look sees restart count 1 and keeps it: only a CHANGE during the watch counts
    (ok, why), _d, _ = _watch(['running|false|1|2026-11-25T18:00:20Z'])
    assert (ok, why) == (True, '')


def test_no_api_container_fails():
    (ok, why), _d, _ = _watch([RUN], cid='')
    assert ok is False and 'not there' in why, why


# ── the wiring: where run_cloudtak_update calls them ─────────────────────────────────────────
def _update_src():
    return _src('run_cloudtak_update')


def test_the_preflight_runs_after_the_checkout_and_before_the_build():
    s = _update_src()
    assert '_cloudtak_api_plugin_preflight(cloudtak_dir, plog, release_tag)' in s
    assert s.index('_cloudtak_api_plugin_preflight(') > s.index('_run_cloudtak_prebuild_hooks(')
    assert s.index('_cloudtak_api_plugin_preflight(') < s.index('Step 3/3: Rebuilding and restarting')
    block = s[s.index('_cloudtak_api_plugin_preflight('):s.index('Step 3/3: Rebuilding and restarting')]
    assert '_cloudtak_revert_checkout(prev_sha' in block and 'return' in block   # undone, nothing built


def test_the_watch_runs_after_the_heals_and_before_the_success_line():
    s = _update_src()
    w = s.index('_cloudtak_api_stability_watch(')
    assert w > s.index('_cloudtak_verify_plugins_in_app(')
    assert w > s.index('_cloudtak_media_hls_heal(')
    assert w < s.index('✓ CloudTAK updated to')
    block = s[w:s.index('✓ CloudTAK updated to')]
    assert '_cloudtak_rollback_after_failed_up(' in block and 'return' in block


def test_the_rollback_pins_live_until_the_watch_has_passed():
    s = _update_src()
    w = s.index('_cloudtak_api_stability_watch(')
    # a drop of the pins before the watch (outside the "files already moved" and, ops #1325,
    # "database already upgraded" no-rollback cases) would leave the rollback with no old images
    for m in re.finditer(r'_cloudtak_drop_rollback_pins\(_ct_snap', s[:w]):
        near = s[m.start():m.start() + 250]
        assert 'Not rolling back' in near or '_cloudtak_update_db_moved_lines' in near, near
    # and once the watch has passed, the pins are dropped before the success line
    ok_line = s.index('\u2713 CloudTAK updated to')
    assert s.rindex('_cloudtak_drop_rollback_pins(_ct_snap', 0, ok_line) > w
