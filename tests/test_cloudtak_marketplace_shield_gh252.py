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
"""GH #252: CloudTAK builds must not lint plugins TAK Portal's marketplace installed.

TAK Portal makes the image build skip lint/typecheck for its plugins by editing tracked
CloudTAK files. Our Update / revert `checkout -f` reset those files while the plugin
folders stayed, so the next build (here: installing the TAK Simulator panel) failed on
271 ESLint errors in five marketplace plugins. Before every build we put the edits back
whenever the plugins dir holds a plugin infra-TAK did not install.
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

# CloudTAK v13.112.3, verbatim where it matters.
APP_LINT = 'eslint --config eslint.config.js ./src/ ./public/ ./plugins/'
APP_PKG = json.dumps({'name': '@tak-ps/cloudtak', 'version': '13.112.3', 'scripts': {
    'check': 'vue-tsc', 'build:types': 'vue-tsc -p tsconfig.build.json', 'build': 'vite build',
    'lint': APP_LINT}}, indent=4) + '\n'
API_ESLINT = ("import eslint from '@eslint/js';\nimport tseslint from 'typescript-eslint';\n\n"
              "export default tseslint.config(\n    eslint.configs.recommended,\n"
              "    ...tseslint.configs.recommended,\n);\n")
OVERLAY = ('{\n  "extends": "./tsconfig.json",\n  "exclude": [\n    "plugins",\n'
           '    "node_modules",\n    "dist"\n  ]\n}\n')


def _body(name):
    return ast.get_source_segment(APP, next(
        n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))


def _const(name):
    node = next(n for n in TREE.body if isinstance(n, ast.Assign)
                and any(getattr(t, 'id', None) == name for t in n.targets))
    return ast.get_source_segment(APP, node)


def _load():
    src = '\n\n'.join([_const('_CT_MARKETPLACE_TSCONFIG'), _const('_CT_MARKETPLACE_ROUTES_RE')]
                      + [_body(n) for n in ('_cloudtak_web_dir', '_cloudtak_plugins_dir',
                                            '_cloudtak_foreign_plugins', '_cloudtak_has_ts_nocheck',
                                            '_cloudtak_rewrite_in_place',
                                            '_cloudtak_shield_foreign_plugins')])
    ns = {'os': os, 're': re, 'json': json, 'subprocess': subprocess,
          'CLOUDTAK_PLUGINS': [{'install_dir': d} for d in
                               ('ping', 'search-containment', 'tak-dispatcher', 'taksim')]}
    exec(compile(src, 'app.py', 'exec'), ns)
    return ns


def _git(ct, *args):
    subprocess.run(['git', '-C', str(ct), '-c', 'user.name=t', '-c', 'user.email=t@t', *args],
                   check=True, capture_output=True)


def _tree(tmp_path, plugins=()):
    """A stock CloudTAK 13.112.3-shaped checkout (committed), plus untracked plugin dirs."""
    ct = tmp_path / 'CloudTAK'
    (ct / 'app' / 'src').mkdir(parents=True)
    (ct / 'app' / 'plugins').mkdir()
    (ct / 'app' / 'plugins' / 'README.md').write_text('upstream\n')
    (ct / 'app' / 'package.json').write_text(APP_PKG)
    (ct / 'api' / 'stateless' / 'routes').mkdir(parents=True)
    (ct / 'api' / 'stateless' / 'routes' / 'basemap.ts').write_text('export default 1;\n')
    (ct / 'api' / 'eslint.config.js').write_text(API_ESLINT)
    _git(ct, 'init', '-q')
    _git(ct, 'add', '-A')
    _git(ct, 'commit', '-qm', 'stock')
    for p in plugins:
        (ct / 'app' / 'plugins' / p).mkdir()
        (ct / 'app' / 'plugins' / p / 'index.ts').write_text('export default {};\n')
    return ct


def _run(ns, ct):
    log = []
    ns['_cloudtak_shield_foreign_plugins'](str(ct), log.append)
    return log


def _scripts(ct):
    return json.loads((ct / 'app' / 'package.json').read_text())['scripts']


def test_marketplace_plugins_get_the_lint_and_typecheck_skip(tmp_path):
    ct = _tree(tmp_path, ('livewx-radar', 'udash', 'taksim'))
    log = _run(_load(), ct)
    s = _scripts(ct)
    assert s['lint'] == 'eslint --config eslint.config.js ./src/ ./public/'
    assert s['check'] == 'vue-tsc --project tsconfig.marketplace.json'
    assert s['build:types'] == 'vue-tsc -p tsconfig.build.json'          # untouched
    assert (ct / 'app' / 'tsconfig.marketplace.json').read_text() == OVERLAY
    cfg = (ct / 'api' / 'eslint.config.js').read_text()
    assert ("export default tseslint.config(\n    /* cloudtak-marketplace-routes */\n"
            "    { ignores: ['stateless/routes/plugin-*.ts'] },\n    eslint.configs.recommended,") in cfg
    assert len(log) == 1 and 'livewx-radar, udash' in log[0] and 'taksim' not in log[0]


def test_only_our_plugins_changes_nothing(tmp_path):
    ct = _tree(tmp_path, ('taksim', 'tak-dispatcher'))
    log = _run(_load(), ct)
    assert log == []
    assert (ct / 'app' / 'package.json').read_text() == APP_PKG
    assert (ct / 'api' / 'eslint.config.js').read_text() == API_ESLINT
    assert not (ct / 'app' / 'tsconfig.marketplace.json').exists()


def test_upstream_tracked_plugin_dir_is_not_foreign(tmp_path):
    ct = _tree(tmp_path)
    (ct / 'app' / 'plugins' / 'example').mkdir()
    (ct / 'app' / 'plugins' / 'example' / 'index.ts').write_text('x\n')
    _git(ct, 'add', '-A')
    _git(ct, 'commit', '-qm', 'upstream example plugin')
    assert _load()['_cloudtak_foreign_plugins'](str(ct)) == []


def test_second_run_is_a_noop(tmp_path):
    ct = _tree(tmp_path, ('incident-manager',))
    ns = _load()
    _run(ns, ct)
    before = {p: (ct / p).read_text() for p in
              ('app/package.json', 'app/tsconfig.marketplace.json', 'api/eslint.config.js')}
    assert _run(ns, ct) == []
    assert {p: (ct / p).read_text() for p in before} == before


def test_tak_portal_block_is_replaced_not_duplicated(tmp_path):
    ct = _tree(tmp_path, ('sidebar-configurator',))
    (ct / 'api' / 'stateless' / 'routes' / 'helper-sync.ts').write_text('// @ts-nocheck\nx\n')
    cfg = ct / 'api' / 'eslint.config.js'
    cfg.write_text(API_ESLINT.replace(
        'tseslint.config(\n', "tseslint.config(\n    /* cloudtak-marketplace-routes */\n"
        "    { ignores: ['stateless/routes/plugin-*.ts'] },\n"))
    _run(_load(), ct)
    text = cfg.read_text()
    assert text.count('cloudtak-marketplace-routes') == 1
    assert "{ ignores: ['stateless/routes/plugin-*.ts', 'stateless/routes/helper-sync.ts'] }," in text


def test_marked_api_lib_files_are_ignored_too(tmp_path):
    ct = _tree(tmp_path, ('replay',))
    lib = ct / 'api' / 'stateless' / 'lib' / 'retention'
    lib.mkdir(parents=True)
    (lib / 'replay.ts').write_text('// @ts-nocheck\nx\n')
    (lib / 'plain.ts').write_text('x\n')
    _run(_load(), ct)
    text = (ct / 'api' / 'eslint.config.js').read_text()
    assert "'stateless/lib/retention/replay.ts'" in text and 'plain.ts' not in text


def test_file_mode_is_kept(tmp_path):
    ct = _tree(tmp_path, ('udash',))
    (ct / 'app' / 'package.json').chmod(0o640)
    _run(_load(), ct)
    assert (ct / 'app' / 'package.json').stat().st_mode & 0o777 == 0o640


def test_never_raises(tmp_path):
    ct = _tree(tmp_path, ('udash',))
    (ct / 'app' / 'package.json').write_bytes(b'{"lint": "\xff\xfe"}')   # not UTF-8
    log = _run(_load(), ct)
    assert len(log) == 1 and 'non-fatal' in log[0]


def test_legacy_api_web_layout(tmp_path):
    ct = tmp_path / 'CloudTAK'
    (ct / 'api' / 'web' / 'plugins' / 'd4h').mkdir(parents=True)
    (ct / 'api' / 'web' / 'package.json').write_text(APP_PKG)
    _run(_load(), ct)
    s = json.loads((ct / 'api' / 'web' / 'package.json').read_text())['scripts']
    assert s['lint'] == 'eslint --config eslint.config.js ./src/ ./public/'


def test_runs_before_every_build():
    """Plugin rebuild, Update, revert and Deploy all shield before they build."""
    plugin = _body('_run_cloudtak_plugin_action')
    assert (plugin.index('_cloudtak_shield_foreign_plugins(ct_dir, plog)')
            < plugin.index("_run_cloudtak_prebuild_hooks(ct_dir, 'plugin'")
            < plugin.index("'compose', 'build', '--no-cache', 'api'"))
    update = _body('run_cloudtak_update')
    assert (update.index('_cloudtak_shield_foreign_plugins(cloudtak_dir, plog)')
            < update.index("_run_cloudtak_prebuild_hooks(cloudtak_dir, 'update'")
            < update.index('Step 3/3: Rebuilding'))
    revert = _body('_cloudtak_revert_hooks')
    assert (revert.index('_cloudtak_shield_foreign_plugins(cloudtak_dir, plog)')
            < revert.index("_run_cloudtak_prebuild_hooks(cloudtak_dir, 'revert'"))
    deploy = _body('run_cloudtak_deploy')
    assert (deploy.index('_cloudtak_shield_foreign_plugins(cloudtak_dir, plog)')
            < deploy.index("'docker', 'compose', 'build', '--no-cache'"))
