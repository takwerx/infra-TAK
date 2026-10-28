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
"""GH #271: a CloudTAK Update must not drop npm packages a marketplace plugin added.

Field (v10.2.28, Ubuntu 22.04, 8 TAK Portal marketplace plugins): 13.112.3 -> 13.113.0 failed
at `npm run build` with only "error during build:" in the hint. Rubber Sheet's install.sh adds
pdfjs-dist to CloudTAK's tracked app/package.json; our `checkout -f` reset it while the plugin
folder stayed, so vite could not resolve `pdfjs-dist/legacy/build/pdf.mjs`. Before each build we
now put back any package a non-infra-TAK plugin imports and declares, and the vite hint prints
the line that names the cause.
"""

import json

from test_cloudtak_marketplace_shield_gh252 import APP_PKG, _git, _load, _run, _tree
from test_cloudtak_build_failure_hint_gh249 import STEP_APP, _text

# Rubber Sheet (ValleyTacticalSolutions/cloudtak-plugin-rubbersheet 38abc5a), trimmed
RS_PKG = json.dumps({'name': 'cloudtak-plugin-rubber-sheet', 'type': 'module', 'devDependencies': {
    '@tak-ps/cloudtak': 'file:../../../CloudTAK/app', 'maplibre-gl': '^5.1.0',
    'pdfjs-dist': '4.10.38', 'vue': '^3.5.26'}}, indent=2) + '\n'
RS_RENDER = ("import { getDocument, GlobalWorkerOptions } from 'pdfjs-dist/legacy/build/pdf.mjs';\n"
             "import workerCode from 'pdfjs-dist/legacy/build/pdf.worker.min.mjs?raw';\n"
             "import type { Map } from 'maplibre-gl';\nimport { x } from './util';\n")


def _rubber_sheet(ct):
    p = ct / 'app' / 'plugins' / 'rubber-sheet'
    (p / 'lib').mkdir(parents=True, exist_ok=True)
    (p / 'index.ts').write_text("export default {};\n")
    (p / 'package.json').write_text(RS_PKG)
    (p / 'lib' / 'pdf-render.ts').write_text(RS_RENDER)
    return p


def _deps(ct):
    return json.loads((ct / 'app' / 'package.json').read_text()).get('dependencies', {})


def test_reset_package_json_gets_pdfjs_back(tmp_path):
    ct = _tree(tmp_path)
    _rubber_sheet(ct)
    log = _run(_load(), ct)
    assert _deps(ct) == {'pdfjs-dist': '4.10.38'}
    assert any('pdfjs-dist@4.10.38 (rubber-sheet)' in ln for ln in log)
    pkg = json.loads((ct / 'app' / 'package.json').read_text())
    assert pkg['scripts']['lint'] == 'eslint --config eslint.config.js ./src/ ./public/'   # #252 too
    assert (ct / 'app' / 'package.json').read_text().startswith('{\n    "name"')            # 4-space kept


def test_existing_deps_are_kept_and_sorted(tmp_path):
    ct = _tree(tmp_path)
    pkg = json.loads(APP_PKG)
    pkg['dependencies'] = {'maplibre-gl': '^5.1.0', 'vue': '^3.5.26'}
    (ct / 'app' / 'package.json').write_text(json.dumps(pkg, indent=4) + '\n')
    _git(ct, 'commit', '-qam', 'deps')
    (_rubber_sheet(ct) / 'index.ts').write_text("import { ref } from 'vue';\nexport default {};\n")
    _run(_load(), ct)
    assert list(_deps(ct).items()) == [('maplibre-gl', '^5.1.0'), ('pdfjs-dist', '4.10.38'),
                                       ('vue', '^3.5.26')]


def test_already_present_is_a_noop(tmp_path):
    ct = _tree(tmp_path)
    _rubber_sheet(ct)
    ns = _load()
    _run(ns, ct)
    before = (ct / 'app' / 'package.json').read_text()
    assert _run(ns, ct) == []
    assert (ct / 'app' / 'package.json').read_text() == before


def test_hoisted_transitive_dep_is_not_added(tmp_path):
    ct = _tree(tmp_path)
    (ct / 'app' / 'package-lock.json').write_text(json.dumps({'packages': {
        '': {}, 'node_modules/pdfjs-dist': {'version': '4.10.38'}}}))
    _rubber_sheet(ct)
    _run(_load(), ct)
    assert 'pdfjs-dist' not in _deps(ct)


def test_undeclared_local_type_only_and_file_specs_are_skipped(tmp_path):
    ct = _tree(tmp_path)
    p = ct / 'app' / 'plugins' / 'odd'
    p.mkdir()
    (p / 'package.json').write_text(json.dumps({'devDependencies': {
        '@tak-ps/cloudtak': 'file:../../../CloudTAK/app', 'only-types': '^1.0.0',
        'evil': '1.0.0 && curl x', 'node:fs': '1.0.0'}}))
    (p / 'index.ts').write_text("import { a } from '@tak-ps/cloudtak/src/x';\n"
                                "import type { T } from 'only-types';\nimport 'evil';\n"
                                "import fs from 'node:fs';\nimport { y } from 'not-declared';\n")
    _run(_load(), ct)
    assert _deps(ct) == {}


def test_sidecar_projects_and_tests_are_not_scanned(tmp_path):
    ct = _tree(tmp_path)
    p = _rubber_sheet(ct)
    (p / 'package.json').write_text(json.dumps({'devDependencies': {
        'pdfjs-dist': '4.10.38', 'express': '^4.21.0', 'jsdom': '^25.0.0'}}))
    (p / 'service').mkdir()
    (p / 'service' / 'package.json').write_text(json.dumps({'dependencies': {'express': '^4.21.0'}}))
    (p / 'service' / 'server.ts').write_text("import express from 'express';\n")
    (p / 'test').mkdir()
    (p / 'test' / 'a.ts').write_text("import { JSDOM } from 'jsdom';\n")
    (p / 'lib' / 'b.spec.ts').write_text("import { JSDOM } from 'jsdom';\n")
    _run(_load(), ct)
    assert _deps(ct) == {'pdfjs-dist': '4.10.38'}


def test_our_own_plugins_are_not_scanned(tmp_path):
    ct = _tree(tmp_path, ('taksim',))
    d = ct / 'app' / 'plugins' / 'taksim'
    (d / 'package.json').write_text(json.dumps({'dependencies': {'leftpad': '1.0.0'}}))
    (d / 'index.ts').write_text("import l from 'leftpad';\n")
    assert _run(_load(), ct) == []
    assert (ct / 'app' / 'package.json').read_text() == APP_PKG


def test_vite_hint_prints_the_cause_and_the_plugin():
    # verbatim from a 13.113.0 + Rubber Sheet build with package.json reset (test6)
    out = _text(['#31 261.0 error during build:',
                 '#31 261.0 Build failed with 1 error:',
                 '#31 261.0 ',
                 '#31 261.0 Error: [vite]: Rolldown failed to resolve import '
                 '"pdfjs-dist/legacy/build/pdf.mjs" from '
                 '"/home/etl/app/plugins/rubber-sheet/lib/pdf-render.ts".', STEP_APP])
    assert 'Likely cause: the CloudTAK web app build (vite) failed.' in out
    assert '  Error: [vite]: Rolldown failed to resolve import "pdfjs-dist/legacy/build/pdf.mjs"' in out
    assert 'plugin folder rubber-sheet (app/plugins/)' in out
    assert 'Build failed with 1 error' not in out


def test_vite_hint_does_not_reach_far_past_the_error():
    out = _text(['#31 261.0 error during build:'] + ['#31 261.0 '] * 8
                + ['#31 262.0 /home/etl/app/plugins/x/y.ts', STEP_APP])
    assert 'plugin folder' not in out and '/plugins/x/' not in out


def test_vite_hint_without_a_plugin_path_names_no_plugin():
    out = _text(['#57 111.1 error during build:', '#57 111.1 RangeError: x', STEP_APP])
    assert '  RangeError: x' in out and 'plugin folder' not in out
