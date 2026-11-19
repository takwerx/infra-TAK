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
"""GH #583: the marketplace shield must never fail silent on the api, and an Update that
fails on a lint error must not tell the operator to "just run Update again".

CloudTAK 13.124.0 moved the api lint from ESLint to OXLint. The shield's api arm only knew
ESLint, did nothing, and logged a line that read as if the plugins were shielded (the web
app arm had applied). GH #563 / #565 taught the arm OXLint (tests in
test_cloudtak_marketplace_shield_gh252.py); this file covers what GH #583 still asked for:

  * an api lint config the shield does not know is a visible warning, not a silent return;
  * the same when an ESLint config has no place to put the skip;
  * a failed OXLint build is named like a failed ESLint build (it prints "Found N warnings
    and M errors", not "✖ N problems");
  * the update-failed footer says "run Update again" only for failures a retry can cure.
"""

import ast
import json
import pathlib
import re

from test_cloudtak_marketplace_shield_gh252 import (
    API_ESLINT, API_OXLINTRC, _body, _const, _load, _run, _tree)

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
STEP_API = ('target api: failed to solve: process "/bin/sh -c npm run lint     && npm run build" '
            'did not complete successfully: exit code: 1')


# ---- the shield: no silent api arm -------------------------------------------------------

def test_api_with_no_known_lint_config_warns(tmp_path):
    ct = _tree(tmp_path, ('replay',))
    (ct / 'api' / 'eslint.config.js').unlink()          # 13.124.0 deleted it; no .oxlintrc.json
    log = _run(_load(), ct)
    warn = [ln for ln in log if 'api' in ln and 'NOT' in ln]
    assert len(warn) == 1, log
    assert 'api/eslint.config.js' in warn[0] and 'api/.oxlintrc.json' in warn[0]
    # and the success line still names only what really changed
    assert any('app/package.json' in ln and 'api/' not in ln.split('(')[-1] for ln in log)


def test_api_with_no_known_lint_config_warns_even_when_the_app_needs_nothing(tmp_path):
    ct = _tree(tmp_path, ('replay',))
    (ct / 'api' / 'eslint.config.js').unlink()
    (ct / 'app' / 'package.json').write_text(json.dumps({'scripts': {'lint': 'eslint ./src/'}}))
    log = _run(_load(), ct)
    assert any('api' in ln and 'NOT' in ln for ln in log), log


def test_eslint_config_without_an_insertion_point_warns(tmp_path):
    ct = _tree(tmp_path, ('replay',))
    (ct / 'api' / 'eslint.config.js').write_text('module.exports = [];\n')   # old flat-config shape
    log = _run(_load(), ct)
    assert (ct / 'api' / 'eslint.config.js').read_text() == 'module.exports = [];\n'
    assert any('api/eslint.config.js' in ln and 'NOT' in ln for ln in log), log


def test_oxlint_config_that_is_not_json_also_says_the_api_is_not_covered(tmp_path):
    ct = _tree(tmp_path, ('udash',), oxlint=True)
    (ct / 'api' / '.oxlintrc.json').write_text('{ // a comment\n  "ignorePatterns": [] }\n')
    log = _run(_load(), ct)
    assert any('not plain JSON' in ln for ln in log)
    assert not any('no lint config' in ln for ln in log)          # one warning, not two


def test_covered_api_gives_no_warning(tmp_path):
    for ox in (False, True):
        ct = _tree(tmp_path / ('ox' if ox else 'es'), ('replay',), oxlint=ox)
        ns = _load()
        first = _run(ns, ct)
        assert not any('NOT' in ln for ln in first), first
        assert _run(ns, ct) == []                                  # second run: silent and clean


def test_covered_api_gives_no_warning_when_only_the_plugins_were_already_listed(tmp_path):
    ct = _tree(tmp_path, ('replay',), oxlint=True)
    cfg = ct / 'api' / '.oxlintrc.json'
    data = json.loads(API_OXLINTRC)
    data['ignorePatterns'] += ['stateless/routes/plugin-*.ts']
    cfg.write_text(json.dumps(data, indent=4) + '\n')
    (ct / 'app' / 'package.json').write_text(json.dumps({'scripts': {'lint': 'eslint ./src/'}}))
    assert not any('NOT' in ln for ln in _run(_load(), ct))


# ---- the build-failure hint: OXLint is named ---------------------------------------------

def _hint_text(lines):
    funcs = {'_cloudtak_build_failure_hint', '_cloudtak_plugin_owning_route'}
    tree = ast.parse(APP)
    parts = [ast.get_source_segment(APP, n) for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name in funcs]
    ns = {'re': re, 'os': __import__('os'), 'CLOUDTAK_PLUGINS': []}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return '\n'.join(ns['_cloudtak_build_failure_hint'](lines))


# shape of the reporter's log (GH #583, CloudTAK 13.123.2 -> 13.124.0)
OXLINT_FAIL = [
    '#58 [api stage-2 21/22] RUN npm run lint     && npm run build',
    '#58 > @tak-ps/CloudTAK.api@13.124.0 lint',
    '#58 > oxlint --type-aware index.ts common/ stateful/ stateless/ test/',
    '#58 7.1   x typescript-eslint(ban-ts-comment): Do not use "@ts-nocheck"',
    '#58 7.1    ,-[stateless/routes/replay.ts:1:1]',
    '#58 7.1   x typescript-eslint(await-thenable): Unexpected `await` of a non-Promise value.',
    '#58 7.1    ,-[stateless/lib/replay-player.ts:40:9]',
    '#58 7.1   x typescript-eslint(ban-ts-comment): Do not use "@ts-nocheck"',
    '#58 7.1    ,-[stateless/routes/plugin-qpd.ts:1:1]',
    '#58 Found 0 warnings and 17 errors.',
    STEP_API,
]


def test_oxlint_failure_is_named():
    out = _hint_text(OXLINT_FAIL)
    assert 'Likely cause: the CloudTAK lint check (OXLint) failed.' in out
    assert 'Found 0 warnings and 17 errors.' in out
    assert 'Failed step: npm run lint' in out


def test_oxlint_failure_names_the_files():
    out = _hint_text(OXLINT_FAIL)
    for f in ('stateless/routes/replay.ts', 'stateless/lib/replay-player.ts',
              'stateless/routes/plugin-qpd.ts'):
        assert f in out, out


def test_oxlint_clean_run_is_not_a_failure():
    out = _hint_text(['#58 > oxlint --type-aware index.ts', '#58 Found 3 warnings and 0 errors.',
                      '#31 140.0 error during build:'])
    assert 'OXLint' not in out and 'lint check' not in out
    assert 'vite' in out


def test_eslint_failure_still_says_eslint():
    out = _hint_text(['#31 30.2 ✖ 1 problem (1 error, 0 warnings)', STEP_API])
    assert 'the CloudTAK lint check (ESLint) failed.' in out


# ---- the footer: retry only when a retry can help ----------------------------------------

def _note():
    tree = ast.parse(APP)
    src = '\n\n'.join([_const('_CT_REPEATABLE_CAUSES')] + [
        ast.get_source_segment(APP, n) for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_update_failed_note'])
    ns = {}
    exec(compile(src, 'app.py', 'exec'), ns)

    def run(hints=None):
        log = []
        if hints is None:
            ns['_cloudtak_update_failed_note'](log.append)
        else:
            ns['_cloudtak_update_failed_note'](log.append, hints)
        return '\n'.join(log)
    return run


def test_footer_keeps_the_retry_line_when_nothing_is_known():
    out = _note()()
    assert 'still running on the previous build' in out
    assert 'just run Update again' in out


def test_footer_keeps_the_retry_line_for_a_network_failure():
    out = _note()(['', 'Likely cause: npm could not download packages (network).'])
    assert 'just run Update again' in out


def test_footer_does_not_send_a_lint_failure_in_a_circle():
    for cause in ('Likely cause: the CloudTAK lint check (OXLint) failed.',
                  'Likely cause: the CloudTAK lint check (ESLint) failed.',
                  'Likely cause: the CloudTAK TypeScript check failed.',
                  'Likely cause: a CloudTAK PLUGIN server route failed the TypeScript check,',
                  'Likely cause: the CloudTAK web app build (vite) failed.'):
        out = _note()(['', cause])
        assert 'just run Update again' not in out, cause
        assert 'same way' in out, cause
        assert 'still running on the previous build' in out


def test_the_build_failure_path_passes_its_hints_to_the_footer():
    body = _body('run_cloudtak_update')
    assert re.search(r'_hints\s*=\s*_cloudtak_build_failure_hint\(', body)
    assert '_cloudtak_update_failed_note(plog, _hints)' in body
