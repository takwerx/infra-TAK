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
"""ops #299: installed CloudTAK plugins stay in the image build.

CloudTAK main (after v13.116.0) added `app/plugins/*` to .dockerignore. We install plugins by
copying folders into app/plugins/, so the first release with that line would build fine and show
no plugin. Before every build the shield writes an untracked Dockerfile.dockerignore (BuildKit
reads it before .dockerignore) that re-includes each installed folder.
"""

import os
import pathlib

from test_cloudtak_marketplace_shield_gh252 import _load, _tree

UPSTREAM = (".git/\n**/node_modules/\n**/dist/\n**/coverage/\n**/*.dump\napi/data\napi/data-dev/\n"
            "app/dev-dist/\napp/ios/\napp/android/\napp/plugins/*\n!app/plugins/*.ts\n"
            "!app/plugins/README.md\n")
OLD = UPSTREAM.replace('app/plugins/*\n!app/plugins/*.ts\n!app/plugins/README.md\n', '')


def _go(tmp_path, plugins, ignore=UPSTREAM):
    ct = _tree(tmp_path, plugins)
    if ignore is not None:
        (ct / '.dockerignore').write_text(ignore)
    log = []
    _load()['_cloudtak_shield_foreign_plugins'](str(ct), log.append)
    return ct, log


def test_installed_plugins_are_reincluded(tmp_path):
    ct, log = _go(tmp_path, ('taksim', 'tak-dispatcher', 'udash'))
    out = (ct / 'Dockerfile.dockerignore').read_text()
    assert out.splitlines()[0].startswith('# infra-TAK (ops #299)')
    assert UPSTREAM in out
    for n in ('taksim', 'tak-dispatcher', 'udash'):
        assert f'\n!app/plugins/{n}\n' in out
        assert f'\napp/plugins/{n}/**/node_modules/\n' in out
    # re-includes come after the exclusion, or they would not win
    assert out.index('app/plugins/*\n') < out.index('!app/plugins/taksim')
    assert any('Dockerfile.dockerignore' in m for m in log)
    assert (ct / '.dockerignore').read_text() == UPSTREAM          # tracked-style file untouched


def test_second_run_is_a_noop(tmp_path):
    ct, _ = _go(tmp_path, ('taksim',))
    first = (ct / 'Dockerfile.dockerignore').read_text()
    log = []
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), log.append)
    assert log == [] and (ct / 'Dockerfile.dockerignore').read_text() == first


def test_old_cloudtak_without_the_exclusion_gets_no_file(tmp_path):
    ct, _ = _go(tmp_path, ('taksim',), ignore=OLD)
    assert not (ct / 'Dockerfile.dockerignore').exists()


def test_no_dockerignore_at_all_gets_no_file(tmp_path):
    ct, _ = _go(tmp_path, ('taksim',), ignore=None)
    assert not (ct / 'Dockerfile.dockerignore').exists()


def test_operators_own_file_is_left_alone(tmp_path):
    ct = _tree(tmp_path, ('taksim',))
    (ct / '.dockerignore').write_text(UPSTREAM)
    (ct / 'Dockerfile.dockerignore').write_text('# mine\nfoo\n')
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), lambda m: None)
    assert (ct / 'Dockerfile.dockerignore').read_text() == '# mine\nfoo\n'


def test_removed_plugin_drops_out_and_last_one_removes_the_file(tmp_path):
    ct, _ = _go(tmp_path, ('taksim', 'udash'))
    ns = _load()
    (ct / 'app' / 'plugins' / 'udash' / 'index.ts').unlink()
    (ct / 'app' / 'plugins' / 'udash').rmdir()
    ns['_cloudtak_keep_plugins_in_build'](str(ct), lambda m: None)
    out = (ct / 'Dockerfile.dockerignore').read_text()
    assert '!app/plugins/taksim' in out and 'udash' not in out
    (ct / 'app' / 'plugins' / 'taksim' / 'index.ts').unlink()
    (ct / 'app' / 'plugins' / 'taksim').rmdir()
    ns['_cloudtak_keep_plugins_in_build'](str(ct), lambda m: None)
    assert not (ct / 'Dockerfile.dockerignore').exists()


def test_odd_folder_names_never_become_patterns(tmp_path):
    ct = _tree(tmp_path, ('taksim',))
    (ct / '.dockerignore').write_text(UPSTREAM)
    (ct / 'app' / 'plugins' / 'a b').mkdir()
    (ct / 'app' / 'plugins' / '!x').mkdir()
    (ct / 'app' / 'plugins' / '.hidden').mkdir()
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), lambda m: None)
    out = (ct / 'Dockerfile.dockerignore').read_text()
    assert '!app/plugins/taksim' in out
    for bad in ('a b', '!x', '.hidden'):
        assert bad not in out.split(UPSTREAM)[1]


def test_legacy_api_web_layout_is_not_touched(tmp_path):
    ct = _tree(tmp_path)
    (ct / '.dockerignore').write_text(UPSTREAM)
    (ct / 'app').rename(ct / 'oldapp')
    (ct / 'api' / 'web' / 'plugins' / 'taksim').mkdir(parents=True)
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), lambda m: None)
    assert not (ct / 'Dockerfile.dockerignore').exists()


def test_never_raises(tmp_path):
    log = []
    _load()['_cloudtak_keep_plugins_in_build'](str(tmp_path / 'missing'), log.append)
    assert log == []


def test_runs_inside_the_shield_that_every_build_calls():
    import ast
    src = pathlib.Path(__file__).resolve().parent.parent.joinpath('app.py').read_text(encoding='utf-8')
    node = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef)
                and n.name == '_cloudtak_shield_foreign_plugins')
    assert '_cloudtak_keep_plugins_in_build(ct_dir, plog)' in ast.get_source_segment(src, node)
    assert os.path.basename(__file__)
