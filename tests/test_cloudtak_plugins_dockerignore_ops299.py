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


# ops #503: the Dispatcher plugin's own installer writes a Dockerfile.dockerignore that re-includes
# only its folder. infra-TAK used to leave it alone, so every other plugin dropped out of the next
# image build with no error.
DISPATCHER_MARK = '# managed by cloudtak-dispatcher-plugin install.sh'


def _dispatcher_file(base=UPSTREAM):
    return (DISPATCHER_MARK + "\n# copy of CloudTAK's .dockerignore + our re-include; re-run install.sh after "
            "updating CloudTAK\n" + base + "\n# re-include the Dispatcher web plugin\n!app/plugins/tak-dispatcher\n")


def test_dispatcher_written_file_is_replaced_so_other_plugins_stay_in_ops503(tmp_path):
    ct = _tree(tmp_path, ('tak-dispatcher', 'taksim', 'livewx-radar'))
    (ct / '.dockerignore').write_text(UPSTREAM)
    (ct / 'Dockerfile.dockerignore').write_text(_dispatcher_file())
    log = []
    _load()['_cloudtak_shield_foreign_plugins'](str(ct), log.append)
    out = (ct / 'Dockerfile.dockerignore').read_text()
    assert out.splitlines()[0].startswith('# infra-TAK (ops #299)')
    for n in ('tak-dispatcher', 'taksim', 'livewx-radar'):
        assert f'\n!app/plugins/{n}\n' in out
    assert any('Dispatcher' in m for m in log)


def test_after_replacing_it_stays_stable_ops503(tmp_path):
    ct = _tree(tmp_path, ('tak-dispatcher', 'taksim'))
    (ct / '.dockerignore').write_text(UPSTREAM)
    (ct / 'Dockerfile.dockerignore').write_text(_dispatcher_file())
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), lambda m: None)
    first = (ct / 'Dockerfile.dockerignore').read_text()
    log = []
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), log.append)
    assert log == [] and (ct / 'Dockerfile.dockerignore').read_text() == first


def test_dispatcher_file_goes_when_cloudtak_stops_excluding_plugins_ops503(tmp_path):
    ct = _tree(tmp_path, ('tak-dispatcher',))
    (ct / '.dockerignore').write_text(OLD)
    (ct / 'Dockerfile.dockerignore').write_text(_dispatcher_file(OLD))
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), lambda m: None)
    assert not (ct / 'Dockerfile.dockerignore').exists()


def test_operators_file_that_drops_plugins_is_kept_but_named_in_the_log_ops503(tmp_path):
    ct = _tree(tmp_path, ('tak-dispatcher', 'taksim'))
    (ct / '.dockerignore').write_text(UPSTREAM)
    mine = '# mine\napp/plugins/*\n!app/plugins/tak-dispatcher\n'
    (ct / 'Dockerfile.dockerignore').write_text(mine)
    log = []
    _load()['_cloudtak_keep_plugins_in_build'](str(ct), log.append)
    assert (ct / 'Dockerfile.dockerignore').read_text() == mine
    warn = ' '.join(log)
    assert 'Dockerfile.dockerignore' in warn and 'taksim' in warn and 'tak-dispatcher' not in warn


def test_operators_file_that_keeps_plugins_gets_no_warning_ops503(tmp_path):
    ct = _tree(tmp_path, ('tak-dispatcher', 'taksim'))
    (ct / '.dockerignore').write_text(UPSTREAM)
    for body in ('# mine\nfoo\n', '# mine\napp/plugins/*\n!app/plugins/tak-dispatcher\n!app/plugins/taksim\n',
                 '# mine\napp/plugins/*\n!app/plugins/*\n'):
        (ct / 'Dockerfile.dockerignore').write_text(body)
        log = []
        _load()['_cloudtak_keep_plugins_in_build'](str(ct), log.append)
        assert log == [], body
        assert (ct / 'Dockerfile.dockerignore').read_text() == body


def test_missing_menu_entry_warning_points_at_the_dockerignore_ops503():
    src = pathlib.Path(__file__).resolve().parent.parent.joinpath('app.py').read_text(encoding='utf-8')
    i = src.index("is NOT in the built web app")
    assert 'Dockerfile.dockerignore' in src[i:i + 900]


# ops #503 follow-up: TAK Portal's marketplace rebuilds CloudTAK through its own helper, which never
# runs the build shield, so a stale Dispatcher-written file used to wait for a console-driven build.
# Now the console puts it right on every start (and every update restarts the console).
def _startup_heal():
    from test_cloudtak_marketplace_shield_gh252 import _body
    ns = _load()
    exec(compile(_body('_cloudtak_heal_dockerignore_at_start'), 'app.py', 'exec'), ns)
    return ns['_cloudtak_heal_dockerignore_at_start']


def test_console_start_replaces_a_stale_dispatcher_file_without_a_build_ops503(tmp_path, capsys):
    ct = _tree(tmp_path, ('tak-dispatcher', 'taksim', 'livewx-radar'))
    (ct / '.dockerignore').write_text(UPSTREAM)
    (ct / 'Dockerfile.dockerignore').write_text(_dispatcher_file())
    _startup_heal()(str(ct))
    out = (ct / 'Dockerfile.dockerignore').read_text()
    assert out.splitlines()[0].startswith('# infra-TAK (ops #299)')
    for n in ('tak-dispatcher', 'taksim', 'livewx-radar'):
        assert f'\n!app/plugins/{n}\n' in out
    assert 'Startup self-heal' in capsys.readouterr().out


def test_console_start_is_quiet_on_a_clean_box_and_keeps_an_operators_file_ops503(tmp_path, capsys):
    ct = _tree(tmp_path, ('taksim',))
    (ct / '.dockerignore').write_text(UPSTREAM)
    heal = _startup_heal()
    heal(str(ct))
    first = (ct / 'Dockerfile.dockerignore').read_text()
    capsys.readouterr()
    heal(str(ct))
    assert (ct / 'Dockerfile.dockerignore').read_text() == first
    assert capsys.readouterr().out == ''
    (ct / 'Dockerfile.dockerignore').write_text('# mine\napp/plugins/*\n')
    heal(str(ct))
    assert (ct / 'Dockerfile.dockerignore').read_text() == '# mine\napp/plugins/*\n'


def test_console_start_with_no_cloudtak_folder_does_not_raise_ops503(tmp_path):
    _startup_heal()(str(tmp_path / 'missing'))


def test_startup_heal_runs_the_dockerignore_fix_before_the_other_cloudtak_heals_ops503():
    src = pathlib.Path(__file__).resolve().parent.parent.joinpath('app.py').read_text(encoding='utf-8')
    start = src[src.index('def _startup_heal_cloudtak_media_hls'):]
    body = start[:start.index('_startup_heal_cloudtak_media_hls()\n')]
    assert '_cloudtak_heal_dockerignore_at_start(_ct_dir)' in body
    assert body.index('_cloudtak_heal_dockerignore_at_start(') < body.index('_cloudtak_upload_limit_heal()')
