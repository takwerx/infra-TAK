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
"""ops #301: the nightly "is each plugin's menu entry in the built CloudTAK" check.

CloudTAK 13.102.0 moved its web app to app/; the Dispatcher's install.sh kept copying into
api/web/, said "installed", and the plugin never reached the build (ops #297). The nightly
(.github/workflows/cloudtak-plugins-nightly.yml) builds CloudTAK with every plugin and runs
.github/ci/cloudtak_plugins/bundle_check.py on the result. These tests cover the checker itself
and keep its plugin list in step with the catalog in app.py.
"""

import ast
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
CI = REPO / '.github' / 'ci' / 'cloudtak_plugins'
WORKFLOW = REPO / '.github' / 'workflows' / 'cloudtak-plugins-nightly.yml'

_spec = importlib.util.spec_from_file_location('bundle_check', CI / 'bundle_check.py')
bc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bc)


def _catalog():
    """{key: install_dir} of CLOUDTAK_PLUGINS in app.py, without importing the 75,000-line app."""
    tree = ast.parse((REPO / 'app.py').read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == 'CLOUDTAK_PLUGINS' for t in node.targets):
            out = {}
            for d in node.value.elts:
                vals = {k.value: v.value for k, v in zip(d.keys, d.values)
                        if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)}
                out[vals['key']] = vals['install_dir']
            return out
    raise AssertionError('CLOUDTAK_PLUGINS not found in app.py')


# ── the plugin list ──────────────────────────────────────────────────────────────

def test_every_catalog_plugin_is_in_the_nightly_manifest():
    by_key = {p['key']: p for p in bc.load_manifest()}
    for key, install_dir in _catalog().items():
        assert key in by_key, (f"plugin '{key}' is in CLOUDTAK_PLUGINS but not in "
                               ".github/ci/cloudtak_plugins/manifest.json: the nightly would never check it")
        assert by_key[key]['install_dir'] == install_dir
        assert by_key[key]['in_catalog'] is True, f"manifest says '{key}' is not in the catalog, but it is"


def test_manifest_only_calls_catalog_plugins_in_catalog():
    cat = _catalog()
    for p in bc.load_manifest():
        if p['in_catalog']:
            assert p['key'] in cat, (f"manifest marks '{p['key']}' in_catalog, but app.py no longer lists it: "
                                     "set in_catalog to false (it stays in the nightly if TAK Portal still installs it)")


def test_manifest_entries_say_where_the_plugin_comes_from():
    keys = set()
    for p in bc.load_manifest():
        assert p['key'] not in keys
        keys.add(p['key'])
        assert bool(p.get('repo')) != bool(p.get('local_path')), p['key']
        if p.get('local_path'):
            assert (REPO / p['local_path']).is_dir()
            assert (REPO / p['local_path'] / 'index.ts').is_file()
        else:
            assert p['repo'].startswith('https://github.com/')


def test_local_simulator_panel_registers_a_menu_entry():
    p = next(x for x in bc.load_manifest() if x['key'] == 'taksim')
    menu = bc.derive_menu(REPO / p['local_path'])
    assert menu and menu[0]['label'] and menu[0]['key']


def test_the_shield_functions_are_still_in_app_py():
    ns = bc.load_shield(catalog=bc.load_manifest())
    for name in bc.SHIELD_FUNCS:
        assert callable(ns[name])


# ── reading the menu entry from a plugin's source ────────────────────────────────

def _src(tmp_path, text, name='index.ts'):
    d = tmp_path / 'plugin'
    d.mkdir(exist_ok=True)
    (d / name).write_text(text)
    return d


def test_constants_and_literals_are_both_read(tmp_path):
    d = _src(tmp_path, """
const MENU_KEY = 'plugin-ping';
export default class P {
    async enable() {
        this.api.menu.add({
            key: MENU_KEY,
            label: 'Cell Ping / RTT',
            route: 'home-menu-ping',
            tooltip: "Manual cell-ping & RTT entry",
            icon: markRaw(IconX),
        });
    }
}
""")
    assert bc.derive_menu(d) == [{'key': 'plugin-ping', 'label': 'Cell Ping / RTT', 'route': 'home-menu-ping',
                                  'tooltip': 'Manual cell-ping & RTT entry', 'file': 'index.ts'}]


def test_a_comment_that_mentions_menu_add_is_not_an_entry(tmp_path):
    d = _src(tmp_path, """
/* PluginAPI.menu.add() guards the route. {not an object} */
export default class P { async enable() { this.api.menu.add({ key: 'print', label: 'Print' }); } }
""")
    assert [e['key'] for e in bc.derive_menu(d)] == ['print']


def test_no_menu_add_is_reported_not_skipped(tmp_path):
    d = _src(tmp_path, 'export default class P { async enable() {} }\n')
    out = bc.plugin_expectation({'key': 'x', 'name': 'X', 'install_dir': 'x'}, d)
    assert out['menu'] == [] and 'menu.add' in out['error']


def test_tests_and_node_modules_are_not_read(tmp_path):
    d = _src(tmp_path, 'export default class P {}\n')
    (d / 'node_modules').mkdir()
    (d / 'node_modules' / 'x.ts').write_text("api.menu.add({ key: 'a', label: 'B' })")
    assert bc.derive_menu(d) == []


# ── looking for it in the built app ──────────────────────────────────────────────

DISPATCHER = {'key': 'plugin-tak-dispatcher', 'label': 'Dispatcher', 'tooltip': 'CloudTAK Dispatcher',
              'description': 'Dispatch incidents on the map — works standalone', 'route': 'home-menu-tak-dispatcher'}
BUILT = ('const a={key:"plugin-tak-dispatcher",label:"Dispatcher",route:"home-menu-tak-dispatcher",'
         'tooltip:"CloudTAK Dispatcher",description:"Dispatch incidents on the map \\u2014 works standalone",icon:s};')


def _dist(tmp_path, files):
    dist = tmp_path / 'dist'
    (dist / 'assets').mkdir(parents=True)
    for name, text in files.items():
        (dist / 'assets' / name).write_text(text)
    return dist


def _expect(*menus):
    return {'plugins': [{'key': f'p{i}', 'name': f'Plugin {i}', 'menu': [m]} for i, m in enumerate(menus)]}


def test_menu_entry_in_the_bundle_passes(tmp_path):
    lines, problems = bc.verify_bundle(_expect(DISPATCHER), _dist(tmp_path, {'index-abc.js': BUILT}))
    assert problems == 0 and lines[0].startswith('ok')


def test_plugin_left_out_of_the_build_fails(tmp_path):
    """The ops #297 case: the app built fine and has everything but the plugin."""
    dist = _dist(tmp_path, {'index-abc.js': 'const core={key:"settings",label:"Settings"};export{core};'})
    lines, problems = bc.verify_bundle(_expect(DISPATCHER), dist)
    assert problems == 1 and lines[0].startswith('FAIL') and 'NOT in the built app' in lines[0]


def test_a_common_label_elsewhere_is_not_enough(tmp_path):
    other = 'const x={key:"settings",label:"Dispatcher",route:"settings"};'
    _lines, problems = bc.verify_bundle(_expect(DISPATCHER), _dist(tmp_path, {'a.js': other}))
    assert problems == 1


def test_key_and_label_in_different_chunks_fail(tmp_path):
    files = {'a.js': 'const x={label:"Dispatcher"};', 'b.js': 'const y="plugin-tak-dispatcher";'}
    _lines, problems = bc.verify_bundle(_expect(DISPATCHER), _dist(tmp_path, files))
    assert problems == 1


def test_minified_constant_key_still_passes(tmp_path):
    built = ('const n="plugin-ping";class P{enable(){this.api.menu.add({key:n,label:"Cell Ping / RTT",'
             'route:"home-menu-ping"})}}')
    entry = {'key': 'plugin-ping', 'label': 'Cell Ping / RTT', 'route': 'home-menu-ping'}
    _lines, problems = bc.verify_bundle(_expect(entry), _dist(tmp_path, {'a.js': built}))
    assert problems == 0


def test_an_unreadable_plugin_is_a_failure(tmp_path):
    expect = {'plugins': [{'key': 'x', 'name': 'X', 'menu': [], 'error': 'could not read a menu.add'}]}
    lines, problems = bc.verify_bundle(expect, _dist(tmp_path, {'a.js': 'x'}))
    assert problems == 1 and 'could not read' in lines[0]


def test_no_javascript_at_all_is_a_failure(tmp_path):
    empty = tmp_path / 'dist'
    empty.mkdir()
    _lines, problems = bc.verify_bundle(_expect(DISPATCHER), empty)
    assert problems == 1


def test_old_installer_layout_is_what_the_check_exists_for(tmp_path):
    """install.sh from before the fix copies to api/web/plugins; CloudTAK 13.102+ builds app/."""
    ct = tmp_path / 'CloudTAK'
    (ct / 'app' / 'src').mkdir(parents=True)
    (ct / 'api' / 'web' / 'plugins' / 'tak-dispatcher').mkdir(parents=True)
    assert bc.web_dir(ct) == ct / 'app'
    assert not (bc.web_dir(ct) / 'plugins' / 'tak-dispatcher').exists()
    old = tmp_path / 'old'
    (old / 'api' / 'web').mkdir(parents=True)
    assert bc.web_dir(old) == old / 'api' / 'web'


# ── the workflow ─────────────────────────────────────────────────────────────────

def test_workflow_has_the_canary_and_both_cloudtak_versions():
    text = WORKFLOW.read_text(encoding='utf-8')
    assert 'schedule:' in text and 'cron:' in text
    assert 'ct: release' in text and 'ct: main' in text
    assert 'expect_red: true' in text, 'the canary (old installer, must be caught) is gone'
    assert 'bundle_check.py' in text
    for line in text.splitlines():
        if line.strip().startswith('- uses:'):
            assert '@' in line and len(line.split('@')[1].split()[0]) == 40, f'unpinned action: {line.strip()}'


def test_workflow_never_runs_on_the_self_hosted_runners():
    runs_on = [ln for ln in WORKFLOW.read_text(encoding='utf-8').splitlines() if ln.strip().startswith('runs-on:')]
    assert runs_on and all('ubuntu-24.04' in ln and 'self-hosted' not in ln for ln in runs_on)


# ── infra-TAK's own look at the app it just built ────────────────────────────────

APP_SRC = (REPO / 'app.py').read_text(encoding='utf-8')


def _app_ns(compose_at):
    """The ops #301 functions from app.py, run against a fake `docker compose exec`."""
    import json as _json
    import os as _os
    import re as _re
    tree = ast.parse(APP_SRC)
    want_funcs = ('_cloudtak_web_dir', '_cloudtak_plugins_dir', '_cloudtak_plugin_menu_entries',
                  '_cloudtak_verify_plugins_in_app')
    want_consts = ('_CT_MENU_ADD_RE', '_CT_JS_STR', '_CT_JS_CONST_RE', '_CT_APP_DIST', '_CT_IN_APP_SH',
                   '_CT_PLUGIN_DIR_RE', '_CT_JS_PLAIN_RE')
    parts = []
    for node in tree.body:
        name = (node.name if isinstance(node, ast.FunctionDef)
                else node.targets[0].id if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) else None)
        if name in want_funcs + want_consts:
            parts.append(ast.get_source_segment(APP_SRC, node))
    ns = {'os': _os, 're': _re, 'json': _json, '_cloudtak_compose_at': compose_at}
    exec(compile('\n\n'.join(parts), 'app.py', 'exec'), ns)
    return ns


def _ct_with_plugin(tmp_path, name='ping', source=None):
    ct = tmp_path / 'CloudTAK'
    (ct / 'app' / 'src').mkdir(parents=True)
    d = ct / 'app' / 'plugins' / name
    d.mkdir(parents=True)
    (d / 'index.ts').write_text(source or "const MENU_KEY = 'plugin-ping';\n"
                                "api.menu.add({ key: MENU_KEY, label: 'Cell Ping / RTT' });\n")
    return ct


def test_infratak_reads_the_menu_entry_from_plugin_source(tmp_path):
    ct = _ct_with_plugin(tmp_path)
    ns = _app_ns(lambda *a, **k: (0, 'FOUND\n'))
    assert ns['_cloudtak_plugin_menu_entries'](str(ct / 'app' / 'plugins' / 'ping')) == [('plugin-ping', 'Cell Ping / RTT')]


def test_infratak_says_nothing_is_wrong_when_the_menu_entry_is_in_the_app(tmp_path):
    ct, log, calls = _ct_with_plugin(tmp_path), [], []

    def fake(ct_dir, args, remote_cfg=None, timeout=0):
        calls.append(args)
        return 0, 'FOUND\n'
    assert _app_ns(fake)['_cloudtak_verify_plugins_in_app'](str(ct), log.append) is True
    assert calls[0][:5] == ['exec', '-T', 'api', 'sh', '-c']
    assert calls[0][-3:] == ['plugin-ping', 'Cell Ping / RTT', '/home/etl/app/dist']
    assert any('✓ ping' in m for m in log)


def test_infratak_warns_when_the_menu_entry_is_not_in_the_app(tmp_path):
    """The ops #297 case: the folder was copied, the build ignored it."""
    ct, log = _ct_with_plugin(tmp_path), []
    ns = _app_ns(lambda *a, **k: (0, 'MISSING\n'))
    assert ns['_cloudtak_verify_plugins_in_app'](str(ct), log.append) is False
    assert any('NOT in the built web app' in m for m in log)


def test_infratak_does_not_claim_anything_when_it_cannot_look(tmp_path):
    ct, log = _ct_with_plugin(tmp_path), []
    for rc, out in ((1, 'service "api" is not running'), (0, 'NODIST\n')):
        assert _app_ns(lambda *a, **k: (rc, out))['_cloudtak_verify_plugins_in_app'](str(ct), log.append) is None


def test_infratak_only_checks_the_plugin_it_just_installed(tmp_path):
    ct = _ct_with_plugin(tmp_path)
    other = ct / 'app' / 'plugins' / 'other'
    other.mkdir()
    (other / 'index.ts').write_text("api.menu.add({ key: 'o', label: 'Other' });\n")
    seen = []

    def fake(ct_dir, args, remote_cfg=None, timeout=0):
        seen.append(args[-2])
        return 0, 'FOUND\n'
    _app_ns(fake)['_cloudtak_verify_plugins_in_app'](str(ct), lambda m: None, only=['other'])
    assert seen == ['Other']


def test_the_check_runs_after_a_plugin_rebuild_and_after_a_cloudtak_update():
    assert "_cloudtak_verify_plugins_in_app(ct_dir, plog, only=[plugin['install_dir']])" in APP_SRC
    assert '_cloudtak_verify_plugins_in_app(cloudtak_dir, plog)' in APP_SRC


@pytest.mark.parametrize('bundle', [
    'const G=`plugin-ping`;a.menu.add({key:G,label:`Cell Ping / RTT`,route:N});',      # rolldown: backticks
    'const G="plugin-ping";a.menu.add({key:G,label:"Cell Ping / RTT",route:N});',      # esbuild: double quotes
    "a.menu.add({key:'plugin-ping',label:'Cell Ping / RTT'});",
])
def test_the_shell_look_inside_the_image_reads_every_quote_style(tmp_path, bundle):
    """The snippet the console runs inside the api container, on a stand-in for /home/etl/app/dist.
    The nightly runs the same snippet in the real image (the first version only knew double quotes
    and the real CloudTAK build writes backticks)."""
    import subprocess
    sh = bc.load_app_consts(('_CT_IN_APP_SH',))['_CT_IN_APP_SH']
    dist = tmp_path / 'dist'
    (dist / 'assets').mkdir(parents=True)
    (dist / 'assets' / 'main-1.js').write_text(bundle)
    (dist / 'assets' / 'other.js').write_text('x({key:"o",label:"Other"})')

    def look(key, label):
        return subprocess.run(['sh', '-c', sh, '_', key, label, str(dist)], capture_output=True, text=True).stdout.strip()
    assert look('plugin-ping', 'Cell Ping / RTT') == 'FOUND'
    assert look('plugin-ping', 'Other') == 'MISSING'                  # key and label in different files
    assert look('nope', 'Cell Ping / RTT') == 'MISSING'
    assert subprocess.run(['sh', '-c', sh, '_', 'a', 'b', str(tmp_path / 'none')], capture_output=True, text=True).stdout.strip() == 'NODIST'
