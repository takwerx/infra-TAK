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
"""ops #1414: the nightly checks a plugin's main action, not only its menu entry.

The menu entry loading does not mean the plugin works. CloudTAK 14.0.0 removed routes (for
example GET /api/basemap/:basemapid/tiles), changed chat and location sharing, and a plugin that
calls a route that is gone still shows its menu and then fails when the user clicks it.
.github/ci/cloudtak_plugins/bundle_check.py now reads every CloudTAK API call each plugin's browser
code makes and checks that CloudTAK's own source (plus the routes the plugin ships) still defines
that route with that method. These tests plant the 14.0.0 removal and the other shapes of call the
plugins use, so the check cannot go blind without a test failing.
"""

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


# ── a small CloudTAK tree: the route lines are copied from real CloudTAK (13.128.0 and 14.0.0) ──

ROUTES_13 = {
    'api/stateless/routes/basemap.ts': ["/basemap", "/basemap/:basemapid/tiles"],
    'api/stateless/routes/core-event.ts': ["/core/event", "/core/event/:event"],
    'api/stateless/routes/marti.ts': ["/marti/group", "/marti/api/contacts/all"],
    'api/stateless/routes/marti-mission.ts': ["/marti/missions/:name/log"],
    'api/stateful/routes/profile.ts': ["/profile"],
}
# 14.0.0 removed the basemap tiles route (and search reverse, fonts); everything else here stayed.
ROUTES_14 = {k: [r for r in v if r != '/basemap/:basemapid/tiles'] for k, v in ROUTES_13.items()}


def _write(root, rel, text):
    f = pathlib.Path(root, rel)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding='utf-8')


def _cloudtak(tmp_path, name, routes):
    root = tmp_path / name
    for rel, paths in routes.items():
        body = ''.join(f"    await schema.get('{p}', {{ name: 'x' }}, async (req, res) => {{}});\n" for p in paths)
        _write(root, rel, "export default async function router(schema: Schema) {\n" + body + "}\n")
    return root


def _plugin(tmp_path, files):
    root = tmp_path / 'plugin'
    for rel, text in files.items():
        _write(root, rel, text)
    return root


def _check(plugin_root, ct_root, **extra):
    calls, unread = bc.derive_calls(plugin_root)
    entry = {'name': 'Fake', 'key': 'fake', 'calls': calls, 'unread': unread, **extra}
    return bc.verify_routes({'plugins': [entry]}, bc.cloudtak_routes(ct_root))


TILES_PLUGIN = {
    'lib/tiles.ts': (
        "import { std } from '../../../src/std.ts';\n"
        "export async function tiles(id: number) { return await std(`/api/basemap/${id}/tiles`); }\n"
        "export async function list() { return await std('/api/basemap?limit=10'); }\n"),
}


# ── the proof: a route the plugin calls is gone in 14.0.0 ───────────────────────

def test_a_route_the_plugin_calls_that_14_removed_is_red(tmp_path):
    plugin = _plugin(tmp_path, TILES_PLUGIN)
    lines, problems = _check(plugin, _cloudtak(tmp_path, 'ct14', ROUTES_14))
    assert problems == 1
    fail = [ln for ln in lines if ln.startswith('FAIL')]
    assert len(fail) == 1 and 'GET /api/basemap/:p/tiles' in fail[0] and 'tiles.ts:2' in fail[0]


def test_the_same_plugin_is_green_on_the_cloudtak_that_still_has_the_route(tmp_path):
    plugin = _plugin(tmp_path, TILES_PLUGIN)
    lines, problems = _check(plugin, _cloudtak(tmp_path, 'ct13', ROUTES_13))
    assert problems == 0 and lines[0].startswith('ok') and 'all 2 CloudTAK API calls' in lines[0]


def test_a_cloudtak_with_no_readable_routes_is_a_failure_not_a_pass(tmp_path):
    plugin = _plugin(tmp_path, TILES_PLUGIN)
    empty = tmp_path / 'empty'
    empty.mkdir()
    lines, problems = _check(plugin, empty)
    assert problems == 1 and lines[0].startswith('FAIL') and 'no routes found' in lines[0]


def test_wrong_method_is_red_and_says_which_one_cloudtak_has(tmp_path):
    plugin = _plugin(tmp_path, {'lib/a.ts': "await std('/api/core/event/abc', { method: 'DELETE' });\n"})
    lines, problems = _check(plugin, _cloudtak(tmp_path, 'ct', ROUTES_14))
    assert problems == 1 and 'has GET for this path but not DELETE' in lines[0]


def test_a_value_in_the_path_matches_a_route_parameter(tmp_path):
    plugin = _plugin(tmp_path, {'lib/a.ts': (
        "await std(`/api/core/event/${encodeURIComponent(known)}`, { method: 'GET' });\n"
        "await std(`/api/marti/missions/${encodeURIComponent(name)}/log`);\n")})
    assert _check(plugin, _cloudtak(tmp_path, 'ct', ROUTES_14))[1] == 0


# ── the shapes of call the four plugins really use ──────────────────────────────

def test_query_string_and_a_ternary_query_are_not_part_of_the_path(tmp_path):
    plugin = _plugin(tmp_path, {'lib/a.ts': (
        "await std(`/api/core/event${fresh ? '?fresh=1' : ''}`, { method: 'GET' });\n"
        "await std(`/api/profile?${qs.toString()}`);\n")})
    calls, _ = bc.derive_calls(plugin)
    assert sorted(c['path'] for c in calls) == ['/api/core/event', '/api/profile']
    assert not any(c['prefix'] for c in calls)


def test_a_constant_base_is_resolved_and_a_removed_route_under_it_is_red(tmp_path):
    plugin = _plugin(tmp_path, {'lib/c.ts': (
        "const BASE = '/api/marti';\n"
        "export const a = () => std(`${BASE}/group`);\n"
        "export const b = () => std(`${BASE}/gone`, { method: 'POST' });\n")})
    lines, problems = _check(plugin, _cloudtak(tmp_path, 'ct', ROUTES_14))
    assert problems == 1 and 'POST /api/marti/gone' in [ln for ln in lines if ln.startswith('FAIL')][0]


def test_base_plus_a_value_added_at_run_time_checks_the_prefix(tmp_path):
    src = {'lib/t.ts': ("const BASE = '/api/marti';\n"
                        "async function call(path: string) { return await std(`${BASE}${path}`, { method }); }\n")}
    calls, _ = bc.derive_calls(_plugin(tmp_path, src))
    assert [(c['path'], c['prefix']) for c in calls if c['file'] == 'lib/t.ts' and c['line'] == 2] == [('/api/marti', True)]
    assert _check(_plugin(tmp_path, src), _cloudtak(tmp_path, 'ct', ROUTES_14))[1] == 0
    # the whole family gone: red
    gone = {'api/stateless/routes/x.ts': ['/other']}
    assert _check(_plugin(tmp_path, src), _cloudtak(tmp_path, 'ct2', gone))[1] == 1


def test_the_typed_client_and_a_plain_fetch_on_the_server_address_are_read(tmp_path):
    plugin = _plugin(tmp_path, {'lib/s.ts': (
        "const r = await server.GET('/api/basemap/{:basemapid}/tiles', { params: { path: { ':basemapid': id } } });\n"
        "const res = await fetch(`${String(serverUrl).replace(/\\/$/, '')}/api/marti/missions/${guid}/log`, { headers });\n")})
    calls, _ = bc.derive_calls(plugin)
    by = {c['path']: c for c in calls}
    assert by['/api/basemap/:p/tiles']['method'] == 'get'
    assert by['/api/marti/missions/:p/log']['method'] == '*'
    assert _check(plugin, _cloudtak(tmp_path, 'ct14', ROUTES_14))[1] == 1      # the typed call hits the 14.0.0 removal
    assert _check(plugin, _cloudtak(tmp_path, 'ct13', ROUTES_13))[1] == 0


def test_stdurl_only_builds_an_address_so_it_matches_any_method(tmp_path):
    plugin = _plugin(tmp_path, {'lib/u.ts': (
        "const url = stdurl(`/api/marti/missions/${guid}/log`);\n"
        "await fetch(url, { method: 'POST' });\n")})
    calls, _ = bc.derive_calls(plugin)
    assert [(c['method'], c['path']) for c in calls] == [('*', '/api/marti/missions/:p/log')]
    # the route has only a GET in this tree: a call that may be a POST is not called wrong
    assert _check(plugin, _cloudtak(tmp_path, 'ct', ROUTES_14))[1] == 0


def test_comments_other_hosts_and_non_api_strings_are_not_calls(tmp_path):
    plugin = _plugin(tmp_path, {'lib/n.ts': (
        "// std('/api/removed/in/a/comment') and GET /api/also/not/a/call\n"
        "/* const x = '/api/block/comment'; */\n"
        "const doc = 'https://example.com/api/other/site';\n"
        "const tile = 'https://tiles.example.com/tiles/basemap';\n"
        "await std('/api/profile');\n")})
    calls, _ = bc.derive_calls(plugin)
    assert [c['path'] for c in calls] == ['/api/profile']


def test_tests_and_node_modules_are_not_read(tmp_path):
    plugin = _plugin(tmp_path, {
        'index.ts': "await std('/api/profile');\n",
        'test/x.test.ts': "await std('/api/only/in/a/test');\n",
        'node_modules/p/i.js': "std('/api/in/node/modules');\n"})
    assert [c['path'] for c in bc.derive_calls(plugin)[0]] == ['/api/profile']


def test_a_variable_path_is_reported_never_silently_skipped(tmp_path):
    plugin = _plugin(tmp_path, {'lib/h.ts': "export const f = (r) => std(r.url);\nawait std('/api/profile');\n"})
    lines, problems = _check(plugin, _cloudtak(tmp_path, 'ct', ROUTES_14))
    assert problems == 0
    assert any(ln.startswith('note') and 'pass a variable' in ln and 'lib/h.ts' in ln for ln in lines)


def test_a_plugin_with_no_call_of_its_own_says_so(tmp_path):
    plugin = _plugin(tmp_path, {'index.ts': "export default class P {}\n"})
    lines, problems = _check(plugin, _cloudtak(tmp_path, 'ct', ROUTES_14))
    assert problems == 0 and 'makes no CloudTAK API call' in lines[0]


# ── routes the plugin ships count; a tolerated gap is shown, a new one is red ───

def test_routes_the_plugin_installs_into_cloudtak_count(tmp_path):
    plugin = _plugin(tmp_path, {'lib/p.ts': "await std('/api/myplugin/events', { method: 'POST' });\n"})
    ct = _cloudtak(tmp_path, 'ct', ROUTES_14)
    assert _check(plugin, ct)[1] == 1
    _write(ct, 'api/stateless/routes/plugin-my.ts',
           "export default async function router(schema) {\n    await schema.post('/myplugin/events', {}, async () => {});\n}\n")
    assert _check(plugin, ct)[1] == 0


def test_a_tolerated_gap_is_shown_as_known_and_a_new_gap_next_to_it_is_red(tmp_path):
    plugin = _plugin(tmp_path, {'lib/t.ts': TILES_PLUGIN['lib/tiles.ts'] + "await std('/api/gone/too');\n"})
    allow = [{'method': 'get', 'path': '/api/basemap/:p/tiles', 'why': 'plugin catches the failure (test)'}]
    lines, problems = _check(plugin, _cloudtak(tmp_path, 'ct', ROUTES_14), allow_missing=allow)
    assert problems == 1
    assert any(ln.startswith('known') and 'tolerated: plugin catches the failure (test)' in ln for ln in lines)
    assert [ln for ln in lines if ln.startswith('FAIL')][0].count('/api/gone/too') == 1


def test_a_private_plugin_is_listed_as_skipped_never_silently_dropped(tmp_path):
    p = next(x for x in bc.load_manifest() if x['key'] == 'hazcmdr')
    e = bc.private_expectation(p)
    lines, problems = bc.verify_routes({'plugins': [e]}, bc.cloudtak_routes(_cloudtak(tmp_path, 'ct', ROUTES_14)))
    assert problems == 0 and lines[0].startswith('skip') and 'private repo' in lines[0]
    menu_lines, menu_problems = bc.verify_bundle({'plugins': [e]}, _bundle(tmp_path))
    assert menu_problems == 0 and menu_lines[0].startswith('skip')


def _bundle(tmp_path):
    d = tmp_path / 'dist'
    _write(d, 'a.js', 'x')
    return d


def test_routes_local_runs_on_a_checkout_and_goes_red_on_a_removed_route(tmp_path, capsys):
    repo = tmp_path / 'repo'
    _write(repo, 'plugin/index.ts', "await std('/api/basemap/' + id + '/tiles');\nawait std(`/api/basemap/${id}/tiles`);\n")
    _write(repo, 'server/plugin-x.ts', "await schema.get('/x/ping', {}, async () => {});\n")
    ct14 = _cloudtak(tmp_path, 'ct14', ROUTES_14)
    ct13 = _cloudtak(tmp_path, 'ct13', ROUTES_13)
    assert bc.main(['routes-local', '--ct', str(ct14), '--plugin', str(repo)]) == 1
    assert 'FAIL' in capsys.readouterr().out
    assert bc.main(['routes-local', '--ct', str(ct13), '--plugin', str(repo)]) == 0


# ── the install step carries the calls into expect.json; the workflow runs the check ──

def test_the_expectation_carries_the_calls_and_the_tolerated_gaps(tmp_path):
    plugin = _plugin(tmp_path, {'index.ts': ("export const a = this.api.menu.add({ key: 'k', label: 'L' });\n"
                                             "await std('/api/profile');\n")})
    allow = [{'method': 'get', 'path': '/api/x', 'why': 'because'}]
    e = bc.plugin_expectation({'key': 'k', 'name': 'K', 'install_dir': 'k', 'allow_missing': allow}, plugin)
    assert [c['path'] for c in e['calls']] == ['/api/profile'] and e['allow_missing'] == allow


def test_every_tolerated_gap_in_the_manifest_has_a_reason():
    for p in bc.load_manifest():
        for a in p.get('allow_missing', []):
            assert a.get('why', '').strip(), f"{p['key']}: a tolerated missing route needs a reason (why)"
            assert a['method'] == a['method'].lower() and a['path'].startswith('/api/')


def test_every_private_plugin_names_its_repo_and_is_not_a_catalog_plugin():
    private = [p for p in bc.load_manifest() if p.get('private')]
    assert {p['key'] for p in private} == {'hazcmdr', 'rapidsos'}
    for p in private:
        assert p['repo'].startswith('https://github.com/takwerx/') and p['in_catalog'] is False


def test_crosstak_is_in_the_nightly():
    p = next(x for x in bc.load_manifest() if x['key'] == 'crosstak')
    assert p['repo'].endswith('/cloudtak-crosstak-plugin') and not p.get('private')


def test_the_workflow_runs_the_route_check_and_has_a_canary_for_it():
    text = WORKFLOW.read_text(encoding='utf-8')
    assert 'bundle_check.py verify-routes' in text
    i = text.index('Check each plugin\'s CloudTAK API calls still have a route')
    j = text.index('Canary - the route check must catch a route that is gone')
    assert i < j
    # the canary adds a route that cannot exist and requires the check to go red
    assert 'route-that-cloudtak-never-had' in text
    # both are skipped on the canary legs that are meant to be red for another reason
    assert text[i:j].count('!matrix.expect_red') == 1 and text[j:j + 400].count('!matrix.expect_red') == 1


@pytest.mark.parametrize('rel', ['bundle_check.py', 'README.md'])
def test_the_readme_and_tool_say_how_private_plugins_are_checked(rel):
    assert 'routes-local' in (CI / rel).read_text(encoding='utf-8')


def test_manifest_still_parses_as_json():
    json.loads((CI / 'manifest.json').read_text(encoding='utf-8'))
