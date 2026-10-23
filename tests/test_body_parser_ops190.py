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
"""body-parser GHSA-27r3-jxmh-p828 (ops #190).

A body-parser below 1.20.9 / 2.4.0 crashes the Node process on a compressed request body
with trailing bytes, before routing. Two halves:

  * build: TAK Portal and Remote Assist are built on the box from upstream lockfiles that
    still pin 2.3.0 / 1.20.5, so every build writes an npm `overrides` entry first;
  * edge: the vhosts in front of Express apps drop the request's Content-Encoding, which
    covers a box as soon as its Caddyfile regenerates (a startup converge does that).

app.py cannot be imported in a test, so the helpers are cut out of it and run against stubs.
"""

import ast
import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)


def _segment(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _load(names, ns=None):
    ns = {'re': re, 'json': json, 'os': __import__('os')} if ns is None else ns
    exec(compile('\n\n'.join(_segment(n) for n in names), 'app.py:' + names[-1], 'exec'), ns)
    return ns


def _overrides_ns():
    return _load(['_semver_tuple', 'NPM_SECURITY_FLOORS', '_npm_security_overrides',
                  '_apply_npm_security_overrides'])


def _lock(*entries):
    """package-lock v3 `packages` from (path, version) pairs."""
    pk = {'': {'name': 'x'}}
    for path, ver in entries:
        pk[path] = {'version': ver}
    return {'lockfileVersion': 3, 'packages': pk}


# ── which overrides a project needs ─────────────────────────────────────────

@pytest.mark.parametrize('entries, want', [
    # TAK Portal 2.0.18 (express 5) and Remote Assist 3.1.4 (express 4), as measured
    ([('node_modules/body-parser', '2.3.0')], {'body-parser': '^2.4.0'}),
    ([('node_modules/body-parser', '1.20.5')], {'body-parser': '^1.20.9'}),
    ([('node_modules/body-parser', '1.20.8')], {'body-parser': '^1.20.9'}),
    # nested copy only
    ([('node_modules/express/node_modules/body-parser', '2.2.1')], {'body-parser': '^2.4.0'}),
    # already fixed upstream: nothing to do, ever (never pulls a box backwards)
    ([('node_modules/body-parser', '2.4.0')], {}),
    ([('node_modules/body-parser', '2.5.1')], {}),
    ([('node_modules/body-parser', '1.20.9')], {}),
    # not in the tree at all
    ([('node_modules/express', '5.2.1')], {}),
    # two majors in one lock: one override would force both onto one — leave it
    ([('node_modules/body-parser', '2.3.0'), ('node_modules/a/node_modules/body-parser', '1.20.5')], {}),
    # a major with no known fix
    ([('node_modules/body-parser', '3.0.0')], {}),
    ([('node_modules/body-parser', '0.9.0')], {}),
    # unparseable lock version
    ([('node_modules/body-parser', '2.3.0-beta.1')], {}),
])
def test_override_follows_the_lockfile(entries, want):
    add, _ = _overrides_ns()['_npm_security_overrides']({'dependencies': {'express': '*'}}, _lock(*entries))
    assert add == want


def test_upstream_override_and_direct_dependency_are_left_alone():
    n = _overrides_ns()
    lock = _lock(('node_modules/body-parser', '2.3.0'))
    add, notes = n['_npm_security_overrides']({'overrides': {'body-parser': '2.3.0'}}, lock)
    assert add == {} and any('upstream already overrides' in x for x in notes)
    # npm refuses an override that differs from a direct dependency's spec (EOVERRIDE)
    add, notes = n['_npm_security_overrides']({'dependencies': {'body-parser': '^2.2.0'}}, lock)
    assert add == {} and any('direct dependency' in x for x in notes)
    # our own pin left behind by a checkout that did not reset the file: silent no-op
    add, notes = n['_npm_security_overrides']({'overrides': {'body-parser': '^2.4.0'}}, lock)
    assert add == {} and notes == []


def test_floors_cover_the_advisory():
    floors = _overrides_ns()['NPM_SECURITY_FLOORS']
    assert floors['body-parser'] == ('1.20.9', '2.4.0')


# ── writing package.json ────────────────────────────────────────────────────

def _project(tmp_path, pkg, lock):
    (tmp_path / 'package.json').write_text(json.dumps(pkg, indent=2) + '\n')
    if lock is not None:
        (tmp_path / 'package-lock.json').write_text(json.dumps(lock))
    return tmp_path


def test_apply_merges_into_upstream_overrides(tmp_path):
    # TAK Portal already carries its own overrides; ours is added next to them
    pkg = {'name': 'tak-portal', 'version': '2.0.18',
           'overrides': {'whatwg-url': '^14.2.0', 'undici': '$undici'},
           'dependencies': {'express': '^5.2.1', 'undici': '7.29.0'}}
    d = _project(tmp_path, pkg, _lock(('node_modules/body-parser', '2.3.0')))
    log = []
    assert _overrides_ns()['_apply_npm_security_overrides'](str(d), plog=log.append) == {'body-parser': '^2.4.0'}
    got = json.loads((d / 'package.json').read_text())
    assert got['overrides'] == {'whatwg-url': '^14.2.0', 'undici': '$undici', 'body-parser': '^2.4.0'}
    assert got['version'] == '2.0.18' and got['dependencies'] == pkg['dependencies']
    assert any('2.3.0 → ^2.4.0' in m for m in log)
    # idempotent: a second build leaves the file alone
    before = (d / 'package.json').read_text()
    assert _overrides_ns()['_apply_npm_security_overrides'](str(d), plog=log.append) == {}
    assert (d / 'package.json').read_text() == before


def test_apply_creates_overrides_when_upstream_has_none(tmp_path):
    pkg = {'name': 'eud-remote-assist-server', 'dependencies': {'express': '^4.21.2'}}
    d = _project(tmp_path, pkg, _lock(('node_modules/body-parser', '1.20.5')))
    assert _overrides_ns()['_apply_npm_security_overrides'](str(d), plog=lambda m: None) == {'body-parser': '^1.20.9'}
    assert json.loads((d / 'package.json').read_text())['overrides'] == {'body-parser': '^1.20.9'}


def test_apply_never_raises(tmp_path):
    n = _overrides_ns()
    log = []
    # no package.json at all
    assert n['_apply_npm_security_overrides'](str(tmp_path / 'missing'), plog=log.append) == {}
    assert any('not applied' in m for m in log)
    # broken JSON
    (tmp_path / 'package.json').write_text('{nope')
    assert n['_apply_npm_security_overrides'](str(tmp_path), plog=log.append) == {}
    # no lockfile: nothing to compare against, file untouched
    d = tmp_path / 'nolock'
    d.mkdir()
    _project(d, {'name': 'x'}, None)
    assert n['_apply_npm_security_overrides'](str(d), plog=log.append) == {}
    assert json.loads((d / 'package.json').read_text()) == {'name': 'x'}


# ── wired into every image build, after the checkout ────────────────────────

def _before(body, first, second):
    assert first in body, first
    assert second in body, second
    assert body.index(first) < body.index(second), f'{first!r} must come before {second!r}'


def test_remote_assist_deploy_and_update_pin_before_building():
    pin = "_apply_npm_security_overrides(os.path.join(ra_dir, 'server'), plog=plog)"
    dep = _segment('_run_remote_assist_deploy')
    _before(dep, "'git', 'clone'", pin)
    _before(dep, pin, "'up', '-d', '--build'")
    upd = _segment('_run_remote_assist_update')
    _before(upd, "'reset', '--hard', 'origin/main'", pin)
    _before(upd, pin, "'up', '-d', '--build'")


def test_remote_assist_restore_resets_the_pinned_file():
    body = _segment('_remote_assist_restore_tracked_files')
    assert "'server/package.json'" in body and "'docker-compose.yml'" in body
    # one file per git call: an unknown path must not stop the other from being reset
    assert re.search(r"for _f in \('docker-compose\.yml', 'server/package\.json'\)", body)


def test_takportal_builds_pin_after_the_checkout():
    upd = _segment('_takportal_run_update')
    _before(upd, '_takportal_update_git(portal_dir)', '_apply_npm_security_overrides(portal_dir')
    _before(upd, '_apply_npm_security_overrides(portal_dir', "['docker', 'compose', 'up', '-d', '--build']")
    dep = _segment('run_takportal_deploy')
    _before(dep, "'checkout', '--force', _tp_tag", '_apply_npm_security_overrides(portal_dir, plog=plog)')
    _before(dep, '_apply_npm_security_overrides(portal_dir, plog=plog)', "'--build', '--no-start'")
    ctl = _segment('takportal_control')
    start = ctl[ctl.index("if action == 'start':"):ctl.index("elif action == 'stop':")]
    _before(start, '_apply_npm_security_overrides(portal_dir)', "'up', '-d', '--build'")


# ── Caddy edge ──────────────────────────────────────────────────────────────

def test_drop_line_is_the_request_header_directive():
    ns = _load(['CADDY_DROP_REQUEST_ENCODING', '_caddy_drop_request_encoding_lines'], {})
    assert ns['CADDY_DROP_REQUEST_ENCODING'] == 'request_header -Content-Encoding'
    lines = ns['_caddy_drop_request_encoding_lines']()
    assert lines[-1] == '    request_header -Content-Encoding'
    assert all(l.startswith('    ') for l in lines)


def _vhost(gen, start, end):
    i = gen.index(start)
    return gen[i:gen.index(end, i)]


@pytest.mark.parametrize('start, end', [
    ('lines.append(f"# Node-RED flow editor")', '_emit_alias_redirect('),
    ('lines.append(f"# TAK Portal")', '_emit_alias_redirect('),
    ('lines.append(f"{ct_map} {{")', '_emit_alias_redirect('),
    ('lines.append(f"{ct_tiles} {{")', '_emit_alias_redirect('),
    ('lines.append(f"{ct_video} {{")', 'lines.append("")'),
    ('lines.append(f"{ct_video_host}:9997 {{")', 'lines.append("")'),
    ('lines.append(f"{ra_host} {{")', '_emit_alias_redirect('),
    ('lines.append(f"{ra_host}:{REMOTE_ASSIST_DEVICE_PORT} {{")', 'lines.append("")'),
])
def test_express_vhosts_drop_request_encoding(start, end):
    v = _vhost(_segment('generate_caddyfile'), start, end)
    assert v.count('_caddy_drop_request_encoding_lines()') == 1, start
    # at site level, outside any route/handle block (it must run before them)
    i = v.index('_caddy_drop_request_encoding_lines()')
    for opener in ('route {{', 'handle @'):
        if opener in v:
            assert i < v.index(opener), (start, opener)


def test_non_express_vhosts_are_untouched():
    gen = _segment('generate_caddyfile')
    for start, end in (('lines.append(f"# TAK Server")', 'lines.append(f"# Authentik")'),
                       ('lines.append(f"# Authentik")', 'portal = modules.get(')):
        assert '_caddy_drop_request_encoding_lines' not in _vhost(gen, start, end)


def test_existing_boxes_converge_at_startup():
    assert '_startup_caddy_request_encoding_converge()' in _segment('_startup_migrations')
    conv = _segment('_startup_caddy_request_encoding_converge')
    # idempotent: returns before regenerating when the directive is already there
    assert conv.index('CADDY_DROP_REQUEST_ENCODING in generated') < conv.index('generate_caddyfile(')
    assert '_CADDY_REGISTRY_READY.is_set()' in conv
    assert '_caddy_reload_if_changed(' in conv and '_caddy_reload()' not in conv


def test_converge_markers_match_the_generator():
    gen = _segment('generate_caddyfile')
    ns = _load(['_CADDY_EXPRESS_VHOST_MARKERS'], {})
    for m in ns['_CADDY_EXPRESS_VHOST_MARKERS']:
        assert f'lines.append(f"{m}' in gen, m


def _converge(caddyfile, regen_to=None, registry=True):
    """Run the converge against a fake Caddyfile; returns (calls, printed)."""
    import threading
    state = {'file': caddyfile}
    calls, printed = [], []
    ev = threading.Event()
    if registry:
        ev.set()

    def gen(s):
        calls.append('generate')
        if regen_to is not None:
            state['file'] = regen_to

    def reload_if_changed(timeout=None):
        calls.append('reload')
        return True, ''

    ns = {'os': type('o', (), {'path': type('p', (), {'exists': staticmethod(lambda p: True)})}),
          'CADDYFILE_PATH': '/etc/caddy/Caddyfile', 'CADDYFILE_USER_BLOCKS_MARKER': '# --- USER ---',
          '_read_priv': lambda p: state['file'], 'load_settings': lambda: {'fqdn': 'x.example'},
          'generate_caddyfile': gen, '_caddy_reload_if_changed': reload_if_changed,
          '_CADDY_REGISTRY_READY': ev, 'print': lambda *a, **k: printed.append(' '.join(map(str, a)))}
    _load(['CADDY_DROP_REQUEST_ENCODING', '_CADDY_EXPRESS_VHOST_MARKERS',
           '_startup_caddy_request_encoding_converge'], ns)
    ns['_startup_caddy_request_encoding_converge']()
    return calls, printed


OLD = '# TAK Portal\nportal.x.example {\n    reverse_proxy 127.0.0.1:3000\n}\n'
NEW = OLD.replace('{\n', '{\n    request_header -Content-Encoding\n', 1)


def test_converge_regenerates_and_reloads_an_old_file():
    calls, printed = _converge(OLD, regen_to=NEW)
    assert calls == ['generate', 'reload'] and any('ops #190' in p for p in printed)


def test_converge_is_a_noop_when_done_or_not_applicable():
    assert _converge(NEW)[0] == []
    assert _converge('# TAK Server\ntak.x {\n}\n')[0] == []
    # the directive only in operator blocks below the marker does not count as done
    assert _converge(OLD + '# --- USER ---\nfoo {\n    request_header -Content-Encoding\n}\n',
                     regen_to=NEW)[0] == ['generate', 'reload']


def test_converge_reports_a_rejected_regen_and_does_not_reload():
    calls, printed = _converge(OLD, regen_to=OLD)
    assert calls == ['generate'] and any('FAILED' in p for p in printed)


def test_converge_defers_to_the_registry_regen():
    calls, printed = _converge(OLD, regen_to=OLD, registry=False)
    assert calls == ['generate'] and any('queued' in p for p in printed)


# ── CloudTAK update notice ──────────────────────────────────────────────────

def _known():
    return _load(['_semver_tuple', 'KNOWN_SECURITY_RELEASES', '_known_security_fixed_by'], {'re': re})


def test_cloudtak_13_113_0_is_a_security_release():
    n = _known()
    e = [x for x in n['KNOWN_SECURITY_RELEASES'] if x['fixed_in'] == '13.113.0']
    assert e and e[0]['component'] == 'cloudtak' and 'GHSA-27r3-jxmh-p828' in e[0]['reason']


@pytest.mark.parametrize('installed, target, flagged', [
    ('13.112.2', '13.113.0', True),
    ('13.112.5', '13.114.0', True),
    ('13.113.0', '13.114.0', False),
    ('13.112.2', '13.112.9', False),
])
def test_cloudtak_13_113_0_range(installed, target, flagged):
    got = [g for g in _known()['_known_security_fixed_by']('cloudtak', installed, target)
           if 'GHSA-27r3-jxmh-p828' in g]
    assert bool(got) is flagged
