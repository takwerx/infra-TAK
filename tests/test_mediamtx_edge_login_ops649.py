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
"""ops #649: the MediaMTX web console is never published on its default login.

The web editor seeds users.json with a default login. Without Authentik the stream vhost was
a plain reverse_proxy to it. Now: no Authentik means the console replaces the default login
with a random password first and Caddy strips client X-Authentik-* on every route; until the
login is checked the vhost answers 503. A failed Authentik check keeps the Authentik block
already on disk.

app.py cannot be imported in a test, so the helpers are cut out of it and run for real; the
wiring is checked on the source.
"""

import ast
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = ('_emit_mediamtx_site', '_mediamtx_vhost_block', '_mediamtx_edge_uses_sso',
          '_mediamtx_vhost_is_safe', '_mediamtx_vhost_needs_regen')
_CONSTS = ('MEDIAMTX_OPEN_PATHS', '_MEDIAMTX_EDITOR_LOGIN_SCRIPT')
AK_HEADERS = ('X-Authentik-Username', 'X-Authentik-Groups', 'X-Authentik-Email',
              'X-Authentik-Name', 'X-Authentik-Uid', 'X-Infratak-Proxy-Auth')
HOST = 'stream.example.com'
EDITOR = '127.0.0.1:5080'


def _ns():
    ns = {'_pub_url': lambda h, s=None: f'https://{h}' if h else ''}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _NAMES + _CONSTS if n not in ns]
    assert not missing, f'ops #649 helpers missing from app.py: {missing}'
    return ns


NS = _ns()


def site(ak_up=None, hls=('127.0.0.1:8888', False), mtx_up=EDITOR, **kw):
    lines = []

    def strip(indent):
        lines.extend(f'{indent}request_header -{h}' for h in AK_HEADERS)

    NS['_emit_mediamtx_site'](lines, HOST, mtx_up, ak_up, hls, strip,
                              lambda root: lines.append(f'        #rescue {root}'), **kw)
    return '\n'.join(lines) + '\n'


def _editor_routes(text, mtx_up=EDITOR):
    """Each `reverse_proxy <editor>` line with the lines of its enclosing block before it."""
    lines = text.split('\n')
    out = []
    for i, ln in enumerate(lines):
        if ln.strip() == f'reverse_proxy {mtx_up}':
            j = i
            while j > 0 and not lines[j].rstrip().endswith('{'):
                j -= 1
            out.append((ln, lines[j:i]))
    return out


# ── the proof: no bare reverse_proxy to the editor without Authentik ───────────


@pytest.mark.parametrize('mtx_up', [EDITOR, '10.0.0.5:5080'])
def test_no_authentik_never_publishes_a_bare_editor(mtx_up):
    # Fails on dev before ops #649: the no-Authentik vhost was `    reverse_proxy <editor>`.
    for kw in ({}, {'login_ok': False}, {'login_ok': True}):
        text = site(mtx_up=mtx_up, **kw)
        for ln, before in _editor_routes(text, mtx_up):
            assert ln.startswith('        '), f'top-level (bare) editor proxy: {text}'
            assert [b.strip() for b in before[1:]] == [f'request_header -{h}' for h in AK_HEADERS], text


def test_login_not_checked_means_503_and_no_editor():
    text = site()
    assert f'reverse_proxy {EDITOR}' not in text
    assert '" 503' in text
    # MediaMTX's own HLS (it asks for its own password) is untouched.
    assert 'handle_path /hls-proxy/* {' in text and 'reverse_proxy 127.0.0.1:8888 {' in text


def test_login_checked_strips_forged_headers_then_proxies():
    text = site(login_ok=True)
    assert text.count(f'reverse_proxy {EDITOR}') == 1
    assert ' 503' not in text
    assert NS['_mediamtx_vhost_is_safe'](text)


def test_dev_bare_vhost_is_not_safe_and_authentik_vhost_is():
    bare = '# MediaMTX Web Console\nstream.example.com {\n    reverse_proxy 127.0.0.1:5080\n}\n'
    assert not NS['_mediamtx_vhost_is_safe'](bare)
    assert NS['_mediamtx_vhost_is_safe'](site(ak_up='127.0.0.1:9090', hls=None))
    assert NS['_mediamtx_vhost_is_safe'](site())          # 503
    assert NS['_mediamtx_vhost_is_safe']('# no mediamtx here\n')


def test_startup_converge_opens_exactly_when_the_login_is_good():
    need = NS['_mediamtx_vhost_needs_regen']
    bare = '# MediaMTX Web Console\nstream.example.com {\n    reverse_proxy 127.0.0.1:5080\n}\n'
    assert need(bare, True) and need(bare, False)
    assert need(site(), True)                     # closed, login now good -> open it
    assert not need(site(), False)
    assert need(site(login_ok=True), False)       # open, login not known good -> close it
    assert not need(site(login_ok=True), True)
    ak = site(ak_up='127.0.0.1:9090', hls=None)
    assert not need(ak, False) and not need(ak, True)
    assert not need('# nothing\n', False)


# ── a failed Authentik check is unknown, not "no Authentik" ────────────────────


def test_failed_authentik_probe_keeps_the_authentik_block_on_disk():
    uses = NS['_mediamtx_edge_uses_sso']
    with_ak = site(ak_up='127.0.0.1:9090', hls=None)
    assert uses({'installed': True, 'probe_ok': True}, '') is True
    assert uses({'installed': False, 'probe_ok': True}, with_ak) is False
    assert uses({'installed': False, 'probe_ok': False}, with_ak) is True
    assert uses({'installed': False, 'probe_ok': False}, site(login_ok=True)) is False
    assert uses({}, with_ak) is True
    # Another vhost's forward_auth does not count.
    other = '# Node-RED flow editor\nnr.example.com {\n    forward_auth x {\n    }\n}\n'
    assert uses({'installed': False, 'probe_ok': False}, other + site()) is False


# ── the users.json script, run for real ────────────────────────────────────────


def _run(path):
    r = subprocess.run([sys.executable, '-I', '-', str(path)], input=NS['_MEDIAMTX_EDITOR_LOGIN_SCRIPT'],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_script_replaces_admin_admin_and_keeps_other_users(tmp_path):
    f = tmp_path / 'users.json'
    f.write_text(json.dumps([{'username': 'admin', 'password': 'admin', 'role': 'admin'},
                             {'username': 'viewer1', 'password': 'pw-viewer', 'role': 'viewer'}]))
    out = _run(f)
    assert out.startswith('MTXLOGIN set ')
    pw = out[len('MTXLOGIN set '):]
    assert len(pw) >= 16 and pw != 'admin'
    users = json.loads(f.read_text())
    assert users == [{'username': 'admin', 'password': pw, 'role': 'admin'},
                     {'username': 'viewer1', 'password': 'pw-viewer', 'role': 'viewer'}]
    assert oct(os.stat(f).st_mode & 0o777) == '0o600'
    assert _run(f) == 'MTXLOGIN keep'                     # idempotent
    assert json.loads(f.read_text())[0]['password'] == pw


def test_script_writes_a_real_password_before_the_editor_seeds_admin_admin(tmp_path):
    f = tmp_path / 'users.json'
    out = _run(f)
    assert out.startswith('MTXLOGIN set ')
    users = json.loads(f.read_text())
    assert [u['username'] for u in users] == ['admin'] and users[0]['password'] != 'admin'


def test_script_leaves_a_changed_password_alone(tmp_path):
    f = tmp_path / 'users.json'
    data = [{'username': 'admin', 'password': 'operator-chose-this', 'role': 'admin'}]
    f.write_text(json.dumps(data))
    assert _run(f) == 'MTXLOGIN keep'
    assert json.loads(f.read_text()) == data


@pytest.mark.parametrize('body', ['{not json', '{"a": 1}'])
def test_script_fails_closed_on_a_file_it_cannot_read(tmp_path, body):
    f = tmp_path / 'users.json'
    f.write_text(body)
    assert _run(f).startswith('MTXLOGIN fail ')
    assert f.read_text() == body


# ── wiring ──────────────────────────────────────────────────────────────────────


def _src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found')


def test_generate_caddyfile_uses_the_probe_rule_and_the_login_gate():
    src = _src('generate_caddyfile')
    assert '_mtx_ak = _mediamtx_edge_uses_sso(ak, _mtx_existing)' in src
    assert 'login_ok=_mtx_ak or _mediamtx_editor_login_ok(settings)' in src


def test_both_deploys_secure_the_login_before_caddy_publishes_it():
    for fn in ('run_mediamtx_deploy', '_run_mediamtx_deploy_remote'):
        src = _src(fn)
        i = src.index('_mediamtx_editor_secure_login(settings, log_fn=plog)')
        assert i < src.index('generate_caddyfile(settings)', i), fn


def test_startup_converge_runs_and_the_password_is_never_on_a_command_line():
    mig = _src('_startup_migrations')
    assert '_startup_mediamtx_editor_login_converge()' in mig
    run = _src('_mediamtx_editor_run_login_script')
    assert "python3 -I - {path}" in run and 'input=_MEDIAMTX_EDITOR_LOGIN_SCRIPT' in run
    assert "'MTXLOGIN set ' + pw" in NS['_MEDIAMTX_EDITOR_LOGIN_SCRIPT']


def test_login_api_is_behind_the_console_login_and_never_lists_the_password():
    for route, fn in (("'/api/mediamtx/editor-login')", 'mediamtx_editor_login_status'),
                      ("'/api/mediamtx/editor-login/reveal', methods=['POST'])", 'mediamtx_editor_login_reveal'),
                      ("'/api/mediamtx/editor-login/check', methods=['POST'])", 'mediamtx_editor_login_check')):
        i = APP.index('@app.route(' + route)
        assert APP[i:APP.index(f'def {fn}(', i)].count('@login_required') == 1, fn
    assert 'reveal' not in _src('mediamtx_editor_login_status').split('jsonify', 1)[1].replace(
        "st.get('reveal')", '')
