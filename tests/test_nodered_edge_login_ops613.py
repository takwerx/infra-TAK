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
"""ops #613: the Node-RED flow editor is never published without a login.

An editor anyone can reach lets them build a flow that runs commands. Without Authentik the Node-RED vhost used to be a bare reverse_proxy. Now it is
Caddy basic_auth with a generated password, or a 503 when no login can be made.
generate_caddyfile needs the whole box, so the vhost lines come from a pure helper that these
tests run for real, and the wiring is checked on the source.
"""

import ast
import json
import pathlib
import re
import secrets
import subprocess
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

_NAMES = ('_nodered_edge_login_load', '_nodered_edge_login_save', '_caddy_hash_password',
          '_nodered_edge_login', '_nodered_no_sso_lines', '_nodered_vhost_has_login',
          '_nodered_vhost_has_forward_auth', '_nodered_edge_uses_sso')
_CONSTS = ('_NODERED_EDGE_LOGIN_FILE', '_NODERED_EDGE_USER', '_NODERED_PUBLIC_PATHS',
           '_NODERED_EDGE_HASH_RE')
HASH = 'JDJhJDE0JGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFiY2RlZg=='


def _ns(tmp_path):
    ns = {'os': __import__('os'), 're': re, 'json': json, 'subprocess': subprocess,
          'secrets': secrets, 'time': time, 'CONFIG_DIR': str(tmp_path)}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _CONSTS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _NAMES if n not in ns]
    assert not missing, f'ops #613 helpers missing from app.py: {missing}'
    return ns


def test_no_login_means_503_and_never_a_proxy(tmp_path):
    ns = _ns(tmp_path)
    for bad in ({}, None, {'user': 'nodered-admin'}, {'user': 'nodered-admin', 'hash': ''}):
        text = '\n'.join(ns['_nodered_no_sso_lines']('127.0.0.1:1880', bad))
        assert 'reverse_proxy' not in text
        assert ' 503' in text


def test_hash_that_could_inject_caddyfile_text_is_refused(tmp_path):
    ns = _ns(tmp_path)
    for evil in (HASH + '\n    reverse_proxy 127.0.0.1:1880', HASH + ' }', HASH + '"x',
                 'short', HASH + '{env.X}'):
        text = '\n'.join(ns['_nodered_no_sso_lines']('127.0.0.1:1880',
                                                    {'user': 'nodered-admin', 'hash': evil}))
        assert 'reverse_proxy' not in text and 'basic_auth' not in text


def test_login_puts_basic_auth_before_the_editor_proxy(tmp_path):
    ns = _ns(tmp_path)
    lines = ns['_nodered_no_sso_lines']('127.0.0.1:1880', {'user': 'nodered-admin', 'hash': HASH})
    text = '\n'.join(lines)
    assert f'nodered-admin {HASH}' in text
    # the two public KML / icon paths stay open (same as the Authentik branch), nothing else
    pub = text.index('handle @nodered_public')
    auth = text.index('basic_auth')
    last_proxy = text.rindex('reverse_proxy')
    assert text.index('path /ipaws/alerts.kml /icons/ipaws/*') < pub < auth < last_proxy
    assert text.count('reverse_proxy') == 2
    assert text[pub:auth].count('reverse_proxy') == 1


def test_create_makes_a_hashed_login_and_keeps_the_password_off_the_command_line(
        tmp_path, monkeypatch):
    ns = _ns(tmp_path)
    seen = {}

    def fake_run(cmd, **kw):
        seen['cmd'], seen['input'] = cmd, kw.get('input')
        return subprocess.CompletedProcess(cmd, 0, stdout=HASH + '\n', stderr='')
    monkeypatch.setattr(ns['subprocess'], 'run', fake_run)
    assert ns['_nodered_edge_login']() == {}                    # read only: makes nothing
    st = ns['_nodered_edge_login'](create=True)
    assert st['user'] == 'nodered-admin' and st['hash'] == HASH
    pw = st['reveal']
    assert len(pw) >= 20 and pw not in ' '.join(seen['cmd']) and seen['input'] == pw + '\n'
    f = tmp_path / 'nodered_edge_login.json'
    assert (f.stat().st_mode & 0o777) == 0o600
    # a second call keeps the same login: Caddy is regenerated often
    assert ns['_nodered_edge_login'](create=True)['hash'] == HASH
    # reset makes a new password
    assert ns['_nodered_edge_login'](rotate=True)['reveal'] != pw


def test_failed_hash_means_no_login_so_the_vhost_is_closed(tmp_path, monkeypatch):
    ns = _ns(tmp_path)
    monkeypatch.setattr(ns['subprocess'], 'run',
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout='', stderr='x'))
    assert ns['_nodered_edge_login'](create=True) == {}
    assert not (tmp_path / 'nodered_edge_login.json').exists()

    def boom(*a, **k):
        raise FileNotFoundError('caddy')
    monkeypatch.setattr(ns['subprocess'], 'run', boom)
    assert ns['_nodered_edge_login'](create=True) == {}


def test_generate_caddyfile_has_no_bare_node_red_proxy():
    src = next(ast.get_source_segment(APP, n) for n in TREE.body
               if isinstance(n, ast.FunctionDef) and n.name == 'generate_caddyfile')
    blk = src[src.index('lines.append(f"# Node-RED flow editor")'):
              src.index("_emit_alias_redirect(_get_service_alias(settings, 'nodered')")]
    assert 'lines += _nodered_no_sso_lines(nodered_up, _nodered_edge_login(create=True))' in blk
    # the old fallback: a plain reverse_proxy appended in the no-Authentik branch
    tail = blk[blk.index('else:'):]
    assert 'lines.append(f"    reverse_proxy {nodered_up}")' not in tail


def test_vhost_check_tells_open_from_closed(tmp_path):
    ns = _ns(tmp_path)
    has = ns['_nodered_vhost_has_login']
    open_vhost = '# Node-RED flow editor\nnodered.x.org {\n    reverse_proxy 127.0.0.1:1880\n}\n\n# TAK\n'
    assert has(open_vhost) is False
    assert has(open_vhost.replace('reverse_proxy', 'forward_auth x {\n}\n    reverse_proxy')) is True
    assert has('# Node-RED flow editor\nn.x {\n    basic_auth {\n    }\n}\n') is True
    assert has('# Node-RED flow editor\nn.x {\n    respond "no" 503\n}\n') is True
    assert has('# TAK Server\nt.x {\n}\n') is True          # no Node-RED vhost: nothing to fix


def test_existing_boxes_are_converged_on_the_console_update():
    body = APP[APP.index('def _startup_migrations():'):]
    assert '_startup_caddy_nodered_login_converge()' in body
    mig = next(ast.get_source_segment(APP, n) for n in TREE.body
               if isinstance(n, ast.FunctionDef) and n.name == '_startup_caddy_nodered_login_converge')
    assert 'generate_caddyfile(s)' in mig and '_caddy_reload_if_changed(' in mig
    # verified against the LIVE file: a rejected Caddyfile is rolled back to the open one
    assert mig.index('_nodered_vhost_has_login(_read_priv(CADDYFILE_PATH))') < mig.index('_caddy_reload_if_changed(')
    assert 'did not write' in mig          # the "check your flows" line, in the log
    # the queued path (the console starts before the Caddy registry is ready: the usual case)
    # prints it too, or the operator would never see it
    queued = mig[mig.index('Node-RED login queued'):mig.index('return', mig.index('Node-RED login queued'))]
    assert 'did not' in queued and 'write, delete it' in queued


@pytest.mark.parametrize('route', ['/api/nodered/edge-login', '/api/nodered/edge-login/reveal',
                                   '/api/nodered/edge-login/reset'])
def test_edge_login_routes_need_a_console_login(route):
    m = re.search(r"@app\.route\('%s'[^\n]*\)\n@login_required\n" % re.escape(route), APP)
    assert m, route


SSO_VHOST = ('# Node-RED flow editor\nn.x.org {\n    route {\n        forward_auth ak:9000 {\n        }\n'
             '        reverse_proxy 127.0.0.1:1880\n    }\n}\n')
OPEN_VHOST = '# Node-RED flow editor\nn.x.org {\n    reverse_proxy 127.0.0.1:1880\n}\n'


def test_failed_authentik_probe_is_unknown_not_no_authentik(tmp_path):
    uses = _ns(tmp_path)['_nodered_edge_uses_sso']
    # Authentik installed: always the Authentik block
    assert uses({'installed': True}, '') is True
    # the probe ran and found no Authentik: the Caddy login (never a bare proxy)
    assert uses({'installed': False, 'probe_ok': True}, SSO_VHOST) is False
    # the probe FAILED (docker call failed) or gave nothing: unknown
    for unknown in ({'installed': False, 'probe_ok': False}, {}, None):
        assert uses(unknown, SSO_VHOST) is True     # keep the Authentik block already on disk
        assert uses(unknown, OPEN_VHOST) is False   # nothing to keep: fail closed
        assert uses(unknown, '') is False           # no Caddyfile yet: fail closed


def test_generate_caddyfile_asks_the_unknown_probe_guard_for_node_red():
    src = next(ast.get_source_segment(APP, n) for n in TREE.body
               if isinstance(n, ast.FunctionDef) and n.name == 'generate_caddyfile')
    blk = src[src.index('lines.append(f"# Node-RED flow editor")'):
              src.index("_emit_alias_redirect(_get_service_alias(settings, 'nodered')")]
    assert '_nodered_edge_uses_sso(ak, _nr_existing)' in blk
    assert "if ak.get('installed'):" not in blk


def test_detect_modules_marks_a_failed_docker_probe():
    seg = APP[APP.index("ak_cfg = _get_module_deployment_config(settings, 'authentik_deployment')"):
              APP.index("# TAK Portal - Docker-based user management")]
    assert "'probe_ok': ak_probe_ok" in seg
    assert 'ak_probe_ok = ak_installed or _akc.returncode == 0' in seg
