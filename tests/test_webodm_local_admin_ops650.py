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
"""ops #650: WebODM's first-visit setup page (/welcome) is never left open.

WebODM ships with no admin, and while none exists its /welcome page lets anyone make one.
The local deploy now makes the admin (as the remote deploy does since ops #629), a console
start makes one with no usable password on boxes that never got one, and Caddy closes
/welcome whether or not Authentik is installed. A failed Authentik probe keeps the
Authentik block already on disk instead of dropping forward_auth.
generate_caddyfile needs the whole box, so the vhost lines come from pure helpers that these
tests run for real, and the wiring is checked on the source.
"""

import ast
import base64
import os
import pathlib
import re
import shutil
import subprocess
import sys
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'webodm.html').read_text(encoding='utf-8')

_FUNCS = ('_caddy_vhost_block', '_vhost_uses_sso', '_webodm_vhost_closed',
          '_webodm_proxy_lines', '_webodm_no_sso_lines', '_webodm_shell_cmd',
          '_webodm_admin_parse', '_webodm_migrations_pending', '_webodm_wait_migrations')
_ASSIGNS = ('_WEBODM_VHOST_MARKER', '_WEBODM_WELCOME_MATCHER', '_WEBODM_ADMIN_LOCK_PY',
            'CADDYFILE_USER_BLOCKS_MARKER')
UP = '127.0.0.1:8765'


def _ns(module_run=None):
    ns = {'re': re, 'os': os, '_b64': base64,
          '_module_run': module_run or (lambda *a, **k: (True, ''))}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _ASSIGNS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _FUNCS + _ASSIGNS if n not in ns]
    assert not missing, f'ops #650 helpers missing from app.py: {missing}'
    return ns


def _func_src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _webodm_section():
    src = _func_src('generate_caddyfile')
    i = src.index("wo_mod = modules.get('webodm'")
    return src[i:src.index("tvr_mod = modules.get('tak_video_restreamer'", i)]


def _vhost(body_lines, marker):
    return '\n'.join([marker, 'webodm.example.com {'] + body_lines + ['}', ''])


# --- Caddy: the proof test --------------------------------------------------------------------

def test_webodm_vhost_is_never_a_bare_proxy_and_always_closes_welcome():
    """Fails on dev a763f42: with no Authentik (or a failed probe) the WebODM vhost was a bare
    `reverse_proxy`, so /welcome reached WebODM and the first visitor became its admin."""
    sec = _webodm_section()
    assert 'lines.append(f"    reverse_proxy {wo_up}")' not in sec, 'bare reverse_proxy to WebODM'
    assert 'reverse_proxy {wo_up}' not in sec, 'every WebODM proxy line comes from _webodm_proxy_lines'
    assert "if ak.get('installed')" not in sec, 'a failed probe must not drop forward_auth'
    assert '_vhost_uses_sso(ak, _wo_existing, _WEBODM_VHOST_MARKER)' in sec
    assert 'lines += _webodm_no_sso_lines(wo_up)' in sec
    assert sec.count('lines += _webodm_proxy_lines(wo_up)') == 1   # Authentik branch
    assert 'lines.append(_WEBODM_VHOST_MARKER)' in sec


def test_no_authentik_lines_close_welcome_before_the_proxy():
    ns = _ns()
    text = '\n'.join(ns['_webodm_no_sso_lines'](UP))
    assert text.count('reverse_proxy') == 1 and 'basic_auth' not in text
    assert 'path /welcome /welcome/*' in text
    assert text.index('respond @wo_welcome') < text.index(f'reverse_proxy {UP}')
    assert re.search(r'respond @wo_welcome "[^"\n]+" 403$', text, re.M)
    # inside one route block, so Caddy keeps this order (respond is terminal when it matches)
    assert text.startswith('    route {') and text.rstrip().endswith('}')


def test_authentik_branch_closes_welcome_too():
    sec = _webodm_section()
    fa = sec.index('forward_auth {ak_up}')
    assert fa < sec.index('lines += _webodm_proxy_lines(wo_up)')
    # ops #648: client-sent X-Authentik-* headers are removed first in the route
    route = sec.index('lines.append(f"    route {{")')
    strip = sec.index('lines.append(f"        {_CADDY_STRIP_AUTHENTIK_HEADERS}")')
    assert route < strip < sec.index('reverse_proxy /outpost.goauthentik.io/*') < fa


def test_failed_probe_keeps_the_authentik_block_on_disk():
    ns = _ns()
    m = ns['_WEBODM_VHOST_MARKER']
    uses = lambda ak, cf: ns['_vhost_uses_sso'](ak, cf, m)
    with_ak = _vhost(['    route {', '        forward_auth 127.0.0.1:9090 {', '        }',
                      f'        reverse_proxy {UP}', '    }'], m)
    bare = _vhost([f'    reverse_proxy {UP}'], m)
    assert uses({'installed': True}, '') is True
    assert uses({'installed': False, 'probe_ok': True}, with_ak) is False   # really no Authentik
    assert uses({'installed': False, 'probe_ok': False}, with_ak) is True   # unknown: keep it
    assert uses({}, with_ak) is True and uses(None, with_ak) is True
    assert uses({'installed': False, 'probe_ok': False}, bare) is False     # still /welcome-closed
    # another vhost's forward_auth does not count
    other = '# Node-RED flow editor\nnr.example.com {\n    forward_auth x {\n    }\n}\n' + bare
    assert uses({'installed': False, 'probe_ok': False}, other) is False


def test_vhost_closed_tells_old_from_new():
    ns = _ns()
    m = ns['_WEBODM_VHOST_MARKER']
    closed = ns['_webodm_vhost_closed']
    assert not closed(_vhost([f'    reverse_proxy {UP}'], m))            # dev a763f42, no Authentik
    assert not closed(_vhost(['    route {', '        forward_auth x {', '        }',
                              f'        reverse_proxy {UP}', '    }'], m))  # dev, Authentik
    assert closed(_vhost(ns['_webodm_no_sso_lines'](UP), m))
    assert closed('# infra-TAK - Auto-generated Caddyfile\n')               # no WebODM at all


@pytest.mark.skipif(not shutil.which('caddy'), reason='caddy not installed here (checked on the box)')
def test_caddy_accepts_the_vhost(tmp_path):
    ns = _ns()
    f = tmp_path / 'Caddyfile'
    f.write_text(_vhost(ns['_webodm_no_sso_lines'](UP), ns['_WEBODM_VHOST_MARKER']))
    r = subprocess.run(['caddy', 'adapt', '--config', str(f), '--adapter', 'caddyfile'],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert '/welcome' in r.stdout and '403' in r.stdout


def test_existing_boxes_get_welcome_closed_on_console_start():
    src = _func_src('_startup_caddy_webodm_welcome_converge')
    assert '_webodm_vhost_closed(generated)' in src
    assert src.index('generate_caddyfile(s)') < src.index('_caddy_reload_if_changed(')
    assert '_startup_caddy_webodm_welcome_converge()' in APP


# --- migrations: the count that never read 0 -------------------------------------------------

SHOW_DONE = 'app\n [X] 0001_initial\n [X] 0002_more\nauth\n [X] 0001_initial\n'


def test_migrations_pending_reads_zero_when_all_are_applied():
    ns = _ns(lambda *a, **k: (True, SHOW_DONE))
    assert ns['_webodm_migrations_pending']({}) == 0
    ns = _ns(lambda *a, **k: (True, SHOW_DONE + ' [ ] 0003_new\n [ ] 0004_new\n'))
    assert ns['_webodm_migrations_pending']({}) == 2
    for bad in ((False, SHOW_DONE), (True, 'Error: No such container: webapp'), (True, '')):
        assert _ns(lambda *a, _b=bad, **k: _b)['_webodm_migrations_pending']({}) == 99


def test_wait_migrations_returns_once_done(monkeypatch):
    seq = iter([(True, ''), (True, SHOW_DONE + ' [ ] 0003\n'), (True, SHOW_DONE)])
    ns = _ns(lambda *a, **k: next(seq))
    monkeypatch.setitem(sys.modules, 'time', types.SimpleNamespace(sleep=lambda s: None))
    log = []
    assert ns['_webodm_wait_migrations']({}, log.append) is True
    assert any('Migrations complete' in ln for ln in log)
    ns = _ns(lambda *a, **k: (True, ''))
    assert ns['_webodm_wait_migrations']({}, log.append, tries=3) is False


# --- local deploy makes the admin ------------------------------------------------------------

def test_local_deploy_makes_the_admin_before_caddy_publishes_webodm():
    src = _func_src('_run_webodm_deploy')
    local = src[src.index("wo_dir = os.path.expanduser('~/webodm')"):]
    wait = local.index('_migrated = _webodm_wait_migrations(deploy_cfg, plog)')
    admin = local.index('_webodm_ensure_admin(deploy_cfg, plog)')
    assert wait < admin < local.index('generate_caddyfile(s)')
    remote = _func_src('_run_webodm_deploy_remote')
    assert 'grep -c' not in remote and 'grep -c' not in local


def test_page_says_the_password_comes_from_the_deploy():
    assert 'Set on first visit' not in TEMPLATE


# --- existing local boxes: admin with no usable password -------------------------------------

def _run_code(code, users):
    """Run the real admin code against a fake Django User model."""
    class U:
        def __init__(self, username, pw, su=True):
            self.username, self.pw, self.is_superuser = username, pw, su

        def check_password(self, p):
            return self.pw is not None and self.pw == p

    db = [U(*u) for u in users]

    class Q(list):
        def exists(self):
            return bool(self)

    class M:
        @staticmethod
        def filter(**kw):
            return Q(u for u in db if all(getattr(u, k) == v for k, v in kw.items()))

        @staticmethod
        def create_superuser(name, email, pw):
            db.append(U(name, pw))

    mod = types.ModuleType('django.contrib.auth.models')
    mod.User = type('User', (), {'objects': M})
    keys = ('django', 'django.contrib', 'django.contrib.auth', 'django.contrib.auth.models')
    saved = {k: sys.modules.get(k) for k in keys}
    for k in keys:
        sys.modules[k] = mod if k.endswith('models') else types.ModuleType(k)
    out = []
    try:
        exec(code, {'print': out.append})
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return out, db


def test_lock_makes_an_admin_with_no_password_when_there_is_none():
    ns = _ns()
    out, db = _run_code(ns['_WEBODM_ADMIN_LOCK_PY'], [('pilot', 'x', False), ('admin', 'y', False)])
    r = ns['_webodm_admin_parse']('\n'.join(out))
    assert r['done'] and r['locked'] == ['infratak-admin'] and not r['new']
    assert db[-1].is_superuser and db[-1].pw is None          # unusable: Account Recovery sets it
    assert not any(len(ln.split(' ')) > 3 for ln in out)       # nothing that looks like a password


def test_lock_leaves_an_existing_admin_alone_and_reports_a_default_password():
    ns = _ns()
    out, db = _run_code(ns['_WEBODM_ADMIN_LOCK_PY'], [('admin', 'admin'), ('ops', 'long-real-pw')])
    r = ns['_webodm_admin_parse']('\n'.join(out))
    assert r['done'] and r['weak'] == ['admin'] and not r['locked']
    assert [u.pw for u in db] == ['admin', 'long-real-pw'] and len(db) == 2


def test_lock_code_travels_as_base64():
    cmd = _ns()['_webodm_shell_cmd']("print('x')")
    assert cmd.startswith('docker exec webapp python manage.py shell -c "$(echo ')
    assert base64.b64decode(re.search(r'echo (\S+) \| base64 -d', cmd).group(1)).decode() == "print('x')"


def test_console_start_runs_the_lock_for_local_webodm_only():
    src = _func_src('_startup_webodm_local_admin')
    assert "if cfg.get('target_mode') == 'remote':" in src
    assert '_webodm_shell_cmd(_WEBODM_ADMIN_LOCK_PY)' in src
    assert '_WEBODM_ADMIN_PY' not in src, 'console start never makes a password (it would reach the journal)'
    assert 'treat the box' in src and 'as taken over' in src
    assert 'threading.Thread(target=_startup_webodm_local_admin, daemon=True).start()' in APP
    # the thread starts after every helper it calls is defined
    start = APP.index('threading.Thread(target=_startup_webodm_local_admin')
    assert APP.index('def _webodm_dir(') < start
