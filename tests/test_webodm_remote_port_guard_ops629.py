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
"""ops #629: a remote WebODM's port is reachable only from the console, and never runs
without an admin or on a default password.

The remote compose publishes 0.0.0.0:<webodm_port> (Caddy on the console proxies to it) and
the deploy scoped it with ufw only, which Docker's published ports skip (ops #615). WebODM
ships with no admin; its /welcome page sets one up while none exists.
The deploy now installs the ops #615 DOCKER-USER guard before the containers start and makes
the admin itself, with a password generated inside the container.
"""

import ast
import base64
import ipaddress
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'webodm.html').read_text(encoding='utf-8')

_FUNCS = ('_docker_port_guard_files', '_remote_docker_port_guard',
          '_webodm_admin_cmd', '_webodm_shell_cmd', '_webodm_admin_parse', '_webodm_ensure_admin')
_ASSIGNS = ('_PORT_GUARD_NAME_RE', '_WEBODM_ADMIN_PY')


def _ns(module_run=None, server_ip=None):
    ns = {'re': re, 'ipaddress': ipaddress, '_b64': base64,
          '_module_run': module_run or (lambda *a, **k: (True, '')),
          '_fedhub_caddy_source_ip': lambda s: server_ip}
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in _FUNCS:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in _ASSIGNS:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in _FUNCS + _ASSIGNS if n not in ns]
    assert not missing, f'ops #629 helpers missing from app.py: {missing}'
    return ns


def _func_src(name):
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found in app.py')


def _admin_code(cmd):
    return base64.b64decode(re.search(r'echo (\S+) \| base64 -d', cmd).group(1)).decode()


# --- port guard -------------------------------------------------------------------------------

def test_remote_deploy_locks_the_port_before_the_containers_start():
    src = _func_src('_run_webodm_deploy_remote')
    assert '"0.0.0.0:{wo_port}:8000"' in src  # still published for Caddy, so the guard is required
    guard = src.index("_remote_docker_port_guard(deploy_cfg, settings, 'webodm', [wo_port]")
    assert guard < src.index('docker compose -f {compose_path_remote} pull') < src.index('docker compose -f {compose_path_remote} up -d')
    after = src[guard:src.index('docker compose -f {compose_path_remote} pull')]
    assert 'if not _wo_guard_ok' in after and 'return' in after, 'no lock must mean no start'


def test_webodm_guard_drops_everyone_but_the_console():
    sent = []

    def run(cfg, cmd, timeout=120, log_fn=None):
        sent.append(cmd)
        if cmd.startswith('echo "SSHSRC'):
            return True, 'SSHSRC 10.0.0.9'
        return True, 'GUARD_OK had=no'

    ok, first = _ns(run, server_ip='198.51.100.7')['_remote_docker_port_guard'](
        {'target_mode': 'remote'}, {}, 'webodm', [8765])
    assert (ok, first) == (True, True)
    install = sent[-1]
    script = base64.b64decode(re.search(r'echo (\S+) \| base64 -d \| \$S tee /usr/local/sbin/', install).group(1)).decode()
    assert 'C=INFRATAK-WEBODM' in script
    assert '-s 10.0.0.9 -j RETURN' in script and '-s 198.51.100.7 -j RETURN' in script
    insert = [ln for ln in script.splitlines() if ln.startswith('iptables -w -C DOCKER-USER ')]
    assert len(insert) == 1 and insert[0].count('--ctorigdstport 8765') == 2
    assert 'iptables -w -A "$C" -j DROP' in script
    assert 'systemctl enable infratak-port-guard-webodm.service' in install


def test_existing_remote_boxes_get_the_guard_and_an_admin_check_on_console_start():
    src = _func_src('_startup_guard_remote_webodm_port')
    assert "_remote_docker_port_guard(cfg, settings, 'webodm', [port]" in src
    assert 'did not add, rebuild the remote box' in src
    assert '_webodm_admin_cmd(False)' in src and '_webodm_admin_cmd(True)' not in src, \
        'startup only checks: a new password there would land in the journal'
    assert 'threading.Thread(target=_startup_guard_remote_webodm_port, daemon=True).start()' in APP


# --- admin account ----------------------------------------------------------------------------

def test_deploy_makes_the_admin_after_migrations():
    src = _func_src('_run_webodm_deploy_remote')
    # ops #650: the migration wait moved into _webodm_wait_migrations (shared with the local deploy)
    assert src.index('_webodm_wait_migrations(deploy_cfg, plog)') < src.index('_webodm_ensure_admin(deploy_cfg, plog)')


def test_admin_code_creates_or_replaces_and_never_sets_admin_admin():
    ns = _ns()
    fix = _admin_code(ns['_webodm_admin_cmd'](True))
    check = _admin_code(ns['_webodm_admin_cmd'](False))
    compile(fix, 'fix', 'exec')
    compile(check, 'check', 'exec')
    assert 'FIX = True' in fix and 'FIX = False' in check
    assert 'secrets.token_urlsafe(18)' in fix and 'create_superuser(' in fix
    assert "check_password('admin')" in fix and 'set_password(p)' in fix
    assert "set_password('admin')" not in fix and "'admin@localhost', 'admin')" not in fix


def test_password_is_made_in_the_container_not_sent_over_ssh():
    cmd = _ns()['_webodm_admin_cmd'](True)
    assert cmd.startswith('docker exec webapp python manage.py shell -c "$(echo ')
    assert 'token_urlsafe' not in cmd  # the code travels base64-encoded, the password not at all


def _run_admin_code(code, users):
    """Run the real admin code against a fake Django User model."""
    import sys
    import types

    class U:
        def __init__(self, username, pw, su=True):
            self.username, self.pw, self.is_superuser = username, pw, su

        def check_password(self, p):
            return self.pw == p

        def set_password(self, p):
            self.pw = p

        def save(self):
            pass

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
    saved = {k: sys.modules.get(k) for k in ('django', 'django.contrib', 'django.contrib.auth', 'django.contrib.auth.models')}
    for k in saved:
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


def test_no_admin_gets_a_generated_one():
    ns = _ns()
    out, db = _run_admin_code(_admin_code(ns['_webodm_admin_cmd'](True)), [])
    r = ns['_webodm_admin_parse']('\n'.join(out))
    assert r['done'] and len(r['new']) == 1
    user, pw = r['new'][0]
    assert user == 'admin' and len(pw) >= 20 and pw != 'admin'
    assert db[0].is_superuser and db[0].pw == pw


def test_admin_admin_is_replaced_and_a_good_password_is_kept():
    ns = _ns()
    out, db = _run_admin_code(_admin_code(ns['_webodm_admin_cmd'](True)),
                              [('admin', 'admin'), ('ops', 'a-long-real-password')])
    r = ns['_webodm_admin_parse']('\n'.join(out))
    assert [u for u, _ in r['reset']] == ['admin'] and not r['new']
    assert db[0].pw not in ('admin', '') and db[1].pw == 'a-long-real-password'


def test_check_mode_reports_and_changes_nothing():
    ns = _ns()
    out, db = _run_admin_code(_admin_code(ns['_webodm_admin_cmd'](False)), [('admin', 'admin')])
    r = ns['_webodm_admin_parse']('\n'.join(out))
    assert r['weak'] == ['admin'] and not r['reset'] and db[0].pw == 'admin'
    out, db = _run_admin_code(_admin_code(ns['_webodm_admin_cmd'](False)), [])
    assert ns['_webodm_admin_parse']('\n'.join(out))['none'] and db == []


def test_ensure_admin_shows_the_password_in_the_deploy_log_only():
    log = []
    ok = _ns(lambda *a, **k: (True, 'boot noise\nWOADMIN NEW admin S3cr3tGenerated\nWOADMIN DONE'))[
        '_webodm_ensure_admin']({'target_mode': 'remote'}, log.append)
    assert ok and any('admin / S3cr3tGenerated' in ln for ln in log)
    failed = []
    assert not _ns(lambda *a, **k: (False, 'Error: No such container: webapp'))[
        '_webodm_ensure_admin']({'target_mode': 'remote'}, failed.append)
    assert any('Could not check the WebODM admin' in ln for ln in failed)


def test_page_no_longer_says_admin_admin():
    assert 'admin / admin' not in TEMPLATE
