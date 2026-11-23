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
"""ops #1107: a console start keeps the stream site file on a REMOTE MediaMTX host current.

mediamtx_ldap_overlay.py (the stream site's sign-in and roles) reached an editor on a
remote host only through a MediaMTX deploy or "Patch web editor". After a console update
the host kept its old copy. The console now ships it at start, over the saved SSH target,
with the editor's Authentik token, API address and trusted peer.

The shell the console sends runs here for real under `sh`, against a fake host: a folder
tree for /opt, /etc and /usr/local/etc, and small stand-ins for systemctl, install, chown,
stat, sha256sum and base64 that keep what happened in files. The host's own question to
Authentik runs for real too, against a small HTTP server that answers like Authentik. So
the tests look at what the host ends up with, not at which strings were sent.

"A console start" below runs the remote pass only when this tree has it. On a tree
without it nothing ships, and the tests fail on the host still holding the old file.
"""

import ast
import base64
import hashlib
import http.server
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
OVERLAY = (REPO / 'mediamtx_ldap_overlay.py').read_text(encoding='utf-8')
OLD_OVERLAY = '# the copy a MediaMTX deploy left here months ago\n'

HOST = 'mtx.example'
CONSOLE_IP = '203.0.113.5'     # TEST-NET-3: Settings → Server IP
TOKEN = 'tok-current-0123456789abcdef'
OLD_TOKEN = 'tok-from-before-authentik-was-redeployed'
ENV_FILE_LINE = 'EnvironmentFile=-/usr/local/etc/mediamtx-webeditor.env'

NAMES = (
    # this change
    '_MEDIAMTX_REMOTE_OVERLAY_ALERT_EVERY_S', '_MEDIAMTX_REMOTE_STAGE_RE',
    '_MEDIAMTX_REMOTE_EDITOR_AK_DEFAULT', '_MEDIAMTX_REMOTE_OVERLAY_PROBE_SH',
    '_MEDIAMTX_REMOTE_AK_CHECK_PY', '_mediamtx_remote_editor_ak_url',
    '_mediamtx_remote_overlay_safe_tail', '_mediamtx_remote_overlay_plan',
    '_mediamtx_remote_overlay_apply_sh', '_mediamtx_remote_overlay_alert',
    '_startup_converge_mediamtx_overlay_remote', '_mediamtx_remote_overlay_held',
    # what it shares with the local pass
    '_unit_text_token_to_envfile', '_MEDIAMTX_EDITOR_AK_TOKEN_RE', '_MEDIAMTX_EDITOR_AK_URL_RE',
    '_mediamtx_editor_authentik_sync', '_unit_text_with_env', '_MEDIAMTX_TRUSTED_PROXIES_KEY',
    '_MEDIAMTX_EDITOR_SECRET_ENV', '_MEDIAMTX_EDITOR_ENVFILE_LINE',
    '_mediamtx_editor_secret_env_text', '_mediamtx_editor_trusted_proxies',
)


def _src(*names):
    """Top-level defs/assignments from app.py, in file order. A name app.py does not have
    is skipped, so the tests run (and fail on the outcome) on a tree without this change."""
    parts = []
    for n in TREE.body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names:
            parts.append(ast.get_source_segment(APP, n))
        elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


# ── a fake Authentik ──────────────────────────────────────────────────────────────

class FakeAuthentik:
    """GET /api/v3/core/users/?username=X with a bearer token, like Authentik.
    mode: 'ok', 'error' (HTTP 500), 'html' (200, not JSON). A wrong token gets 403."""

    def __init__(self, token=TOKEN):
        self.mode = 'ok'
        self.token = token
        self.calls = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                fake.calls.append(self.path)
                if fake.mode == 'error':
                    code, body = 500, b'{"detail": "down"}'
                elif self.headers.get('Authorization') != 'Bearer ' + fake.token:
                    code, body = 403, b'{"detail": "Token invalid/expired"}'
                elif fake.mode == 'html':
                    code, body = 200, b'<html>a captive portal</html>'
                else:
                    code, body = 200, json.dumps({'pagination': {}, 'results': []}).encode()
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def authentik():
    a = FakeAuthentik()
    yield a
    a.close()


# ── a fake remote host ────────────────────────────────────────────────────────────

_SHIMS = {
    'systemctl': r'''#!/bin/sh
echo "systemctl $*" >> "$FAKE/calls"
case "$1" in
  is-active) S=$(cat "$FAKE/active" 2>/dev/null || echo active); echo "$S"; [ "$S" = active ] ;;
  try-restart) [ -f "$FAKE/restart_fails" ] && exit 1; exit 0 ;;
  *) exit 0 ;;
esac
''',
    # `install -m MODE [-o X] [-g X] SRC DST`: a new file at DST, never through a link.
    'install': r'''#!/bin/sh
echo "install $*" >> "$FAKE/calls"
[ -f "$FAKE/install_fails" ] && exit 1
MODE=644
while [ $# -gt 2 ]; do case "$1" in -m) MODE=$2; shift 2 ;; -o|-g) shift 2 ;; *) shift ;; esac; done
rm -f "$2"; cp "$1" "$2" && chmod "$MODE" "$2"
''',
    'chown': '#!/bin/sh\necho "chown $*" >> "$FAKE/calls"\nexit 0\n',
    'stat': '#!/bin/sh\necho 993:993\n',
    'restorecon': '#!/bin/sh\nexit 0\n',
    'sha256sum': r'''#!/usr/bin/env python3
import hashlib, sys
if len(sys.argv) > 1:
    try:
        data = open(sys.argv[1], 'rb').read()
    except OSError:
        sys.stderr.write('sha256sum: %s: No such file or directory\n' % sys.argv[1])
        sys.exit(1)
    name = sys.argv[1]
else:
    data, name = sys.stdin.buffer.read(), '-'
print('%s  %s' % (hashlib.sha256(data).hexdigest(), name))
''',
    'base64': r'''#!/usr/bin/env python3
import base64, sys
try:
    sys.stdout.write(base64.encodebytes(open(sys.argv[1], 'rb').read()).decode())
except OSError:
    sys.exit(1)
''',
}


class FakeHost:
    """The remote MediaMTX host as a folder tree. Commands the console sends run under sh
    with the host's absolute paths pointed into the tree."""

    PATHS = ('/opt/mediamtx-webeditor', '/etc/systemd/system', '/usr/local/etc', '/tmp/infratak-mtx.')

    def __init__(self, root):
        self.root = str(root)
        self.fake = os.path.join(self.root, 'fake')
        self.bin = os.path.join(self.fake, 'bin')
        for d in ('opt/mediamtx-webeditor', 'etc/systemd/system', 'usr/local/etc', 'tmp', 'fake/bin'):
            os.makedirs(os.path.join(self.root, d))
        for name, text in _SHIMS.items():
            p = os.path.join(self.bin, name)
            with open(p, 'w') as f:
                f.write(text)
            os.chmod(p, 0o755)
        self.overlay = self.p('/opt/mediamtx-webeditor/mediamtx_ldap_overlay.py')
        self.unit = self.p('/etc/systemd/system/mediamtx-webeditor.service')
        self.env = self.p('/usr/local/etc/mediamtx-webeditor.env')
        self.user_runs, self.root_runs, self.copies = [], [], []
        self.reachable = True
        self.copy_fails = False

    def p(self, path):
        return self.root + path

    def _here(self, text):
        for path in self.PATHS:
            text = text.replace(path, self.root + path)
        return text

    def _sh(self, cmd):
        if not self.reachable:
            return False, 'ssh: connect to host mtx.example port 22: Connection timed out'
        env = dict(os.environ, FAKE=self.fake, PATH=self.bin + os.pathsep + os.environ.get('PATH', ''))
        r = subprocess.run(['sh', '-c', self._here(cmd)], capture_output=True, text=True,
                           timeout=60, env=env)
        return r.returncode == 0, ((r.stdout or '') + (r.stderr or '')).replace(self.root, '')

    def run(self, cfg, cmd, timeout=120, log_fn=None):
        self.user_runs.append(cmd)
        return self._sh(cmd)

    def run_root(self, cfg, cmd, timeout=120, log_fn=None):
        self.root_runs.append(cmd)
        return self._sh(cmd)

    def copy(self, cfg, local_path, remote_path, timeout=30, log_fn=None):
        self.copies.append(remote_path)
        if not self.reachable or self.copy_fails:
            return False, 'scp: Connection closed'
        shutil.copy2(local_path, self._here(remote_path))
        return True, ''

    # what the tests read
    def calls(self):
        try:
            with open(os.path.join(self.fake, 'calls')) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def restarts(self):
        return [c for c in self.calls() if c.startswith('systemctl') and 'restart' in c]

    def leftovers(self):
        return os.listdir(self.p('/tmp'))

    def read(self, path):
        with open(path) as f:
            return f.read()

    def write(self, path, text, mode=0o644):
        with open(path, 'w') as f:
            f.write(text)
        os.chmod(path, mode)

    def state(self):
        return {p: (self.read(p) if os.path.exists(p) else None)
                for p in (self.overlay, self.unit, self.env)}


def _unit(api_url, trusted, token_in_unit=None, ldap=True):
    """The editor unit a remote MediaMTX deploy writes."""
    ldap_lines = ''
    if ldap:
        ldap_lines = ('Environment=LDAP_ENABLED=1\n'
                      f'Environment=AUTHENTIK_API_URL={api_url}\n'
                      f'Environment=INFRATAK_TRUSTED_PROXIES={trusted}\n'
                      + (f'Environment=AUTHENTIK_TOKEN={token_in_unit}\n' if token_in_unit
                         else ENV_FILE_LINE + '\n'))
    return ('[Unit]\nDescription=MediaMTX Web Configuration Editor\n'
            'After=network.target mediamtx.service\n\n[Service]\nType=simple\n'
            'ExecStart=/usr/bin/python3 /opt/mediamtx-webeditor/mediamtx_config_editor.py\n'
            'WorkingDirectory=/opt/mediamtx-webeditor\nEnvironment=PORT=5080\n'
            'Environment=MEDIAMTX_API_URL=http://127.0.0.1:9898\n'
            f'{ldap_lines}Restart=always\nRestartSec=5\nUser=takwerx\n\n'
            '[Install]\nWantedBy=multi-user.target\n')


def _env(token):
    return ('# Written by infra-TAK. Mode 600: the Authentik token is kept out of the\n'
            '# mediamtx-webeditor unit file, which every local user can read.\n'
            f'AUTHENTIK_TOKEN={token}\n')


class Console:
    """The pieces of app.py this pass uses, wired to a FakeHost and a FakeAuthentik."""

    def __init__(self, tmp_path, host, authentik_url, token=TOKEN, deployment=None,
                 email='ops@example.com'):
        self.host = host
        self.mails = []
        self.editor_up = True
        self.settings = {'guarddog_alert_email': email, 'server_ip': CONSOLE_IP, 'fqdn': 'example.org'}
        self.deployment = deployment if deployment is not None else {
            'target_mode': 'remote', 'deployed': True, 'remote': {'host': HOST, 'ssh_user': 'fiops'}}
        self.config_dir = str(tmp_path / 'console-config')
        os.makedirs(self.config_dir, exist_ok=True)
        ns = {'re': re, 'os': os, 'json': json, 'time': time, 'shlex': shlex, 'hashlib': hashlib,
              'tempfile': tempfile, 'socket': socket, '_b64': base64,
              '__file__': str(REPO / 'app.py'),
              'CONFIG_DIR': self.config_dir,
              'load_settings': lambda: dict(self.settings),
              '_get_module_deployment_config': lambda s, k: json.loads(json.dumps(self.deployment)),
              '_w1_ak_ctx': lambda: (('http://127.0.0.1:9090',
                                      {'Authorization': f'Bearer {token}'}, self.settings)
                                     if token else (None, None, self.settings)),
              '_module_run': host.run, '_module_run_root': host.run_root, '_module_copy': host.copy,
              '_mediamtx_remote_editor_check': lambda cfg, plog: self.editor_up,
              '_guarddog_server_identifier': lambda s: 'console1',
              '_guarddog_send_alert_email_via_relay':
                  lambda to, subj, body: self.mails.append((to, subj, body)) or True,
              '_pub_hostport': lambda h, settings=None: h,
              '_get_authentik_host': lambda s: 'tak.example.org'}
        exec(compile(_src(*NAMES), 'app.py', 'exec'), ns)
        self.real_ak_url = ns.get('_mediamtx_remote_editor_ak_url')
        # The host asks the fake Authentik (plain http on loopback), not a public name.
        ns['_mediamtx_remote_editor_ak_url'] = lambda s: authentik_url
        self.ns = ns
        self.trusted = ns['_mediamtx_editor_trusted_proxies'](
            self.settings, {'target_mode': 'remote'})

    def start(self):
        """A console start: the remote pass, when this tree has one."""
        fn = self.ns.get('_startup_converge_mediamtx_overlay_remote')
        return fn() if fn else 'this tree ships nothing to a remote host'


@pytest.fixture
def host(tmp_path):
    return FakeHost(tmp_path / 'host')


def _current_host(host, console, authentik, overlay=OVERLAY, token=TOKEN):
    """A remote editor in Authentik mode whose unit and token are already right."""
    host.write(host.overlay, overlay)
    host.write(host.unit, _unit(authentik.url, console.trusted))
    host.write(host.env, _env(token), 0o600)


# ── the proof: an old file on the remote host is replaced by a console start ──────

def test_console_start_replaces_an_old_file_on_the_remote_host(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    result = console.start()
    assert host.read(host.overlay) == OVERLAY, (
        'the remote host still has the old stream site file after a console start (%s)' % result)
    assert result == 'updated'
    assert host.restarts() == ['systemctl try-restart mediamtx-webeditor']
    assert host.leftovers() == []                       # the staging folder is gone
    assert authentik.calls, 'the host did not ask Authentik before the change'
    assert console.mails == []


def test_same_file_means_no_copy_and_no_restart(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik)
    before = host.state()
    assert console.start() == 'current'
    assert host.state() == before
    assert host.copies == [] and host.user_runs == [] and len(host.root_runs) == 1   # one look
    assert host.restarts() == []
    assert not any(c.startswith('install') for c in host.calls())


def test_second_console_start_changes_nothing(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    assert console.start() == 'updated'
    assert console.start() == 'current'
    assert len(host.restarts()) == 1


@pytest.mark.parametrize('deployment', [
    {},                                                                    # never deployed
    {'target_mode': 'local', 'deployed': True, 'remote': {'host': ''}},     # on the console box
    {'target_mode': 'remote', 'deployed': False, 'remote': {'host': HOST}},  # set up, not deployed
    {'target_mode': 'remote', 'deployed': True, 'remote': {'host': ''}},    # no SSH target
])
def test_no_remote_target_means_nothing_happens(tmp_path, host, authentik, deployment):
    console = Console(tmp_path, host, authentik.url, deployment=deployment)
    host.write(host.overlay, OLD_OVERLAY)
    fn = console.ns.get('_startup_converge_mediamtx_overlay_remote')
    assert fn is not None, 'this tree has no pass for a remote host'
    assert fn() == 'none'
    assert host.user_runs == [] and host.root_runs == [] and host.copies == []


def test_host_without_an_editor_is_left_alone(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    os.rmdir(host.p('/opt/mediamtx-webeditor'))
    fn = console.ns.get('_startup_converge_mediamtx_overlay_remote')
    assert fn is not None, 'this tree has no pass for a remote host'
    assert fn() == 'none'
    assert host.copies == [] and host.calls() == [c for c in host.calls() if 'is-active' in c]


# ── the editor's Authentik token, address and trusted peer, in the same pass ──────

def test_stale_token_and_address_are_set_with_the_file(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    host.write(host.overlay, OLD_OVERLAY)
    host.write(host.unit, _unit('http://127.0.0.1:9090', '127.0.0.1,::1'))
    host.write(host.env, _env(OLD_TOKEN), 0o600)
    assert console.start() == 'updated'
    assert host.read(host.overlay) == OVERLAY
    unit = host.read(host.unit).split('\n')
    assert f'Environment=AUTHENTIK_API_URL={authentik.url}' in unit
    assert f'Environment=INFRATAK_TRUSTED_PROXIES={console.trusted}' in unit
    assert CONSOLE_IP in console.trusted
    assert f'AUTHENTIK_TOKEN={TOKEN}' in host.read(host.env).splitlines()
    assert stat.S_IMODE(os.stat(host.env).st_mode) == 0o600
    calls = host.calls()
    assert any(c.startswith('install -m 600 -o root -g root') for c in calls)
    assert 'systemctl daemon-reload' in calls
    assert calls.index('systemctl daemon-reload') < calls.index('systemctl try-restart mediamtx-webeditor')
    assert len(host.restarts()) == 1


def test_only_a_stale_token_is_fixed_and_restarts_once(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, token=OLD_TOKEN)
    unit_before = host.read(host.unit)
    assert console.start() == 'updated'
    assert f'AUTHENTIK_TOKEN={TOKEN}' in host.read(host.env).splitlines()
    assert host.read(host.unit) == unit_before and host.read(host.overlay) == OVERLAY
    assert len(host.restarts()) == 1
    assert console.start() == 'current'


def test_token_in_the_unit_moves_to_the_600_file(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    host.write(host.overlay, OVERLAY)
    host.write(host.unit, _unit(authentik.url, console.trusted, token_in_unit=OLD_TOKEN))
    assert console.start() == 'updated'
    unit = host.read(host.unit)
    assert 'AUTHENTIK_TOKEN' not in unit and ENV_FILE_LINE in unit.split('\n')
    assert f'AUTHENTIK_TOKEN={TOKEN}' in host.read(host.env).splitlines()
    assert stat.S_IMODE(os.stat(host.env).st_mode) == 0o600


def test_console_without_a_token_ships_the_file_and_keeps_the_hosts_token(tmp_path, host, authentik):
    authentik.token = OLD_TOKEN                      # the host's own token still works
    console = Console(tmp_path, host, authentik.url, token='')
    host.write(host.overlay, OLD_OVERLAY)
    host.write(host.unit, _unit(authentik.url, console.trusted))
    host.write(host.env, _env(OLD_TOKEN), 0o600)
    unit_before, env_before = host.read(host.unit), host.read(host.env)
    assert console.start() == 'updated'
    assert host.read(host.overlay) == OVERLAY
    assert host.read(host.unit) == unit_before and host.read(host.env) == env_before


def test_editor_not_in_authentik_mode_gets_the_file_and_nothing_else(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    host.write(host.overlay, OLD_OVERLAY)
    host.write(host.unit, _unit('', '', ldap=False))
    unit_before = host.read(host.unit)
    assert console.start() == 'updated'
    assert host.read(host.overlay) == OVERLAY
    assert host.read(host.unit) == unit_before and not os.path.exists(host.env)
    assert host.restarts() == [] and authentik.calls == []      # the file is not loaded there


# ── no answer from Authentik on the host: nothing changes, and the operator is told ─

@pytest.mark.parametrize('break_it', ['error', 'html', 'wrong_token', 'down', 'no_token_file'])
def test_no_answer_from_authentik_changes_nothing_on_the_host(tmp_path, host, authentik, break_it):
    console = Console(tmp_path, host, authentik.url)
    host.write(host.overlay, OLD_OVERLAY)
    host.write(host.unit, _unit('http://127.0.0.1:9090', '127.0.0.1,::1'))
    host.write(host.env, _env(OLD_TOKEN), 0o600)
    if break_it in ('error', 'html'):
        authentik.mode = break_it
    elif break_it == 'wrong_token':
        authentik.token = 'authentik-knows-another-token'
    elif break_it == 'down':
        authentik.close()
    else:
        os.remove(host.env)
        console = Console(tmp_path, host, authentik.url, token='')
    before = host.state()
    assert console.start() == 'held'
    assert host.state() == before, 'the host changed although it got no answer from Authentik'
    assert host.restarts() == []
    assert not any(c.startswith(('install', 'systemctl daemon-reload')) for c in host.calls())
    assert host.leftovers() == []
    assert len(console.mails) == 1
    to, subj, body = console.mails[0]
    assert to == 'ops@example.com' and HOST in subj and 'waiting' in subj
    # the address the editor would use: the console's, or (no console token) the unit's own
    asked = 'http://127.0.0.1:9090' if break_it == 'no_token_file' else authentik.url
    assert asked in body and 'restart the infra-TAK console' in body
    assert TOKEN not in body and OLD_TOKEN not in body
    assert console.start() == 'held'                  # the daily console restart
    assert len(console.mails) == 1                    # one mail a day per box
    assert host.state() == before


def test_held_host_is_updated_at_the_next_start_once_authentik_answers(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    authentik.mode = 'error'
    assert console.start() == 'held'
    authentik.mode = 'ok'
    assert console.start() == 'updated'
    assert host.read(host.overlay) == OVERLAY


def test_unit_with_an_address_that_is_not_a_web_address_is_held(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url, token='')
    host.write(host.overlay, OLD_OVERLAY)
    host.write(host.unit, _unit('http://x/$(touch /tmp/pwned)', console.trusted))
    host.write(host.env, _env(OLD_TOKEN), 0o600)
    before = host.state()
    assert console.start() == 'held'
    assert host.state() == before and host.copies == [] and host.user_runs == []


# ── an editor that is stopped stays stopped; a host that cannot be reached is only logged ─

def test_stopped_editor_is_never_started(tmp_path, host, authentik):
    """The firewall check stops the editor on a box with no firewall (ops #630)."""
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    host.write(os.path.join(host.fake, 'active'), 'inactive\n')
    console.editor_up = False                         # it is down, and that is not this pass's doing
    assert console.start() == 'updated'
    assert host.read(host.overlay) == OVERLAY
    systemctl = [c for c in host.calls() if c.startswith('systemctl')]
    assert 'systemctl try-restart mediamtx-webeditor' in systemctl
    assert not any(re.search(r'systemctl (restart|start|enable|reload-or-restart)\b', c)
                   for c in systemctl)
    assert console.mails == []


def test_editor_that_does_not_come_back_is_reported(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    console.editor_up = False
    assert console.start() == 'failed'
    assert len(console.mails) == 1 and 'did not start' in console.mails[0][1]
    assert 'Patch web editor' in console.mails[0][2]


def test_unreachable_host_is_only_logged(tmp_path, host, authentik, capsys):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    host.reachable = False
    assert console.start() == 'unknown'
    assert console.mails == [] and host.copies == []
    assert 'The next console start tries again' in capsys.readouterr().out
    host.reachable = True
    assert console.start() == 'updated'


def test_failed_copy_changes_nothing_and_leaves_no_folder(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    before = host.state()
    host.copy_fails = True
    assert console.start() == 'unknown'
    assert host.state() == before and host.leftovers() == [] and host.restarts() == []


def test_failed_write_on_the_host_is_reported_not_called_done(tmp_path, host, authentik, capsys):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    host.write(os.path.join(host.fake, 'install_fails'), '')
    assert console.start() == 'failed'
    assert host.read(host.overlay) == OLD_OVERLAY and host.restarts() == []
    assert host.leftovers() == []
    assert 'did not finish' in capsys.readouterr().out


# ── nothing secret in a log line; the pieces the console start is built from ──────

def test_log_lines_never_carry_the_unit_or_the_token(tmp_path, host, authentik, capsys):
    console = Console(tmp_path, host, authentik.url)
    host.write(host.overlay, OLD_OVERLAY)
    host.write(host.unit, _unit('http://127.0.0.1:9090', '127.0.0.1,::1', token_in_unit=OLD_TOKEN))
    assert console.start() == 'updated'
    authentik.mode = 'error'
    host.write(host.overlay, OLD_OVERLAY)
    assert console.start() == 'held'
    out = capsys.readouterr().out
    assert TOKEN not in out and OLD_TOKEN not in out
    assert base64.b64encode(OLD_TOKEN.encode()).decode()[:16] not in out
    tail = console.ns['_mediamtx_remote_overlay_safe_tail'](
        'INFRATAK_EDITOR=present\nTOKEN_SHA=abc\nUNIT_B64=c2VjcmV0\nsudo: a password is required')
    assert 'c2VjcmV0' not in tail and 'abc' not in tail and 'password is required' in tail


def test_probe_that_cannot_be_read_is_not_a_plan(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    plan = console.ns['_mediamtx_remote_overlay_plan']
    sha = hashlib.sha256(OVERLAY.encode('utf-8')).hexdigest()
    assert plan('', sha, authentik.url, TOKEN, console.trusted) is None
    assert plan('INFRATAK_EDITOR=present\n', sha, authentik.url, TOKEN, console.trusted) is None
    assert plan('INFRATAK_EDITOR=present\nOVERLAY_SHA=\nUNIT_B64=***\n',
                sha, authentik.url, TOKEN, console.trusted) is None
    ok = plan('INFRATAK_EDITOR=present\nOVERLAY_SHA=%s\nUNIT_B64=\n' % sha,
              sha, authentik.url, TOKEN, console.trusted)
    assert ok == {'overlay': False, 'unit': None, 'env': None, 'ldap': False, 'api_url': '', 'active': ''}


def test_remote_address_is_the_public_one_and_the_deploy_uses_the_same(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    assert console.real_ak_url is not None, 'this tree has no pass for a remote host'
    assert console.real_ak_url({'fqdn': 'example.org'}) == 'https://tak.example.org'
    assert console.real_ak_url({}) is None            # no domain: no public address
    deploy = next(ast.get_source_segment(APP, n) for n in TREE.body
                  if isinstance(n, ast.FunctionDef) and n.name == '_run_mediamtx_deploy_remote')
    assert '_mediamtx_remote_editor_ak_url(settings)' in deploy


def test_console_start_runs_the_pass_in_the_background_after_the_firewall_check():
    fn = next(n for n in TREE.body
              if isinstance(n, ast.FunctionDef) and n.name == '_startup_migrations')
    body = ast.get_source_segment(APP, fn)
    m = re.search(r'(\w+) = threading\.Thread\(target=_startup_converge_mediamtx_remote_firewall,', body)
    assert m, 'the firewall check thread has no name to wait for'
    assert re.search(r'threading\.Thread\(target=_startup_converge_mediamtx_overlay_remote,\s*'
                     r'args=\(%s,\),\s*daemon=True' % re.escape(m.group(1)), body)


def test_pass_waits_for_the_firewall_check(tmp_path, host, authentik):
    console = Console(tmp_path, host, authentik.url)
    _current_host(host, console, authentik, overlay=OLD_OVERLAY)
    fn = console.ns.get('_startup_converge_mediamtx_overlay_remote')
    assert fn is not None, 'this tree has no pass for a remote host'
    seen = []

    def firewall_check():
        time.sleep(0.3)
        seen.append(list(host.root_runs))

    t = threading.Thread(target=firewall_check)
    t.start()
    assert fn(t) == 'updated'
    assert seen == [[]], 'the pass talked to the host while the firewall check still ran'


def test_root_wrapper_keeps_the_whole_script_as_root():
    """The apply script goes through _module_run_root: one `sudo -n sh -c` for a non-root
    SSH user, so every step after the first is root too."""
    fn = next((ast.get_source_segment(APP, n) for n in TREE.body
               if isinstance(n, ast.FunctionDef)
               and n.name == '_startup_converge_mediamtx_overlay_remote'), None)
    assert fn is not None, 'this tree has no pass for a remote host'
    assert re.search(r'_module_run_root\(\s*cfg, _mediamtx_remote_overlay_apply_sh\(', fn)
    assert re.search(r'_module_run_root\(cfg, _MEDIAMTX_REMOTE_OVERLAY_PROBE_SH', fn)
    assert 'sudo' not in fn
