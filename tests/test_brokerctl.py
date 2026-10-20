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
"""The light broker client keeps `takwerx_broker.py exec`'s contract (v10.2.2 W1).

Every privileged call the non-root console makes goes through this client, so
"same contract" is checked the only way that means anything: BOTH clients are
run against the same fake daemon and must produce the same exit code, the same
stdout/stderr bytes and the same request on the wire.

The fake daemon is a unix socket in a temp dir — the real broker is never
stopped or touched ([[never-execute-destructive-negative-tests]]).
"""

import ast
import base64
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
OLD = REPO / 'broker' / 'takwerx_broker.py'
NEW = REPO / 'broker' / 'takwerx_brokerctl.py'
SHIM_INSTALLER = REPO / 'broker' / 'install-shims.sh'
CLIENTS = {'old': OLD, 'new': NEW}


# ---------------------------------------------------------------------------
# fake daemon
# ---------------------------------------------------------------------------
class FakeBroker:
    """One-shot-per-connection unix socket server: records each request,
    answers with `reply` (bytes), or closes without answering when None."""

    def __init__(self, reply):
        # AF_UNIX paths cap at 104 bytes on macOS; pytest's tmp_path is longer.
        self.dir = tempfile.mkdtemp(prefix='bctl', dir='/tmp')
        self.path = os.path.join(self.dir, 's')
        self.reply = reply
        self.requests = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(8)
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                buf = bytearray()
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                self.requests.append(json.loads(bytes(buf).decode()))
                if self.reply is not None:
                    conn.sendall(self.reply)

    def close(self):
        self.sock.close()
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
def broker_factory():
    made = []

    def make(reply):
        b = FakeBroker(reply)
        made.append(b)
        return b

    yield make
    for b in made:
        b.close()


def run_client(which, args, sock, stdin=None, env_extra=None, cwd=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith('TAKWERX_BROKER')}
    env['TAKWERX_BROKER_SOCKET'] = sock
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, '-I', '-S', str(CLIENTS[which])] + args,
        input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL,
        capture_output=True, env=env, cwd=cwd or tempfile.gettempdir(), timeout=60)


def ok_reply(stdout=b'', stderr=b'', rc=0):
    return json.dumps({'ok': True, 'returncode': rc,
                       'stdout_b64': base64.b64encode(stdout).decode(),
                       'stderr_b64': base64.b64encode(stderr).decode()}).encode()


def both(broker_factory, reply, args, **kw):
    """Run old and new against fresh identical daemons; return {which: (proc, requests)}."""
    out = {}
    for which in CLIENTS:
        b = broker_factory(reply)
        p = run_client(which, args, b.path, **kw)
        out[which] = (p, b.requests)
    return out


# ---------------------------------------------------------------------------
# constants + shape
# ---------------------------------------------------------------------------
def _module_assigns(path):
    tree = ast.parse(path.read_text())
    return {t.id: node.value for node in tree.body if isinstance(node, ast.Assign)
            for t in node.targets if isinstance(t, ast.Name)}


@pytest.mark.parametrize('name', ['SOCKET_PATH', 'MAX_MSG', 'DEFAULT_TIMEOUT', 'MAX_TIMEOUT'])
def test_duplicated_constants_match_the_daemon(name):
    old, new = _module_assigns(OLD)[name], _module_assigns(NEW)[name]
    if name == 'SOCKET_PATH':
        # os.environ.get('TAKWERX_BROKER_SOCKET', '/run/takwerx-broker.sock')
        assert ast.dump(old) == ast.dump(new)
    else:
        ev = lambda n: eval(compile(ast.Expression(n), name, 'eval'), {'__builtins__': {}})
        assert ev(old) == ev(new)


def test_client_is_stdlib_only_and_imports_nothing_from_the_daemon():
    tree = ast.parse(NEW.read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name.split('.')[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, 'relative import in the light client'
            mods.add(node.module.split('.')[0])
    # subprocess + time: ops #113's restart wait (`systemctl is-active`, bounded poll).
    assert mods <= {'base64', 'json', 'os', 'socket', 'subprocess', 'sys', 'time'}, mods


# ---------------------------------------------------------------------------
# contract parity: old vs new against the same daemon
# ---------------------------------------------------------------------------
def assert_same(res):
    (po, ro), (pn, rn) = res['old'], res['new']
    assert (pn.returncode, pn.stdout, pn.stderr) == (po.returncode, po.stdout, po.stderr)
    assert rn == ro
    return pn, rn


def test_success_passes_bytes_and_exit_code_through(broker_factory):
    reply = ok_reply(stdout=b'out\x00\xff\n', stderr=b'warn\n', rc=3)
    p, reqs = assert_same(both(broker_factory, reply, ['exec', '--', 'systemctl', 'is-active', 'caddy']))
    assert (p.returncode, p.stdout, p.stderr) == (3, b'out\x00\xff\n', b'warn\n')
    assert reqs[0]['op'] == 'exec'
    assert reqs[0]['argv'] == ['systemctl', 'is-active', 'caddy']
    assert reqs[0]['input_b64'] is None
    assert 'timeout' not in reqs[0]


def test_denied_is_126_with_the_daemons_reason(broker_factory):
    reply = json.dumps({'ok': False, 'code': 'DENIED',
                        'error': 'path not in allow-list: /home/x'}).encode()
    p, _ = assert_same(both(broker_factory, reply, ['exec', '--', 'rm', '-f', '/home/x']))
    assert p.returncode == 126
    assert p.stderr == b'takwerx_broker: DENIED: path not in allow-list: /home/x\n'
    assert p.stdout == b''


@pytest.mark.parametrize('reply', [None, b'{"ok": true, "stdout_b64": "', b'\xff\xfe'],
                         ids=['empty', 'truncated', 'not-utf8'])
def test_daemon_dying_mid_request_is_125_not_a_traceback(broker_factory, reply):
    # v10.1.40 B3a: an empty/truncated response used to escape as exit 1.
    p, _ = assert_same(both(broker_factory, reply, ['exec', '--', 'true']))
    assert p.returncode == 125
    assert p.stderr.startswith(b'takwerx_broker: cannot reach broker: ')
    assert b'Traceback' not in p.stderr


def test_unreachable_socket_is_125():
    sock = os.path.join(tempfile.mkdtemp(prefix='bctl', dir='/tmp'), 'absent')
    res = {w: run_client(w, ['exec', '--', 'true'], sock) for w in CLIENTS}
    for p in res.values():
        assert p.returncode == 125
        assert p.stderr.startswith(b'takwerx_broker: cannot reach broker: ')
    assert res['new'].stderr == res['old'].stderr


def test_stdin_and_cwd_are_forwarded(broker_factory):
    cwd = os.path.realpath(tempfile.mkdtemp(prefix='bctlcwd', dir='/tmp'))
    try:
        _, reqs = assert_same(both(broker_factory, ok_reply(), ['exec', '--', 'tee', '/etc/x'],
                                   stdin=b'payload\x00\n', cwd=cwd))
        assert base64.b64decode(reqs[0]['input_b64']) == b'payload\x00\n'
        assert os.path.realpath(reqs[0]['cwd']) == cwd
    finally:
        shutil.rmtree(cwd, ignore_errors=True)


@pytest.mark.parametrize('val,expect', [('300', 300), ('9999', 7200), ('abc', None), ('0', None), ('', None)])
def test_timeout_env_rides_the_request_clamped(broker_factory, val, expect):
    _, reqs = assert_same(both(broker_factory, ok_reply(), ['exec', '--', 'true'],
                               env_extra={'TAKWERX_BROKER_TIMEOUT': val}))
    assert reqs[0].get('timeout') == expect


def test_argv_without_double_dash_and_missing_command(broker_factory):
    _, reqs = assert_same(both(broker_factory, ok_reply(), ['exec', 'docker', 'ps', '--', '-a']))
    assert reqs[0]['argv'] == ['docker', 'ps', '--', '-a']   # only a LEADING -- is eaten
    _, reqs = assert_same(both(broker_factory, ok_reply(), ['exec', '--', '--', 'x']))
    assert reqs[0]['argv'] == ['--', 'x']                    # ...and only ONE of them
    p, reqs = assert_same(both(broker_factory, ok_reply(), ['exec', '--']))
    assert p.returncode == 2 and p.stderr == b'takwerx_broker exec: no command\n'
    assert reqs == []


# ---------------------------------------------------------------------------
# new-client-only behavior
# ---------------------------------------------------------------------------
def test_non_object_json_is_125(broker_factory):
    # The daemon always answers a dict; anything else means a broken peer. The
    # old client died with an AttributeError traceback (exit 1) here.
    b = broker_factory(b'[1, 2]')
    p = run_client('new', ['exec', '--', 'true'], b.path)
    assert p.returncode == 125
    assert p.stderr == b'takwerx_broker: cannot reach broker: response is not a JSON object\n'


@pytest.mark.parametrize('args', [[], ['ping'], ['selftest'], ['serve']])
def test_only_exec_is_implemented(args):
    p = run_client('new', args, '/tmp/bctl-unused')
    assert p.returncode == 2
    assert p.stderr.startswith(b'usage: takwerx_brokerctl.py exec')


# ---------------------------------------------------------------------------
# wiring: _sudo_wrap and the PATH shims exec the light client
# ---------------------------------------------------------------------------
def _app_function_src(name):
    src = (REPO / 'app.py').read_text()
    m = re.search(rf'^def {name}\(.*?(?=^def |\Z)', src, re.S | re.M)
    assert m, name
    return m.group(0)


def test_sudo_wrap_execs_the_light_client():
    body = _app_function_src('_sudo_wrap')
    assert '_BROKER_CLIENT' in body
    assert '_BROKER_SCRIPT' not in body


def test_generated_shims_exec_the_file_their_guard_checks():
    d = tempfile.mkdtemp(prefix='bctlshim', dir='/tmp')
    client = '/opt/infratak/broker/takwerx_brokerctl.py'
    try:
        r = subprocess.run(['bash', str(SHIM_INSTALLER), d, client], capture_output=True,
                           text=True, env=dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin'))
        assert r.returncode == 0, r.stderr
        shims = sorted(os.listdir(d))
        assert {'docker', 'systemctl', 'mkdir', 'tee'} <= set(shims)
        for name in shims:
            text = open(os.path.join(d, name)).read()
            assert f'-f "{client}"' in text, name
            calls = re.findall(r'python3 (.*?) exec --', text)
            assert calls, name
            assert all(c == f'-I -S "{client}"' for c in calls), (name, calls)
            assert 'takwerx_broker.py' not in text, name
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_shim_installer_default_is_the_light_client():
    text = SHIM_INSTALLER.read_text()
    assert 'BROKER="${2:-/opt/infratak/broker/takwerx_brokerctl.py}"' in text
