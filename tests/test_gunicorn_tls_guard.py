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
"""A client that resets TCP before the TLS handshake no longer kills the console
worker (v10.2.23, ops #109).

Field (nuc, Rocky 9): `Exception in worker process` from gthread's
enqueue_req -> conn.init() -> ssl_wrap_socket, `ConnectionResetError: [Errno 104]`
or `ssl.SSLError: Closed before TLS handshake with data in recv buffer`, 9 and 16
times in ~7 minutes. The live tests below run a REAL gunicorn gthread worker with
TLS and reset connections at it, with and without the guard.
"""

import os
import pathlib
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import gunicorn_tls_guard as guard  # noqa: E402

APP = (REPO / 'app.py').read_text(encoding='utf-8')


# ── unit: the wrapper ────────────────────────────────────────────────────────

class _Log:
    def __init__(self):
        self.lines = []

    def warning(self, msg, *args):
        self.lines.append(msg % args)


class _Conn:
    def __init__(self, exc=None, client=('203.0.113.7', 40123)):
        self.exc = exc
        self.client = client
        self.closed = False

    def init(self):
        if self.exc:
            raise self.exc

    def close(self):
        self.closed = True


def _worker_cls():
    class Worker:
        def __init__(self):
            self.nr_conns = 1          # accept() counted the connection
            self.log = _Log()
            self.submitted = []

        def enqueue_req(self, conn):   # same shape as gunicorn 23.0.0 gthread
            conn.init()
            self.submitted.append(conn)
    return Worker


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    guard._seen.clear()
    yield
    guard._seen.clear()


@pytest.mark.parametrize('exc', [
    ConnectionResetError(104, 'Connection reset by peer'),
    ssl.SSLError('Closed before TLS handshake with data in recv buffer.'),
    OSError(107, 'Transport endpoint is not connected'),
])
def test_reset_before_handshake_drops_only_that_connection(exc):
    cls = _worker_cls()
    assert guard.install(cls) is True
    w, conn = cls(), _Conn(exc)
    w.enqueue_req(conn)                                   # must not raise
    assert conn.closed and w.nr_conns == 0 and w.submitted == []
    assert len(w.log.lines) == 1
    assert '203.0.113.7:40123' in w.log.lines[0]
    assert type(exc).__name__ in w.log.lines[0]


def test_healthy_connection_is_untouched():
    cls = _worker_cls()
    guard.install(cls)
    w, conn = cls(), _Conn()
    w.enqueue_req(conn)
    assert w.submitted == [conn] and not conn.closed and w.nr_conns == 1
    assert w.log.lines == []


def test_non_socket_errors_still_surface():
    # Only OSError is a dead client; anything else is a bug and must not be hidden.
    cls = _worker_cls()
    guard.install(cls)
    with pytest.raises(RuntimeError):
        cls().enqueue_req(_Conn(RuntimeError('bug')))


def test_install_is_idempotent():
    cls = _worker_cls()
    guard.install(cls)
    once = cls.enqueue_req
    guard.install(cls)
    assert cls.enqueue_req is once


def test_log_is_rate_limited_per_address():
    cls = _worker_cls()
    guard.install(cls)
    w = cls()
    for _ in range(50):
        w.nr_conns += 1
        w.enqueue_req(_Conn(ConnectionResetError(104, 'reset')))
    w.enqueue_req(_Conn(ConnectionResetError(104, 'reset'), client=('198.51.100.9', 1)))
    assert len(w.log.lines) == 2          # one per address, not one per connection
    assert w.nr_conns == 0

    # next window: one line carrying the count it held back
    guard._seen['203.0.113.7'][0] -= guard.LOG_WINDOW_S + 1
    w.enqueue_req(_Conn(ConnectionResetError(104, 'reset')))
    assert '+49 more from this address' in w.log.lines[-1]


def test_ipv6_peer_is_bracketed():
    assert guard._peer(_Conn(client=('2001:db8::1', 443, 0, 0)))[1] == '[2001:db8::1]:443'


def test_install_without_gunicorn_is_a_no_op():
    class NoEnqueue:
        pass
    assert guard.install(NoEnqueue) is False


def test_app_installs_the_guard_at_import():
    # Must run at import (gunicorn loads the app in the worker BEFORE worker.run()),
    # not inside a function or thread that might run later.
    assert '\nimport gunicorn_tls_guard\nif gunicorn_tls_guard.install():' in APP


# ── live: a real gunicorn gthread worker with TLS ────────────────────────────

_TINY_APP = '''
import os, sys
sys.path.insert(0, os.environ["GUARD_REPO"])
if os.environ.get("TLS_GUARD") == "1":
    import gunicorn_tls_guard
    gunicorn_tls_guard.install()

def app(environ, start_response):
    body = str(os.getpid()).encode()
    start_response("200 OK", [("Content-Type", "text/plain"),
                              ("Content-Length", str(len(body)))])
    return [body]
'''


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    pytest.importorskip('gunicorn')
    if not shutil.which('openssl'):
        pytest.skip('openssl CLI not available')
    cert, key = tmp_path / 'c.crt', tmp_path / 'c.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                    '-keyout', str(key), '-out', str(cert)],
                   check=True, capture_output=True)
    (tmp_path / 'tinyapp.py').write_text(_TINY_APP)
    procs = []

    def start(guarded):
        port = _free_port()
        errlog = tmp_path / f'gunicorn-{port}.log'
        env = dict(os.environ, GUARD_REPO=str(REPO), TLS_GUARD='1' if guarded else '0')
        p = subprocess.Popen(
            [sys.executable, '-m', 'gunicorn', '--chdir', str(tmp_path),
             '--bind', f'127.0.0.1:{port}', '--workers', '1', '--threads', '4',
             '--certfile', str(cert), '--keyfile', str(key), 'tinyapp:app'],
            env=env, stdout=subprocess.DEVNULL, stderr=open(errlog, 'w'))
        procs.append(p)
        ctx = ssl.create_default_context(cafile=str(cert))
        for _ in range(100):
            try:
                _get_pid(port, ctx)
                break
            except OSError:
                time.sleep(0.1)
        return port, ctx, errlog

    yield start
    for p in procs:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


def _get_pid(port, ctx):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname='127.0.0.1') as s:
            s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
            data = b''
            while chunk := s.recv(4096):
                data += chunk
    return int(data.split(b'\r\n\r\n', 1)[1])


def _reset_before_handshake(port, payload=b''):
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    if payload:
        s.sendall(payload)
    # SO_LINGER {on, 0}: close() sends RST instead of FIN.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    s.close()


def _attack(port):
    for i in range(20):
        # bare reset (ConnectionResetError) and reset after a partial ClientHello
        # (SSLError "Closed before TLS handshake with data in recv buffer")
        _reset_before_handshake(port, b'' if i % 2 else b'\x16\x03\x01\x00')
        time.sleep(0.05)
    time.sleep(0.5)


def test_live_worker_survives_resets_with_guard(server):
    port, ctx, errlog = server(guarded=True)
    pid = _get_pid(port, ctx)
    _attack(port)
    assert _get_pid(port, ctx) == pid, errlog.read_text()
    log = errlog.read_text()
    assert 'Exception in worker process' not in log
    assert '[tls-guard] dropped a connection from 127.0.0.1:' in log


def test_live_reproduces_the_crash_without_guard(server):
    # Proves the live test above exercises the field bug: the stock worker dies.
    port, ctx, errlog = server(guarded=False)
    pid = _get_pid(port, ctx)
    _attack(port)
    for _ in range(100):           # the arbiter respawns the worker
        try:
            new_pid = _get_pid(port, ctx)
            break
        except OSError:
            time.sleep(0.1)
    log = errlog.read_text()
    assert 'Exception in worker process' in log
    assert 'ssl_wrap_socket' in log            # the field stack, not some other death
    assert new_pid != pid
