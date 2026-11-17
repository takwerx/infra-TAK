"""ops #845: Guard Dog alert texts (SMS) never left the box.

The console answers HTTPS only on 127.0.0.1:5001 (gunicorn runs with --certfile).
scripts/guarddog/sms_send.py posted to plain http://, got no answer, and hid the error
(`except Exception: pass`). The Test SMS button calls the provider directly, so it passed
while every real alert text was dropped.

sms_send.py now does what send-alert-email.sh does: HTTPS first (loopback, no certificate
check), then HTTP only when HTTPS got no answer at all, and one line in the journal
(logger -t guarddog-sms) when nothing got through.

These tests run the real script against a real TLS listener, a real plain listener and
no listener. They fail on dev 22e58b1 (the TLS case sends nothing).
"""
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'guarddog' / 'sms_send.py'


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope='module')
def cert(tmp_path_factory):
    if not shutil.which('openssl'):
        pytest.skip('openssl not available')
    d = tmp_path_factory.mktemp('cert')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-keyout', str(d / 'k.pem'), '-out', str(d / 'c.pem')],
                   check=True, capture_output=True, timeout=60)
    return str(d / 'c.pem'), str(d / 'k.pem')


class _Console:
    """A stand-in for the console's /api/guarddog/send-sms. Records what it receives."""

    def __init__(self, tls_cert=None, status=200):
        self.received = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get('Content-Length') or 0)
                outer.received.append((self.path, json.loads(self.rfile.read(n) or b'{}')))
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"success": true}' if status == 200 else b'{"error": "x"}')

            def log_message(self, *a):
                pass

        self.port = _free_port()
        self.httpd = HTTPServer(('127.0.0.1', self.port), H)
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def run(tmp_path):
    """Run sms_send.py with CONSOLE_PORT=port and a fake `logger` that records its argv."""
    stubs = tmp_path / 'bin'
    stubs.mkdir()
    logfile = tmp_path / 'logger.txt'
    (stubs / 'logger').write_text('#!/bin/sh\necho "$@" >> "%s"\n' % logfile)
    (stubs / 'logger').chmod(0o755)
    body = tmp_path / 'body.txt'
    body.write_text('disk is 95% full')

    def _run(port):
        env = {'PATH': '%s:/usr/bin:/bin' % stubs, 'CONSOLE_PORT': str(port)}
        r = subprocess.run([sys.executable, str(SCRIPT), 'Disk alert', str(body)],
                           capture_output=True, text=True, timeout=60, env=env)
        logged = logfile.read_text() if logfile.exists() else ''
        return r, logged
    return _run


def test_text_reaches_a_console_that_answers_https_only(cert, run):
    """The real case: gunicorn with --certfile. Fails on dev 22e58b1: nothing arrives."""
    with _Console(tls_cert=cert) as c:
        r, logged = run(c.port)
    assert c.received == [('/api/guarddog/send-sms',
                           {'subject': 'Disk alert', 'body': 'disk is 95% full'})]
    assert r.returncode == 0, r.stderr
    assert logged == ''


def test_text_reaches_a_console_that_runs_without_a_certificate(run):
    """A console on plain HTTP still works (HTTP is tried when HTTPS got no answer)."""
    with _Console() as c:
        r, logged = run(c.port)
    assert len(c.received) == 1 and c.received[0][1]['subject'] == 'Disk alert'
    assert r.returncode == 0, r.stderr
    assert logged == ''


def test_failure_is_logged_when_the_console_cannot_be_reached(run):
    """Before the fix this printed and logged nothing, so an operator could not tell."""
    r, logged = run(_free_port())            # nothing listens here
    assert r.returncode == 3
    assert 'NOT SENT' in r.stderr and 'Disk alert' in r.stderr
    assert 'guarddog-sms' in logged and 'NOT SENT' in logged and 'Disk alert' in logged


def test_no_second_post_when_the_console_answered_with_an_error(cert, run):
    """An HTTP status (even 400 or 500) means the console answered. Asking again over HTTP
    could send the same text twice, so the script logs it and stops."""
    with _Console(tls_cert=cert, status=400) as c:
        r, logged = run(c.port)
    assert len(c.received) == 1
    assert r.returncode == 3
    assert 'HTTP 400' in r.stderr and 'NOT SENT' in logged


def test_https_is_tried_before_http():
    src = SCRIPT.read_text()
    assert src.index('_post("https"') < src.index('_post("http"')
    assert 'http://127.0.0.1:5001' not in src


def test_no_arguments_is_a_quiet_no_op():
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and r.stdout == '' and r.stderr == ''
