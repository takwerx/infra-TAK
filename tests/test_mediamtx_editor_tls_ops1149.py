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
"""ops #1149: the web editor on a remote MediaMTX host takes TLS on its own port.

Caddy on the console reaches that editor over the network. The stream site code
(mediamtx_ldap_overlay.py) makes the editor's server take TLS with the stream certificate
that is on the host already, and still take plain http on the same port (an older console
keeps working).

What runs here for real: the shipped handler in a werkzeug server on a loopback port, a
certificate made with `openssl`, and clients that speak plain http and TLS to it.
On a tree without the change the editor answers plain http only and the TLS tests fail.
"""

import http.client
import importlib.util
import pathlib
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

flask = pytest.importorskip('flask')
from werkzeug.serving import WSGIRequestHandler, make_server  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
NAME = 'stream.example.org'

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='needs the openssl program')


def _client_ctx(ca=None):
    """A client that checks the certificate against `ca` (None: the machine's own store)."""
    ctx = ssl.create_default_context(cafile=str(ca) if ca else None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _make_cert(folder, tag):
    crt, key = folder / f'{tag}.crt', folder / f'{tag}.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-keyout', str(key), '-out', str(crt), '-subj', f'/CN={NAME}',
                    '-addext', f'subjectAltName=DNS:{NAME}'],
                   check=True, capture_output=True, timeout=120)
    return crt, key


@pytest.fixture(scope='module')
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp('certs')
    return _make_cert(d, 'first'), _make_cert(d, 'second')


@pytest.fixture
def overlay():
    spec = importlib.util.spec_from_file_location('overlay_ops1149', REPO / 'mediamtx_ldap_overlay.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Editor:
    """A small Flask app served the way the editor is, with the overlay's handler when the
    tree has one (a tree without the change serves plain http only)."""

    def __init__(self, overlay, folder):
        self.overlay = overlay
        self.crt, self.key = folder / 'stream.crt', folder / 'stream.key'
        overlay.EDITOR_TLS_CERT, overlay.EDITOR_TLS_KEY = str(self.crt), str(self.key)
        app = flask.Flask('editor')

        @app.route('/who')
        def who():
            return flask.request.remote_addr + ' ' + flask.request.headers.get('Host', '')

        make = getattr(overlay, '_editor_tls_handler', None)
        self.server = make_server('127.0.0.1', 0, app, threaded=True,
                                  request_handler=make(WSGIRequestHandler) if make else WSGIRequestHandler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def install(self, pair):
        """Put a certificate where the editor looks (what the console's copy does on a host)."""
        for src, dst in zip(pair, (self.crt, self.key)):
            tmp = dst.with_suffix('.new')
            shutil.copyfile(src, tmp)
            tmp.replace(dst)

    def plain(self, timeout=10):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=timeout)
        c.request('GET', '/who', headers={'Host': NAME})
        r = c.getresponse()
        body = r.read().decode()
        c.close()
        return r.status, body

    def tls(self, ca, timeout=10):
        """One https request, the certificate checked against `ca` and the stream name, the
        way Caddy on the console does. Returns (status, body, the certificate served)."""
        ctx = _client_ctx(ca)
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=NAME)
        try:
            der = s.getpeercert(binary_form=True)
            s.sendall(f'GET /who HTTP/1.0\r\nHost: {NAME}\r\n\r\n'.encode())
            data = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        head, _, body = data.partition(b'\r\n\r\n')
        return int(head.split()[1]), body.decode(), der

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def editor(overlay, tmp_path):
    e = Editor(overlay, tmp_path)
    yield e
    e.close()


# ── the proof test ─────────────────────────────────────────────────────────────────────────

def test_editor_answers_https_with_the_stream_certificate(editor, certs):
    """What Caddy on the console does after the change: https to the editor's port, the
    certificate checked against the stream name."""
    first, _ = certs
    editor.install(first)
    status, body, der = editor.tls(first[0])
    assert status == 200
    assert body == f'127.0.0.1 {NAME}', 'the editor must still see the peer address (its peer pin reads it)'
    assert ssl.DER_cert_to_PEM_cert(der).strip() == first[0].read_text().strip()


def test_plain_http_still_works_on_the_same_port(editor, certs):
    """An older console (a rollback) speaks plain http to the same port."""
    editor.install(certs[0])
    assert editor.plain() == (200, f'127.0.0.1 {NAME}')
    assert editor.tls(certs[0][0])[0] == 200
    assert editor.plain()[0] == 200


def test_a_renewed_certificate_is_served_without_a_restart(editor, certs):
    first, second = certs
    editor.install(first)
    assert editor.tls(first[0])[0] == 200
    editor.install(second)
    status, _, der = editor.tls(second[0])
    assert status == 200
    assert ssl.DER_cert_to_PEM_cert(der).strip() == second[0].read_text().strip()
    with pytest.raises(ssl.SSLError):
        editor.tls(first[0])       # the old certificate is no longer the one served


def test_a_certificate_for_another_name_is_refused_by_the_client(editor, certs):
    """The check Caddy makes: this is why the console sets the stream name on the upstream."""
    editor.install(certs[0])
    ctx = _client_ctx(certs[0][0])
    raw = socket.create_connection(('127.0.0.1', editor.port), timeout=10)
    with pytest.raises(ssl.SSLCertVerificationError):
        ctx.wrap_socket(raw, server_hostname='other.example.org')
    raw.close()
    assert editor.plain()[0] == 200


def test_no_certificate_on_the_host_gives_tls_no_answer_and_plain_still_works(editor, certs):
    with pytest.raises((ssl.SSLError, OSError)):
        editor.tls(certs[0][0])
    assert editor.plain()[0] == 200


def test_a_broken_key_file_gives_tls_no_answer_and_plain_still_works(editor, certs):
    editor.install(certs[0])
    editor.key.write_text('not a key\n')
    with pytest.raises((ssl.SSLError, OSError)):
        editor.tls(certs[0][0])
    assert editor.plain()[0] == 200
    editor.install(certs[0])       # put right again: served without a restart
    assert editor.tls(certs[0][0])[0] == 200


def test_a_peer_that_starts_tls_and_stalls_holds_up_nobody(editor, certs, overlay):
    editor.install(certs[0])
    overlay.EDITOR_TLS_HANDSHAKE_SECONDS = 2
    stalled = socket.create_connection(('127.0.0.1', editor.port), timeout=10)
    stalled.sendall(b'\x16')                 # looks like a handshake, then nothing
    silent = socket.create_connection(('127.0.0.1', editor.port), timeout=10)   # sends nothing at all
    try:
        t0 = time.time()
        assert editor.plain(timeout=5)[0] == 200
        assert editor.tls(certs[0][0], timeout=5)[0] == 200
        assert time.time() - t0 < 1.5, 'requests waited for the stalled peer'
        stalled.settimeout(8)
        assert stalled.recv(64) == b'', 'the stalled handshake was not dropped'
    finally:
        stalled.close()
        silent.close()


def test_bytes_that_are_neither_get_the_plain_server_error_not_a_crash(editor, certs):
    editor.install(certs[0])
    s = socket.create_connection(('127.0.0.1', editor.port), timeout=10)
    s.sendall(b'\x16\x03\x01\x00\x05hello')      # a handshake record with nonsense in it
    s.settimeout(8)
    try:
        s.recv(256)
    except OSError:
        pass
    s.close()
    assert editor.plain()[0] == 200 and editor.tls(certs[0][0])[0] == 200


# ── how the editor gets it ─────────────────────────────────────────────────────────────────

def test_the_overlay_puts_the_handler_on_app_run(overlay):
    seen = {}

    class App:
        def run(self, *a, **k):
            seen['a'], seen['k'] = a, dict(k)

    app = App()
    overlay._editor_tls_install(app)
    app.run(host='0.0.0.0', port=5080, debug=False)       # the editor's own call
    assert seen['k']['host'] == '0.0.0.0' and seen['k']['port'] == 5080
    assert issubclass(seen['k']['request_handler'], WSGIRequestHandler)
    assert seen['k']['request_handler'].__name__ == 'TlsOrPlainHandler'
    app.run(request_handler=WSGIRequestHandler)           # a handler the editor names is kept
    assert seen['k']['request_handler'] is WSGIRequestHandler
    app.run(ssl_context='adhoc')                          # an editor that does TLS itself keeps its own way
    assert 'request_handler' not in seen['k']


def test_install_is_the_first_thing_the_overlay_does():
    src = (REPO / 'mediamtx_ldap_overlay.py').read_text(encoding='utf-8')
    body = src[src.index('def apply_ldap_overlay(app):'):]
    assert body.index('_editor_tls_install(app)') < body.index('@app.before_request')


def test_default_paths_are_where_the_console_copies_the_stream_certificate():
    src = (REPO / 'mediamtx_ldap_overlay.py').read_text(encoding='utf-8')
    app = (REPO / 'app.py').read_text(encoding='utf-8')
    for path in ('/etc/mediamtx/certs/stream.crt', '/etc/mediamtx/certs/stream.key'):
        assert path in src and path in app


# ── the console side: ask first, then Caddy ────────────────────────────────────────────────

import ast  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import tempfile  # noqa: E402
import types  # noqa: E402

APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
HOST = '10.0.0.5'
CONSOLE_NAMES = (
    '_MEDIAMTX_REMOTE_EDITOR_TLS_FILE', '_mediamtx_remote_editor_tls',
    '_MEDIAMTX_REMOTE_EDITOR_TLS_REASONS', '_mediamtx_remote_editor_tls_probe',
    '_mediamtx_remote_editor_tls_road', '_startup_converge_mediamtx_remote_editor_tls',
    'MEDIAMTX_OPEN_PATHS', '_MEDIAMTX_VHOST_MARKER', '_CADDY_STRIP_AUTHENTIK_HEADERS',
    '_emit_mediamtx_site', '_MEDIAMTX_IDENTITY_MARKER', '_MEDIAMTX_AK_COPY_HEADERS',
    # ops #1081, ops #1108: the one writer of every forward_auth block
    '_caddy_forward_auth_lines', '_CADDY_FORWARD_AUTH_URI', '_CADDY_FORWARD_AUTH_PIN', '_CADDY_APP_HEADER',
    '_CADDY_APP_LOCK_MATCHER', '_CADDY_APP_LOCK_TEXT', '_CADDY_APP_SLUG_RE',
)


def _src(*names):
    parts = []
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in names:
            parts.append(ast.get_source_segment(APP, n))
        elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


class Console:
    """app.py's side of the hop. Its connection to `HOST:5080` lands on the test editor, and
    its trust store is the test certificate (None: the machine's own store, which does not
    know that certificate)."""

    def __init__(self, tmp, port, ca, fqdn='example.org'):
        self.cfg_dir = tmp / 'config'
        self.cfg_dir.mkdir()
        self.cfg = {'target_mode': 'remote', 'deployed': True, 'remote': {'host': HOST}}
        self.settings = {'fqdn': fqdn, 'mediamtx_deployment': self.cfg}
        self.log, self.dialed, self.caddy = [], [], []
        self.registry_ready = threading.Event()
        self.registry_ready.set()

        def connect(addr, timeout=None):
            self.dialed.append(addr)
            assert addr == (HOST, 5080)
            return socket.create_connection(('127.0.0.1', port), timeout=timeout)

        ns = {
            'os': os, 're': re, 'tempfile': tempfile, 'CONFIG_DIR': str(self.cfg_dir),
            'socket': types.SimpleNamespace(create_connection=connect),
            'ssl': types.SimpleNamespace(
                SSLError=ssl.SSLError, SSLCertVerificationError=ssl.SSLCertVerificationError,
                TLSVersion=ssl.TLSVersion, create_default_context=lambda: _client_ctx(ca)),
            '_get_module_deployment_config': lambda s, k: self.cfg,
            '_get_service_domain': lambda s, m: NAME,
            '_pub_url': lambda h: 'https://' + h,
            'generate_caddyfile': lambda *a: self.caddy.append('generate'),
            '_caddy_reload_if_changed': lambda timeout=60: (self.caddy.append('reload'), (True, ''))[1],
            '_CADDY_REGISTRY_READY': self.registry_ready,
        }
        exec(_src(*CONSOLE_NAMES), ns)
        self.ns = ns

    def road(self):
        fn = self.ns.get('_mediamtx_remote_editor_tls_road')
        return fn(self.settings, self.cfg, self.log.append) if fn else None

    def start(self):
        fn = self.ns.get('_startup_converge_mediamtx_remote_editor_tls')
        return fn(self.settings, self.cfg, self.log.append) if fn else None

    def marked(self):
        p = self.cfg_dir / 'mediamtx_remote_editor_tls'
        return p.read_text().strip() if p.exists() else None

    def site(self):
        """The stream site Caddy would get now."""
        lines = []
        tls = self.ns.get('_mediamtx_remote_editor_tls')
        kw = {'editor_tls': tls(self.settings)} if tls else {}
        self.ns['_emit_mediamtx_site'](lines, NAME, f'{HOST}:5080', '127.0.0.1:9090', None,
                                       lambda indent: None, lambda url: None, **kw)
        return '\n'.join(lines)


PLAIN_HOP = f'reverse_proxy {HOST}:5080'
TLS_HOP = (f'reverse_proxy https://{HOST}:5080 {{\n'
           '            header_up Host {hostport}\n'
           '            transport http {\n'
           f'                tls_server_name {NAME}\n'
           '            }\n'
           '        }')


def test_console_start_changes_caddy_to_https_after_the_editor_answered_tls(editor, certs, tmp_path):
    """The customer's update: the console starts on the new version, nothing is pressed."""
    editor.install(certs[0])
    c = Console(tmp_path, editor.port, certs[0][0])
    assert PLAIN_HOP in c.site()
    assert c.start() == 'switched'
    assert c.marked() == HOST and c.caddy == ['generate', 'reload']
    site = c.site()
    assert site.count(TLS_HOP) == 4, site            # the three open paths and the signed-in route
    assert PLAIN_HOP not in site and f'reverse_proxy http://{HOST}' not in site
    assert any('Caddy now speaks https to it' in ln for ln in c.log)


def test_second_start_changes_nothing(editor, certs, tmp_path):
    editor.install(certs[0])
    c = Console(tmp_path, editor.port, certs[0][0])
    c.start()
    c.caddy.clear()
    c.log.clear()
    assert c.start() == 'on' and c.caddy == [] and c.log == []


def test_caddy_change_waits_for_the_modules_at_an_early_start(editor, certs, tmp_path):
    editor.install(certs[0])
    c = Console(tmp_path, editor.port, certs[0][0])
    c.registry_ready.clear()
    assert c.start() == 'switched'
    assert c.caddy == ['generate'] and any('queued' in ln for ln in c.log)


def test_a_host_without_a_certificate_stays_on_plain_http(editor, certs, tmp_path):
    c = Console(tmp_path, editor.port, certs[0][0])
    assert c.start() == 'plain'
    assert c.marked() is None and c.caddy == []
    assert c.site().count(PLAIN_HOP) == 4 and 'https://' + HOST not in c.site()
    assert any('stays plain http' in ln and 'answered without TLS' in ln for ln in c.log)


def test_a_certificate_the_console_does_not_trust_stays_on_plain_http(editor, certs, tmp_path):
    editor.install(certs[0])
    c = Console(tmp_path, editor.port, None)           # the machine's own trust store
    assert c.road() == 'plain' and c.marked() is None
    assert any('not one this box trusts' in ln for ln in c.log)


def test_a_host_that_cannot_be_reached_changes_nothing(certs, tmp_path):
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()                                          # nothing listens here now
    c = Console(tmp_path, port, certs[0][0])
    assert c.road() == 'plain' and c.marked() is None
    assert any('could not open port 5080' in ln for ln in c.log)


def test_a_later_failed_check_never_goes_back_to_plain_http(editor, certs, tmp_path):
    editor.install(certs[0])
    c = Console(tmp_path, editor.port, certs[0][0])
    assert c.start() == 'switched'
    editor.crt.unlink()                                # the certificate on the host is gone
    c.caddy.clear()
    assert c.start() == 'kept'
    assert c.marked() == HOST and c.caddy == []
    assert c.site().count(TLS_HOP) == 4 and PLAIN_HOP not in c.site()
    assert any('Caddy stays on https' in ln for ln in c.log)


def test_no_name_no_question(editor, certs, tmp_path):
    editor.install(certs[0])
    c = Console(tmp_path, editor.port, certs[0][0], fqdn='')
    assert c.road() == 'plain' and c.dialed == [] and c.marked() is None


def test_the_mark_is_for_one_host_only(editor, certs, tmp_path):
    editor.install(certs[0])
    c = Console(tmp_path, editor.port, certs[0][0])
    c.start()
    c.cfg['remote']['host'] = '10.0.0.9'               # MediaMTX moved to another host
    assert c.ns['_mediamtx_remote_editor_tls'](c.settings) is False
    c.cfg['target_mode'] = 'local'
    assert c.ns['_mediamtx_remote_editor_tls'](c.settings) is False


def test_site_without_the_mark_is_the_site_from_before(tmp_path):
    c = Console(tmp_path, 1, None)
    lines = []
    c.ns['_emit_mediamtx_site'](lines, NAME, f'{HOST}:5080', '127.0.0.1:9090', None,
                                lambda indent: None, lambda url: None)
    assert '\n'.join(lines) == c.site() and c.site().count(PLAIN_HOP) == 4


def _fn(name):
    return next(ast.get_source_segment(APP, n) for n in TREE.body
                if isinstance(n, ast.FunctionDef) and n.name == name)


def test_where_the_console_asks():
    gen = _fn('generate_caddyfile')
    assert 'editor_tls=_mediamtx_remote_editor_tls(settings))' in gen
    start = _fn('_startup_converge_mediamtx_remote_hls_port')
    assert start.index('_startup_converge_mediamtx_remote_editor_tls(') < start.index('_mediamtx_remote_hls_port(settings, cfg')
    dep = _fn('_run_mediamtx_deploy_remote')
    cert = dep.index("mv /tmp/mediamtx_stream.crt /etc/mediamtx/certs/stream.crt")
    ask = dep.index('_mediamtx_remote_editor_tls_road(settings, cfg, plog)')
    port = dep.index('_mediamtx_remote_hls_port(settings, cfg, plog)')
    assert cert < ask < port, 'the deploy asks after the certificate is on the host and before the port step'
