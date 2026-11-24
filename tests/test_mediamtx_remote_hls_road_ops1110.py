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
"""ops #1110: video on the stream site of a REMOTE MediaMTX host goes through the sign-in.

On one box, Caddy sends the stream site's /hls-proxy/* through the Authentik sign-in to the
web editor, whose stream site applies the private/public rule and fetches from MediaMTX
itself. For MediaMTX on a remote host it was sent straight to MediaMTX on that host. A
console start now asks the host if the editor there serves /hls-proxy/, and only then
writes the Caddy site without the direct road.

What runs here for real:
  * the check the console sends to the host (`python3 -c ...` under sh), against
  * the shipped stream site code (mediamtx_ldap_overlay.py) in a Flask server, in front of
  * a small HTTP server that answers like MediaMTX's HLS port, and
  * `_emit_mediamtx_site` with the `_mtx_direct = ...` statement cut out of
    generate_caddyfile, so the Caddy site is the one this tree would write.

On a tree without the change, a console start changes nothing and the tests fail on the
Caddy site still holding the direct road to MediaMTX.
"""

import ast
import http.server
import importlib.util
import os
import pathlib
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import threading

import pytest

flask = pytest.importorskip('flask')
from werkzeug.serving import make_server  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

HOST = '10.0.0.5'                 # the remote MediaMTX host
STREAM = 'stream.example.org'
AK_UP = '127.0.0.1:9090'
DIRECT = 'handle_path /hls-proxy/*'

NAMES = (
    # this change
    '_MEDIAMTX_REMOTE_HLS_ROAD_FILE', '_mediamtx_remote_hls_via_editor', '_mediamtx_hls_direct',
    '_MEDIAMTX_REMOTE_HLS_ROAD_CHECK_PY', '_MEDIAMTX_REMOTE_HLS_ROAD_REASONS',
    '_mediamtx_remote_hls_road_check', '_mediamtx_remote_hls_road',
    '_startup_converge_mediamtx_remote_hls_road',
    # what it builds on
    'MEDIAMTX_OPEN_PATHS', '_MEDIAMTX_VHOST_MARKER', '_CADDY_STRIP_AUTHENTIK_HEADERS',
    '_emit_mediamtx_site', '_caddy_vhost_block', 'CADDYFILE_USER_BLOCKS_MARKER',
    '_MEDIAMTX_IDENTITY_MARKER', '_MEDIAMTX_AK_COPY_HEADERS',
)


def _fn_src(name):
    return next((ast.get_source_segment(APP, n) for n in TREE.body
                 if isinstance(n, ast.FunctionDef) and n.name == name), None)


def _src(*names):
    """Top-level defs/assignments from app.py, in file order. A name app.py does not have
    is skipped, so the tests run (and fail on the outcome) on a tree without this change."""
    parts = []
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in names:
            parts.append(ast.get_source_segment(APP, n))
        elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in names for t in n.targets):
            parts.append(ast.get_source_segment(APP, n))
    return '\n\n'.join(parts)


GEN_SRC = _fn_src('generate_caddyfile')
# The statement generate_caddyfile itself uses to choose the road, as shipped.
MTX_DIRECT_STMT = re.search(r'(?m)^\s+(_mtx_direct = [^\n]+)\n\s+_emit_mediamtx_site\(', GEN_SRC).group(1)


# ── a fake MediaMTX HLS port ──────────────────────────────────────────────────────

class FakeMediaMTX:
    """Answers like MediaMTX's HLS listener. mode: 'ok' (a playlist for a live stream, 404
    for a stream that does not exist), 'tls' (HTTP 400: a plain request to a TLS listener),
    'password' (HTTP 401)."""

    def __init__(self):
        self.mode = 'ok'
        self.live = ('cam1', 'secret')
        self.paths = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                fake.paths.append(self.path)
                name = self.path.split('?')[0].strip('/').rsplit('/', 1)[0]
                if fake.mode == 'tls':
                    code, body = 400, b'Client sent an HTTP request to an HTTPS server.\n'
                elif fake.mode == 'password':
                    code, body = 401, b''
                elif name in fake.live:
                    code, body = 200, b'#EXTM3U\n'
                else:
                    code, body = 404, b''
                self.send_response(code)
                self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(app):
    srv = make_server('127.0.0.1', 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ── the remote host: the shipped stream site in front of the fake MediaMTX ─────────

class RemoteHost:
    """What the console reaches over SSH. `editor` picks what listens on the editor port:
    'stream-site' (the editor with the shipped mediamtx_ldap_overlay.py), 'plain' (an editor
    without it), 'down' (nothing listens)."""

    def __init__(self, tmp_path, monkeypatch, editor='stream-site'):
        self.mediamtx = FakeMediaMTX()
        self.mediamtx_up = True
        self.reachable = True
        self.runs = []
        self.servers = []
        yml = tmp_path / 'mediamtx.yml'
        yml.write_text('hlsEncryption: no\nhlsServerCert:\nauthInternalUsers:\n'
                       '- user: hlsviewer\n  pass: s3cretPW\n')
        monkeypatch.setenv('MEDIAMTX_CONFIG', str(yml))
        app = flask.Flask('remote-editor')
        app.secret_key = 'test'
        if editor == 'stream-site':
            spec = importlib.util.spec_from_file_location('overlay_ops1110', REPO / 'mediamtx_ldap_overlay.py')
            ov = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ov)
            vis = tmp_path / 'stream_visibility.json'
            vis.write_text('{"secret": "private"}')
            monkeypatch.setattr(ov, 'VISIBILITY_FILE', str(vis))
            real_urlopen = ov.urllib.request.urlopen
            host = self

            def to_fake_mediamtx(req, timeout=None, context=None):
                # The stream site asks MediaMTX on its own loopback, port 8888.
                port = host.mediamtx.port if host.mediamtx_up else host.closed_port
                req.full_url = req.full_url.replace('127.0.0.1:8888', '127.0.0.1:%d' % port)
                return real_urlopen(req, timeout=timeout)
            monkeypatch.setattr(ov.urllib.request, 'urlopen', to_fake_mediamtx)
            ov.apply_ldap_overlay(app)
        self.closed_port = _free_port()
        if editor == 'down':
            self.editor_port = self.closed_port
        else:
            srv = _serve(app)
            self.servers.append(srv)
            self.editor_port = srv.server_address[1]
        # `python3` for the command the console sends: this interpreter.
        self.bin = str(tmp_path / 'hostbin')
        os.makedirs(self.bin)
        os.symlink(sys.executable, os.path.join(self.bin, 'python3'))

    def run(self, cfg, cmd, timeout=120, log_fn=None):
        """_module_run: the command runs under sh, with the editor's port put in."""
        self.runs.append(cmd)
        if not self.reachable:
            return False, 'ssh: connect to host 10.0.0.5 port 22: Connection timed out'
        cmd = cmd.replace('127.0.0.1:5080', '127.0.0.1:%d' % self.editor_port)
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get('PATH', ''))
        r = subprocess.run(['sh', '-c', cmd], capture_output=True, text=True, timeout=90, env=env)
        return r.returncode == 0, (r.stdout or '') + (r.stderr or '')

    def close(self):
        for srv in self.servers:
            srv.shutdown()
        self.mediamtx.close()


@pytest.fixture
def host(tmp_path, monkeypatch):
    h = RemoteHost(tmp_path, monkeypatch)
    yield h
    h.close()


# ── the console ───────────────────────────────────────────────────────────────────

AK_HEADERS = ('X-Authentik-Username', 'X-Authentik-Groups')


class Console:
    """The pieces of app.py this change uses, wired to a RemoteHost. The Caddyfile is a
    file here; generate_caddyfile is the MediaMTX part of the real one."""

    def __init__(self, tmp_path, host, authentik=True, remote_host=HOST):
        self.host = host
        self.authentik = authentik
        self.overlay_pass = 'current'     # what the ops #1107 pass says about the file on the host
        self.events = []
        self.log = []
        self.settings = {'fqdn': 'example.org'}
        self.deployment = {'target_mode': 'remote', 'deployed': True,
                           'remote': {'host': remote_host, 'ssh_user': 'fiops'}}
        self.config_dir = str(tmp_path / 'console-config')
        os.makedirs(self.config_dir, exist_ok=True)
        self.caddyfile = str(tmp_path / 'Caddyfile')
        self.registry_ready = threading.Event()
        self.registry_ready.set()
        self.reload_ok = True
        ns = {'re': re, 'os': os, 'shlex': shlex, 'tempfile': tempfile,
              'CONFIG_DIR': self.config_dir, 'CADDYFILE_PATH': self.caddyfile,
              'load_settings': lambda: dict(self.settings),
              '_get_module_deployment_config': lambda s, k: dict(self.deployment),
              '_module_run': self._run,
              '_startup_converge_mediamtx_overlay_remote': self._overlay_pass,
              '_read_priv': self._read, 'generate_caddyfile': self.generate,
              '_CADDY_REGISTRY_READY': self.registry_ready,
              '_caddy_reload_if_changed': self._reload,
              '_pub_url': lambda h, s=None: f'https://{h}' if h else ''}
        exec(compile(_src(*NAMES), 'app.py', 'exec'), ns)
        self.ns = ns
        self.generate()                   # the file the console wrote before this start
        self.events = []

    def _run(self, cfg, cmd, timeout=120, log_fn=None):
        self.events.append('ask-host')
        return self.host.run(cfg, cmd, timeout=timeout)

    def _overlay_pass(self, after=None):
        self.events.append('overlay-pass')
        return self.overlay_pass

    def _read(self, path):
        with open(path) as f:
            return f.read()

    def _reload(self, timeout=60):
        self.events.append('caddy-reload')
        return (True, '') if self.reload_ok else (False, 'adapt failed')

    @property
    def mtx_up(self):
        if self.deployment.get('target_mode') == 'remote':
            return '%s:5080' % self.deployment['remote']['host']
        return '127.0.0.1:5080'

    def direct(self):
        """generate_caddyfile's own choice of road, for this console's state."""
        scope = dict(self.ns, settings=dict(self.settings), _mtx_ak=self.authentik, mtx_up=self.mtx_up)
        exec(MTX_DIRECT_STMT, scope)
        return scope['_mtx_direct']

    def generate(self, settings=None):
        self.events.append('caddy-generate')
        lines = ['# infra-TAK - Auto-generated Caddyfile', '']

        def strip(indent):
            lines.extend(f'{indent}request_header -{h}' for h in AK_HEADERS)

        hls = ('%s:8888' % self.mtx_up.split(':')[0], False) if self.direct() else None
        self.ns['_emit_mediamtx_site'](lines, STREAM, self.mtx_up, AK_UP if self.authentik else None,
                                       hls, strip, lambda root: None, login_ok=True)
        text = '\n'.join(lines) + '\n' + self.ns['CADDYFILE_USER_BLOCKS_MARKER'] + '\n'
        if self.registry_ready.is_set():      # before the modules load the write is put off
            with open(self.caddyfile, 'w') as f:
                f.write(text)
        return text

    def site(self):
        return self.ns['_caddy_vhost_block'](self._read(self.caddyfile), self.ns['_MEDIAMTX_VHOST_MARKER'])

    def start(self):
        """A console start: the remote MediaMTX thread of _startup_migrations. On a tree
        without the change that thread is the ops #1107 pass alone."""
        fn = self.ns.get('_startup_converge_mediamtx_remote_hls_road')
        with _printed(self.log):
            return fn() if fn else self._overlay_pass()

    def mark(self):
        try:
            with open(os.path.join(self.config_dir, 'mediamtx_remote_hls_via_editor')) as f:
                return f.read()
        except OSError:
            return None


class _printed:
    """Collect what the code prints (the console's journal)."""

    def __init__(self, into):
        self.into = into

    def __enter__(self):
        import builtins
        self._b, self._real = builtins, builtins.print
        builtins.print = lambda *a, **k: self.into.append(' '.join(str(x) for x in a))

    def __exit__(self, *exc):
        self._b.print = self._real
        return False


def _need(console, name):
    fn = console.ns.get(name)
    assert fn is not None, 'this tree has no %s' % name
    return fn


# ── the proof: after a console start the Caddy site has no road around the sign-in ──

def test_console_start_sends_remote_video_through_the_sign_in(tmp_path, host):
    console = Console(tmp_path, host)
    assert DIRECT in console.site()            # how every console wrote it for a remote host
    result = console.start()
    site = console.site()
    assert DIRECT not in site and ':8888' not in site, (
        'after a console start the stream site of a remote MediaMTX host still sends '
        '/hls-proxy/* straight to MediaMTX, outside the sign-in (%s)' % result)
    assert result == 'switched'
    lines = site.split('\n')
    # /hls-proxy/* now falls into the catch-all: sign-in first, then the editor on the host.
    fa = lines.index(f'        forward_auth {AK_UP} {{')
    assert lines.index('        request_header /hls-proxy/* -Authorization') < fa
    assert f'        reverse_proxy {HOST}:5080' in lines[fa:]
    assert 'route /hls-proxy' not in site
    assert console.events.count('caddy-reload') == 1
    assert console.mark() == HOST + '\n'
    assert any('sign-in' in ln and HOST in ln for ln in console.log)


def test_caddy_changes_only_after_the_host_answered(tmp_path, host):
    console = Console(tmp_path, host)
    console.start()
    ev = console.events
    assert ev[0] == 'overlay-pass', 'the stream site file on the host must be current first'
    assert ev.index('ask-host') < ev.index('caddy-generate') < ev.index('caddy-reload')
    # The host was asked for a stream that does not exist, on the editor's own port, and
    # the stream site there asked MediaMTX: that answer is the proof.
    assert host.mediamtx.paths == ['/infratak-road-check/index.m3u8']
    assert len(host.runs) == 1 and 'sudo' not in host.runs[0]


@pytest.mark.parametrize('case, word', [
    ('editor-down', 'no-editor'),           # nothing listens on 5080
    ('editor-plain', 'no-route'),           # an editor without the stream site code
    ('mediamtx-tls', 'mediamtx-400'),       # the stream site speaks plain http to a TLS listener
    ('mediamtx-password', 'mediamtx-401'),  # MediaMTX wants a password from its own box
    ('mediamtx-down', 'mediamtx-down'),
    ('ssh-down', 'unreached'),
])
def test_a_host_that_cannot_serve_video_keeps_the_old_road(tmp_path, monkeypatch, case, word):
    editor = {'editor-down': 'down', 'editor-plain': 'plain'}.get(case, 'stream-site')
    host = RemoteHost(tmp_path, monkeypatch, editor=editor)
    try:
        if case == 'mediamtx-tls':
            host.mediamtx.mode = 'tls'
        elif case == 'mediamtx-password':
            host.mediamtx.mode = 'password'
        elif case == 'mediamtx-down':
            host.mediamtx_up = False
        elif case == 'ssh-down':
            host.reachable = False
        console = Console(tmp_path, host)
        before = console.site()
        check = _need(console, '_mediamtx_remote_hls_road_check')
        assert check(console.deployment) == word
        assert console.start() == 'direct'
        # Video would stop if Caddy pointed at an editor that cannot serve it.
        assert console.site() == before and DIRECT in before
        assert console.mark() is None
        assert 'caddy-generate' not in console.events and 'caddy-reload' not in console.events
        reason = console.ns['_MEDIAMTX_REMOTE_HLS_ROAD_REASONS'][word]
        assert any(reason in ln for ln in console.log), console.log
    finally:
        host.close()


@pytest.mark.parametrize('overlay_pass', ['none', 'unknown', 'held', 'failed'])
def test_nothing_is_asked_while_the_file_on_the_host_is_not_current(tmp_path, host, overlay_pass):
    console = Console(tmp_path, host)
    console.overlay_pass = overlay_pass
    _need(console, '_startup_converge_mediamtx_remote_hls_road')
    before = console.site()
    assert console.start() == overlay_pass
    assert host.runs == [] and console.site() == before and console.mark() is None


def test_a_stream_with_the_checks_own_name_does_not_block_the_change(tmp_path, host):
    # A publisher uses the very name the check asks for: MediaMTX answers 200, not 404.
    host.mediamtx.live += ('infratak-road-check',)
    console = Console(tmp_path, host)
    assert _need(console, '_mediamtx_remote_hls_road_check')(console.deployment) == 'ok'
    assert console.start() == 'switched' and DIRECT not in console.site()


def test_second_console_start_changes_nothing(tmp_path, host):
    console = Console(tmp_path, host)
    assert console.start() == 'switched'
    console.events = []
    assert console.start() == 'on'
    assert 'caddy-generate' not in console.events and 'caddy-reload' not in console.events
    assert DIRECT not in console.site()


def test_once_through_the_sign_in_a_failed_check_never_puts_the_direct_road_back(tmp_path, host):
    console = Console(tmp_path, host)
    assert console.start() == 'switched'
    host.mediamtx_up = False
    console.log = []
    assert console.start() == 'kept'
    assert console.mark() == HOST + '\n'
    console.generate()                         # any later regeneration (a deploy, a save)
    assert DIRECT not in console.site()
    assert any('stays behind the sign-in' in ln and 'no answer from MediaMTX' in ln for ln in console.log)


def test_an_old_caddyfile_is_put_right_at_the_next_start(tmp_path, host):
    # A restored backup, or a reload Caddy refused: the mark is there, the file is old.
    console = Console(tmp_path, host)
    old = console._read(console.caddyfile)
    assert console.start() == 'switched'
    with open(console.caddyfile, 'w') as f:
        f.write(old)
    console.events = []
    assert console.start() == 'on'
    assert DIRECT not in console.site() and console.events.count('caddy-reload') == 1


def test_before_the_modules_load_the_write_is_left_to_the_catch_up(tmp_path, host):
    console = Console(tmp_path, host)
    console.registry_ready.clear()
    assert console.start() == 'switched'
    # generate_caddyfile queued the catch-up regen (GH #137); no reload of a file not written.
    assert 'caddy-generate' in console.events and 'caddy-reload' not in console.events
    assert console.mark() == HOST + '\n'
    console.registry_ready.set()
    console.generate()                         # _caddy_registry_loaded()
    assert DIRECT not in console.site()


def test_a_refused_reload_is_said(tmp_path, host):
    console = Console(tmp_path, host)
    console.reload_ok = False
    assert console.start() == 'switched'
    assert any('did not load' in ln for ln in console.log)


# ── the rule generate_caddyfile uses ──────────────────────────────────────────────

def test_the_mark_is_for_one_host(tmp_path, host):
    console = Console(tmp_path, host)
    assert console.start() == 'switched'
    assert console.direct() is False
    console.deployment['remote']['host'] = '10.0.0.9'      # MediaMTX moved to another host
    assert console.direct() is True, 'a host the console never checked got the road through its editor'
    console.deployment = {'target_mode': 'local', 'remote': {'host': ''}}
    assert console.direct() is False                        # the editor on the console's own box


def test_road_rule(tmp_path, host):
    console = Console(tmp_path, host)
    rule = _need(console, '_mediamtx_hls_direct')
    s = dict(console.settings)
    assert rule(s, False, '127.0.0.1:5080') is True         # no Authentik: no stream site decides
    assert rule(s, False, f'{HOST}:5080') is True
    assert rule(s, True, '127.0.0.1:5080') is False         # one box, as before
    assert rule(s, True, f'{HOST}:5080') is True            # remote, not checked yet
    console.start()
    assert rule(s, True, f'{HOST}:5080') is False           # remote, checked
    assert rule(s, False, f'{HOST}:5080') is True           # Authentik gone: straight again


def test_without_authentik_the_site_is_left_alone(tmp_path, host):
    console = Console(tmp_path, host, authentik=False)
    before = console.site()
    console.start()
    assert console.site() == before and 'caddy-reload' not in console.events


def test_mark_file_is_private_and_holds_only_the_host(tmp_path, host):
    console = Console(tmp_path, host)
    console.start()
    path = os.path.join(console.config_dir, 'mediamtx_remote_hls_via_editor')
    assert os.path.exists(path), 'the console did not record the checked host'
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert os.listdir(console.config_dir) == ['mediamtx_remote_hls_via_editor']    # no temp file left


def test_generate_caddyfile_uses_the_rule():
    assert MTX_DIRECT_STMT == '_mtx_direct = _mediamtx_hls_direct(settings, _mtx_ak, mtx_up)'
    assert '_get_mediamtx_hls_upstream(settings) if _mtx_direct else None' in GEN_SRC


# ── how the console start and the deploy use it ───────────────────────────────────

def test_console_start_runs_it_after_the_firewall_check_and_the_file_pass():
    body = _fn_src('_startup_migrations')
    m = re.search(r'(\w+) = threading\.Thread\(target=_startup_converge_mediamtx_remote_firewall,', body)
    assert m
    assert re.search(r'threading\.Thread\(target=_startup_converge_mediamtx_remote_hls_road,\s*'
                     r'args=\(%s,\),\s*daemon=True' % re.escape(m.group(1)), body)
    fn = _fn_src('_startup_converge_mediamtx_remote_hls_road')
    assert fn is not None, 'this tree has no video road pass for a remote host'
    assert fn.index('_startup_converge_mediamtx_overlay_remote(after)') < fn.index(
        'road = _mediamtx_remote_hls_road(settings, cfg')


def test_remote_deploy_checks_the_host_before_it_writes_caddy():
    deploy = _fn_src('_run_mediamtx_deploy_remote')
    step7 = deploy[deploy.index('Step 7/8: Caddy Integration'):deploy.index('Step 8/8')]
    assert '_mediamtx_remote_hls_road(settings, cfg, plog)' in step7, (
        'a new remote deploy leaves video on the direct road until the next console start')
    assert step7.index('_mediamtx_remote_hls_road(settings, cfg, plog)') < step7.index('generate_caddyfile(settings)')
    # Only when this same deploy put the current stream site file on the host.
    assert step7.index('if ak_installed and _mtx_overlay_shipped:') < step7.index(
        '_mediamtx_remote_hls_road(settings, cfg, plog)')
    assert ("_mtx_overlay_shipped = bool(_module_run_root(deploy_cfg, "
            "'mv /tmp/mediamtx_ldap_overlay.py /opt/mediamtx-webeditor/mediamtx_ldap_overlay.py'") in deploy
    assert deploy.index('_mtx_overlay_shipped = False') < deploy.index('_mtx_overlay_shipped = bool(')
    # After the editor on the host was started and checked.
    assert deploy.index('_mediamtx_remote_editor_check(deploy_cfg, plog)') < deploy.index(
        '_mediamtx_remote_hls_road(settings, cfg, plog)')


# ── the stream site on a remote host with HLS over TLS ────────────────────────────

@pytest.mark.parametrize('yml, scheme', [
    # A remote deploy keeps the certificate here: no domain in the path.
    ('hlsEncryption: yes\nhlsServerCert: /etc/mediamtx/certs/stream.crt\n', 'https'),
    ('hlsEncryption: no\nhlsServerCert: /etc/mediamtx/certs/stream.crt\n', 'http'),
    ('hlsEncryption: no\nhlsServerCert:\n', 'http'),
    # One box: the certificate path carries the domain, as before.
    ('hlsEncryption: yes\nhlsServerCert: /var/lib/caddy/certificates/x/stream.example.org/stream.example.org.crt\n', 'https'),
])
def test_stream_site_speaks_mediamtx_protocol_whatever_the_certificate_path(tmp_path, monkeypatch, yml, scheme):
    cfg = tmp_path / 'mediamtx.yml'
    cfg.write_text(yml + 'authInternalUsers:\n- user: hlsviewer\n  pass: s3cretPW\n')
    monkeypatch.setenv('MEDIAMTX_CONFIG', str(cfg))
    spec = importlib.util.spec_from_file_location('overlay_ops1110_tls', REPO / 'mediamtx_ldap_overlay.py')
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    vis = tmp_path / 'stream_visibility.json'
    vis.write_text('{}')
    monkeypatch.setattr(ov, 'VISIBILITY_FILE', str(vis))
    urls = []

    class Resp:
        headers = {'Content-Type': 'application/vnd.apple.mpegurl', 'Content-Length': '8'}

        def __init__(self):
            self.body = b'#EXTM3U\n'

        def read(self, n=-1):
            out, self.body = self.body, b''
            return out

        def close(self):
            pass

    def fake_urlopen(req, timeout=None, context=None):
        urls.append(req.full_url)
        return Resp()
    monkeypatch.setattr(ov.urllib.request, 'urlopen', fake_urlopen)
    app = flask.Flask('overlay-tls')
    app.secret_key = 'test'
    ov.apply_ldap_overlay(app)
    assert app.test_client().get('/hls-proxy/cam1/index.m3u8').status_code == 200
    assert urls == [f'{scheme}://127.0.0.1:8888/cam1/index.m3u8']
