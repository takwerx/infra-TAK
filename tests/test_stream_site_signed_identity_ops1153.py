# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1153: the stream site reads who is signed in from Authentik's signed token.

Authentik's outpost sends the person's name twice: as plain text (X-Authentik-Username)
and inside the token Authentik signed for the sign-in (X-Authentik-Jwt). Caddy now passes
the token to the stream site (the MediaMTX editor overlay) and says so with
`X-Infratak-Identity: signed`. With that line the overlay takes the name from the token,
after it checked the signature with this site's own key, and from nothing else.

Part 1 runs the real overlay on a bare Flask app against a small HTTP server that answers
like Authentik's API (users, the `stream` application, its provider). Every request is
built the way Caddy sends it after forward_auth passed.
Part 2 holds the Caddyfile lines and the overlay's names together.
"""

import ast
import base64
import hashlib
import hmac
import http.server
import importlib.util
import json
import pathlib
import re
import threading
import time
import urllib.parse

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
ADMINS = 'authentik Admins'
STREAM_PK = 7
OTHER_PK = 9


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def make_token(secret, claims, alg='HS256', head=None):
    """A token as Authentik makes it for a proxy provider: HS256 with the client secret."""
    header = {'alg': alg, 'typ': 'JWT'}
    header.update(head or {})
    signed = _b64(json.dumps(header).encode()) + '.' + _b64(json.dumps(claims).encode())
    sig = b'' if alg == 'none' else hmac.new(secret.encode(), signed.encode(), hashlib.sha256).digest()
    return signed + '.' + _b64(sig)


class FakeAuthentik:
    """The parts of Authentik's API the overlay asks: core/users/, core/applications/<slug>/
    and providers/oauth2/<pk>/. mode: 'ok' or 'error' (HTTP 500 on everything)."""

    def __init__(self):
        self.users = {}
        self.mode = 'ok'
        self.calls = []
        self.apps = {'stream': STREAM_PK, 'other-app': OTHER_PK}
        self.providers = {
            STREAM_PK: {'pk': STREAM_PK, 'name': 'MediaMTX', 'client_id': 'stream-client-id',
                        'client_secret': 'stream-secret-' + 'a' * 40, 'signing_key': None},
            OTHER_PK: {'pk': OTHER_PK, 'name': 'Other', 'client_id': 'other-client-id',
                       'client_secret': 'other-secret-' + 'b' * 40, 'signing_key': None},
        }
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                fake.calls.append(self.path)
                if self.headers.get('Authorization') != 'Bearer box-token':
                    return self._send(403, {'detail': 'bad token'})
                if fake.mode == 'error':
                    return self._send(500, {'detail': 'boom'})
                url = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(url.query)
                if url.path == '/api/v3/core/users/':
                    want = query.get('username', [None])[0]
                    rows = [u for u in fake.users.values() if u['username'] == want]
                    return self._send(200, {'results': rows})
                m = re.fullmatch(r'/api/v3/core/applications/([a-z0-9-]+)/', url.path)
                if m and m.group(1) in fake.apps:
                    return self._send(200, {'slug': m.group(1), 'provider': fake.apps[m.group(1)]})
                m = re.fullmatch(r'/api/v3/providers/oauth2/(\d+)/', url.path)
                if m and int(m.group(1)) in fake.providers:
                    return self._send(200, fake.providers[int(m.group(1))])
                return self._send(404, {'detail': 'Not found.'})

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def add(self, username, groups=()):
        self.users[username] = {
            'pk': len(self.users) + 1, 'username': username, 'is_active': True,
            'groups_obj': [{'pk': 'g-%d' % i, 'name': g} for i, g in enumerate(groups)]}

    def token_for(self, username, pk=STREAM_PK, **claims):
        """The token Authentik signs when `username` signs in to the app of provider `pk`."""
        prov = self.providers[pk]
        body = {'iss': 'https://tak.example.com/application/o/stream/', 'aud': prov['client_id'],
                'sub': 'hashed-' + username, 'exp': int(time.time()) + 3600,
                'iat': int(time.time()), 'preferred_username': username,
                'groups': [g['name'] for g in self.users.get(username, {}).get('groups_obj', [])]}
        body.update(claims)
        return make_token(prov['client_secret'], body)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def authentik():
    fake = FakeAuthentik()
    fake.add('akadmin', [ADMINS])
    fake.add('alice', ['vid_private'])
    fake.add('mallory', ['vid_public'])
    yield fake
    fake.stop()


@pytest.fixture
def clock(monkeypatch):
    real = time.time
    state = {'offset': 0.0}
    monkeypatch.setattr(time, 'time', lambda: real() + state['offset'])

    class Clock:
        @staticmethod
        def forward(seconds):
            state['offset'] += seconds
    return Clock


class _Playlist:
    headers = {'Content-Type': 'application/vnd.apple.mpegurl', 'Content-Length': '8'}

    def __init__(self):
        self._body = b'#EXTM3U\n'

    def read(self, n=-1):
        out, self._body = self._body, b''
        return out

    def close(self):
        pass


@pytest.fixture
def site(tmp_path, monkeypatch, authentik, clock):
    cfg = tmp_path / 'mediamtx.yml'
    cfg.write_text('authInternalUsers:\n- user: hlsviewer\n  pass: "pw"\n')
    monkeypatch.setenv('MEDIAMTX_CONFIG', str(cfg))
    spec = importlib.util.spec_from_file_location('overlay_ops1153', REPO / 'mediamtx_ldap_overlay.py')
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    monkeypatch.setattr(ov, 'AK_URL', authentik.url)
    monkeypatch.setattr(ov, 'AK_TOKEN', 'box-token')
    vis = tmp_path / 'stream_visibility.json'
    vis.write_text(json.dumps({'secret': 'private'}))
    monkeypatch.setattr(ov, 'VISIBILITY_FILE', str(vis))
    real_urlopen = ov.urllib.request.urlopen

    def urlopen(req, timeout=None, context=None):
        if ':8888/' in req.full_url:          # MediaMTX's HLS port: stubbed
            return _Playlist()
        return real_urlopen(req, timeout=timeout)
    monkeypatch.setattr(ov.urllib.request, 'urlopen', urlopen)
    app = flask.Flask('overlay-ops1153')
    app.secret_key = 'test'

    @app.route('/')
    def editor_home():                        # stands in for the editor's own admin page
        return 'EDITOR user=%s role=%s' % (flask.session.get('username'), flask.session.get('role'))
    ov.apply_ldap_overlay(app)

    class Site:
        overlay = ov

        @staticmethod
        def browser():
            return app.test_client()
    return Site


def as_caddy(browser, path, token=None, name_header=None, marker=True, method='get', **kw):
    """A request the way Caddy sends it to the editor from the stream vhost: the marker on
    every route; after forward_auth passed, the token and the plain identity headers that
    the outpost answered with. `name_header` is what the plain name header says."""
    headers = {}
    if marker:
        headers['X-Infratak-Identity'] = 'signed'
    if token is not None:
        headers['X-Authentik-Jwt'] = token
    if name_header is not None:
        headers['X-Authentik-Username'] = name_header
        headers['X-Authentik-Groups'] = ADMINS
    return getattr(browser, method)(path, headers=headers, **kw)


def admin_doors(browser, **req):
    """How many of the editor's admin doors open for this request shape (0 or 3)."""
    home = as_caddy(browser, '/', **req)
    api = as_caddy(browser, '/api/stream-visibility', **req)
    write = as_caddy(browser, '/api/stream-visibility', method='post',
                     json={'stream': 'scratch', 'level': 'private'}, **req)
    doors = [home.status_code == 200 and b'role=admin' in home.data,
             api.status_code == 200, write.status_code == 200]
    assert all(doors) or not any(doors), doors
    return sum(doors)


# --- Part 1: the overlay ------------------------------------------------------------------

def test_the_name_comes_from_the_signed_token_not_from_the_plain_header(site, authentik):
    """Proof test for ops #1153. mallory (a viewer) is the person who signed in: the token
    Authentik signed says so. The plain name header says akadmin. Fails before the fix:
    the overlay took the name from the plain header and gave the admin side."""
    b = site.browser()
    req = {'token': authentik.token_for('mallory'), 'name_header': 'akadmin'}
    assert admin_doors(b, **req) == 0
    # The refused write changed nothing.
    assert json.loads(pathlib.Path(site.overlay.VISIBILITY_FILE).read_text()) == {'secret': 'private'}
    # She is mallory, a viewer: the viewer page, and no private stream.
    r = as_caddy(b, '/', **req)
    assert r.status_code == 302 and r.headers['Location'].endswith('/viewer')
    assert as_caddy(b, '/hls-proxy/secret/index.m3u8', **req).status_code == 403
    with b.session_transaction() as s:
        assert s['username'] == 'mallory' and s['role'] == 'viewer'


@pytest.mark.parametrize('token', ['', 'x', 'a.b.c', 'e30.e30.'])
def test_a_plain_name_with_no_good_token_signs_nobody_in(site, token):
    b = site.browser()
    assert admin_doors(b, token=token, name_header='akadmin') == 0
    r = as_caddy(b, '/', token=token, name_header='akadmin')
    assert r.status_code == 200 and b'user=None role=None' in r.data
    assert admin_doors(b, token=None, name_header='akadmin') == 0


def test_a_token_this_site_did_not_get_from_authentik_is_refused(site, authentik):
    b = site.browser()
    stream = authentik.providers[STREAM_PK]
    claims = {'aud': stream['client_id'], 'exp': int(time.time()) + 3600,
              'preferred_username': 'akadmin'}
    forged = {
        'wrong key': make_token('some-other-secret-' + 'c' * 30, claims),
        'no signature': make_token('', claims, alg='none'),
        'alg none, signed': make_token(stream['client_secret'], claims).replace(
            _b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()),
            _b64(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())),
        'another algorithm name': make_token(stream['client_secret'], claims, alg='HS512'),
        # A real token of another application of the same Authentik, signed with that
        # application's own secret (whoever runs that application knows its secret).
        'another application': authentik.token_for('akadmin', pk=OTHER_PK),
        'other audience, our key': make_token(stream['client_secret'], dict(claims, aud='other-client-id')),
        'no name': make_token(stream['client_secret'], {k: v for k, v in claims.items()
                                                         if k != 'preferred_username'}),
        'name not text': make_token(stream['client_secret'], dict(claims, preferred_username=['akadmin'])),
        'no end time': make_token(stream['client_secret'], {k: v for k, v in claims.items() if k != 'exp'}),
        'ended': make_token(stream['client_secret'], dict(claims, exp=int(time.time()) - 3600)),
        'not yet valid': make_token(stream['client_secret'], dict(claims, nbf=int(time.time()) + 3600)),
    }
    for what, token in forged.items():
        assert admin_doors(b, token=token, name_header='akadmin') == 0, what
        r = as_caddy(b, '/', token=token, name_header='akadmin')
        assert b'user=None role=None' in r.data, what
    # The same claims with the right key are accepted (the cases above failed for their reason).
    assert admin_doors(b, token=make_token(stream['client_secret'], claims), name_header='akadmin') == 3


def test_an_admin_still_gets_the_admin_side(site, authentik):
    b = site.browser()
    assert admin_doors(b, token=authentik.token_for('akadmin'), name_header='akadmin') == 3
    with b.session_transaction() as s:
        assert s['username'] == 'akadmin' and s['identity_source'] == 'signed'


def test_viewers_still_see_what_their_group_allows(site, authentik):
    alice, mallory = site.browser(), site.browser()
    a = {'token': authentik.token_for('alice'), 'name_header': 'alice'}
    m = {'token': authentik.token_for('mallory'), 'name_header': 'mallory'}
    assert as_caddy(alice, '/hls-proxy/secret/index.m3u8', **a).status_code == 200
    assert as_caddy(mallory, '/hls-proxy/secret/index.m3u8', **m).status_code == 403
    assert as_caddy(mallory, '/hls-proxy/open/index.m3u8', **m).status_code == 200
    assert admin_doors(alice, **a) == 0
    # A watch page is outside the login: Caddy sends the marker and no identity. The
    # sign-in from the request before still counts there.
    assert as_caddy(alice, '/watch/secret').status_code == 200
    assert as_caddy(mallory, '/watch/secret').status_code == 403
    assert as_caddy(site.browser(), '/watch/secret').status_code == 403


def test_inside_the_login_a_request_with_no_token_keeps_no_sign_in(site, authentik):
    """Every path but the open ones came through forward_auth. A request there with the
    marker and no identity at all is nobody's sign-in: a session from an earlier request
    (a person since taken out of a group, or an old cookie) does not stand in for it."""
    b = site.browser()
    assert admin_doors(b, token=authentik.token_for('akadmin'), name_header='akadmin') == 3
    r = as_caddy(b, '/')                                     # marker only, not an open path
    assert r.status_code == 200 and b'user=None role=None' in r.data
    assert as_caddy(b, '/api/stream-visibility').status_code != 200
    v = site.browser()
    alice = {'token': authentik.token_for('alice'), 'name_header': 'alice'}
    assert as_caddy(v, '/hls-proxy/secret/index.m3u8', **alice).status_code == 200
    assert as_caddy(v, '/hls-proxy/secret/index.m3u8').status_code == 403
    # ... and the open path after that has no sign-in to lean on.
    assert as_caddy(v, '/watch/secret').status_code == 403


def test_the_open_paths_are_the_ones_caddy_leaves_outside_the_login(site):
    ns = _app_ns()
    assert site.overlay.OPEN_PATH_PREFIXES == tuple(p.rstrip('*') for p in ns['MEDIAMTX_OPEN_PATHS'])
    assert all(p.startswith('/') and p.endswith('/') for p in site.overlay.OPEN_PATH_PREFIXES)


def test_the_editors_own_login_is_left_alone(site, authentik):
    """The editor's own login page is the way in when Authentik's sign-in cannot be
    checked (no key). A session made there has no ldap_mode and is not this code's."""
    b = site.browser()
    with b.session_transaction() as s:
        s.update({'username': 'local-admin', 'logged_in': True, 'role': 'admin'})
    authentik.mode = 'error'                                  # no key: every token is refused
    for req in ({'token': authentik.token_for('akadmin'), 'name_header': 'akadmin'},
                {'token': 'a.b.c', 'name_header': 'akadmin'}, {}):
        r = as_caddy(b, '/', **req)
        assert r.status_code == 200 and b'user=local-admin role=admin' in r.data, req


def test_odd_tokens_are_refused_with_their_reason(site, authentik):
    ov = site.overlay
    stream = authentik.providers[STREAM_PK]
    base = {'aud': stream['client_id'], 'preferred_username': 'akadmin'}
    assert ov._signed_username('x' * (ov.TOKEN_MAX_BYTES + 1)) == (None, 'too-long')
    assert ov._signed_username('') == (None, 'no-token')
    for exp in (float('inf'), float('nan'), True, '9999999999', None):
        token = make_token(stream['client_secret'], dict(base, exp=exp))
        assert ov._signed_username(token) == (None, 'expired'), exp
    assert ov._signed_username(make_token(stream['client_secret'], dict(base, exp=int(time.time()) + 600))) \
        == ('akadmin', None)
    # The audience may be a list that holds this site's client id.
    listed = make_token(stream['client_secret'], dict(base, exp=int(time.time()) + 600,
                                                      aud=['x', stream['client_id']]))
    assert ov._signed_username(listed) == ('akadmin', None)
    for reason in ('no-token', 'too-long', 'not-a-token', 'algorithm', 'no-key', 'signature', 'expired', 'no-name'):
        assert reason in ov._TOKEN_REASONS


def test_a_sign_in_from_before_the_token_was_checked_is_not_kept(site):
    """An editor session made from the plain header (a Caddyfile from before this change)
    ends at the first request from a Caddyfile that passes the token."""
    b = site.browser()
    assert admin_doors(b, marker=False, name_header='akadmin') == 3      # the old contract
    assert as_caddy(b, '/watch/secret').status_code == 403
    r = as_caddy(b, '/')
    assert r.status_code == 200 and b'user=None role=None' in r.data


def test_without_the_marker_the_plain_header_works_as_before(site, authentik):
    """A Caddyfile from before this change (a console rolled back, or not yet regenerated)
    sends no marker and no token. Nobody is locked out: the old contract holds."""
    b = site.browser()
    assert admin_doors(b, marker=False, name_header='akadmin') == 3
    v = site.browser()
    assert admin_doors(v, marker=False, name_header='mallory') == 0
    r = as_caddy(v, '/', marker=False, name_header='mallory')
    assert r.status_code == 302 and r.headers['Location'].endswith('/viewer')


def test_no_key_from_authentik_signs_nobody_in_and_heals(site, authentik, clock):
    b = site.browser()
    req = {'token': authentik.token_for('akadmin'), 'name_header': 'akadmin'}
    authentik.mode = 'error'
    assert admin_doors(b, **req) == 0
    authentik.mode = 'ok'
    clock.forward(site.overlay.TOKEN_KEY_RETRY_SECONDS + 1)
    assert admin_doors(b, token=authentik.token_for('akadmin'), name_header='akadmin') == 3
    # With a key in hand, Authentik going away later locks nobody out.
    authentik.mode = 'error'
    clock.forward(site.overlay.TOKEN_KEY_RECHECK_SECONDS + 1)
    for _ in range(3):
        home = as_caddy(b, '/', token=authentik.token_for('akadmin'), name_header='akadmin')
        assert b'user=akadmin' in home.data
        clock.forward(site.overlay.TOKEN_KEY_RETRY_SECONDS + 1)


def test_a_changed_client_secret_is_picked_up(site, authentik, clock):
    b = site.browser()
    assert admin_doors(b, token=authentik.token_for('akadmin'), name_header='akadmin') == 3
    authentik.providers[STREAM_PK]['client_secret'] = 'rotated-secret-' + 'd' * 40
    clock.forward(site.overlay.TOKEN_KEY_RETRY_SECONDS + 1)
    assert admin_doors(b, token=authentik.token_for('akadmin'), name_header='akadmin') == 3


def test_the_key_is_asked_once_not_on_every_request(site, authentik):
    b = site.browser()
    for _ in range(5):
        assert as_caddy(b, '/hls-proxy/open/index.m3u8', token=authentik.token_for('alice'),
                        name_header='alice').status_code == 200
    assert len([c for c in authentik.calls if '/providers/oauth2/' in c]) == 1
    assert len([c for c in authentik.calls if '/core/applications/' in c]) == 1


def test_a_provider_with_its_own_signing_key_is_not_guessed_at(site, authentik):
    """Then Authentik does not sign with the client secret. The overlay knows HS256 only,
    so it accepts nothing rather than a token it cannot check."""
    authentik.providers[STREAM_PK]['signing_key'] = '0b7f3b1e-0000-4000-8000-000000000001'
    b = site.browser()
    assert admin_doors(b, token=authentik.token_for('akadmin'), name_header='akadmin') == 0


def test_headers_from_a_peer_that_is_not_the_proxy_are_ignored(site, authentik):
    b = site.browser()
    for marker in (True, False):
        r = as_caddy(b, '/', token=authentik.token_for('akadmin'), name_header='akadmin',
                     marker=marker, environ_base={'REMOTE_ADDR': '10.9.9.9'})
        assert b'user=None role=None' in r.data


# --- Part 2: Caddy and the overlay hold the same contract -----------------------------------

def _app_ns():
    names = ('_emit_mediamtx_site', '_caddy_vhost_block', '_mediamtx_vhost_is_safe',
             '_mediamtx_vhost_needs_regen')
    consts = ('MEDIAMTX_OPEN_PATHS', '_MEDIAMTX_VHOST_MARKER', '_CADDY_STRIP_AUTHENTIK_HEADERS',
              '_MEDIAMTX_AK_COPY_HEADERS', '_MEDIAMTX_IDENTITY_MARKER', 'CADDYFILE_USER_BLOCKS_MARKER')
    ns = {'_pub_url': lambda h, s=None: f'https://{h}' if h else '', 're': re}
    for node in ast.parse(APP).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            exec(ast.get_source_segment(APP, node), ns)
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') in consts:
            exec(ast.get_source_segment(APP, node), ns)
    missing = [n for n in names + consts if n not in ns]
    assert not missing, missing
    return ns


def _vhost(ns, ak_up='127.0.0.1:9090', hls=None, **kw):
    lines = []

    def strip(indent):       # as generate_caddyfile's own emitter: one line per named header
        lines.extend(f'{indent}request_header -{h}' for h in ('X-Authentik-Username', 'X-Authentik-Groups'))
    ns['_emit_mediamtx_site'](lines, 'stream.example.com', '127.0.0.1:5080', ak_up, hls, strip,
                              lambda root: lines.append(f'        #rescue {root}'), **kw)
    return '\n'.join(lines) + '\n'


def test_caddy_passes_the_token_and_marks_every_route_to_the_editor(site):
    ns = _app_ns()
    ov = site.overlay
    assert ns['_MEDIAMTX_IDENTITY_MARKER'] == 'request_header %s %s' % (
        ov.IDENTITY_MARKER_HEADER, ov.IDENTITY_MARKER_SIGNED)
    assert ns['_MEDIAMTX_AK_COPY_HEADERS'].startswith('copy_headers ')
    assert 'X-Authentik-Jwt' in ns['_MEDIAMTX_AK_COPY_HEADERS'].split()
    for hls in (None, ('10.0.0.5:8888', True)):
        text = _vhost(ns, hls=hls)
        lines = text.split('\n')
        assert text.count('            ' + ns['_MEDIAMTX_AK_COPY_HEADERS'] + '\n') == 1
        editor = [i for i, ln in enumerate(lines) if ln.strip() == 'reverse_proxy 127.0.0.1:5080']
        assert len(editor) == 4          # three open paths and the catch-all
        for i in editor:
            j = i
            while not lines[j].rstrip().endswith('{') or lines[j].lstrip().startswith('forward_auth'):
                j -= 1
            block = lines[j:i]
            assert block[0].startswith('    route'), block
            marker = block.index('        ' + ns['_MEDIAMTX_IDENTITY_MARKER'])
            # After the strip of client headers, before forward_auth and the proxy.
            assert marker > block.index('        request_header -X-Authentik-*')
            assert not any('forward_auth' in ln for ln in block[:marker])
    # Without Authentik there is no token and no marker.
    for kw in ({}, {'login_ok': True}):
        text = _vhost(ns, ak_up=None, hls=('127.0.0.1:8888', False), **kw)
        assert 'X-Infratak-Identity' not in text and 'X-Authentik-Jwt' not in text


def test_a_vhost_from_before_this_change_is_regenerated_on_console_start():
    ns = _app_ns()
    need = ns['_mediamtx_vhost_needs_regen']
    new = _vhost(ns)
    assert not need(new, False) and not need(new, True)
    old = new.replace(' X-Authentik-Jwt', '').replace(
        '        ' + ns['_MEDIAMTX_IDENTITY_MARKER'] + '\n', '')
    assert 'X-Infratak-Identity' not in old and 'forward_auth' in old
    assert ns['_mediamtx_vhost_is_safe'](old)
    assert need(old, False) and need(old, True)
    # Half of the pair is not the contract.
    assert need(new.replace(' X-Authentik-Jwt', ''), True)
    assert need(new.replace('        ' + ns['_MEDIAMTX_IDENTITY_MARKER'] + '\n', '', 1), True)
    # The startup pass that regenerates says what it did in plain words, not "secured".
    run = APP[APP.index('def _mediamtx_editor_login_converge_run('):]
    run = run[:run.index('\ndef ', 10)]
    assert '_was_safe = _mediamtx_vhost_is_safe(before)' in run
    assert run.index('if _was_safe:') < run.index('vhost secured and Caddy')
