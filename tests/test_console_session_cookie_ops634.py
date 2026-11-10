"""ops #634: the console session cookie stays on the console's own host.

The cookie used to be scoped to `.<fqdn>` with no Secure flag, so the browser sent the
console admin session to every module site (Node-RED, TAK Portal, CloudTAK, ...) and over
plain HTTP. Any code behind a module site could copy it and act as console admin.

Runs the real cookie setup, session interface, before/after-request hooks and auth helpers
from app.py in a small Flask app, with the real Flask session machinery and the werkzeug test
client's cookie jar (which applies the browser's Domain matching rules).
"""

import ast
import email.message
import http.cookiejar
import json
import os
import pathlib
import re
import secrets
import stat
import urllib.request
from datetime import datetime

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

CONSOLE = 'https://infratak.example.com'
NODERED = 'https://nodered.example.com'


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    return None


def _assign(name):
    for n in TREE.body:
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and getattr(n.targets[0], 'id', None) == name):
            return ast.get_source_segment(APP, n)
    return None


def _cookie_setup_region():
    start = APP.index('# Persist the secret key')
    end = APP.index('# In-memory rate limiter')
    return APP[start:end]


@pytest.fixture
def console(tmp_path):
    cfg = tmp_path / '.config'
    cfg.mkdir()
    (cfg / 'settings.json').write_text(json.dumps({'fqdn': 'example.com'}))
    (cfg / 'auth.json').write_text(json.dumps({'password_hash': 'pbkdf2:sha256:1$a$b'}))
    app = flask.Flask('console_under_test')
    ns = {
        '__file__': str(tmp_path / 'app.py'), '__name__': 'console_under_test',
        'app': app, 'request': flask.request, 'session': flask.session,
        'jsonify': flask.jsonify, 'os': os, 'json': json, 'secrets': secrets,
        'hmac': __import__('hmac'), 'hashlib': __import__('hashlib'), 'datetime': datetime,
        'CONFIG_DIR': str(cfg),
        'load_settings': lambda: json.loads((cfg / 'settings.json').read_text()),
        '_client_ip': lambda: '127.0.0.1', '_is_rate_limited': lambda *a, **k: False,
        '_same_origin_ok': lambda: True,
    }
    exec(compile(_cookie_setup_region(), 'app.py:cookie-setup', 'exec'), ns)
    for name in ('SESSION_TOKEN_KEY', '_session_token_cache'):
        src = _assign(name)
        if src:
            exec(src, ns)
    for name in ('load_auth', 'save_auth', '_session_auth_token', '_stamp_session_login',
                 '_drop_stale_session', '_end_all_sessions'):
        src = _func(name)
        if src:
            exec(src, ns)
    # The per-request hook (renamed by the fix) and the legacy-cookie cleanup.
    hook = next(n for n in ('ensure_session_valid', 'ensure_session_cookie_domain') if _func(n))
    exec(_func(hook), ns)
    app.before_request(ns[hook])
    if _func('clear_legacy_session_cookie'):
        exec(_func('clear_legacy_session_cookie'), ns)
        app.after_request(ns['clear_legacy_session_cookie'])

    @app.route('/login', methods=['POST'])
    def login():
        flask.session.clear()
        flask.session['authenticated'] = True
        if '_stamp_session_login' in ns:
            ns['_stamp_session_login']()
        return 'ok'

    # The real logout route.
    ns.update(audit=lambda *a, **k: None, redirect=flask.redirect, url_for=flask.url_for)
    exec(_func('logout'), ns)
    app.add_url_rule('/logout', 'logout', ns['logout'], methods=['POST'])
    app.add_url_rule('/', 'index', lambda: 'login page')

    @app.route('/console')
    def page():
        return ('in', 200) if flask.session.get('authenticated') else ('out', 401)

    @app.route('/whoami')
    def whoami():
        return json.dumps(sorted(flask.request.cookies))

    app.ns = ns
    app.cfg = cfg
    return app


def _browser_sends(responses, send_to):
    """Store Set-Cookie headers the way a browser does (stdlib http.cookiejar applies the
    Domain and Secure rules), one response at a time, then return the Cookie header it would
    send to `send_to`. `responses` is a list of (url, [Set-Cookie, ...])."""
    jar = http.cookiejar.CookieJar()

    class _Resp:
        def __init__(self, headers):
            self.headers = headers

        def info(self):
            m = email.message.Message()
            for h in self.headers:
                m['Set-Cookie'] = h
            return m

    for url, headers in responses:
        jar.extract_cookies(_Resp(headers), urllib.request.Request(url))
    req = urllib.request.Request(send_to)
    jar.add_cookie_header(req)
    return req.get_header('Cookie') or ''


def _set_cookie(resp):
    found = [h for h in resp.headers.getlist('Set-Cookie') if 'session' in h.split('=', 1)[0]]
    assert found, 'no session cookie was set'
    return found[0]


# --------------------------------------------------------------------------- #
# The cookie itself
# --------------------------------------------------------------------------- #

def test_cookie_on_the_fqdn_is_host_only_secure_and_host_prefixed(console):
    resp = console.test_client().post('/login', base_url=CONSOLE)
    sc = _set_cookie(resp)
    assert 'domain=' not in sc.lower(), sc
    assert '; Secure' in sc, sc
    assert sc.startswith('__Host-infratak_session='), sc
    assert 'HttpOnly' in sc and 'SameSite=Lax' in sc and 'Path=/' in sc, sc


def test_browser_does_not_send_console_cookie_to_a_module_site(console):
    sc = console.test_client().post('/login', base_url=CONSOLE).headers.getlist('Set-Cookie')
    assert _browser_sends([(CONSOLE + '/login', sc)], CONSOLE + '/console')   # still works at home
    for site in (NODERED, 'https://takportal.example.com', 'https://example.com'):
        assert not _browser_sends([(CONSOLE + '/login', sc)], site + '/'), site


def test_browser_never_sends_it_over_plain_http(console):
    sc = console.test_client().post('/login', base_url=CONSOLE).headers.getlist('Set-Cookie')
    for site in ('http://infratak.example.com', 'http://atlas.example.com'):
        assert not _browser_sends([(CONSOLE + '/login', sc)], site + '/'), site


def test_break_glass_localhost_and_ip_logins_still_hold(console):
    for base in ('https://localhost:5001', 'https://203.0.113.10:5001'):
        c = console.test_client()
        c.post('/login', base_url=base)
        assert c.get('/console', base_url=base).status_code == 200, base


def test_plain_http_console_gets_a_working_non_secure_cookie(console):
    """A console with no TLS cert serves plain HTTP; a Secure cookie would never come back."""
    c = console.test_client()
    sc = _set_cookie(c.post('/login', base_url='http://203.0.113.10:5001',
                            environ_overrides={'REMOTE_ADDR': '198.51.100.7'}))
    assert sc.startswith('infratak_session=') and 'Secure' not in sc and 'domain=' not in sc.lower()
    assert c.get('/console', base_url='http://203.0.113.10:5001',
                 environ_overrides={'REMOTE_ADDR': '198.51.100.7'}).status_code == 200


def test_forwarded_proto_trusted_only_from_local_caddy(console):
    is_https = console.ns['_request_is_https']
    with console.test_request_context('/', base_url='http://x', headers={'X-Forwarded-Proto': 'https'},
                                      environ_overrides={'REMOTE_ADDR': '127.0.0.1'}):
        assert is_https()
    with console.test_request_context('/', base_url='http://x', headers={'X-Forwarded-Proto': 'https'},
                                      environ_overrides={'REMOTE_ADDR': '198.51.100.7'}):
        assert not is_https()


def test_old_shared_cookie_is_expired_on_the_parent_domain(console):
    resp = console.test_client(use_cookies=False).get(
        '/console', base_url=CONSOLE, headers={'Cookie': 'session=old-value'})
    sc = resp.headers.getlist('Set-Cookie')
    expiring = [h for h in sc if h.startswith('session=;')]
    assert any('Domain=example.com' in h for h in expiring), sc
    assert all('Expires=Thu, 01 Jan 1970' in h for h in expiring), sc
    # A browser holding the old .example.com cookie drops it.
    old = (CONSOLE + '/', ['session=old-value; Domain=.example.com; Path=/'])
    assert _browser_sends([old], NODERED + '/')            # before: it reached Node-RED
    assert not _browser_sends([old, (CONSOLE + '/console', sc)], NODERED + '/')


# --------------------------------------------------------------------------- #
# Ending sessions
# --------------------------------------------------------------------------- #

def test_password_change_ends_other_sessions(console):
    c = console.test_client()
    c.post('/login', base_url=CONSOLE)
    auth = json.loads((console.cfg / 'auth.json').read_text())
    auth['password_hash'] = 'pbkdf2:sha256:1$new$hash'
    (console.cfg / 'auth.json').write_text(json.dumps(auth))   # like reset-console-password.sh
    assert c.get('/console', base_url=CONSOLE).status_code == 401


def test_logout_ends_every_session(console):
    stolen, admin = console.test_client(), console.test_client()
    stolen.post('/login', base_url=CONSOLE)
    admin.post('/login', base_url=CONSOLE)
    admin.post('/logout', base_url=CONSOLE)
    assert stolen.get('/console', base_url=CONSOLE).status_code == 401
    admin.post('/login', base_url=CONSOLE)
    assert admin.get('/console', base_url=CONSOLE).status_code == 200


def test_anonymous_logout_cannot_end_other_sessions(console):
    admin = console.test_client()
    admin.post('/login', base_url=CONSOLE)
    console.test_client().post('/logout', base_url=CONSOLE)   # no session
    assert admin.get('/console', base_url=CONSOLE).status_code == 200


def test_session_without_login_token_is_dropped(console):
    """A session signed before the fix carries no token and must not be honoured."""
    c = console.test_client()
    with c.session_transaction(base_url=CONSOLE) as s:
        s['authenticated'] = True
    assert c.get('/console', base_url=CONSOLE).status_code == 401


def test_token_reveals_nothing_about_the_password_hash(console):
    with console.test_request_context('/'):
        tok = console.ns['_session_auth_token']()
    assert re.fullmatch(r'[0-9a-f]{64}', tok)
    assert 'pbkdf2' not in tok and '$a$b' not in tok


# --------------------------------------------------------------------------- #
# Key rotation on update
# --------------------------------------------------------------------------- #

def test_update_mints_a_new_key_and_removes_the_old_file(tmp_path):
    cfg = tmp_path / '.config'
    cfg.mkdir()
    (cfg / 'secret_key').write_text('a' * 64)
    app = flask.Flask('k')
    ns = {'__file__': str(tmp_path / 'app.py'), 'app': app, 'os': os, 'json': json,
          'secrets': secrets, 'request': flask.request}
    exec(compile(_cookie_setup_region(), 'app.py:cookie-setup', 'exec'), ns)
    assert app.secret_key and app.secret_key != 'a' * 64
    assert not (cfg / 'secret_key').exists()
    key_file = cfg / 'session_key'
    assert key_file.read_text() == app.secret_key
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    # Second start keeps the same key (sessions survive a plain restart).
    app2 = flask.Flask('k2')
    ns2 = dict(ns, app=app2)
    exec(compile(_cookie_setup_region(), 'app.py:cookie-setup', 'exec'), ns2)
    assert app2.secret_key == app.secret_key


def test_old_key_file_that_cannot_be_removed_does_not_break_the_key(tmp_path):
    """If the old file is not ours to remove, the console must still keep one stable key
    (a random key per start would log everyone out on every restart)."""
    cfg = tmp_path / '.config'
    cfg.mkdir()
    (cfg / 'secret_key').write_text('a' * 64)

    class _Os:
        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def remove(path):
            raise PermissionError(13, 'Permission denied', path)

    keys = []
    for _ in range(2):
        app = flask.Flask('k')
        ns = {'__file__': str(tmp_path / 'app.py'), 'app': app, 'os': _Os(), 'json': json,
              'secrets': secrets, 'request': flask.request}
        exec(compile(_cookie_setup_region(), 'app.py:cookie-setup', 'exec'), ns)
        keys.append(app.secret_key)
    assert keys[0] == keys[1] == (cfg / 'session_key').read_text() != 'a' * 64


# --------------------------------------------------------------------------- #
# Wiring in app.py
# --------------------------------------------------------------------------- #

def test_every_login_path_stamps_the_token():
    for name, marker in (('_apply_authentik_session', "session['authentik_username'] = uname"),
                         ('login', "session['authenticated'] = True"),
                         ('index', "session['authenticated'] = True")):
        body = _func(name)
        assert body.index(marker) < body.index('_stamp_session_login()'), name


def test_logout_and_password_change_wiring():
    assert '_end_all_sessions()' in _func('logout')
    body = _func('console_password_reset')
    assert body.index('save_auth(auth)') < body.index('_stamp_session_login()')


def test_nothing_sets_a_shared_cookie_domain():
    hits = [i for i, line in enumerate(APP.splitlines(), 1) if 'SESSION_COOKIE_DOMAIN' in line]
    assert not hits, f'app.py still sets a cookie Domain at lines {hits}'
