# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #813: who gets a console session from Authentik sign-in, and for how long.

The console is root on the box. A session made by Authentik sign-in is for a console
administrator only (an active Authentik user in `authentik Admins`), it ends when
Authentik stops saying so, and every session cookie has a set lifetime.

Runs the real sign-in, session and idle-lock code from app.py in a small Flask app, with
the real Flask session machinery, against a small HTTP server that answers like
Authentik's user API. The clock is moved with a patched time.time().
"""

import ast
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

ADMINS = 'authentik Admins'
PROXY_SECRET = 'a' * 64
PASSWORD = 'correct horse battery'


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


# --- a stand-in for Authentik's user API ---------------------------------------------

class FakeAuthentik:
    """GET /api/v3/core/users/?username=X and /api/v3/core/users/<pk>/, like Authentik.
    mode: 'ok', 'error' (HTTP 500), 'forbidden' (HTTP 403), 'ignore_filter' (returns every
    user whatever the filter says, which is what Authentik does with a filter it does not
    know), 'no_groups_in_list' (the list leaves groups out; the detail has them)."""

    def __init__(self):
        self.users = {}
        self.mode = 'ok'
        self.calls = []
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
                if fake.mode == 'forbidden':
                    return self._send(403, {'detail': 'Token invalid/expired'})
                url = urllib.parse.urlsplit(self.path)
                m = re.fullmatch(r'/api/v3/core/users/(\d+)/', url.path)
                if m:
                    for u in fake.users.values():
                        if u['pk'] == int(m.group(1)):
                            return self._send(200, fake._row(u, True))
                    return self._send(404, {'detail': 'Not found.'})
                if url.path == '/api/v3/core/users/':
                    want = urllib.parse.parse_qs(url.query).get('username', [None])[0]
                    rows = [u for u in fake.users.values()
                            if fake.mode == 'ignore_filter' or u['username'] == want]
                    with_groups = fake.mode != 'no_groups_in_list'
                    return self._send(200, {'results': [fake._row(u, with_groups) for u in rows]})
                return self._send(404, {'detail': 'Not found.'})

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @staticmethod
    def _row(u, with_groups):
        row = {'pk': u['pk'], 'username': u['username'], 'is_active': u['is_active'],
               'is_superuser': u['is_superuser']}
        if with_groups:
            row['groups_obj'] = [{'pk': 'g-%d' % i, 'name': g} for i, g in enumerate(u['groups'])]
        return row

    def add(self, username, groups=(), is_active=True, is_superuser=False):
        self.users[username] = {'pk': len(self.users) + 1, 'username': username,
                                'groups': list(groups), 'is_active': is_active,
                                'is_superuser': is_superuser}

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def authentik():
    fake = FakeAuthentik()
    fake.add('alice', [ADMINS, 'tak_ROLE_ADMIN'])
    fake.add('bob', ['tak_Users', 'authentik-ACME-AgencyAdmin'])
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


# --- the console under test -------------------------------------------------------------

class Console:
    def __init__(self, tmp_path, authentik):
        cfg = tmp_path / '.config'
        cfg.mkdir()
        (cfg / 'auth.json').write_text(json.dumps({'password_hash': 'hash-of:' + PASSWORD}))
        (cfg / 'proxy_auth.json').write_text(json.dumps({'secret': PROXY_SECRET, 'enforce': True}))
        self.hardening = {}
        self.audit = []
        self.ak_ctx = lambda: (authentik.url, {'Authorization': 'Bearer box-token'}, {})
        app = flask.Flask('console_under_test')
        self.app = app
        ns = {
            '__file__': str(tmp_path / 'app.py'), '__name__': 'console_under_test',
            'app': app, 'request': flask.request, 'session': flask.session,
            'jsonify': flask.jsonify, 'redirect': flask.redirect, 'url_for': flask.url_for,
            'os': os, 'json': json, 'secrets': secrets, 'hmac': hmac, 'hashlib': hashlib,
            'time': time, 'threading': threading, 'urllib': urllib, 'datetime': datetime,
            'timedelta': timedelta, 'wraps': __import__('functools').wraps,
            'CONFIG_DIR': str(cfg), 'VERSION': 'test',
            'load_settings': lambda: {'fqdn': 'example.com'},
            '_client_ip': lambda: '127.0.0.1', '_is_rate_limited': lambda *a, **k: False,
            '_rate_limit_ip_key': lambda ip: ip,   # ops #815: IPv6 is counted per /64
            '_same_origin_ok': lambda: True,
            'audit': lambda event, detail='', force=False: self.audit.append((event, detail)),
            '_w1_ak_ctx': lambda: self.ak_ctx(),
            'load_hardening': lambda: self.hardening,
            '_widle_sso_logout_active': lambda h: False,
            '_console_signout_url': lambda settings=None: '',
            'render_template': lambda name, **kw: 'PAGE %s error=%s' % (name, kw.get('error')),
            '_login_logo_url': lambda: '',
            'check_password_hash': lambda h, p: h == 'hash-of:' + p,
            '_upgrade_password_hash': lambda auth, p: None,
            '_note_password_length': lambda p: None,
            '_console_log_failed_login': lambda path: None,
            '_safe_next_path': lambda: '',
            'stored_hash_unusable': lambda h: None,
        }
        self.ns = ns
        exec(compile(_cookie_setup_region(), 'app.py:cookie-setup', 'exec'), ns)
        for name in ('CONSOLE_SESSION_LIFETIME_SECONDS', 'SESSION_TOKEN_KEY', '_session_token_cache',
                     '_PROXY_AUTH_FILE', '_proxy_auth_cache', 'SESSION_IDLE_MAX_DEFAULT',
                     'WIDLE_STATE_KEY', 'CONSOLE_SSO_ADMIN_GROUP', 'SSO_RECHECK_SECONDS',
                     'SSO_UNKNOWN_RETRY_SECONDS', 'SSO_UNCONFIRMED_MAX_SECONDS',
                     'SSO_LOOKUP_TIMEOUT_SECONDS', 'SSO_LOOKUP_WAIT_SECONDS', '_sso_dir_lock',
                     '_sso_dir_cache', '_sso_dir_inflight', '_sso_dir_last_admin', '_sso_dir_ctx'):
            src = _assign(name)
            if src:
                exec(src, ns)
        lifetime = re.search(r"^app\.config\['PERMANENT_SESSION_LIFETIME'\] = .*$", APP, re.M)
        if lifetime:
            exec(lifetime.group(0), ns)
        for name in ('load_auth', 'save_auth', '_session_auth_token', '_stamp_session_login',
                     '_drop_stale_session', '_end_all_sessions', '_save_proxy_auth_state',
                     '_stamp_notice_login',
                     '_proxy_auth_state', '_authentik_header_groups', '_sso_directory_ctx',
                     '_sso_directory_lookup', '_sso_directory_verdict',
                     '_sso_user_is_console_admin', '_session_made_by_sso',
                     '_sso_session_still_current', '_sso_denied_message',
                     '_apply_authentik_session', 'login_required', 'login', 'logout', 'index',
                     'ensure_session_valid', 'ensure_sso_session_current',
                     '_enforce_session_idle_lock'):
            src = _func(name)
            if src:
                exec(src, ns)
        # Same order as app.py registers them.
        for hook in ('ensure_session_valid', 'ensure_sso_session_current',
                     '_enforce_session_idle_lock'):
            if hook in ns:
                app.before_request(ns[hook])
        app.add_url_rule('/login', 'login', ns['login'], methods=['GET', 'POST'])
        app.add_url_rule('/logout', 'logout', ns['logout'], methods=['POST'])
        app.add_url_rule('/', 'index', ns['index'], methods=['GET', 'POST'])

        @ns['login_required']
        def console_page():
            return 'CONSOLE as %s via %s' % (flask.session.get('authentik_username'),
                                             flask.session.get('auth_via'))
        app.add_url_rule('/console', 'console_page', console_page)

        @ns['login_required']
        def api_metrics():
            return flask.jsonify({'cpu': 1})
        app.add_url_rule('/api/metrics', 'api_metrics', api_metrics)

        @ns['login_required']
        def api_restart():
            return flask.jsonify({'success': True})
        app.add_url_rule('/api/restart', 'api_restart', api_restart, methods=['POST'])

    def browser(self):
        return self.app.test_client()


def through_authentik(browser, path, user, groups, secret=PROXY_SECRET, **kw):
    """A page request the way Caddy sends it after forward_auth passed: from loopback, with
    the identity headers and the proxy-auth secret."""
    headers = {'X-Authentik-Username': user, 'X-Authentik-Groups': '|'.join(groups)}
    if secret is not None:
        headers['X-Infratak-Proxy-Auth'] = secret
    return browser.get(path, headers=headers, **kw)


@pytest.fixture
def console(tmp_path, authentik, clock):
    return Console(tmp_path, authentik)


ALICE_GROUPS = [ADMINS, 'tak_ROLE_ADMIN']
BOB_GROUPS = ['tak_Users', 'authentik-ACME-AgencyAdmin']


# --- 1. only a console administrator gets a session from Authentik sign-in --------------

def test_admin_signs_in_through_authentik(console):
    b = console.browser()
    r = through_authentik(b, '/console', 'alice', ALICE_GROUPS)
    assert r.status_code == 200 and b'CONSOLE as alice via sso' in r.data
    # The dashboard's background calls skip forward_auth: no headers, only the cookie.
    assert b.get('/api/metrics').status_code == 200
    assert b.post('/api/restart').status_code == 200


def test_non_admin_authentik_user_gets_no_console_session(console):
    """Passing forward_auth is not enough: a normal TAK Portal user gets no session."""
    b = console.browser()
    r = through_authentik(b, '/console', 'bob', BOB_GROUPS)
    assert r.status_code == 403
    assert b'CONSOLE' not in r.data
    assert b.get('/api/metrics').status_code == 401
    assert b.post('/api/restart').status_code == 401
    assert through_authentik(b, '/', 'bob', BOB_GROUPS).status_code == 403


def test_refused_user_is_told_why(console):
    b = console.browser()
    r = through_authentik(b, '/console', 'bob', BOB_GROUPS)
    text = r.get_data(as_text=True)
    assert 'bob' in text and ADMINS in text and 'console password' in text
    # Someone who is simply not signed in gets the plain page, not this message.
    plain = console.browser().get('/console')
    assert plain.status_code == 302 and plain.headers['Location'].endswith('/login')


@pytest.mark.parametrize('mode', ['error', 'forbidden'])
def test_non_admin_refused_when_authentik_api_gives_no_answer(console, authentik, mode):
    """No answer from the API must not open the door: the group header decides."""
    authentik.mode = mode
    b = console.browser()
    assert through_authentik(b, '/console', 'bob', BOB_GROUPS).status_code == 403
    assert b.get('/api/metrics').status_code == 401


@pytest.mark.parametrize('mode', ['error', 'forbidden'])
def test_admin_not_locked_out_when_authentik_api_gives_no_answer(console, authentik, mode):
    """Upgrade safety: a box whose API token does not work still lets an administrator
    in on the group header that forward_auth supplied."""
    authentik.mode = mode
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    assert b.get('/api/metrics').status_code == 200


@pytest.mark.parametrize('groups', [
    ['authentik Admins2'], ['not authentik Admins'], ['authentik', 'Admins'],
    ['authentik admins'], ['tak_Users,authentik Admins'], [],
])
def test_group_header_must_name_the_group_exactly(console, authentik, groups):
    authentik.mode = 'error'   # header-only decision
    b = console.browser()
    assert through_authentik(b, '/console', 'bob', groups).status_code == 403
    assert b.get('/api/metrics').status_code == 401


def test_group_header_is_pipe_separated(console, authentik):
    authentik.mode = 'error'
    b = console.browser()
    r = b.get('/console', headers={'X-Authentik-Username': 'alice',
                                   'X-Authentik-Groups': 'tak_Users|authentik Admins|tak_ROLE_ADMIN',
                                   'X-Infratak-Proxy-Auth': PROXY_SECRET})
    assert r.status_code == 200


def test_authentik_no_beats_a_stale_group_header(console, authentik):
    """The outpost keeps the group list from sign-in time. A person removed from the group
    still arrives with the old header; Authentik's live answer wins."""
    authentik.users['alice']['groups'] = ['tak_ROLE_ADMIN']
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 403
    assert b.get('/api/metrics').status_code == 401


def test_authentik_superuser_is_an_administrator(console, authentik):
    authentik.add('root2', ['Ops'], is_superuser=True)
    b = console.browser()
    assert through_authentik(b, '/console', 'root2', ['Ops']).status_code == 200


def test_lookup_reads_the_right_user_when_the_filter_is_ignored(console, authentik):
    """Authentik ignores a filter it does not know and returns every user. The lookup must
    judge the named user, not the first row (alice, an administrator)."""
    authentik.mode = 'ignore_filter'
    b = console.browser()
    assert through_authentik(b, '/console', 'bob', BOB_GROUPS).status_code == 403
    assert through_authentik(console.browser(), '/console', 'mallory', [ADMINS]).status_code == 403


def test_lookup_reads_groups_from_the_user_detail_when_the_list_has_none(console, authentik):
    authentik.mode = 'no_groups_in_list'
    assert through_authentik(console.browser(), '/console', 'alice', []).status_code == 200
    assert through_authentik(console.browser(), '/console', 'bob', [ADMINS]).status_code == 403


def test_identity_headers_without_the_proxy_secret_still_do_nothing(console):
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS, secret=None).status_code == 302
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS, secret='b' * 64).status_code == 302
    r = through_authentik(b, '/console', 'alice', ALICE_GROUPS,
                          environ_overrides={'REMOTE_ADDR': '203.0.113.9'})
    assert r.status_code == 302
    assert b.get('/api/metrics').status_code == 401


# --- 2. a session made by Authentik sign-in ends when access is removed -----------------

def test_sso_session_stops_on_api_after_removal_from_the_group(console, authentik, clock):
    """/api/* skips forward_auth, so the session itself must end with the access."""
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    assert b.get('/api/metrics').status_code == 200
    authentik.users['alice']['groups'] = ['tak_ROLE_ADMIN']
    clock.forward(61)
    assert b.get('/api/metrics').status_code == 401
    assert b.post('/api/restart').status_code == 401
    # And it stays ended, even if the next call would hit a fresh answer.
    authentik.users['alice']['groups'] = ALICE_GROUPS
    clock.forward(61)
    assert b.get('/api/metrics').status_code == 401


def test_sso_session_stops_after_the_account_is_deactivated(console, authentik, clock):
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    authentik.users['alice']['is_active'] = False
    clock.forward(61)
    assert b.post('/api/restart').status_code == 401


def test_sso_session_stops_after_the_account_is_deleted(console, authentik, clock):
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    del authentik.users['alice']
    clock.forward(61)
    assert b.get('/api/metrics').status_code == 401


def test_copied_cookie_of_a_removed_admin_is_dead(console, authentik, clock):
    b = console.browser()
    through_authentik(b, '/console', 'alice', ALICE_GROUPS)
    cookie = next(c for c in b._cookies.values() if 'infratak_session' in c.key)
    authentik.users['alice']['groups'] = []
    clock.forward(120)
    thief = console.browser()
    thief.set_cookie(cookie.key, cookie.value, domain='localhost')
    assert thief.get('/api/metrics').status_code == 401


def test_sso_session_survives_a_short_authentik_outage(console, authentik, clock):
    """An Authentik update or restart from the console takes Authentik away for a few
    minutes while the page polls. That must not sign the administrator out."""
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    authentik.mode = 'error'
    for _ in range(9):
        clock.forward(90)
        assert b.get('/api/metrics').status_code == 200
    authentik.mode = 'ok'
    clock.forward(90)
    assert b.get('/api/metrics').status_code == 200


def test_sso_session_ends_when_nothing_confirms_it_for_too_long(console, authentik, clock):
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    authentik.mode = 'error'
    clock.forward(14 * 60)
    assert b.get('/api/metrics').status_code == 200
    clock.forward(2 * 60 + 5)
    assert b.get('/api/metrics').status_code == 401
    # A page that passes forward_auth again starts a new session.
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    assert b.get('/api/metrics').status_code == 200


def test_long_stay_on_one_page_keeps_working_for_an_admin(console, authentik, clock):
    """A deploy log is watched for an hour with only /api calls. No page load, no
    forward_auth. Authentik keeps confirming, so the session holds."""
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    for _ in range(40):
        clock.forward(90)
        assert b.get('/api/metrics').status_code == 200
    assert b.post('/api/restart').status_code == 200


def test_authentik_is_asked_at_most_once_a_minute_per_user(console, authentik, clock):
    b = console.browser()
    through_authentik(b, '/console', 'alice', ALICE_GROUPS)
    for _ in range(50):
        b.get('/api/metrics')
    assert len(authentik.calls) == 1
    clock.forward(61)
    for _ in range(50):
        b.get('/api/metrics')
    assert len(authentik.calls) == 2


def test_background_poll_does_not_rewrite_the_cookie(console, authentik, clock):
    """A poll that rewrote the cookie could overwrite a newer one from a click that
    was in flight (the idle clock lives in the cookie)."""
    b = console.browser()
    through_authentik(b, '/console', 'alice', ALICE_GROUPS)
    clock.forward(61)
    r = b.get('/api/metrics')
    assert r.status_code == 200 and 'Set-Cookie' not in r.headers


def test_cookie_from_before_the_update_is_checked_too(console, authentik, clock):
    """A cookie made by Authentik sign-in before this change has no marker. It names an
    Authentik user, so it gets the same check."""
    for user, expect in (('alice', 200), ('bob', 401)):
        b = console.browser()
        with console.app.test_request_context():
            token = console.ns['_session_auth_token']()
        with b.session_transaction() as s:
            s['authenticated'] = True
            s['authentik_username'] = user
            s['login_token'] = token
            s['last_activity'] = int(time.time())
        assert b.get('/api/metrics').status_code == expect, user


# --- 3. the console password is its own way in ------------------------------------------

def test_password_session_does_not_depend_on_authentik(console, authentik, clock):
    b = console.browser()
    assert b.post('/login', data={'password': PASSWORD}).status_code == 302
    authentik.mode = 'error'
    authentik.users.clear()
    clock.forward(3600)
    assert b.get('/api/metrics').status_code == 200
    assert b.post('/api/restart').status_code == 200
    assert authentik.calls == []


def test_password_login_at_root_also_works(console):
    b = console.browser()
    assert b.post('/', data={'password': PASSWORD}).status_code == 302
    r = b.get('/console')
    assert r.status_code == 200 and b'via password' in r.data
    assert console.browser().post('/', data={'password': 'wrong'}).status_code == 200


def test_password_session_survives_a_non_admin_authentik_identity(console):
    """Standard posture: the administrator signed in with the console password, and the
    browser's Authentik identity is a normal user. The password session stands."""
    b = console.browser()
    b.post('/login', data={'password': PASSWORD})
    r = through_authentik(b, '/console', 'bob', BOB_GROUPS)
    assert r.status_code == 200 and b'via password' in r.data
    assert b.get('/api/metrics').status_code == 200


def test_password_session_stays_a_password_session_under_an_admin_identity(console, authentik, clock):
    b = console.browser()
    b.post('/login', data={'password': PASSWORD})
    r = through_authentik(b, '/console', 'alice', ALICE_GROUPS)
    assert r.status_code == 200 and b'CONSOLE as alice via password' in r.data
    authentik.users['alice']['groups'] = []
    clock.forward(120)
    assert b.get('/api/metrics').status_code == 200


def test_password_login_replaces_an_authentik_made_session(console, authentik, clock):
    b = console.browser()
    through_authentik(b, '/console', 'alice', ALICE_GROUPS)
    assert b.post('/', data={'password': PASSWORD}).status_code == 302
    authentik.users['alice']['groups'] = []
    clock.forward(120)
    r = b.get('/console')
    assert r.status_code == 200 and b'CONSOLE as None via password' in r.data


def test_logout_still_ends_every_session(console):
    a, b = console.browser(), console.browser()
    through_authentik(a, '/console', 'alice', ALICE_GROUPS)
    b.post('/login', data={'password': PASSWORD})
    assert b.get('/api/metrics').status_code == 200
    a.post('/logout')
    assert a.get('/api/metrics').status_code == 401
    assert b.get('/api/metrics').status_code == 401


# --- 4. the session cookie has a set lifetime -------------------------------------------

def test_session_lifetime_is_set_and_short():
    m = re.search(r'^CONSOLE_SESSION_LIFETIME_SECONDS = (.+)$', APP, re.M)
    assert m, 'no explicit session lifetime'
    assert 3600 <= eval(m.group(1).split('#')[0]) <= 24 * 3600
    assert re.search(r"^app\.config\['PERMANENT_SESSION_LIFETIME'\] = "
                     r"timedelta\(seconds=CONSOLE_SESSION_LIFETIME_SECONDS\)$", APP, re.M)


def test_untouched_session_cookie_ends_after_the_lifetime(console, clock):
    """A cookie that is left alone is refused after the set lifetime."""
    b = console.browser()
    b.post('/login', data={'password': PASSWORD})
    clock.forward(11 * 3600)
    assert b.get('/api/metrics').status_code == 200    # a poll: does not extend it
    clock.forward(2 * 3600)
    assert b.get('/api/metrics').status_code == 401


def test_session_in_use_does_not_end_at_the_lifetime(console, clock):
    """Standard posture has no idle lock. A real action (page, button) every few hours
    keeps the session; only one left alone ends."""
    b = console.browser()
    b.post('/login', data={'password': PASSWORD})
    for _ in range(6):
        clock.forward(5 * 3600)
        assert b.get('/console').status_code == 200
    assert b.post('/api/restart').status_code == 200


def test_sso_session_cookie_also_ends_after_the_lifetime(console, authentik, clock):
    b = console.browser()
    through_authentik(b, '/console', 'alice', ALICE_GROUPS)
    clock.forward(13 * 3600)
    assert b.get('/api/metrics').status_code == 401


# --- 5. Hardened posture: the idle lock is unchanged --------------------------------------

def test_hardened_idle_lock_still_locks_an_sso_session(console, authentik, clock):
    console.hardening.update(posture='hardened', applied={'W2_session': {'idle_max_seconds': 1800}})
    b = console.browser()
    assert through_authentik(b, '/console', 'alice', ALICE_GROUPS).status_code == 200
    clock.forward(20 * 60)
    assert b.get('/api/metrics').status_code == 200     # a poll is not activity
    clock.forward(11 * 60)
    r = b.get('/api/metrics')
    assert r.status_code == 401 and b'idle lock' in r.data
    # A click before the limit keeps it.
    b2 = console.browser()
    through_authentik(b2, '/console', 'alice', ALICE_GROUPS)
    clock.forward(20 * 60)
    assert b2.post('/api/restart').status_code == 200
    clock.forward(20 * 60)
    assert b2.get('/api/metrics').status_code == 200


def test_hardened_idle_lock_still_locks_a_password_session(console, clock):
    console.hardening.update(posture='hardened', applied={'W2_session': {'idle_max_seconds': 1800}})
    b = console.browser()
    b.post('/login', data={'password': PASSWORD})
    assert b.get('/console').status_code == 200
    clock.forward(31 * 60)
    r = b.get('/console')
    assert r.status_code == 302 and r.headers['Location'].endswith('/login')
    assert b.get('/api/metrics').status_code == 401


# --- 6. the pieces the check depends on stay in place -----------------------------------

def test_console_vhost_still_hands_the_group_header_to_the_console():
    src = _func('generate_caddyfile') or APP
    # ops #1081: the block comes from the one writer of every forward_auth block. The console
    # hands it the header list and its own matcher.
    call = src[src.index("_caddy_forward_auth_lines(ak_up, \"        \", _CADDY_AK_COPY_HEADERS,"):]
    call = call[:call.index('reverse_proxy 127.0.0.1:5001')]
    assert "matcher='@needs_sso'" in call
    assert 'X-Authentik-Groups' in APP[APP.index('_CADDY_AK_COPY_HEADERS = ('):][:200]
    writer = APP[APP.index('def _caddy_forward_auth_lines('):]
    assert "out.append(f'    copy_headers {copy_headers}')" in writer[:writer.index('\ndef ')]
    assert "'X-Authentik-Groups'" in src[src.index('_AK_FWD_HEADERS = ('):][:200], \
        'the client-sent group header must be stripped before forward_auth sets the real one'


def test_every_way_into_a_session_goes_through_the_checks():
    """A new place that sets session['authenticated'] must be a known one."""
    setters = [n.name for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)
               and re.search(r"session\[['\"]authenticated['\"]\]\s*=\s*True",
                             ast.get_source_segment(APP, n) or '')]
    assert sorted(setters) == ['_apply_authentik_session', 'index', 'login']
    body = _func('_apply_authentik_session')
    gate = body.index('_sso_user_is_console_admin(')
    assert gate < body.index("session['authenticated'] = True")
    for name in ('login', 'index'):
        assert "session['auth_via'] = 'password'" in _func(name)
