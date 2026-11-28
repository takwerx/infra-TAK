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
"""Console login and session hardening (ops #815).

The contract pinned here, with the real functions from app.py in a small Flask app:
- the page a login sends you to is always a path on the console, whatever `next` holds;
  the setup-AP link to /connectivity still works;
- in Hardened posture a session with no activity stamp is an expired session, a password
  login stamps one, a password login at / starts from an empty session, and an error
  in the lock ends the session instead of letting the request through; a password
  sign-in sent with the expired cookie works the first time, except where the Authentik
  sign-out must run first;
- the three endpoints meant for the box's own scripts refuse a request that came through
  a proxy on the box (X-Forwarded-For), like /api/guarddog/cloudtak-repair does;
- /logout only acts on a request from the console's own origin;
- the rate limiter counts IPv6 per /64 and forgets addresses that have gone quiet, and a
  wrong console password typed into any "confirm with your password" form is recorded
  like a failed login (once per request);
- the public health endpoint answers while another caller holds a connection open, keeps
  its answer for a few seconds, and reaches a running box when its script changes.
"""

import ast
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import pathlib
import re
import secrets
import socket
import subprocess
import threading
import time
import types
import urllib.parse
import urllib.request
from collections import defaultdict, deque

import pytest

flask = pytest.importorskip('flask')
werkzeug_security = pytest.importorskip('werkzeug.security')

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
_TREE = ast.parse(APP)
HEALTH_SCRIPT = REPO / 'scripts' / 'guarddog' / 'tak-health-endpoint.py'

CONSOLE = 'https://infratak.example.com'
RIGHT = 'correct-horse-battery'

_FUNCS = (
    '_client_ip', '_rate_limit_ip_key', '_is_rate_limited', '_effective_request_host',
    '_same_origin_ok', 'ensure_session_valid', 'verify_password',
    '_safe_next_path', '_console_note_failed_password_check', '_console_log_failed_login',
    '_console_log_login_ok',
    'login', 'logout', 'index', '_enforce_session_idle_lock', 'hardening_apply',
    'console_restart_safe', 'console_power_api',
    'guarddog_send_alert_email', 'guarddog_send_sms',
)
_ASSIGNS = (
    '_RATE_LOCK', '_RATE_HITS', '_RATE_EXPIRES', '_RATE_SWEEP', '_RATE_SWEEP_EVERY',
    '_SAFE_NEXT_PATH_RE', '_PW_FAIL_KEY', '_PW_FAIL_SEEN', '_PW_FAIL_SEEN_MAX', '_PW_FAIL_SAME_WINDOW',
    'CONSOLE_PASSWORD_MIN_LEN', 'CONSOLE_LOGIN_FAIL_LOG', 'CONSOLE_LOGIN_FAIL_LOG_MAX',
)


def _func_src(name):
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(APP, node)
    return None


def _assign_src(name):
    for node in _TREE.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], 'id', None) == name):
            return ast.get_source_segment(APP, node)
    return None


class _Clock:
    """Stands in for the `time` module inside the code under test."""

    def __init__(self):
        self.offset = 0.0

    def time(self):
        return time.time() + self.offset


@pytest.fixture
def console(tmp_path):
    cfg = tmp_path / 'config'
    cfg.mkdir()
    state = {
        'hardening': {},            # {} = Standard posture
        'settings': {'guarddog_alert_email': 'ops@example.com',
                     'guarddog_sms': {'provider': 'twilio'}},
        'emails': [], 'sms': [], 'audits': [], 'ended_all': 0, 'power': [],
    }
    auth = {'password_hash': werkzeug_security.generate_password_hash(RIGHT, method='pbkdf2:sha256')}
    clock = _Clock()

    app = flask.Flask('ops815')
    app.secret_key = 'test'
    ns = {
        '__name__': 'ops815',
        'os': os, 'json': json, 're': re, 'urllib': urllib, 'ipaddress': ipaddress,
        'hmac': hmac, 'hashlib': hashlib, 'secrets': secrets,
        'threading': threading, 'defaultdict': defaultdict, 'deque': deque,
        'datetime': datetime.datetime, 'time': clock,
        'CONFIG_DIR': str(cfg), 'VERSION': 'test',
        'SESSION_IDLE_MAX_DEFAULT': 1800, 'WIDLE_STATE_KEY': 'WIDLE',
        'app': app, 'request': flask.request, 'session': flask.session, 'g': flask.g,
        'has_request_context': flask.has_request_context,
        'redirect': flask.redirect, 'url_for': flask.url_for, 'jsonify': flask.jsonify,
        'render_template': lambda tpl, **kw: 'page error=%s' % kw.get('error'),
        '_werkzeug_check_password_hash': werkzeug_security.check_password_hash,
        'load_auth': lambda: dict(auth), 'save_auth': lambda d: None,
        'load_settings': lambda: dict(state['settings']),
        'load_hardening': lambda: state['hardening'],
        'save_hardening': lambda h: state.__setitem__('hardening', h),
        '_hardening_registry': lambda: [],
        '_hardening_history': lambda h, what, detail: None,
        '_upgrade_password_hash': lambda a, pw: None,
        '_note_password_length': lambda pw: None,
        'stored_hash_unusable': lambda h: None,
        '_apply_authentik_session': lambda: False,
        '_sso_denied_message': lambda: None,   # ops #813: the sign-in page's "not an administrator" text
        '_login_logo_url': lambda: None,
        '_stamp_session_login': lambda: None,
        '_stamp_notice_login': lambda fresh: None,   # root-console bar (PR 525) calls it on every login
        '_drop_stale_session': lambda: None,
        '_end_all_sessions': lambda: state.__setitem__('ended_all', state['ended_all'] + 1),
        '_widle_sso_logout_active': lambda h: False,
        '_console_signout_url': lambda: '',
        '_console_busy_reason': lambda: None,
        '_detached_power_action': lambda action, delay=2: state['power'].append(action),
        '_gd_quiet_state': lambda: (False, ''),
        '_gd_alerts_pause_state': lambda: (False, ''),
        '_guarddog_send_alert_email_via_relay':
            lambda to, subject, body: state['emails'].append((to, subject)) or True,
        '_guarddog_send_sms_now': lambda sms, text: state['sms'].append(text),
        'audit': lambda ev, detail='', force=False: state['audits'].append((ev, detail)),
        'print': lambda *a, **kw: None,
    }
    for name in _ASSIGNS:
        src = _assign_src(name)
        if src:
            exec(src, ns)
    for name in _FUNCS:
        src = _func_src(name)
        if src:
            exec(src, ns)
    ns['check_password_hash'] = ns['verify_password']      # as app.py binds it

    app.before_request(ns['ensure_session_valid'])
    app.before_request(ns['_enforce_session_idle_lock'])
    app.add_url_rule('/login', 'login', ns['login'], methods=['GET', 'POST'])
    app.add_url_rule('/logout', 'logout', ns['logout'], methods=['POST'])
    app.add_url_rule('/', 'index', ns['index'], methods=['GET', 'POST'])
    app.add_url_rule('/api/console/restart-safe', 'restart_safe', ns['console_restart_safe'])
    app.add_url_rule('/api/console/power', 'power', ns['console_power_api'], methods=['POST'])
    app.add_url_rule('/api/hardening/apply', 'hardening_apply', ns['hardening_apply'], methods=['POST'])
    app.add_url_rule('/api/guarddog/send-alert-email', 'gd_email',
                     ns['guarddog_send_alert_email'], methods=['POST'])
    app.add_url_rule('/api/guarddog/send-sms', 'gd_sms', ns['guarddog_send_sms'], methods=['POST'])

    def _page():
        return ('in', 200) if flask.session.get('authenticated') else ('out', 401)

    app.add_url_rule('/console', 'console_page', _page)
    app.add_url_rule('/connectivity', 'connectivity', _page)
    app.add_url_rule('/api/metrics', 'metrics', lambda: flask.jsonify(ok=True))

    return types.SimpleNamespace(app=app, ns=ns, state=state, clock=clock,
                                 log=cfg / 'console-auth.log')


def _log_lines(console):
    # failed-login lines only: a good login adds a `login ok` line for the Guard Dog watch (ops #1406)
    lines = console.log.read_text().splitlines() if console.log.exists() else []
    return [ln for ln in lines if 'failed login' in ln]


def _login(console, client, path='/login', **kw):
    return client.post(path, data={'password': RIGHT}, base_url=CONSOLE,
                       headers={'Origin': CONSOLE}, **kw)


def _browser_target(location, base=CONSOLE):
    """Where a browser goes for this Location header: it drops tab and newline
    characters and surrounding spaces before it reads the URL (WHATWG URL)."""
    cleaned = re.sub(r'[\t\n\r]', '', location or '').strip()
    return urllib.parse.urlsplit(urllib.parse.urljoin(base + '/login', cleaned))


# --------------------------------------------------------------------------- #
# 1. The page after login is always on the console
# --------------------------------------------------------------------------- #

OFF_SITE_NEXT = [
    '/\t/evil.example', '/\n/evil.example', '/\r/evil.example', '/\r\n/evil.example',
    '/\t\\evil.example', '/ /evil.example', '/\x0b/evil.example', '/\x00/evil.example',
    '//evil.example', '/\\evil.example', '\\/evil.example', 'https://evil.example/',
    '/x://evil.example', '/.//evil.example', '/a/..//evil.example', '/\u00a0/evil.example',
    '/\u2028/evil.example', 'evil.example', '/@evil.example//', '/;//evil.example',
]


@pytest.mark.parametrize('path', ['/login', '/'])
@pytest.mark.parametrize('nxt', OFF_SITE_NEXT)
def test_login_never_sends_the_browser_to_another_site(console, path, nxt):
    c = console.app.test_client()
    r = c.post(path, query_string={'next': nxt}, data={'password': RIGHT}, base_url=CONSOLE)
    assert r.status_code == 302
    target = _browser_target(r.headers['Location'])
    assert target.netloc == 'infratak.example.com', r.headers['Location']
    assert r.headers['Location'] == '/console', r.headers['Location']


@pytest.mark.parametrize('nxt', ['/\t/evil.example', '//evil.example'])
def test_next_in_the_posted_form_is_checked_too(console, nxt):
    c = console.app.test_client()
    r = c.post('/login', data={'password': RIGHT, 'next': nxt}, base_url=CONSOLE)
    assert r.headers['Location'] == '/console'


@pytest.mark.parametrize('path', ['/login', '/'])
@pytest.mark.parametrize('nxt', ['/connectivity', '/connectivity?from=setup-ap', '/takserver'])
def test_setup_ap_deep_link_still_lands_on_its_page(console, path, nxt):
    c = console.app.test_client()
    r = c.post(path, query_string={'next': nxt}, data={'password': RIGHT}, base_url=CONSOLE)
    assert r.status_code == 302 and r.headers['Location'] == nxt
    assert c.get('/connectivity', base_url=CONSOLE).status_code == 200


def test_no_next_goes_to_the_console(console):
    c = console.app.test_client()
    assert _login(console, c).headers['Location'] == '/console'


# --------------------------------------------------------------------------- #
# 2. Idle lock (Hardened posture)
# --------------------------------------------------------------------------- #

HARDENED = {'posture': 'hardened', 'applied': {'W2_session': {'idle_max_seconds': 1800}}}


def _forge_session(client, **values):
    with client.session_transaction(base_url=CONSOLE) as s:
        s.clear()
        s.update(values)


@pytest.mark.parametrize('path', ['/login', '/'])
def test_password_login_stamps_the_idle_clock(console, path):
    console.state['hardening'] = HARDENED
    c = console.app.test_client()
    _login(console, c, path)
    with c.session_transaction(base_url=CONSOLE) as s:
        assert s.get('authenticated') is True
        assert abs(int(s['last_activity']) - int(time.time())) < 5


def test_hardened_session_without_a_stamp_is_locked(console):
    """A cookie that never got a stamp, replayed with background GETs only."""
    console.state['hardening'] = HARDENED
    c = console.app.test_client()
    _forge_session(c, authenticated=True)
    for _ in range(3):
        r = c.get('/api/metrics', base_url=CONSOLE)
        assert r.status_code == 401 and r.get_json()['login_required'] is True
    r = c.get('/console', base_url=CONSOLE)
    assert r.status_code == 302 and r.headers['Location'].endswith('/login')
    assert c.get('/console', base_url=CONSOLE).status_code == 401      # session is gone


@pytest.mark.parametrize('stamp', ['not-a-number', [], {'a': 1}])
def test_hardened_session_with_an_unreadable_stamp_is_locked(console, stamp):
    console.state['hardening'] = HARDENED
    c = console.app.test_client()
    _forge_session(c, authenticated=True, last_activity=stamp)
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 401


def test_standard_posture_has_no_idle_lock(console):
    c = console.app.test_client()
    _forge_session(c, authenticated=True)
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200
    assert c.get('/console', base_url=CONSOLE).status_code == 200


def test_hardened_lock_still_works_the_normal_way(console):
    console.state['hardening'] = HARDENED
    c = console.app.test_client()
    _login(console, c)
    assert c.get('/console', base_url=CONSOLE).status_code == 200
    console.clock.offset = 1700                     # polls do not count as activity
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200
    console.clock.offset = 1900
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 401
    r = c.get('/console', base_url=CONSOLE)
    assert r.status_code == 302 and r.headers['Location'].endswith('/login')
    # and a new login works at once
    _login(console, c)
    assert c.get('/console', base_url=CONSOLE).status_code == 200
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200


@pytest.mark.parametrize('path', ['/login', '/'])
def test_sign_in_right_after_the_idle_lock_works_the_first_time(console, path):
    """The 10.4.2 T&E saw a password session "still open" 10 s past the limit. It was not:
    the background call was told 401 on time, but the sign-in that came next (same cookie,
    no page load in between) was sent back to /login with its password unread, so the
    test tool only got in again one poll later."""
    console.state['hardening'] = {'posture': 'hardened',
                                  'applied': {'W2_session': {'idle_max_seconds': 30}}}
    c = console.app.test_client()
    _login(console, c)
    console.clock.offset = 29
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200
    console.clock.offset = 32                       # past the limit: locked at once
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 401
    audits = len(console.state['audits'])
    r = _login(console, c, path)                    # the first sign-in after the lock
    assert r.status_code == 302 and r.headers['Location'] == '/console', r.headers['Location']
    assert console.state['audits'][audits:] == [('auth:login-password', 'console password / break-glass')]
    assert c.get('/console', base_url=CONSOLE).status_code == 200
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200


@pytest.mark.parametrize('path', ['/login', '/'])
def test_wrong_password_right_after_the_idle_lock_gets_the_error_and_no_session(console, path):
    console.state['hardening'] = HARDENED
    c = console.app.test_client()
    _forge_session(c, authenticated=True, authentik_username='someone.else',
                   last_activity=int(time.time()) - 4000)
    r = c.post(path, data={'password': 'wrong-guess-123'}, base_url=CONSOLE,
               headers={'Origin': CONSOLE})
    assert r.status_code == 200 and 'Invalid password' in r.get_data(as_text=True)
    assert len(_log_lines(console)) == 1            # recorded as a failed login
    with c.session_transaction(base_url=CONSOLE) as s:
        assert not s.get('authenticated') and 'authentik_username' not in s
    assert c.get('/console', base_url=CONSOLE).status_code == 401


SIGNOUT = CONSOLE + '/outpost.goauthentik.io/sign_out'


def _arm_sso_signout(console):
    """W-IDLE armed and the console SSO-locked, with app.py's own test for it: an expired
    session on a request that came through Authentik is also signed out of Authentik."""
    console.state['hardening'] = {
        'posture': 'hardened',
        'applied': {'W2_session': {'idle_max_seconds': 1800},
                    'W1_sso': {'caddy_login_locked': True},
                    'WIDLE': {'mode': 'sso_signout', 'signout_url': SIGNOUT}}}
    for name in ('_w1_console_locked', '_widle_sso_logout_active'):
        exec(_func_src(name), console.ns)
    console.ns['_console_signout_url'] = lambda: SIGNOUT


VIA_AUTHENTIK = {'X-Authentik-Username': 'akadmin'}      # what Caddy adds after forward_auth


def test_sign_in_right_after_the_idle_lock_works_with_sso_signout_armed(console):
    """test12 in the T&E: W-IDLE armed, a password session on the IP and port way in
    (no Authentik in front of it, so there is nothing to sign out of)."""
    _arm_sso_signout(console)
    c = console.app.test_client()
    _login(console, c, '/')
    console.clock.offset = 1900
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 401
    r = _login(console, c, '/')
    assert r.status_code == 302 and r.headers['Location'] == '/console', r.headers['Location']
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200


@pytest.mark.parametrize('values', [
    {'auth_via': 'sso', 'authentik_username': 'akadmin'},         # made by Authentik
    {'authentik_username': 'akadmin'},                            # cookie from before ops #813
    {'auth_via': 'password', 'authentik_username': 'akadmin'},    # password session seen through Authentik
    {'auth_via': 'password'},
])
@pytest.mark.parametrize('password', [RIGHT, 'wrong-guess-123'])
def test_sign_in_does_not_skip_the_authentik_sign_out(console, values, password):
    """With W-IDLE armed, a sign-in POST that came through Authentik must not leave a live
    Authentik session behind an ended console session: the next page would sign the
    browser in again with no prompt."""
    _arm_sso_signout(console)
    c = console.app.test_client()
    _forge_session(c, authenticated=True, last_activity=int(time.time()) - 4000, **values)
    r = c.post('/login', data={'password': password}, base_url=CONSOLE,
               headers=dict(VIA_AUTHENTIK, Origin=CONSOLE))
    assert r.status_code == 302 and r.headers['Location'] == SIGNOUT, r.headers['Location']
    assert console.state['audits'] == [] and _log_lines(console) == []   # password not read
    with c.session_transaction(base_url=CONSOLE) as s:
        assert not s.get('authenticated')


def test_an_expired_authentik_session_sent_to_the_port_gets_no_way_in(console):
    """The Authentik-made cookie replayed on the IP and port way in, with a wrong password."""
    _arm_sso_signout(console)
    c = console.app.test_client()
    _forge_session(c, authenticated=True, auth_via='sso', authentik_username='akadmin',
                   last_activity=int(time.time()) - 4000)
    r = c.post('/', data={'password': 'wrong-guess-123'}, base_url=CONSOLE,
               headers={'Origin': CONSOLE})
    assert r.status_code == 200 and 'Invalid password' in r.get_data(as_text=True)
    with c.session_transaction(base_url=CONSOLE) as s:
        assert dict(s) == {}
    assert c.get('/console', base_url=CONSOLE).status_code == 401


@pytest.mark.parametrize('method,path', [('POST', '/logout'), ('GET', '/login'), ('GET', '/'),
                                         ('GET', '/console')])
def test_only_a_sign_in_passes_an_expired_session(console, method, path):
    """Every other request with an expired session is still sent to the sign-in page."""
    console.state['hardening'] = HARDENED
    c = console.app.test_client()
    _forge_session(c, authenticated=True, last_activity=int(time.time()) - 4000)
    r = c.open(path, method=method, base_url=CONSOLE, headers={'Origin': CONSOLE})
    assert r.status_code == 302 and r.headers['Location'].endswith('/login')
    assert console.state['ended_all'] == 0          # an expired session cannot end the others
    with c.session_transaction(base_url=CONSOLE) as s:
        assert not s.get('authenticated')


@pytest.mark.parametrize('path', ['/login', '/'])
def test_sign_in_still_works_when_the_lock_itself_fails(console, path):
    """An error in the lock ends the session, but must not eat the password that comes with it."""
    console.state['hardening'] = {'posture': 'hardened', 'applied': {'W2_session': 'broken'}}
    c = console.app.test_client()
    _forge_session(c, authenticated=True, last_activity=int(time.time()))
    r = _login(console, c, path)
    assert r.status_code == 302 and r.headers['Location'] == '/console'


def test_page_use_keeps_a_hardened_session_alive(console):
    console.state['hardening'] = HARDENED
    c = console.app.test_client()
    _login(console, c)
    for offset in (1000, 2000, 3000):
        console.clock.offset = offset
        assert c.get('/console', base_url=CONSOLE).status_code == 200


def test_an_error_in_the_lock_ends_the_session_on_a_hardened_box(console):
    console.state['hardening'] = {'posture': 'hardened', 'applied': {'W2_session': 'broken'}}
    poller = console.app.test_client()
    _forge_session(poller, authenticated=True, last_activity=int(time.time()))
    assert poller.get('/api/metrics', base_url=CONSOLE).status_code == 401
    c = console.app.test_client()
    _forge_session(c, authenticated=True, last_activity=int(time.time()))
    r = c.get('/console', base_url=CONSOLE)
    assert r.status_code == 302 and r.headers['Location'].endswith('/login')
    assert c.get('/console', base_url=CONSOLE).status_code == 401
    # the login page itself still works, so the operator is not locked out
    assert c.get('/login', base_url=CONSOLE).status_code == 200


def test_a_bad_idle_setting_falls_back_to_the_default_not_to_no_lock(console):
    console.state['hardening'] = {'posture': 'hardened',
                                  'applied': {'W2_session': {'idle_max_seconds': 'soon'}}}
    c = console.app.test_client()
    _login(console, c)
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200
    console.clock.offset = 1900                     # past the 1800 s default
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 401


def test_turning_hardened_on_does_not_lock_the_operator_who_did_it(console):
    """The idle clock does not run in Standard posture, so the stamp is as old as the login."""
    c = console.app.test_client()
    _login(console, c)
    console.clock.offset = 7200                     # two hours of work in Standard posture
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200
    console.state['hardening'] = {'applied': {'W2_session': {'idle_max_seconds': 1800}}}
    r = c.post('/api/hardening/apply', base_url=CONSOLE, headers={'Origin': CONSOLE})
    assert r.status_code == 200 and console.state['hardening']['posture'] == 'hardened'
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 200
    assert c.get('/console', base_url=CONSOLE).status_code == 200
    console.clock.offset = 7200 + 1900              # and the lock works from then on
    assert c.get('/api/metrics', base_url=CONSOLE).status_code == 401


def test_password_login_at_root_starts_from_an_empty_session(console):
    """An old SSO name must not stay in the cookie: the audit log reads it."""
    c = console.app.test_client()
    _forge_session(c, authenticated=True, authentik_username='someone.else', leftover='x')
    _login(console, c, '/')
    with c.session_transaction(base_url=CONSOLE) as s:
        assert s.get('authenticated') is True
        assert 'authentik_username' not in s and 'leftover' not in s


# --------------------------------------------------------------------------- #
# 3. Endpoints for the box's own scripts
# --------------------------------------------------------------------------- #

LOCAL = {'REMOTE_ADDR': '127.0.0.1'}
SCRIPT_ENDPOINTS = [
    ('GET', '/api/console/restart-safe'),
    ('POST', '/api/guarddog/send-alert-email'),
    ('POST', '/api/guarddog/send-sms'),
]


def _call(client, method, path, **kw):
    if method == 'POST':
        kw.setdefault('json', {'subject': 'Guard Dog test', 'body': 'hello'})
    return client.open(path, method=method, **kw)


@pytest.mark.parametrize('method,path', SCRIPT_ENDPOINTS)
def test_script_endpoint_answers_the_box_itself(console, method, path):
    r = _call(console.app.test_client(), method, path, environ_base=LOCAL)
    assert r.status_code == 200, r.get_data(as_text=True)


def test_guard_dog_alert_email_and_sms_are_sent_for_the_box_itself(console):
    c = console.app.test_client()
    assert _call(c, 'POST', '/api/guarddog/send-alert-email', environ_base=LOCAL).get_json() == \
        {'success': True, 'suppressed': False}
    assert _call(c, 'POST', '/api/guarddog/send-sms', environ_base=LOCAL).get_json() == {'success': True}
    assert console.state['emails'] == [('ops@example.com', 'Guard Dog test')]
    assert console.state['sms'] == ['Guard Dog test: hello']
    assert _call(c, 'GET', '/api/console/restart-safe', environ_base=LOCAL).get_json() == \
        {'safe': True, 'reason': None}


@pytest.mark.parametrize('method,path', SCRIPT_ENDPOINTS)
@pytest.mark.parametrize('xff', ['203.0.113.9', '127.0.0.1', '10.0.0.5, 203.0.113.9'])
def test_script_endpoint_refuses_a_request_that_came_through_a_proxy(console, method, path, xff):
    r = _call(console.app.test_client(), method, path, environ_base=LOCAL,
              headers={'X-Forwarded-For': xff})
    assert r.status_code == 403
    assert console.state['emails'] == [] and console.state['sms'] == []


@pytest.mark.parametrize('method,path', SCRIPT_ENDPOINTS)
def test_script_endpoint_refuses_another_host(console, method, path):
    r = _call(console.app.test_client(), method, path, environ_base={'REMOTE_ADDR': '203.0.113.9'})
    assert r.status_code == 403
    assert console.state['emails'] == [] and console.state['sms'] == []


# --------------------------------------------------------------------------- #
# 4. Logout only from the console's own origin
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('headers', [
    {'Origin': 'https://nodered.example.com'},
    {'Origin': 'https://evil.example'},
    {'Referer': 'https://takportal.example.com/some/page'},
    {'Origin': 'null'},
    {},
])
def test_logout_from_another_site_does_nothing(console, headers):
    c = console.app.test_client()
    _login(console, c)
    r = c.post('/logout', base_url=CONSOLE, headers=headers)
    assert r.status_code == 403
    assert console.state['ended_all'] == 0
    assert c.get('/console', base_url=CONSOLE).status_code == 200       # still signed in
    assert not [a for a in console.state['audits'] if a[0] == 'auth:logout']


@pytest.mark.parametrize('headers', [
    {'Origin': CONSOLE},
    {'Referer': CONSOLE + '/console'},
])
def test_logout_from_the_console_signs_out(console, headers):
    c = console.app.test_client()
    _login(console, c)
    r = c.post('/logout', base_url=CONSOLE, headers=headers)
    assert r.status_code == 302
    assert console.state['ended_all'] == 1
    assert c.get('/console', base_url=CONSOLE).status_code == 401
    assert [a for a in console.state['audits'] if a[0] == 'auth:logout']


def test_logout_on_the_ip_and_port_way_in(console):
    c = console.app.test_client()
    base = 'https://198.51.100.20:5001'
    c.post('/login', data={'password': RIGHT}, base_url=base)
    assert c.get('/console', base_url=base).status_code == 200
    r = c.post('/logout', base_url=base, headers={'Origin': base})
    assert r.status_code == 302 and c.get('/console', base_url=base).status_code == 401


def test_logout_behind_the_proxy_uses_the_public_name(console):
    c = console.app.test_client()
    fwd = {'X-Forwarded-Host': 'infratak.example.com', 'X-Forwarded-For': '203.0.113.7'}
    c.post('/login', data={'password': RIGHT}, base_url='http://127.0.0.1:5001', headers=fwd)
    r = c.post('/logout', base_url='http://127.0.0.1:5001', headers=dict(fwd, Origin=CONSOLE))
    assert r.status_code == 302 and console.state['ended_all'] == 1


# --------------------------------------------------------------------------- #
# 5. Rate limiter and failed password checks
# --------------------------------------------------------------------------- #

def test_ipv6_is_counted_per_64(console):
    key = console.ns.get('_rate_limit_ip_key')
    assert key, '_rate_limit_ip_key is not in app.py'
    assert key('2001:db8:1:2::1') == key('2001:db8:1:2:ffff:ffff:ffff:ffff') == '2001:db8:1:2::/64'
    assert key('2001:db8:1:3::1') != key('2001:db8:1:2::1')
    assert key('203.0.113.7') == '203.0.113.7'
    assert key('::ffff:203.0.113.7') == '203.0.113.7'
    assert key('fe80::1%eth0') == 'fe80::/64'
    assert key('unknown') == 'unknown' and key('') == ''


def test_login_limit_holds_across_one_ipv6_64(console):
    c = console.app.test_client()
    for i in range(1, 13):
        r = c.post('/login', data={'password': 'wrong-guess-%d' % i}, base_url=CONSOLE,
                   environ_base={'REMOTE_ADDR': '2001:db8:1:2::%x' % i})
        assert r.status_code == 200
    r = c.post('/login', data={'password': 'wrong-guess-13'}, base_url=CONSOLE,
               environ_base={'REMOTE_ADDR': '2001:db8:1:2:aaaa::99'})
    assert r.status_code == 429
    # another /64, and IPv4, are not held back by it
    for addr in ('2001:db8:1:3::1', '203.0.113.7'):
        assert c.post('/login', data={'password': 'x'}, base_url=CONSOLE,
                      environ_base={'REMOTE_ADDR': addr}).status_code == 200


def test_login_limit_per_ipv4_address_is_unchanged(console):
    c = console.app.test_client()
    for _ in range(12):
        assert c.post('/login', data={'password': 'x'}, base_url=CONSOLE,
                      environ_base={'REMOTE_ADDR': '203.0.113.7'}).status_code == 200
    assert c.post('/login', data={'password': 'x'}, base_url=CONSOLE,
                  environ_base={'REMOTE_ADDR': '203.0.113.7'}).status_code == 429
    assert c.post('/login', data={'password': 'x'}, base_url=CONSOLE,
                  environ_base={'REMOTE_ADDR': '203.0.113.8'}).status_code == 200
    console.clock.offset = 301                      # the window passes
    assert c.post('/login', data={'password': 'x'}, base_url=CONSOLE,
                  environ_base={'REMOTE_ADDR': '203.0.113.7'}).status_code == 200


def test_rate_limiter_forgets_quiet_addresses(console):
    limited, hits = console.ns['_is_rate_limited'], console.ns['_RATE_HITS']
    for i in range(500):
        assert limited('login:198.51.100.%d' % i, 12, 300) is False
    assert len(hits) == 500
    console.clock.offset = 400                      # every window has passed
    assert limited('login:203.0.113.7', 12, 300) is False
    assert set(hits) == {'login:203.0.113.7'}
    # a key still inside its window survives a sweep, and keeps its count
    for _ in range(11):
        limited('login:203.0.113.7', 12, 300)
    console.clock.offset = 400 + 120
    limited('apiw:203.0.113.9', 240, 60)
    assert len(hits['login:203.0.113.7']) == 12
    assert limited('login:203.0.113.7', 12, 300) is True


def _power(client, password, addr='203.0.113.7'):
    return client.post('/api/console/power', json={'action': 'reboot', 'password': password},
                       base_url=CONSOLE, headers={'Origin': CONSOLE},
                       environ_base={'REMOTE_ADDR': addr})


def test_wrong_password_on_a_confirm_form_is_recorded_like_a_failed_login(console):
    c = console.app.test_client()
    _login(console, c)
    assert _power(c, 'wrong-guess-123').status_code == 403
    lines = _log_lines(console)
    assert len(lines) == 1
    assert re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d console: failed login from 203\.0\.113\.7', lines[0])
    assert 'wrong-guess-123' not in console.log.read_text()
    assert console.state['audits'][-1][0] == 'auth:login-failed'
    assert console.state['power'] == []


def test_the_same_wrong_password_sent_again_is_one_failed_login(console):
    """The uninstall dialog sends one typed password up to three times (check, open, submit)."""
    c = console.app.test_client()
    _login(console, c)
    for _ in range(4):
        assert _power(c, 'wrong-guess-123').status_code == 403
    assert len(_log_lines(console)) == 1
    assert _power(c, 'wrong-guess-124').status_code == 403         # a new guess is a new line
    assert _power(c, 'wrong-guess-123').status_code == 403         # and so is going back
    assert len(_log_lines(console)) == 3
    assert _power(c, 'wrong-guess-123', addr='203.0.113.8').status_code == 403     # per address
    assert len(_log_lines(console)) == 4
    console.clock.offset = 601                                      # after 10 minutes it counts again
    assert _power(c, 'wrong-guess-123', addr='203.0.113.8').status_code == 403
    assert len(_log_lines(console)) == 5
    assert 'wrong-guess' not in console.log.read_text()
    seen = console.ns['_PW_FAIL_SEEN']
    assert all(isinstance(v[0], bytes) and len(v[0]) == 32 for v in seen.values())    # digests only


def test_wrong_password_memory_stays_small(console):
    note, seen = console.ns['_console_note_failed_password_check'], console.ns['_PW_FAIL_SEEN']
    limit = console.ns['_PW_FAIL_SEEN_MAX']
    for i in range(limit + 50):
        with console.app.test_request_context('/api/console/power', method='POST',
                                              environ_base={'REMOTE_ADDR': '10.%d.%d.1' % (i // 250, i % 250)}):
            note('wrong-guess-123')
    assert len(seen) <= limit


@pytest.mark.parametrize('path', ['/login', '/'])
def test_every_failed_login_on_the_login_page_is_still_recorded(console, path):
    c = console.app.test_client()
    for _ in range(3):
        c.post(path, data={'password': 'wrong-guess-123'}, base_url=CONSOLE,
               environ_base={'REMOTE_ADDR': '203.0.113.7'})
    assert len(_log_lines(console)) == 3


def test_right_or_empty_password_on_a_confirm_form_records_nothing(console):
    c = console.app.test_client()
    _login(console, c)
    assert _power(c, '').status_code == 403         # the form asking "do I need a password?"
    assert _log_lines(console) == []
    assert _power(c, RIGHT).status_code == 200
    assert _log_lines(console) == [] and console.state['power'] == ['reboot']


@pytest.mark.parametrize('path', ['/login', '/'])
@pytest.mark.parametrize('password', ['wrong-guess-123', ''])
def test_failed_login_is_still_one_line_not_two(console, path, password):
    c = console.app.test_client()
    c.post(path, data={'password': password}, base_url=CONSOLE,
           environ_base={'REMOTE_ADDR': '203.0.113.7'})
    assert len(_log_lines(console)) == 1


def test_password_check_outside_a_request_records_nothing_and_never_raises(console):
    verify = console.ns['verify_password']
    pwhash = werkzeug_security.generate_password_hash(RIGHT, method='pbkdf2:sha256')
    assert verify(pwhash, 'wrong-guess-123') is False
    assert verify(pwhash, RIGHT) is True
    assert _log_lines(console) == []


def test_uninstall_dialog_does_not_send_part_typed_passwords():
    """Each one would now count as a failed login and could ban the operator."""
    page = (REPO / 'templates' / 'help.html').read_text(encoding='utf-8')
    m = re.search(r'function fullUninstallPasswordInput\(\)\{(.*?)\}\s*\n', page, re.S)
    assert m, 'fullUninstallPasswordInput not found in help.html'
    assert 'fullUninstallValidatePassword' not in m.group(1)
    assert 'onblur="fullUninstallValidatePassword()"' in page       # the tick still shows


# --------------------------------------------------------------------------- #
# 6. Public health endpoint
# --------------------------------------------------------------------------- #

@pytest.fixture
def health(monkeypatch):
    # Compiled here, not imported from its path: an import leaves scripts/guarddog/__pycache__
    # behind, and other tests read every entry of that folder as a script.
    mod = types.ModuleType('tak_health_endpoint_ops815')
    exec(compile(HEALTH_SCRIPT.read_text(encoding='utf-8'), str(HEALTH_SCRIPT), 'exec'), mod.__dict__)
    calls = []
    behaviour = {'hang': False, 'delay': 0}

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        if behaviour['delay']:
            time.sleep(behaviour['delay'])
        if behaviour['hang']:
            if 'timeout' not in kw:
                time.sleep(30)
            raise subprocess.TimeoutExpired(cmd, kw['timeout'])
        return types.SimpleNamespace(returncode=0, stdout='LISTEN 0 128 *:8089' if kw.get('text') else b'',
                                     stderr='')

    monkeypatch.setattr(mod.subprocess, 'run', fake_run)
    monkeypatch.setattr(mod, '_conf', {}, raising=False)
    shipped_timeout = mod.HealthHandler.timeout
    monkeypatch.setattr(mod.HealthHandler, 'timeout', 1, raising=False)
    server_cls = getattr(mod, 'HealthServer', None) or mod.HTTPServer
    server = server_cls(('127.0.0.1', 0), mod.HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield types.SimpleNamespace(mod=mod, port=server.server_address[1], calls=calls,
                                behaviour=behaviour, shipped_timeout=shipped_timeout)
    threading.Thread(target=server.shutdown, daemon=True).start()
    server.socket.close()


def _get_health(port, timeout=4):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/health' % port, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_health_answers(health):
    status, body = _get_health(health.port)
    assert status == 200
    assert body == {'takserver': True, 'port_8089': True, 'messaging': True, 'api': True,
                    'healthy': True}


def test_health_answers_while_another_caller_holds_a_connection_open(health):
    idle = [socket.create_connection(('127.0.0.1', health.port)) for _ in range(5)]
    try:
        idle[0].sendall(b'GET /health HTTP/1.1\r\nHost: x\r\n')        # never finishes
        started = time.time()
        status, _ = _get_health(health.port, timeout=3)
        assert status == 200 and time.time() - started < 2
    finally:
        for s in idle:
            s.close()


def test_health_closes_a_connection_that_sends_nothing(health):
    assert health.shipped_timeout and 0 < health.shipped_timeout <= 10, \
        'the shipped handler has no socket timeout'
    s = socket.create_connection(('127.0.0.1', health.port))
    s.settimeout(4)
    try:
        assert s.recv(100) == b''          # closed by the server at its 1 s (test) timeout
    finally:
        s.close()


def test_health_keeps_its_answer_for_a_few_seconds(health):
    for _ in range(25):
        assert _get_health(health.port)[0] == 200
    assert len(health.calls) <= 4, 'the checks ran for every request: %d commands' % len(health.calls)


def test_health_runs_the_checks_again_after_the_cache_time(health, monkeypatch):
    monkeypatch.setattr(health.mod, 'CACHE_TTL_S', 0.2, raising=False)
    _get_health(health.port)
    first = len(health.calls)
    time.sleep(0.4)
    _get_health(health.port)
    assert len(health.calls) == 2 * first


def _closed_by_server(sock, within):
    sock.settimeout(within)
    try:
        return sock.recv(100) == b''
    except ConnectionResetError:
        return True
    except socket.timeout:
        return False


def test_health_ends_a_connection_that_sends_a_byte_now_and_then(health, monkeypatch):
    """The socket timeout is per read; only a deadline for the whole request stops this."""
    monkeypatch.setattr(health.mod, 'REQUEST_DEADLINE_S', 1, raising=False)
    s = socket.create_connection(('127.0.0.1', health.port))
    closed, started = False, time.time()
    try:
        while time.time() - started < 4 and not closed:
            try:
                s.sendall(b'G')
            except OSError:
                closed = True
                break
            closed = _closed_by_server(s, 0.3)
    finally:
        s.close()
    assert closed, 'a slow caller held its connection for 4 s'
    assert time.time() - started < 3


def test_health_gives_the_last_answer_while_new_checks_run(health, monkeypatch):
    monkeypatch.setattr(health.mod, 'CACHE_TTL_S', 0.2, raising=False)
    assert _get_health(health.port)[0] == 200
    time.sleep(0.3)
    health.behaviour['delay'] = 0.5                 # the next set of checks takes 2 s
    slow = threading.Thread(target=_get_health, args=(health.port, 8), daemon=True)
    slow.start()
    time.sleep(0.3)
    started = time.time()
    status, body = _get_health(health.port, timeout=3)
    assert status == 200 and body['healthy'] is True
    assert time.time() - started < 0.5, 'a caller waited for another caller\'s checks'
    slow.join(8)


def test_health_caps_the_connections_of_one_outside_address(health, monkeypatch):
    monkeypatch.setattr(health.mod, '_is_loopback', lambda address: False, raising=False)
    monkeypatch.setattr(health.mod, 'MAX_PER_ADDRESS', 1, raising=False)
    first = socket.create_connection(('127.0.0.1', health.port))
    time.sleep(0.2)
    second = socket.create_connection(('127.0.0.1', health.port))
    try:
        assert _closed_by_server(second, 0.6), 'a second connection from the address was served'
    finally:
        second.close()
        first.close()
    time.sleep(1.3)
    assert _get_health(health.port)[0] == 200
    assert health.mod._slots == {'total': 0, 'by_address': {}} or _wait_slots_empty(health.mod)


def _wait_slots_empty(mod, seconds=3):
    end = time.time() + seconds
    while time.time() < end:
        if mod._slots == {'total': 0, 'by_address': {}}:
            return True
        time.sleep(0.1)
    return False


def test_health_caps_the_connections_it_serves_at_once(health, monkeypatch):
    monkeypatch.setattr(health.mod, 'MAX_CONNECTIONS', 2, raising=False)
    idle = [socket.create_connection(('127.0.0.1', health.port)) for _ in range(2)]
    time.sleep(0.2)
    extra = socket.create_connection(('127.0.0.1', health.port))
    extra.settimeout(0.6)
    try:
        try:
            data = extra.recv(100)
        except ConnectionResetError:
            data = b''
        assert data == b'', 'the connection over the cap was served'
    finally:
        extra.close()
        for s in idle:
            s.close()
    time.sleep(1.3)                         # the idle ones time out and free their places
    assert _get_health(health.port)[0] == 200


def test_health_says_unhealthy_when_a_check_command_hangs(health):
    health.behaviour['hang'] = True
    started = time.time()
    status, body = _get_health(health.port, timeout=10)
    assert status == 503 and body['healthy'] is False and body['takserver'] is False
    assert time.time() - started < 5


def test_health_script_change_restarts_the_running_service():
    """The endpoint is a long-running service: a new file alone changes nothing."""
    name, restart = _assign_src('_GD_HEALTH_SCRIPT'), _func_src('_gd_restart_health_endpoint')
    assert name and restart, 'the restart helper is not in app.py'
    ran = []
    ns = {'subprocess': types.SimpleNamespace(run=lambda argv, **kw: ran.append(argv)),
          '_sudo_wrap': lambda argv: argv, 'print': lambda *a, **kw: None}
    exec(name, ns)
    exec(restart, ns)
    assert ns['_GD_HEALTH_SCRIPT'] == 'tak-health-endpoint.py'
    ns['_gd_restart_health_endpoint']()
    assert ran == [['systemctl', 'try-restart', 'tak-health.service']]
    # never raises
    ns['subprocess'] = types.SimpleNamespace(run=lambda *a, **kw: 1 / 0)
    ns['_gd_restart_health_endpoint']()
    # both install paths call it, and only for a changed health script
    startup = _func_src('_auto_update_guarddog')
    assert re.search(r'if _gd_install_script\(name, template, vals\):\s+updated \+= 1\s+'
                     r'if name == _GD_HEALTH_SCRIPT:\s+_gd_restart_health_endpoint\(\)', startup)
    deploy = _func_src('run_guarddog_deploy')
    assert deploy and re.search(r'if _GD_HEALTH_SCRIPT in changed:\s+_gd_restart_health_endpoint\(\)',
                                deploy)
