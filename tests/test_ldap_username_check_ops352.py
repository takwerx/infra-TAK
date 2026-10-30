# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Console check for usernames TAK Server cannot look up in LDAP (ops #352).

Measured on test12 (TAK Server 5.8-RELEASE92 + Authentik 2026.8.5): "/" logs in but gets no
groups (JNDI Context.lookup treats "/" as a composite-name separator), and \\ , + " < > ;
cannot log in at all. = # * ( ) . @ space and accents work. The tests pin which characters are
flagged, what the endpoint returns, and that the TAK Server page shows it.
"""

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
JS = (REPO / 'static' / 'takserver.js').read_text(encoding='utf-8')
TPL = (REPO / 'templates' / 'takserver.html').read_text(encoding='utf-8')


def _block(start_marker, end_marker):
    a = APP.index(start_marker)
    return APP[a:APP.index(end_marker, a)]


def _load():
    src = _block('_LDAP_SILENT_NOGROUP_CHARS = ', "_vacuum_status = {'running'")
    ns = {}

    class _App:
        def route(self, *a, **k):
            return lambda f: f

    ns.update(app=_App(), login_required=lambda f: f, jsonify=lambda d: d)
    exec(compile(src, 'app.py:ldap_username_check', 'exec'), ns)
    return ns


@pytest.mark.parametrize('name', ['grantcew', 'a=b', 'a b', 'a#b', 'a*b', 'a(b)', 'a.b', 'a@b', 'é', 'a-b_c'])
def test_names_that_work_are_not_flagged(name):
    assert _load()['_ldap_username_problem'](name) is None


def test_slash_logs_in_but_gets_no_groups():
    assert _load()['_ldap_username_problem']('alexistestcy/ew') == {'kind': 'no_groups', 'chars': ['/']}


@pytest.mark.parametrize('ch', list('\\,+"<>;'))
def test_chars_that_break_the_bind_are_flagged_no_login(ch):
    p = _load()['_ldap_username_problem'](f'ab{ch}cd')
    assert p == {'kind': 'no_login', 'chars': [ch]}


def test_login_failure_wins_over_slash():
    p = _load()['_ldap_username_problem']('a/b,c')
    assert p['kind'] == 'no_login' and set(p['chars']) == {',', '/'}


def test_endpoint_lists_only_flagged_active_real_users_across_pages():
    ns = _load()
    pages = {
        1: {'results': [{'username': 'ok1', 'is_active': True, 'type': 'internal'},
                        {'username': 'bad/one', 'is_active': True, 'type': 'internal'},
                        {'username': 'off/line', 'is_active': False, 'type': 'internal'}],
            'pagination': {'next': 2}},
        2: {'results': [{'username': 'svc/acct', 'is_active': True, 'type': 'service_account'},
                        {'username': 'x,y', 'is_active': True, 'type': 'external'}],
            'pagination': {'next': 0}},
    }
    seen = []

    def fake_get(url, path, headers):
        seen.append(path)
        return pages[int(re.search(r'page=(\d+)', path).group(1))]

    ns['_w1_ak_ctx'] = lambda: ('http://ak', {}, {})
    ns['_w1_ak_get'] = fake_get
    out = ns['takserver_ldap_username_check']()
    assert out['available'] is True
    assert [(u['username'], u['kind']) for u in out['users']] == [('bad/one', 'no_groups'), ('x,y', 'no_login')]
    assert len(seen) == 2


def test_endpoint_unavailable_without_authentik_token_or_api():
    ns = _load()
    ns['_w1_ak_ctx'] = lambda: (None, None, {})
    assert ns['takserver_ldap_username_check']() == {'available': False, 'users': []}
    ns['_w1_ak_ctx'] = lambda: ('http://ak', {}, {})

    def boom(*a):
        raise OSError('down')

    ns['_w1_ak_get'] = boom
    out = ns['takserver_ldap_username_check']()
    assert out['available'] is False and out['users'] == []


def test_route_is_login_protected_and_read_only():
    i = APP.index('def takserver_ldap_username_check(')
    head = APP[:i].rsplit('@app.route', 1)[1]
    assert "'/api/takserver/ldap-username-check'" in head and '@login_required' in head
    assert 'methods=' not in head


def test_page_shows_the_banner_and_fills_it_without_innerhtml():
    assert 'id="ldap-username-banner"' in TPL and 'id="ldap-username-msg"' in TPL
    fn = JS[JS.index('async function checkLdapUsernames'):]
    fn = fn[:fn.index('function _sleep')]
    assert "fetch('/api/takserver/ldap-username-check')" in fn
    assert 'innerHTML' not in fn          # usernames are untrusted text
    assert "checkLdapUsernames();" in JS
