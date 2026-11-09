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
"""CloudTAK can't end up set up with no admin, and says so when it does (ops #587).

CloudTAK (api/stateless/routes/server.ts) counts as set up once its server row holds a cert and
key, and makes the first system admin only in that same request, only when it carries a TAK
username and password. From then on any TAK user can log in (routes/login.ts) and gets a plain
profile. So a CloudTAK that is set up with no admin looks fine and can't be managed. The page now:
  * says "No CloudTAK admin yet" with a one-step fix (a TAK user who has logged in once);
  * refuses to report first-time setup as done when the admin was not made;
  * only ever makes an admin while there is none.
"""

import ast
import pathlib
import types
import urllib.parse

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'cloudtak.html').read_text(encoding='utf-8')
JS = APP[APP.index("CLOUDTAK_PAGE_JS = r'''"):]
USERNAME_RE = None
for _n in TREE.body:
    if isinstance(_n, ast.Assign) and getattr(_n.targets[0], 'id', '') == '_CLOUDTAK_USERNAME_RE':
        USERNAME_RE = ast.get_source_segment(APP, _n)


class _Lock:
    def __init__(self):
        self.held = 0

    def acquire(self, blocking=True):
        self.held += 1
        return True

    def release(self):
        self.held -= 1


class CT:
    """CloudTAK as the console sees it: /api/server, /api/user/<name>, the profile table."""

    def __init__(self, status='configured', admins=(), profiles=(), readable=True, local=True, accepts_patch=True):
        self.status, self.admins, self.profiles = status, list(admins), list(profiles)
        self.readable, self.local, self.accepts_patch = readable, local, accepts_patch
        self.calls, self.audits = [], []

    def request(self, method, url, payload=None, timeout=25, headers=None):
        assert headers and headers['Authorization'].startswith('Bearer ')
        self.calls.append((method, url, payload))
        if url.endswith('/api/server'):
            return True, 200, {'status': self.status, 'connection_status': 'live'}
        if '/api/user/' in url and method == 'PATCH':
            if not self.accepts_patch:
                return False, 400, {'message': 'nope'}
            name = urllib.parse.unquote(url.rsplit('/', 1)[1])
            if payload.get('system_admin'):
                self.admins.append(name)
            return True, 200, {}
        raise AssertionError((method, url))

    def postgis(self, sql):
        if not self.readable:
            return None
        return list(self.admins) if 'system_admin' in sql else list(self.profiles)


def _ns(ct, body=None):
    ns = {'_cloudtak_local_with_local_tak': lambda s=None: ct.local, '_cloudtak_signing_secret': lambda: 's',
          '_cloudtak_admin_token': lambda s: 'jwt', '_cloudtak_request_json': ct.request,
          '_cloudtak_postgis_json': ct.postgis, '_tak_live_trust_bundle': lambda: '', '_tak_ca_bundle': lambda: '',
          '_cert_signed_by': lambda c, b: None, 'jsonify': lambda d: d, 'load_settings': lambda: {},
          'urllib': types.SimpleNamespace(parse=urllib.parse), '_CLOUDTAK_CONNECT_LOCK': _Lock(),
          'request': types.SimpleNamespace(get_json=lambda silent=True: body),
          'audit': lambda ev, detail='', force=False: ct.audits.append((ev, detail, force)),
          'print': lambda *a, **k: None}
    exec('import re', ns)
    exec(USERNAME_RE, ns)
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in (
                '_cloudtak_untrusted_user_certs', '_cloudtak_admin_users', '_cloudtak_profile_names',
                '_cloudtak_connect_state_core', '_cloudtak_connect_state', 'cloudtak_make_admin_api'):
            exec(ast.get_source_segment(APP, n), ns)
    return ns


def _status(r):
    return r[1] if isinstance(r, tuple) else 200


def _body(r):
    return r[0] if isinstance(r, tuple) else r


# ── the state: "No CloudTAK admin yet" ────────────────────────────────────────────────

def test_a_set_up_cloudtak_with_no_admin_is_flagged_and_lists_who_could_be_made_admin():
    ct = CT(admins=[], profiles=['plainuser', 'other'])
    st = _ns(ct)['_cloudtak_connect_state']({})
    assert st['status'] == 'connected' and st['admins'] == []
    assert st['no_admin'] is True and st['profiles'] == ['plainuser', 'other']


def test_no_flag_while_there_is_an_admin_before_setup_on_remote_or_when_unreadable():
    assert 'no_admin' not in _ns(CT(admins=['boss']))['_cloudtak_connect_state']({})
    # Before setup the only rows are a half-finished attempt's leftovers: not a missing admin.
    assert 'no_admin' not in _ns(CT(status='unconfigured', admins=[]))['_cloudtak_connect_state']({})
    assert 'no_admin' not in _ns(CT(local=False))['_cloudtak_connect_state']({})
    # Can't read the table = can't tell = no warning rather than a false one.
    assert 'no_admin' not in _ns(CT(readable=False))['_cloudtak_connect_state']({})


# ── the one-step fix ───────────────────────────────────────────────────────────────────

def test_make_admin_promotes_an_existing_user_through_cloudtaks_own_api():
    ct = CT(admins=[], profiles=['someone', 'Plain-User'])
    r = _ns(ct, {'username': 'plain-user'})['cloudtak_make_admin_api']()
    assert _status(r) == 200 and _body(r)['success'] and _body(r)['username'] == 'Plain-User'
    # The stored (exact) name goes to CloudTAK, not what was typed.
    assert ct.calls[-1] == ('PATCH', 'http://127.0.0.1:5000/api/user/Plain-User', {'system_admin': True})
    assert ct.audits == [('cloudtak:make-admin', 'Plain-User is now a CloudTAK system admin', True)]


def test_make_admin_refuses_when_cloudtak_already_has_an_admin():
    ct = CT(admins=['boss'], profiles=['boss', 'plain'])
    r = _ns(ct, {'username': 'plain'})['cloudtak_make_admin_api']()
    assert _status(r) == 409 and not _body(r)['success'] and 'boss' in _body(r)['error']
    assert not [c for c in ct.calls if c[0] == 'PATCH'] and ct.audits == []


def test_make_admin_needs_a_user_that_has_logged_in_once():
    ct = CT(admins=[], profiles=['someone'])
    r = _ns(ct, {'username': 'ghost'})['cloudtak_make_admin_api']()
    assert _status(r) == 404 and 'Log in to CloudTAK once' in _body(r)['error']
    assert not [c for c in ct.calls if c[0] == 'PATCH']


def test_make_admin_refuses_before_setup_remote_unreadable_and_odd_names():
    for ct, body, code in ((CT(status='unconfigured', profiles=['a']), {'username': 'a'}, 409),
                           (CT(local=False), {'username': 'a'}, 400),
                           (CT(readable=False), {'username': 'a'}, 502),
                           (CT(profiles=['a']), {'username': "x' or 1=1 --"}, 400),
                           (CT(profiles=['a']), {'username': ''}, 400),
                           (CT(profiles=['a']), None, 400)):
        r = _ns(ct, body)['cloudtak_make_admin_api']()
        assert _status(r) == code, (body, r)
        assert not [c for c in ct.calls if c[0] == 'PATCH'] and ct.audits == []


def test_make_admin_says_so_when_cloudtak_refuses_or_the_change_does_not_show():
    ct = CT(admins=[], profiles=['a'], accepts_patch=False)
    r = _ns(ct, {'username': 'a'})['cloudtak_make_admin_api']()
    assert _status(r) == 400 and 'CloudTAK refused' in _body(r)['error'] and ct.audits == []

    class Silent(CT):
        def request(self, method, url, payload=None, timeout=25, headers=None):
            if method == 'PATCH':
                return True, 200, {}                      # accepted, but the table still has no admin
            return super().request(method, url, payload, timeout, headers)
    ct = Silent(admins=[], profiles=['a'])
    r = _ns(ct, {'username': 'a'})['cloudtak_make_admin_api']()
    assert _status(r) == 500 and 'does not show as an admin' in _body(r)['error'] and ct.audits == []


def test_make_admin_holds_the_connect_lock_and_lets_go_of_it():
    ct = CT(admins=[], profiles=['a'])
    ns = _ns(ct, {'username': 'a'})
    ns['cloudtak_make_admin_api']()
    assert ns['_CLOUDTAK_CONNECT_LOCK'].held == 0


def test_make_admin_route_needs_a_login_and_the_name_never_enters_sql():
    i = APP.index("@app.route('/api/cloudtak/make-admin', methods=['POST'])")
    assert APP[i:i + 200].split('\n')[1] == '@login_required'
    src = ast.get_source_segment(APP, next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                                           and n.name == 'cloudtak_make_admin_api'))
    assert 'psql' not in src and 'subprocess' not in src and 'where username' not in src.lower()
    assert "force=True" in src                                     # granting admin is always audited


# ── first-time setup must not report done without the admin ──────────────────────────

def test_first_time_setup_is_not_reported_done_when_the_admin_was_not_made():
    src = ast.get_source_segment(APP, next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
                                           and n.name == '_cloudtak_connect_tak'))
    i_cfg = src.index("v.get('status') != 'configured'")
    i_admin = src.index('_cloudtak_admin_users()')
    i_ok = src.index("'mode': 'configured'")
    assert i_cfg < i_admin < i_ok
    assert 'did not become its admin' in src[i_admin:i_ok]


# ── the page ────────────────────────────────────────────────────────────────────────────

def test_the_page_warns_and_offers_the_one_step():
    assert 'id="ct-noadmin"' in TEMPLATE and 'No CloudTAK admin yet' in TEMPLATE
    assert TEMPLATE.index('id="ct-noadmin"') > TEMPLATE.index('id="ct-connect-admins"')
    assert 'onclick="ctMakeAdmin(this)"' in TEMPLATE and 'id="ct-noadmin-user"' in TEMPLATE
    assert "noadm.style.display = d.no_admin ? '' : 'none'" in JS
    assert "fetch('/api/cloudtak/make-admin'" in JS and 'window.ctMakeAdmin = function' in JS
    # Names from the profile table go into the page escaped.
    assert "'<option value=\"' + esc(n) + '\">'" in JS
