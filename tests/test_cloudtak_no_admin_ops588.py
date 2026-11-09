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
"""CloudTAK set up and working, with no admin user (ops #588).

CloudTAK's own setup call makes the named user a system admin and refuses to configure without
one, so a box can only reach "set up, no admin" later: the admin was disabled or taken off, or
the people signing in are not the user setup named. The CloudTAK page now says "No admin created
yet" and offers the one fix: make an existing CloudTAK user the admin, only while there is none.
Setup also reads the admin back, so it never reports success with nobody in charge.
"""

import ast
import pathlib
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)
TEMPLATE = (REPO / 'templates' / 'cloudtak.html').read_text(encoding='utf-8')
JS = APP[APP.index("CLOUDTAK_PAGE_JS = r'''"):]


class _Box:
    """CloudTAK's API and database, faked: one server state, a profile table."""

    def __init__(self, status='configured', profiles=None, readable=True, patch_ok=True):
        # profiles: {username: {'admin': bool, 'cert': bool, 'disabled': bool}}
        self.srv = {'status': status, 'connection_status': 'live'}
        self.profiles = profiles or {}
        self.readable = readable
        self.patch_ok = patch_ok
        self.patches = []
        self.audits = []

    def request(self, method, url, payload=None, timeout=25, headers=None):
        assert headers and headers['Authorization'].startswith('Bearer ')
        if method == 'PATCH':
            self.patches.append((url, payload))
            if not self.patch_ok:
                return False, 403, {'message': 'nope'}
            name = url.rsplit('/', 1)[1]
            self.profiles[name]['admin'] = True
            return True, 200, {}
        return True, 200, dict(self.srv)

    def postgis(self, sql):
        if not self.readable:
            return None
        live = {n: p for n, p in self.profiles.items() if not p['disabled']}
        if 'where system_admin' in sql:
            return [n for n, p in live.items() if p['admin']]
        if 'where not system_admin' in sql:
            return sorted(n for n, p in live.items() if not p['admin'] and p['cert'])
        return ''


def _ns(box, local=True):
    ns = {'_cloudtak_local_with_local_tak': lambda s: local, '_cloudtak_signing_secret': lambda: 's',
          '_cloudtak_admin_token': lambda s: 'jwt', '_cloudtak_request_json': box.request,
          '_cloudtak_postgis_json': box.postgis, '_tak_live_trust_bundle': lambda: '',
          '_tak_ca_bundle': lambda: '', '_cert_signed_by': lambda c, b: None,
          'jsonify': lambda d, *a: (d,) + a if a else d, 'urllib': __import__('urllib'),
          'audit': lambda ev, detail='', force=False: box.audits.append((ev, detail))}
    ns['urllib.parse'] = __import__('urllib.parse')
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name in (
                '_cloudtak_untrusted_user_certs', '_cloudtak_admin_users', '_cloudtak_admin_candidates',
                '_cloudtak_connect_state_core', '_cloudtak_connect_state', '_cloudtak_make_admin'):
            exec(ast.get_source_segment(APP, n), ns)
    return ns


def _p(admin=False, cert=True, disabled=False):
    return {'admin': admin, 'cert': cert, 'disabled': disabled}


# ── The warning ─────────────────────────────────────────────────────────────────────────

def test_a_set_up_cloudtak_with_no_admin_says_so_and_lists_who_can_be_made_admin():
    box = _Box(profiles={'alice': _p(), 'bob': _p(), 'never-signed-in': _p(cert=False)})
    st = _ns(box)['_cloudtak_connect_state']({})
    assert st['status'] == 'connected' and st['no_admin'] is True and st['admins'] == []
    assert st['admin_candidates'] == ['alice', 'bob']


def test_a_disabled_admin_is_no_admin():
    box = _Box(profiles={'boss': _p(admin=True, disabled=True), 'alice': _p()})
    st = _ns(box)['_cloudtak_connect_state']({})
    assert st['no_admin'] is True and st['admin_candidates'] == ['alice']


def test_no_warning_when_there_is_an_admin_or_it_cannot_be_told():
    assert 'no_admin' not in _ns(_Box(profiles={'boss': _p(admin=True)}))['_cloudtak_connect_state']({})
    # Unreadable table: say nothing rather than cry wolf.
    assert 'no_admin' not in _ns(_Box(profiles={'a': _p()}, readable=False))['_cloudtak_connect_state']({})
    # Before setup the card asks for the first admin already; leftovers are not "no admin".
    assert 'no_admin' not in _ns(_Box('unconfigured', {'a': _p()}))['_cloudtak_connect_state']({})
    assert 'no_admin' not in _ns(_Box(profiles={'a': _p()}), local=False)['_cloudtak_connect_state']({})


# ── The fix ─────────────────────────────────────────────────────────────────────────────

def test_make_admin_promotes_one_listed_user_through_cloudtaks_own_api():
    box = _Box(profiles={'alice': _p(), 'bob': _p()})
    r = _ns(box)['_cloudtak_make_admin']('alice')
    assert r['success'] is True
    assert box.patches == [('http://127.0.0.1:5000/api/user/alice', {'system_admin': True})]
    assert box.audits == [('cloudtak:make-admin', 'user=alice')]
    assert _ns(box)['_cloudtak_connect_state']({}).get('no_admin') is None


def test_make_admin_refuses_when_cloudtak_already_has_an_admin():
    box = _Box(profiles={'boss': _p(admin=True), 'alice': _p()})
    r = _ns(box)['_cloudtak_make_admin']('alice')
    assert r[1] == 409 and 'already has an admin' in r[0]['error'] and box.patches == []


def test_make_admin_refuses_unlisted_names_and_odd_input():
    box = _Box(profiles={'alice': _p(), 'ghost': _p(cert=False), 'off': _p(disabled=True)})
    for bad in ('ghost', 'off', 'nobody', 'ALICE', '../../server', "alice' or 1=1 --", ''):
        r = _ns(box)['_cloudtak_make_admin'](bad)
        assert r[1] == 400, bad
    assert box.patches == []


def test_make_admin_needs_a_set_up_cloudtak_and_a_readable_table():
    r = _ns(_Box('unconfigured', {'alice': _p()}))['_cloudtak_make_admin']('alice')
    assert r[1] == 409
    box = _Box(profiles={'alice': _p()}, readable=False)
    r = _ns(box)['_cloudtak_make_admin']('alice')
    assert r[1] == 502 and box.patches == []


def test_make_admin_reports_a_refusal_and_a_change_that_did_not_stick():
    box = _Box(profiles={'alice': _p()}, patch_ok=False)
    r = _ns(box)['_cloudtak_make_admin']('alice')
    assert r[1] == 400 and 'CloudTAK refused' in r[0]['error'] and box.audits == []


def test_the_route_is_login_protected_post_only_and_locked():
    i = APP.index("@app.route('/api/cloudtak/make-admin'")
    head = APP[i:i + 700]
    assert "methods=['POST']" in head and '@login_required' in head
    assert '_CLOUDTAK_CONNECT_LOCK.acquire' in head
    # The user name is never put into SQL.
    fn = next(ast.get_source_segment(APP, n) for n in TREE.body
              if isinstance(n, ast.FunctionDef) and n.name == '_cloudtak_make_admin')
    assert 'where username' not in fn.lower()


# ── First-time setup reads the admin back ───────────────────────────────────────────────

def _setup_ns(admins_after):
    from test_cloudtak_ca_change_recovery import _CT, _connect_ns
    ct = _CT('unconfigured', profiles=['someone-else'])
    ns = _connect_ns(ct)
    ns['_cloudtak_admin_users'] = lambda: admins_after(ct)
    return ct, ns


def test_setup_is_not_reported_done_when_the_named_user_is_not_an_admin():
    ct, ns = _setup_ns(lambda ct: [])
    r = ns['_cloudtak_connect_tak']({}, {'username': 'cloudtakadmin-ps', 'password': 'x'})
    assert r[1] == 500 and 'was not made a CloudTAK admin' in r[0]['error']


def test_setup_names_the_admin_in_its_success_message():
    ct, ns = _setup_ns(lambda ct: ct.admins)
    r = ns['_cloudtak_connect_tak']({}, {'username': 'cloudtakadmin-ps', 'password': 'x'})
    assert r['success'] and "cloudtakadmin-ps is CloudTAK's admin" in r['message']


def test_setup_does_not_fail_when_the_table_cannot_be_read():
    ct, ns = _setup_ns(lambda ct: None)
    r = ns['_cloudtak_connect_tak']({}, {'username': 'cloudtakadmin-ps', 'password': 'x'})
    assert r['success']


# ── The page ────────────────────────────────────────────────────────────────────────────

def test_the_page_shows_the_warning_and_the_one_action_and_escapes_names():
    assert 'No admin created yet' in JS and "if (d.no_admin)" in JS
    assert "onclick=\"ctMakeAdmin(this)\"" in JS and 'Make admin' in JS
    assert 'cands.map(function(u)' in JS and 'esc(u)' in JS
    assert "fetch('/api/cloudtak/make-admin'" in JS and "method: 'POST'" in JS
    # With nobody signed in yet it says what to do instead of showing an empty list.
    assert 'Sign in to CloudTAK once as the person who should be admin' in JS


def test_setup_text_says_only_that_user_sees_the_admin_pages():
    assert "Only this user sees CloudTAK's admin pages" in TEMPLATE
