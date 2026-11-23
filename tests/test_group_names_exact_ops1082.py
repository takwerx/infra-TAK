# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #1082: a role comes from the exact group names, never from a split of a header.

Authentik's outpost gives a person's groups to the app behind it as ONE header value,
the names joined with "|". An Authentik group name is free text and may hold "|" itself,
so splitting the value does not give back the names that went in. The stream site (the
MediaMTX editor overlay) and the console therefore ask Authentik's user API, which
returns the names as a list.

Part 1 runs the real overlay on a bare Flask app against a small HTTP server that
answers like Authentik's user API. The requests carry the group header exactly as the
outpost builds it ('|'.join(names)), to show that it no longer decides anything.
Part 2 runs the console's group name check. The console's own sign-in is covered in
test_console_sso_session_ops813.py.
"""

import ast
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
OVERLAY_SRC = (REPO / 'mediamtx_ldap_overlay.py').read_text(encoding='utf-8')
APP = (REPO / 'app.py').read_text(encoding='utf-8')
ADMINS = 'authentik Admins'


class FakeAuthentik:
    """GET /api/v3/core/users/?username=X, /api/v3/core/users/<pk>/ and
    /api/v3/core/groups/, like Authentik. mode: 'ok', 'error' (HTTP 500), 'forbidden'
    (HTTP 403), 'ignore_filter' (returns every user), 'no_groups_in_list'."""

    def __init__(self):
        self.users = {}
        self.extra_groups = []
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
                query = urllib.parse.parse_qs(url.query)
                m = re.fullmatch(r'/api/v3/core/users/(\d+)/', url.path)
                if m:
                    for u in fake.users.values():
                        if u['pk'] == int(m.group(1)):
                            return self._send(200, fake._row(u, True))
                    return self._send(404, {'detail': 'Not found.'})
                if url.path == '/api/v3/core/users/':
                    want = query.get('username', [None])[0]
                    rows = [u for u in fake.users.values()
                            if fake.mode == 'ignore_filter' or u['username'] == want]
                    with_groups = fake.mode != 'no_groups_in_list'
                    return self._send(200, {'results': [fake._row(u, with_groups) for u in rows]})
                if url.path == '/api/v3/core/groups/':
                    names = sorted(fake.group_names())
                    page = int(query.get('page', ['1'])[0])
                    size = int(query.get('page_size', ['100'])[0])
                    chunk = names[(page - 1) * size:page * size]
                    return self._send(200, {
                        'pagination': {'next': page + 1 if page * size < len(names) else 0},
                        'results': [{'pk': 'g-%d' % i, 'name': n} for i, n in enumerate(chunk)]})
                return self._send(404, {'detail': 'Not found.'})

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @staticmethod
    def _row(u, with_groups):
        row = {'pk': u['pk'], 'username': u['username'], 'is_active': u['is_active'],
               'is_superuser': False}
        if with_groups:
            row['groups_obj'] = [{'pk': 'g-%d' % i, 'name': g} for i, g in enumerate(u['groups'])]
        return row

    def add(self, username, groups=(), is_active=True):
        self.users[username] = {'pk': len(self.users) + 1, 'username': username,
                                'groups': list(groups), 'is_active': is_active}

    def group_names(self):
        names = set(self.extra_groups) | {ADMINS}
        for u in self.users.values():
            names.update(u['groups'])
        return names

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def authentik():
    fake = FakeAuthentik()
    fake.add('akadmin', [ADMINS])
    fake.add('alice', ['vid_private', 'tak_Fire'])
    fake.add('bob', ['vid_public'])
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


# --- Part 1: the stream site (MediaMTX editor overlay) ----------------------------------

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
    spec = importlib.util.spec_from_file_location('overlay_ops1082', REPO / 'mediamtx_ldap_overlay.py')
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
    app = flask.Flask('overlay-ops1082')
    app.secret_key = 'test'

    @app.route('/')
    def editor_home():                        # stands in for the editor's own admin page
        return 'EDITOR role=%s' % flask.session.get('role')
    ov.apply_ldap_overlay(app)

    class Site:
        overlay = ov

        @staticmethod
        def browser():
            return app.test_client()
    return Site


def as_outpost(browser, path, user, groups, method='get', **kw):
    """A request the way Caddy sends it after forward_auth passed: the identity headers
    the outpost builds, the group names joined with '|'."""
    headers = {'X-Authentik-Username': user, 'X-Authentik-Groups': '|'.join(groups)}
    return getattr(browser, method)(path, headers=headers, **kw)


def is_admin(browser, user, groups):
    """True when the person gets the editor's admin side. Checks three admin doors."""
    home = as_outpost(browser, '/', user, groups)
    page = as_outpost(browser, '/stream-access', user, groups)
    api = as_outpost(browser, '/api/stream-visibility', user, groups)
    write = as_outpost(browser, '/api/stream-visibility', user, groups, method='post',
                       json={'stream': 'scratch', 'level': 'private'})
    doors = [home.status_code == 200 and b'role=admin' in home.data,
             page.status_code == 200, api.status_code == 200, write.status_code == 200]
    assert all(doors) or not any(doors), doors
    return all(doors)


def sees_private(browser, user, groups):
    r = as_outpost(browser, '/hls-proxy/secret/index.m3u8', user, groups)
    assert r.status_code in (200, 403)
    return r.status_code == 200


@pytest.mark.parametrize('name', [
    'tak_x|authentik Admins',
    'authentik Admins|tak_x',
    'tak_x|authentik Admins|tak_y',
    'tak_x| authentik Admins ',
])
def test_group_named_with_the_separator_gives_no_admin_role(site, authentik, name):
    """Proof test for ops #1082. ONE group whose name holds the separator. A split of the
    header reads `authentik Admins` in it; the person is in no such group."""
    authentik.add('mallory', ['tak_Users', name])
    b = site.browser()
    assert not is_admin(b, 'mallory', ['tak_Users', name])
    # The refused write changed nothing.
    assert json.loads(pathlib.Path(site.overlay.VISIBILITY_FILE).read_text()) == {'secret': 'private'}
    # Landing page is the viewer page, as for every non-admin.
    r = as_outpost(b, '/', 'mallory', ['tak_Users', name])
    assert r.status_code == 302 and r.headers['Location'].endswith('/viewer')


@pytest.mark.parametrize('name', ['tak_x|vid_private', 'vid_private|tak_x'])
def test_group_named_with_the_separator_shows_no_private_stream(site, authentik, name):
    authentik.add('mallory', [name])
    b = site.browser()
    assert not sees_private(b, 'mallory', [name])
    r = as_outpost(b, '/watch/secret', 'mallory', [name])
    assert r.status_code == 403


def test_an_admin_still_gets_the_admin_side(site):
    assert is_admin(site.browser(), 'akadmin', [ADMINS])


def test_viewers_still_see_what_their_group_allows(site):
    alice, bob = site.browser(), site.browser()
    assert sees_private(alice, 'alice', ['vid_private', 'tak_Fire'])
    assert not sees_private(bob, 'bob', ['vid_public'])
    assert not is_admin(alice, 'alice', ['vid_private', 'tak_Fire'])
    for b, user, groups in ((alice, 'alice', ['vid_private']), (bob, 'bob', ['vid_public'])):
        assert as_outpost(b, '/viewer', user, groups).status_code == 200


def test_the_header_alone_gives_nothing(site, authentik):
    """The header says admin and private viewer; Authentik's list says neither."""
    authentik.add('carol', ['tak_Users'])
    b = site.browser()
    assert not is_admin(b, 'carol', [ADMINS, 'vid_private'])
    assert not sees_private(b, 'carol', [ADMINS, 'vid_private'])


def test_a_person_taken_out_of_the_group_loses_the_role(site, authentik, clock):
    """The outpost keeps the list from sign-in time; Authentik's live list wins."""
    b = site.browser()
    assert is_admin(b, 'akadmin', [ADMINS])
    authentik.users['akadmin']['groups'] = []
    clock.forward(61)
    assert not is_admin(b, 'akadmin', [ADMINS])


def test_deactivated_and_unknown_accounts_have_no_groups(site, authentik):
    authentik.add('dave', [ADMINS, 'vid_private'], is_active=False)
    assert not is_admin(site.browser(), 'dave', [ADMINS])
    assert not sees_private(site.browser(), 'dave', ['vid_private'])
    assert not is_admin(site.browser(), 'nobody', [ADMINS])


def test_lookup_judges_the_named_user_when_the_filter_is_ignored(site, authentik):
    """Authentik ignores a filter it does not know and returns every user (akadmin first)."""
    authentik.mode = 'ignore_filter'
    assert not is_admin(site.browser(), 'bob', [ADMINS])
    assert not is_admin(site.browser(), 'mallory', [ADMINS])
    assert is_admin(site.browser(), 'akadmin', [ADMINS])


def test_lookup_reads_groups_from_the_user_detail_when_the_list_has_none(site, authentik):
    authentik.mode = 'no_groups_in_list'
    assert is_admin(site.browser(), 'akadmin', [])
    assert not is_admin(site.browser(), 'bob', [ADMINS])


@pytest.mark.parametrize('mode', ['error', 'forbidden'])
def test_no_answer_from_authentik_gives_no_role(site, authentik, mode):
    """Fails closed: with no answer the header is still not read."""
    authentik.mode = mode
    for user, groups in (('mallory', ['tak_x|authentik Admins']), ('akadmin', [ADMINS])):
        b = site.browser()
        assert not is_admin(b, user, groups)
        assert not sees_private(b, user, groups + ['vid_private'])
        # Public streams stay open to a signed-in person.
        assert as_outpost(b, '/viewer', user, groups).status_code == 200


def test_no_token_gives_no_role(site, monkeypatch):
    monkeypatch.setattr(site.overlay, 'AK_TOKEN', '')
    assert not is_admin(site.browser(), 'akadmin', [ADMINS])


@pytest.mark.parametrize('mode', ['error', 'forbidden'])
def test_short_authentik_outage_does_not_take_roles_away(site, authentik, clock, mode):
    """An Authentik update or restart: the last answer stands for 15 minutes."""
    admin, alice = site.browser(), site.browser()
    assert is_admin(admin, 'akadmin', [ADMINS])
    assert sees_private(alice, 'alice', ['vid_private'])
    authentik.mode = mode
    for _ in range(9):
        clock.forward(90)
        assert is_admin(admin, 'akadmin', [ADMINS])
        assert sees_private(alice, 'alice', ['vid_private'])
    # ... and no longer than that, counted from the last real answer.
    clock.forward(2 * 60)
    assert not is_admin(admin, 'akadmin', [ADMINS])
    assert not sees_private(alice, 'alice', ['vid_private'])
    authentik.mode = 'ok'
    clock.forward(21)
    assert is_admin(admin, 'akadmin', [ADMINS])
    assert sees_private(alice, 'alice', ['vid_private'])


def test_authentik_is_asked_at_most_once_a_minute_per_user(site, authentik, clock):
    b = site.browser()
    for _ in range(40):
        as_outpost(b, '/hls-proxy/secret/index.m3u8', 'alice', ['vid_private'])
    assert len(authentik.calls) == 1
    clock.forward(61)
    for _ in range(40):
        as_outpost(b, '/hls-proxy/secret/index.m3u8', 'alice', ['vid_private'])
    assert len(authentik.calls) == 2


def test_no_answer_is_asked_again_after_a_short_wait_only(site, authentik, clock):
    authentik.mode = 'error'
    b = site.browser()
    for _ in range(20):
        as_outpost(b, '/viewer', 'alice', ['vid_private'])
    assert len(authentik.calls) == 1
    clock.forward(21)
    as_outpost(b, '/viewer', 'alice', ['vid_private'])
    assert len(authentik.calls) == 2


def test_username_goes_into_the_api_address_as_one_value(site, authentik):
    """A username is free text too. It must not add a filter of its own to the lookup."""
    authentik.add('eve&username=akadmin', [])
    assert not is_admin(site.browser(), 'eve&username=akadmin', [ADMINS])
    assert all('username=eve%26username%3Dakadmin' in c for c in authentik.calls)


def test_untrusted_peer_still_gets_no_session_from_headers(site):
    b = site.browser()
    r = as_outpost(b, '/api/stream-visibility', 'akadmin', [ADMINS],
                   environ_overrides={'REMOTE_ADDR': '203.0.113.9'})
    assert r.status_code == 403


def test_no_code_takes_a_decision_from_the_group_header():
    """Guard: neither file reads X-Authentik-Groups from a request."""
    pat = re.compile(r"""(headers|environ)\s*(\.get\s*\(|\[)\s*['"](HTTP_)?X[-_]Authentik[-_]Groups""", re.I)
    for name, src in (('mediamtx_ldap_overlay.py', OVERLAY_SRC), ('app.py', APP)):
        assert not pat.search(src), name
    for path in sorted((REPO / 'modules').glob('*.py')) + sorted((REPO / 'broker').glob('*.py')):
        assert not pat.search(path.read_text(encoding='utf-8')), path.name


# --- Part 2: the console's check of Authentik group names --------------------------------

TREE = ast.parse(APP)


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError('app.py has no %s' % name)


def _assign(name):
    for n in TREE.body:
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and getattr(n.targets[0], 'id', None) == name):
            return ast.get_source_segment(APP, n)
    raise AssertionError('app.py has no %s' % name)


@pytest.fixture
def checker(authentik, capsys):
    audit = []

    def _get(ak_url, path, ak_headers):
        import urllib.request
        r = urllib.request.Request(f'{ak_url}/api/v3/{path}', headers=ak_headers)
        return json.loads(urllib.request.urlopen(r, timeout=5).read().decode())
    ns = {'threading': threading, 'time': time, 'json': json,
          'CONSOLE_SSO_ADMIN_GROUP': ADMINS,
          '_w1_ak_ctx': lambda: (authentik.url, {'Authorization': 'Bearer box-token'}, {}),
          '_w1_ak_get': _get,
          'audit': lambda event, detail='', force=False: audit.append((event, detail))}
    for name in ('AK_GROUP_NAME_SEPARATORS', 'AK_GROUP_NAME_SCAN_SECONDS',
                 'AK_GROUP_NAME_PAGE_SECONDS', '_ak_group_names_lock', '_ak_group_names_state'):
        exec(_assign(name), ns)
    for name in ('_ak_group_name_findings', '_ak_group_names_scan'):
        exec(_func(name), ns)
    ns['audit_log'] = audit
    return ns


def test_findings_name_the_group_and_what_it_reads_as(checker):
    find = checker['_ak_group_name_findings']
    names = [ADMINS, 'vid_private', 'vid_public', 'tak_Fire', 'tak_Rescue, Station 1',
             'tak_x|authentik Admins', 'tak_y;AUTHENTIK ADMINS ', 'tak_z,vid_private',
             'tak_a|b', 'Smith, John', 'tak_Fire;tak_Police']
    got = {f['name']: f['reads_as'] for f in find(names)}
    assert got == {
        'tak_x|authentik Admins': [ADMINS],
        'tak_y;AUTHENTIK ADMINS ': [ADMINS],
        'tak_z,vid_private': ['vid_private'],
        'tak_a|b': [],                       # holds the header's own separator
        'tak_Fire;tak_Police': ['tak_Fire'],
    }
    # A comma or semicolon in an ordinary name is not reported.
    assert 'tak_Rescue, Station 1' not in got and 'Smith, John' not in got


def test_the_admin_group_is_watched_even_before_it_is_listed(checker):
    assert checker['_ak_group_name_findings'](['tak_x;authentik admins']) == [
        {'name': 'tak_x;authentik admins', 'reads_as': [ADMINS]}]


def test_clean_box_reports_nothing(checker, authentik, capsys):
    got = checker['_ak_group_names_scan'](force=True)
    assert got['available'] is True and got['findings'] == []
    assert got['groups_checked'] == len(authentik.group_names())
    assert 'GROUP NAME WARNING' not in capsys.readouterr().out
    assert checker['audit_log'] == []


def test_scan_reads_every_page_logs_once_and_audits(checker, authentik, capsys):
    authentik.extra_groups = ['tak_%03d' % i for i in range(250)] + ['zz_x|authentik Admins']
    scan = checker['_ak_group_names_scan']
    got = scan(force=True)
    assert got['findings'] == [{'name': 'zz_x|authentik Admins', 'reads_as': [ADMINS]}]
    assert got['groups_checked'] == len(authentik.group_names()) > 250
    out = capsys.readouterr().out
    assert out.count('GROUP NAME WARNING') == 1 and 'zz_x|authentik Admins' in out
    assert [e for e, _ in checker['audit_log']] == ['authentik:group-name-separator']
    # The next look finds the same group: no second log line, no second audit row.
    scan(force=True)
    assert 'GROUP NAME WARNING' not in capsys.readouterr().out
    assert len(checker['audit_log']) == 1


def test_scan_is_cached_between_looks(checker, authentik):
    scan = checker['_ak_group_names_scan']
    scan(force=True)
    n = len(authentik.calls)
    scan()
    scan(max_age=120)
    assert len(authentik.calls) == n


def test_scan_says_when_authentik_gives_no_answer(checker, authentik):
    authentik.mode = 'error'
    got = checker['_ak_group_names_scan'](force=True)
    assert got['available'] is False and 'error' in got


def test_group_names_route_needs_a_console_login_and_the_page_shows_the_warning():
    route = APP[APP.index("@app.route('/api/authentik/group-names')"):][:200]
    assert '@login_required' in route
    assert "target=_ak_group_names_watch" in APP
    page = (REPO / 'templates' / 'authentik.html').read_text(encoding='utf-8')
    assert 'id="group-names-warning" style="display:none' in page
    js = page[page.index('async function refreshGroupNames()'):][:1400]
    assert "/api/authentik/group-names" in js
    # Group names are free text: they go into the page escaped.
    assert 'escapeHtml(f.name)' in js and 'escapeHtml(n)' in js
    assert 'refreshGroupNames();' in page
