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
"""MediaMTX editor overlay: nested stream paths (v10.2.4, GH #82).

OBS and DJI publish to rtmp://host/live/<name>, so stream names are nested. The
overlay assumed they were not:

1. /hls-proxy/ checked the FIRST path segment's visibility, so a PRIVATE live/<name>
   was looked up as "live" (no entry -> public) and served to anyone.
2. The hlsviewer password kept its YAML quotes, so MediaMTX refused every off-box
   viewer (on-box requests pass as the loopback `any` user, which hid it).
3. /watch/<name> could not match live/<name> (404) — and it wrote the name unescaped
   into a JS string, so a quote in the URL ran script.

v10.2.6 made /hls-proxy/ the stream domain's only HLS path (Caddy sends it here, behind
the login, instead of straight to MediaMTX), so it has to carry MediaMTX's ?session=
query and stream segments. /api/viewer/hlscred, which gave every viewer the all-paths
credential, is gone.

Exercised on the real overlay applied to a bare Flask app, MediaMTX stubbed.
"""

import base64
import importlib.util
import json
import pathlib
import urllib.parse

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent


SEGMENT = bytes(range(256)) * 600   # > one 64 KiB read, so the proxy has to loop


class _Resp:
    def __init__(self, body=b'#EXTM3U\n', ctype='application/vnd.apple.mpegurl'):
        self._body = body
        self.headers = {'Content-Type': ctype, 'Content-Length': str(len(body))}
        self.closed = False

    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self._body)
        out, self._body = self._body[:n], self._body[n:]
        return out

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / 'mediamtx.yml'
    cfg.write_text('authInternalUsers:\n- user: any\n  ips: [127.0.0.1]\n'
                   '- user: hlsviewer\n  pass: "s3cretPW"\n  permissions:\n  - action: read\n')
    monkeypatch.setenv('MEDIAMTX_CONFIG', str(cfg))
    spec = importlib.util.spec_from_file_location('overlay_under_test', REPO / 'mediamtx_ldap_overlay.py')
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    vis = tmp_path / 'stream_visibility.json'
    vis.write_text(json.dumps({'live/secret': 'private', 'secret': 'private'}))
    monkeypatch.setattr(ov, 'VISIBILITY_FILE', str(vis))
    fetched = []

    # ops #1082: the overlay reads a person's groups from Authentik's user API, not from
    # the X-Authentik-Groups header. This is that API's answer for the three people below.
    monkeypatch.setattr(ov, 'AK_TOKEN', 'box-token')
    ak_groups = {'alice': ['vid_private'], 'bob': ['vid_public'], 'akadmin': ['authentik Admins']}

    def fake_urlopen(req, timeout=None, context=None):
        url = req.full_url
        if '/api/v3/core/users/' in url:
            name = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get('username', [''])[0]
            rows = [{'pk': 1, 'username': name, 'is_active': True,
                     'groups_obj': [{'name': g} for g in ak_groups[name]]}] if name in ak_groups else []
            return _Resp(json.dumps({'results': rows}).encode(), 'application/json')
        if '/v3/paths/list' in url:
            r = _Resp(json.dumps({'items': [{'name': 'live/public', 'ready': True},
                                            {'name': 'live/secret', 'ready': True}]}).encode(),
                      'application/json')
        elif url.split('?')[0].endswith('.ts'):
            r = _Resp(SEGMENT, 'video/mp2t')
        else:
            r = _Resp()
        fetched.append({'url': url, 'auth': req.get_header('Authorization'), 'resp': r})
        return r
    monkeypatch.setattr(ov.urllib.request, 'urlopen', fake_urlopen)
    app = flask.Flask('overlay-test')
    app.secret_key = 'test'
    ov.apply_ldap_overlay(app)
    return ov, app.test_client(), fetched


VIEWER_PRIVATE = {'X-Authentik-Username': 'alice', 'X-Authentik-Groups': 'vid_private'}
VIEWER_PUBLIC = {'X-Authentik-Username': 'bob', 'X-Authentik-Groups': 'vid_public'}
ADMIN = {'X-Authentik-Username': 'akadmin', 'X-Authentik-Groups': 'authentik Admins'}


def test_private_nested_stream_is_not_served_to_anonymous(env):
    _, c, fetched = env
    for p in ('/hls-proxy/live/secret/index.m3u8', '/hls-proxy/live/secret/abc_seg7.mp4',
              '/hls-proxy/live/secret/', '/hls-proxy/live/secret', '/hls-proxy/secret/index.m3u8',
              '/hls-proxy/secret/', '/hls-proxy/secret'):
        assert c.get(p).status_code == 403, p
    assert fetched == []


def test_public_nested_stream_is_proxied_to_the_same_path(env):
    _, c, fetched = env
    r = c.get('/hls-proxy/live/public/index.m3u8')
    assert r.status_code == 200 and r.data == b'#EXTM3U\n'
    assert fetched[-1]['url'] == 'http://127.0.0.1:8888/live/public/index.m3u8'


def test_private_nested_stream_follows_vid_private(env):
    _, c, _ = env
    assert c.get('/hls-proxy/live/secret/index.m3u8', headers=VIEWER_PRIVATE).status_code == 200
    assert c.get('/hls-proxy/live/secret/index.m3u8', headers=VIEWER_PUBLIC).status_code == 403


@pytest.mark.parametrize('path', [
    '/hls-proxy/live/pub/../secret/index.m3u8',
    '/hls-proxy/pub/../secret/index.m3u8',
    '/hls-proxy/live/./secret/index.m3u8',
    '/hls-proxy/live//secret/index.m3u8',
    '/hls-proxy/live/pub/..%2Fsecret/index.m3u8',
    '/hls-proxy/live/secret%3F/index.m3u8',
])
def test_names_another_layer_could_normalise_are_refused(env, path):
    # The visibility lookup is literal; a name that a proxy or MediaMTX might resolve
    # to a different (private) path must never be looked up as an unknown -> public one.
    _, c, fetched = env
    r = c.get(path, environ_overrides={'PATH_INFO': path.replace('%2F', '/').replace('%3F', '?')})
    assert r.status_code == 404, path
    assert fetched == []


def test_hls_password_reaches_mediamtx_without_its_yaml_quotes(env):
    _, c, fetched = env
    c.get('/hls-proxy/live/public/index.m3u8')
    assert fetched[-1]['auth'] == 'Basic ' + base64.b64encode(b'hlsviewer:s3cretPW').decode()


def test_yaml_scalar_text(env):
    ov = env[0]
    assert ov._yaml_scalar_text(' "s3cretPW" ') == 's3cretPW'
    assert ov._yaml_scalar_text('"a\\"b\\\\c"') == 'a"b\\c'
    assert ov._yaml_scalar_text("'it''s'") == "it's"
    assert ov._yaml_scalar_text(' plain ') == 'plain'
    assert ov._yaml_scalar_text('"') == '"'


def test_watch_serves_nested_paths_and_keeps_private_private(env):
    _, c, _ = env
    r = c.get('/watch/live/xbotgo')
    assert r.status_code == 200 and b'url="/hls-proxy/live/xbotgo/index.m3u8"' in r.data
    assert c.get('/watch/teststream').status_code == 200
    assert c.get('/watch/live/secret').status_code == 403
    assert c.get('/watch/live/secret', headers=VIEWER_PRIVATE).status_code == 200


@pytest.mark.parametrize('name', ['";alert(1);"', 'live/<script>', "x'y", 'live/../secret', 'a b'])
def test_watch_refuses_names_that_are_not_plain_path_segments(env, name):
    # Before v10.2.4 `/watch/";alert(1);"` returned 200 with the quote inside the page's
    # JS string literal — reflected script on an anonymous page.
    _, c, _ = env
    r = c.get('/watch/x', environ_overrides={'PATH_INFO': '/watch/' + name})
    assert r.status_code == 404
    assert b'alert' not in r.data and b'<script>' not in r.data


# ── v10.2.6: /hls-proxy/ is the stream domain's only HLS path ────────────────────


def test_mediamtx_session_query_reaches_mediamtx(env):
    # MediaMTX >= 1.18 writes ?session=<id> into every variant and segment URL and
    # answers 401 without it (measured test6, v1.20.0). Before v10.2.6 the query was
    # dropped: the first playlist played, nothing after it did.
    _, c, fetched = env
    r = c.get('/hls-proxy/live/public/main_stream.m3u8?session=5bca2987-3c7b')
    assert r.status_code == 200
    assert fetched[-1]['url'] == 'http://127.0.0.1:8888/live/public/main_stream.m3u8?session=5bca2987-3c7b'
    c.get('/hls-proxy/live/public/seg11.ts?session=abc&_HLS_msn=4&_HLS_part=1')
    assert fetched[-1]['url'] == 'http://127.0.0.1:8888/live/public/seg11.ts?session=abc&_HLS_msn=4&_HLS_part=1'
    c.get('/hls-proxy/live/public/index.m3u8')
    assert fetched[-1]['url'] == 'http://127.0.0.1:8888/live/public/index.m3u8'


def test_a_query_never_opens_a_private_stream(env):
    _, c, fetched = env
    assert c.get('/hls-proxy/live/secret/index.m3u8?session=x').status_code == 403
    assert c.get('/hls-proxy/live/secret/seg1.ts?x=../../live/public').status_code == 403
    assert fetched == []


def test_segments_stream_through_with_their_type(env):
    _, c, fetched = env
    r = c.get('/hls-proxy/live/public/seg11.ts?session=abc')
    assert r.status_code == 200 and r.data == SEGMENT
    assert r.headers['Content-Type'] == 'video/mp2t'
    assert r.headers['Content-Length'] == str(len(SEGMENT))
    assert 'no-cache' not in r.headers.get('Cache-Control', '')
    assert fetched[-1]['resp'].closed


def test_playlists_are_not_cached(env):
    _, c, _ = env
    r = c.get('/hls-proxy/live/public/index.m3u8')
    assert r.headers['Content-Type'] == 'application/vnd.apple.mpegurl'
    assert r.headers['Cache-Control'] == 'no-cache'


def test_private_stream_plays_on_the_session_cookie_alone(env):
    # The session the viewer page set is enough on its own; a request carrying no
    # identity headers still gets the viewer's own access, no more.
    _, c, _ = env
    assert c.get('/hls-proxy/live/secret/index.m3u8').status_code == 403
    assert c.get('/viewer', headers=VIEWER_PRIVATE).status_code == 200
    assert c.get('/hls-proxy/live/secret/index.m3u8').status_code == 200


def test_public_viewer_session_still_cannot_play_private(env):
    _, c, _ = env
    assert c.get('/viewer', headers=VIEWER_PUBLIC).status_code == 200
    assert c.get('/hls-proxy/live/secret/index.m3u8').status_code == 403
    assert c.get('/hls-proxy/live/public/index.m3u8').status_code == 200


def test_admin_session_plays_private(env):
    _, c, _ = env
    c.get('/', headers=ADMIN)
    assert c.get('/hls-proxy/live/secret/index.m3u8').status_code == 200


@pytest.mark.parametrize('who', [None, VIEWER_PUBLIC, VIEWER_PRIVATE, ADMIN])
def test_no_route_hands_the_hlsviewer_credential_to_a_browser(env, who):
    # /api/viewer/hlscred gave the credential that reads EVERY path to any viewer,
    # vid_public included. Nothing used it; it is gone.
    _, c, _ = env
    r = c.get('/api/viewer/hlscred', headers=who or {})
    assert r.status_code in (302, 404)
    assert b's3cretPW' not in r.data


def test_viewer_stream_list_points_at_the_overlay_not_8888(env):
    _, c, _ = env
    r = c.get('/api/viewer/streams', headers=VIEWER_PRIVATE)
    assert {s['name']: s['hls_url'] for s in r.get_json()['streams']} == {
        'live/public': '/hls-proxy/live/public/index.m3u8',
        'live/secret': '/hls-proxy/live/secret/index.m3u8',
    }
    r = c.get('/api/viewer/streams', headers=VIEWER_PUBLIC)
    assert [s['name'] for s in r.get_json()['streams']] == ['live/public']


def test_viewer_page_keeps_the_slash_in_nested_names(env):
    # encodeURIComponent('live/x') is 'live%2Fx' — one segment, not the stream's path.
    html = env[0].ACTIVE_STREAMS_VIEWER_HTML
    assert "name.split('/').map(encodeURIComponent).join('/')" in html
    assert "'/hls-proxy/'+streamPath(name)+'/index.m3u8'" in html
    assert "'/watch/'+streamPath(name)" in html
    assert "'/hls-proxy/'+encodeURIComponent(name)" not in html
