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
"""MediaMTX editor overlay: share links made by signed-in viewers (ops #1272).

A viewer makes a link only for a stream they may watch, the link ends within 24
hours, and only an admin lists links. The overlay is applied to a bare Flask app that
has stand-ins for the editor's two share-link routes, so a request that reaches a
stand-in was let through by the overlay.
"""

import json
import importlib.util
import pathlib
import urllib.parse

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent


class _Resp:
    def __init__(self, body):
        self._body = body
        self.headers = {'Content-Type': 'application/json'}

    def read(self, n=-1):
        return self._body

    def close(self):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / 'mediamtx.yml'
    cfg.write_text('authInternalUsers:\n- user: any\n  ips: [127.0.0.1]\n')
    monkeypatch.setenv('MEDIAMTX_CONFIG', str(cfg))
    spec = importlib.util.spec_from_file_location('overlay_share_under_test', REPO / 'mediamtx_ldap_overlay.py')
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    vis = tmp_path / 'stream_visibility.json'
    vis.write_text(json.dumps({'secret': 'private', 'live': 'private', 'cam/one': 'private'}))
    monkeypatch.setattr(ov, 'VISIBILITY_FILE', str(vis))
    monkeypatch.setattr(ov, 'SHARE_LINKS_FILE', str(tmp_path / 'share_links.json'))
    monkeypatch.setattr(ov, 'SHARE_LINKS_CAP_MARKER_FILE', str(tmp_path / 'share_links_capped.json'))
    monkeypatch.setattr(ov, 'AK_TOKEN', 'box-token')
    ak_groups = {'alice': ['vid_private'], 'bob': ['vid_public'], 'carol': [],
                 'akadmin': ['authentik Admins']}

    def fake_urlopen(req, timeout=None, context=None):
        name = urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query).get('username', [''])[0]
        rows = [{'pk': 1, 'username': name, 'is_active': True,
                 'groups_obj': [{'name': g} for g in ak_groups[name]]}] if name in ak_groups else []
        return _Resp(json.dumps({'results': rows}).encode())
    monkeypatch.setattr(ov.urllib.request, 'urlopen', fake_urlopen)

    app = flask.Flask('overlay-share-test')
    app.secret_key = 'test'
    reached = []

    @app.route('/api/share-links')
    def _list():
        reached.append('list')
        return flask.jsonify({'links': [{'token': 'tok'}]})

    @app.route('/api/share-links/generate', methods=['POST'])
    def _generate():
        reached.append('generate')
        return flask.jsonify({'ok': True})

    ov.apply_ldap_overlay(app)
    return app.test_client(), reached


def _h(name):
    return {'X-Authentik-Username': name}


def _gen(c, who, stream, **extra):
    body = {'stream': stream}
    body.update(extra)
    return c.post('/api/share-links/generate', json=body, headers=_h(who))


@pytest.mark.parametrize('who', ['alice', 'bob', 'carol'])
def test_viewers_do_not_get_the_list(env, who):
    c, reached = env
    assert c.get('/api/share-links', headers=_h(who)).status_code in (302, 403)
    # a session that already holds the viewer role and sends no identity header
    assert c.get('/api/share-links').status_code in (302, 403)
    assert 'list' not in reached


def test_admin_still_gets_the_list(env):
    c, reached = env
    r = c.get('/api/share-links', headers=_h('akadmin'))
    assert r.status_code == 200 and 'tok' in r.get_data(as_text=True)


def test_public_viewer_cannot_make_a_link_for_a_private_stream(env):
    c, reached = env
    for stream in ('secret', 'live/anything', 'cam/one'):
        r = _gen(c, 'bob', stream, ttl=14400)
        assert r.status_code == 403, stream
    assert reached == []


def test_private_viewer_can_make_a_link_for_a_private_stream(env):
    c, reached = env
    assert _gen(c, 'alice', 'secret', ttl=14400).status_code == 200
    assert reached == ['generate']


def test_public_viewer_can_make_a_link_for_a_public_stream(env):
    c, reached = env
    assert _gen(c, 'bob', 'open', ttl=14400).status_code == 200
    assert reached == ['generate']


def test_signed_in_with_no_video_group_makes_no_link(env):
    c, reached = env
    assert _gen(c, 'carol', 'open', ttl=14400).status_code == 403
    assert reached == []


@pytest.mark.parametrize('extra', [{}, {'ttl': 0}, {'ttl': None}, {'ttl': -5}, {'ttl': 86401},
                                   {'ttl': '14400'}, {'ttl': True}, {'ttl': 1.5}, {'ttl': [14400]}])
def test_viewer_link_must_end_within_24_hours(env, extra):
    c, reached = env
    assert _gen(c, 'alice', 'open', **extra).status_code == 400
    assert reached == []


@pytest.mark.parametrize('ttl', [3600, 14400, 86400])
def test_viewer_link_with_a_good_lifetime_goes_through(env, ttl):
    c, reached = env
    assert _gen(c, 'bob', 'open', ttl=ttl).status_code == 200


@pytest.mark.parametrize('stream', ['', 'a/../secret', 'a b', '<x>', 'live//x'])
def test_viewer_link_for_a_bad_stream_name_is_refused(env, stream):
    c, reached = env
    assert _gen(c, 'alice', stream, ttl=14400).status_code in (400, 403)
    assert reached == []


def test_admin_can_still_make_a_link_that_never_ends(env):
    c, reached = env
    assert _gen(c, 'akadmin', 'secret', ttl=0).status_code == 200
    assert reached == ['generate']


# ── Links made before the update that never end (ops #1272) ───────────────────

def _overlay_in(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('overlay_cap_under_test', REPO / 'mediamtx_ldap_overlay.py')
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    monkeypatch.setattr(ov, 'SHARE_LINKS_FILE', str(tmp_path / 'share_links.json'))
    monkeypatch.setattr(ov, 'SHARE_LINKS_CAP_MARKER_FILE', str(tmp_path / 'share_links_capped.json'))
    return ov


def _old_links(tmp_path):
    (tmp_path / 'share_links.json').write_text(json.dumps({
        'oldA': {'stream': 'cam1', 'expires': None, 'ttl_label': 'Until revoked'},
        'oldB': {'stream': 'cam2', 'ttl_label': 'Until revoked'},
        'timed': {'stream': 'cam3', 'expires': 2000000000, 'ttl_label': '4 hours'},
    }))


def test_never_ending_links_end_24_hours_after_the_update(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    _old_links(tmp_path)
    assert ov.cap_never_ending_share_links(now=1700000000) == 2
    links = json.loads((tmp_path / 'share_links.json').read_text())
    assert links['oldA']['expires'] == links['oldB']['expires'] == 1700000000 + 86400
    assert links['timed']['expires'] == 2000000000
    assert links['oldA']['stream'] == 'cam1'


def test_cap_runs_once_so_a_later_admin_link_that_never_ends_is_kept(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    _old_links(tmp_path)
    ov.cap_never_ending_share_links()
    links = json.loads((tmp_path / 'share_links.json').read_text())
    links['made-later'] = {'stream': 'cam1', 'expires': None}
    (tmp_path / 'share_links.json').write_text(json.dumps(links))
    assert ov.cap_never_ending_share_links() == 0
    assert json.loads((tmp_path / 'share_links.json').read_text())['made-later']['expires'] is None


def test_a_box_with_no_links_still_gets_the_marker(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    assert ov.cap_never_ending_share_links() == 0
    assert (tmp_path / 'share_links_capped.json').exists()


def test_an_unreadable_links_file_is_never_written_over(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    (tmp_path / 'share_links.json').write_text('{not json')
    assert ov.cap_never_ending_share_links() is None
    assert (tmp_path / 'share_links.json').read_text() == '{not json'
    assert not (tmp_path / 'share_links_capped.json').exists()


def test_the_overlay_does_the_cap_when_it_starts(tmp_path, monkeypatch):
    """Applying the overlay (the editor start) caps the old links, so an infra-TAK box needs no new editor."""
    cfg = tmp_path / 'mediamtx.yml'
    cfg.write_text('authInternalUsers:\n- user: any\n  ips: [127.0.0.1]\n')
    monkeypatch.setenv('MEDIAMTX_CONFIG', str(cfg))
    ov = _overlay_in(tmp_path, monkeypatch)
    _old_links(tmp_path)
    app = flask.Flask('overlay-cap-start-test')
    app.secret_key = 'test'
    ov.apply_ldap_overlay(app)
    links = json.loads((tmp_path / 'share_links.json').read_text())
    assert links['oldA']['expires'] and links['oldB']['expires']
