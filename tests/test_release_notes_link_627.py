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
"""An update notice links to that release's notes (infra-TAK #627, ops #1045).

A user who sees "update" next to TAK Portal, CloudTAK or another app must be able to read what
changed without looking on GitHub by hand. The console builds the link, and it must:
  * appear only while an update is on offer, never on an up-to-date or unknown card;
  * point at github.com and at the release the Update will install;
  * never be built from text a container or remote host sent (ops #827 made those untrusted);
  * show on the dashboard card (server-rendered AND the 30 s refresh) and on the TAK Portal and
    CloudTAK pages.
The functions are run from app.py's own source, so a change there changes these results.
"""
import json
import pathlib
import re
import shutil
import subprocess
import types
import urllib.parse

import jinja2
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
CONSOLE = (ROOT / 'templates' / 'console.html').read_text(encoding='utf-8')

BLOCK = APP[APP.index('_MODULE_VERSION_RE = re.compile'):APP.index("@app.route('/api/modules/version')")]


def _ns(**extra):
    ns = {'re': re, 'urllib': urllib, 'print': lambda *a, **k: None, 'time': __import__('time')}
    ns.update(extra)
    exec(compile(BLOCK, 'app.py[#627 block]', 'exec'), ns)
    return ns


@pytest.fixture(scope='module')
def url():
    return _ns()['_module_release_notes_url']


def _upd(**kw):
    return dict({'update_available': True}, **kw)


# ── the link points at the release the Update installs ──────────────────────────────────────

def test_takportal_links_to_the_latest_release(url):
    assert url('takportal', _upd(latest='2.0.29', channel='release')) == \
        'https://github.com/ValleyTacticalSolutions/TAK-Portal/releases/latest'


def test_takportal_beta_channel_gets_no_link(url):
    """Beta Update follows the main branch, so a release page would describe the wrong thing."""
    assert url('takportal', _upd(latest='2.0.29', channel='beta')) == ''


@pytest.mark.parametrize('key,latest,expected', [
    ('cloudtak', '13.117.2', 'https://github.com/dfpc-coe/CloudTAK/releases/tag/v13.117.2'),
    ('authentik', '2026.5.6', 'https://github.com/goauthentik/authentik/releases/tag/version%2F2026.5.6'),
    ('webodm', '4.0.1', 'https://github.com/OpenDroneMap/WebODM/releases/tag/v4.0.1'),
])
def test_tagged_modules_link_to_their_exact_tag(url, key, latest, expected):
    assert url(key, _upd(latest=latest)) == expected


def test_mediamtx_binary_links_to_its_tag_and_editor_only_to_the_installer(url):
    assert url('mediamtx', _upd(latest='1.21.4', binary_update_available=True)) == \
        'https://github.com/bluenviron/mediamtx/releases/tag/v1.21.4'
    assert url('mediamtx', _upd(latest='1.21.4', binary_update_available=False, editor_update_available=True)) == \
        'https://github.com/takwerx/mediamtx-installer/releases'
    assert url('mediamtx', _upd(latest='1.21.4', binary_update_available=False,
                                editor_update_available=False)) == ''


@pytest.mark.parametrize('latest,expected', [
    ('0.82.1', 'https://github.com/netbirdio/netbird/releases/tag/v0.82.1'),
    ('0.82.1 · dash 2.96.1', 'https://github.com/netbirdio/netbird/releases/tag/v0.82.1'),
    ('dash 2.96.1', 'https://github.com/netbirdio/dashboard/releases/tag/v2.96.1'),
])
def test_netbird_links_the_server_release_then_the_dashboard(url, latest, expected):
    assert url('netbird', _upd(latest=latest)) == expected


# ── no link when there is nothing to link to ─────────────────────────────────────────────────

@pytest.mark.parametrize('key', ['takportal', 'cloudtak', 'authentik', 'mediamtx', 'netbird', 'webodm'])
def test_no_link_without_an_update(url, key):
    info = {'update_available': False, 'latest': '9.9.9', 'binary_update_available': True,
            'editor_update_available': True}
    assert url(key, info) == ''
    assert url(key, {'latest': '9.9.9'}) == ''


@pytest.mark.parametrize('key', ['caddy', 'fail2ban', 'takserver', 'fedhub', 'nodered', 'guarddog', 'nope'])
def test_modules_without_a_public_release_page_get_no_link(url, key):
    assert url(key, _upd(latest='1.2.3')) == ''


def test_missing_or_odd_info_gives_no_link(url):
    assert url('cloudtak', None) == ''
    assert url('cloudtak', 'update') == ''
    assert url('cloudtak', _upd()) == ''
    assert url('cloudtak', _upd(latest=None)) == ''
    assert url('cloudtak', _upd(latest=['13.1.0'])) == ''


# ── a hostile version never reaches the link ─────────────────────────────────────────────────

HOSTILE = ['1.0"><script>pwn()</script>', '../../evil', '1.2.3/../../x', 'javascript:alert(1)',
           '1.2.3 onmouseover=pwn()', 'latest', 'v1.2.3', '1.2.3-rc1', '', ' ']


@pytest.mark.parametrize('bad', HOSTILE)
@pytest.mark.parametrize('key', ['cloudtak', 'authentik', 'webodm', 'mediamtx', 'netbird'])
def test_hostile_version_is_refused(url, key, bad):
    got = url(key, _upd(latest=bad, binary_update_available=True))
    assert got == ''


def test_every_link_is_a_github_https_url(url):
    cases = [('takportal', {}), ('cloudtak', {'latest': '13.1.0'}), ('authentik', {'latest': '2026.5.6'}),
             ('mediamtx', {'latest': '1.2.3', 'binary_update_available': True}),
             ('mediamtx', {'editor_update_available': True}), ('netbird', {'latest': '0.1.2'}),
             ('webodm', {'latest': '4.0.1'})]
    for key, extra in cases:
        got = url(key, _upd(**extra))
        assert got.startswith('https://github.com/'), (key, got)
        assert re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases(/latest|/tag/[A-Za-z0-9_.%-]+)?', got), got


# ── the dashboard card data (the same function /api/modules/version serves) ─────────────────

def _card_data(version_info, key='takportal'):
    """get_all_module_versions() with one installed module whose helper returns version_info."""
    ns = _ns()
    ns.update({
        'detect_modules': lambda: {key: {'installed': True}},
        'load_settings': lambda: {},
        'update_cache': {},
        '_node_card_gaps': lambda: {},
        '_get_takportal_version_info': lambda: version_info,
        '_get_cloudtak_version_info': lambda: version_info,
    })
    return ns['get_all_module_versions']()


def test_card_data_carries_the_link_while_an_update_is_on_offer():
    data = _card_data({'version': '2.0.14', 'latest': '2.0.29', 'update_available': True, 'channel': 'release'})
    assert data['takportal']['release_notes_url'] == \
        'https://github.com/ValleyTacticalSolutions/TAK-Portal/releases/latest'


def test_card_data_has_no_link_when_up_to_date():
    data = _card_data({'version': '2.0.29', 'latest': '2.0.29', 'update_available': False, 'channel': 'release'})
    assert 'release_notes_url' not in data['takportal']


def test_card_data_does_not_link_a_version_that_failed_the_ops827_check():
    """The module sent a non-version string; _safe_module_version_info blanks it, so no link."""
    data = _card_data({'version': '1.0.0', 'latest': '13.1.0"><b>', 'update_available': True}, key='cloudtak')
    assert 'release_notes_url' not in data['cloudtak']


def test_card_data_does_not_change_the_helpers_own_dict():
    cached = {'version': '13.0.0', 'latest': '13.1.0', 'update_available': True}
    data = _card_data(cached, key='cloudtak')
    assert data['cloudtak']['release_notes_url'].endswith('/releases/tag/v13.1.0')
    assert 'release_notes_url' not in cached


# ── the server-rendered dashboard card ───────────────────────────────────────────────────────

CARD = next(l for l in CONSOLE.split('\n') if 'module-version-line' in l and 'module_versions.get(key)' in l)


def _render_card(key, v):
    env = jinja2.Environment(autoescape=True)
    return env.from_string(CARD).render(module_versions={key: v}, key=key)


@pytest.mark.parametrize('key', ['takportal', 'cloudtak', 'authentik', 'mediamtx', 'netbird', 'webodm'])
def test_card_shows_whats_new_next_to_update(key):
    link = 'https://github.com/x/y/releases/tag/v1.2.3'
    html = _render_card(key, {'version': '1.0.0', 'update_available': True, 'release_notes_url': link})
    assert 'href="%s"' % link in html
    assert "What's new" in html
    assert 'rel="noopener noreferrer"' in html and 'target="_blank"' in html


@pytest.mark.parametrize('key', ['takportal', 'cloudtak', 'authentik', 'mediamtx', 'netbird', 'webodm'])
def test_card_has_no_link_without_an_update_or_url(key):
    link = 'https://github.com/x/y/releases/tag/v1.2.3'
    assert "What's new" not in _render_card(key, {'version': '1.0.0', 'update_available': False,
                                                  'release_notes_url': link})
    assert "What's new" not in _render_card(key, {'version': '1.0.0', 'update_available': True})


def test_card_escapes_the_url():
    html = _render_card('takportal', {'version': '1', 'update_available': True,
                                      'release_notes_url': 'https://github.com/a"><script>pwn()</script>'})
    assert '<script>' not in html


# ── the 30 s refresh of the card ─────────────────────────────────────────────────────────────

def _function(src, name):
    lines = src.split('\n')
    for i, line in enumerate(lines):
        if re.match(r'function\s+%s\s*\(' % re.escape(name), line):
            for j in range(i + 1, len(lines)):
                if lines[j].rstrip() == '}':
                    return '\n'.join(lines[i:j + 1])
    raise AssertionError('function %s not found' % name)


def _refresh(data):
    node = shutil.which('node')
    if node is None:
        pytest.skip('no node on PATH, so the card refresh script is unexercised')
    program = ('var __els = {};\n'
               'var document = {getElementById: function(id){ if(!__els[id]) __els[id] = {id:id, innerHTML:"", style:{display:"none"}}; return __els[id]; }};\n'
               'function escapeHtml(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")'
               '.replace(/"/g,"&quot;").replace(/\'/g,"&#39;"); }\n'
               'function fetch(){ return Promise.resolve({json: function(){ return Promise.resolve(%s); }}); }\n'
               '%s\n'
               'refreshModuleVersions();\n'
               'setTimeout(function(){ var o={}; for(var k in __els) o[k]=__els[k].innerHTML; console.log(JSON.stringify(o)); }, 20);\n'
               % (json.dumps(data), _function(CONSOLE, 'refreshModuleVersions')))
    r = subprocess.run([node, '-'], input=program, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_refresh_adds_the_link_for_a_github_url():
    link = 'https://github.com/dfpc-coe/CloudTAK/releases/tag/v13.117.2'
    out = _refresh({'cloudtak': {'version': '13.117.0', 'latest': '13.117.2', 'update_available': True,
                                 'release_notes_url': link}})['module-version-cloudtak']
    assert 'href="%s"' % link in out
    assert 'What\'s new' in out
    assert 'rel="noopener noreferrer"' in out


@pytest.mark.parametrize('bad', ['javascript:alert(1)', 'http://github.com/x', 'https://evil.example/x',
                                 'data:text/html,x', 5, None])
def test_refresh_refuses_any_url_that_is_not_https_github(bad):
    out = _refresh({'takportal': {'version': '2.0.1', 'update_available': True,
                                  'release_notes_url': bad}})['module-version-takportal']
    assert 'What\'s new' not in out and 'href' not in out


def test_refresh_hides_the_link_when_the_update_is_done():
    out = _refresh({'takportal': {'version': '2.0.29', 'update_available': False,
                                  'release_notes_url': 'https://github.com/x/y/releases/latest'}})
    assert 'What\'s new' not in out['module-version-takportal']


def test_refresh_escapes_a_quote_in_the_url():
    out = _refresh({'takportal': {'version': '1', 'update_available': True,
                                  'release_notes_url': 'https://github.com/x" onmouseover="pwn()'}})['module-version-takportal']
    assert '" onmouseover="' not in out


# ── the TAK Portal and CloudTAK pages ────────────────────────────────────────────────────────

def _render_page_snippet(template, marker_re, **ctx):
    src = (ROOT / 'templates' / template).read_text(encoding='utf-8')
    lines = [l for l in src.split('\n') if re.search(marker_re, l)]
    assert lines, marker_re
    env = jinja2.Environment(autoescape=True)
    return [env.from_string(l).render(**ctx) for l in lines]


def test_takportal_page_banners_show_the_link_only_when_an_update_is_offered():
    base = dict(container_info={}, portal_version='v2.0.14', portal_latest='2.0.29', portal_channel='release')
    on = _render_page_snippet('takportal.html', r'portal_update_available and portal_latest', **base,
                              portal_update_available=True,
                              portal_release_notes_url='https://github.com/x/y/releases/latest')
    assert len(on) == 2  # the running banner and the stopped banner
    assert all('href="https://github.com/x/y/releases/latest"' in h and "What's new" in h for h in on)
    off = _render_page_snippet('takportal.html', r'portal_update_available and portal_latest', **base,
                               portal_update_available=False, portal_release_notes_url='')
    assert all("What's new" not in h for h in off)
    none = _render_page_snippet('takportal.html', r'portal_update_available and portal_latest', **base,
                                portal_update_available=True, portal_release_notes_url='')
    assert all("What's new" not in h and 'available' in h for h in none)


def test_cloudtak_page_heading_shows_the_link_only_when_an_update_is_offered():
    ver = {'version': '13.117.0', 'latest': '13.117.2', 'update_available': True,
           'release_notes_url': 'https://github.com/dfpc-coe/CloudTAK/releases/tag/v13.117.2'}
    on = _render_page_snippet('cloudtak.html', r'cloudtak_version_info\.update_available and', cloudtak_version_info=ver,
                              cloudtak_icon='')
    assert 'href="%s"' % ver['release_notes_url'] in on[0]
    ver2 = dict(ver, update_available=False)
    off = _render_page_snippet('cloudtak.html', r'cloudtak_version_info\.update_available and', cloudtak_version_info=ver2,
                               cloudtak_icon='')
    assert "What's new" not in off[0] and 'latest' in off[0]


def test_authentik_page_notices_show_the_link_only_when_an_update_is_offered():
    """Four notices: running and stopped, on the dev channel and on main."""
    src = (ROOT / 'templates' / 'authentik.html').read_text(encoding='utf-8')
    lines = [l for l in src.split('\n') if 'ak_version_info.update_available and ak_version_info.latest' in l]
    assert len(lines) == 2  # the running banner and the stopped banner, each with both channels
    env = jinja2.Environment(autoescape=True)
    link = 'https://github.com/goauthentik/authentik/releases/tag/version%2F2026.8.6'
    for channel in ('dev', 'main'):
        for line in lines:
            base = dict(ak_version_info={'version': '2026.8.5', 'latest': '2026.8.6', 'channel': channel,
                                         'vetted_release': '2026.8.5', 'update_available': True,
                                         'release_notes_url': link},
                        ak={'running': True, 'installed': True}, authentik_logo_url='', container_info={})
            on = env.from_string(line).render(**base)
            assert 'href="%s"' % link in on and "What's new" in on, channel
            base['ak_version_info'] = dict(base['ak_version_info'], update_available=False)
            assert "What's new" not in env.from_string(line).render(**base), channel
            base['ak_version_info'] = dict(base['ak_version_info'], update_available=True, release_notes_url='')
            off = env.from_string(line).render(**base)
            assert "What's new" not in off and 'v2026.8.6 available' in off, channel


def test_with_release_notes_url_copies_and_leaves_empty_alone():
    with_url = _ns()['_with_release_notes_url']
    cached = {'version': '2026.8.5', 'latest': '2026.8.6', 'update_available': True}
    got = with_url('authentik', cached)
    assert got['release_notes_url'].endswith('/releases/tag/version%2F2026.8.6')
    assert 'release_notes_url' not in cached
    assert with_url('authentik', {}) == {}
    assert with_url('authentik', None) is None


def test_pages_are_given_the_link_by_their_routes():
    assert "portal_release_notes_url = _module_release_notes_url('takportal', vinfo)" in APP
    assert 'portal_release_notes_url=portal_release_notes_url' in APP
    assert "ct_vinfo = _with_release_notes_url('cloudtak', ct_vinfo)" in APP
    assert "ak_version_info=_with_release_notes_url('authentik', _get_authentik_version_info())" in APP
